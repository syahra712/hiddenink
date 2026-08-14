"""Container metadata removal.

One rule decides everything in this module:

    Remove metadata that identifies **the user**.
    Keep metadata that identifies the content as **AI-generated**.

Those two things are routinely bundled together and treated as one blob, which
is why the tools in this space either strip nothing useful or strip the
disclosure along with the private data. They are not the same:

* An EXIF GPS tag, a camera serial number, an author name, a Windows username
  embedded in a document path -- these identify a person. Publishing them is a
  privacy leak, and removing them before publishing is ordinary practice.
* A C2PA manifest says "a model was involved in making this". Removing it makes
  AI-generated content look human-made, which is the thing this project does
  not do.

So a PNG loses its ``tEXt`` comments and ``eXIf`` block and keeps its ``caBX``
manifest. If you need the manifest gone as well, this is not the tool -- and
the report says so rather than pretending the file is now unmarked, because
C2PA soft bindings live in the pixels and survive metadata removal anyway.
"""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO

from ..report import Report, Undeterminable
from .jpeg import JPEG_SIGNATURE
from .png import PNG_SIGNATURE

__all__ = [
    "CLEANABLE",
    "PROVENANCE_PRESERVED_NOTICE",
    "clean_png",
    "clean_jpeg",
    "clean_bytes",
]

#: Formats whose metadata this module can rewrite.
CLEANABLE = ("png", "jpeg")

PROVENANCE_PRESERVED_NOTICE = (
    "C2PA provenance manifest: PRESERVED, deliberately. marklens removes "
    "metadata that identifies you and keeps metadata that discloses AI "
    "involvement. Removing the manifest would not make the file unmarked in any "
    "case: C2PA soft bindings are carried in the pixels."
)

# --- PNG ---------------------------------------------------------------------

#: Chunks carrying user-identifying metadata. Everything not listed is kept,
#: which is the safe default for a format where unknown ancillary chunks may
#: still be meaningful to a decoder.
_PNG_PRIVACY_CHUNKS = frozenset(
    {
        b"tEXt",  # Latin-1 keyword/value pairs
        b"zTXt",  # compressed ditto
        b"iTXt",  # UTF-8 ditto, where XMP usually lives
        b"eXIf",  # EXIF: GPS, camera serial, timestamps
        b"tIME",  # last-modification time
    }
)

#: Chunks that disclose provenance and are therefore preserved.
_PNG_PROVENANCE_CHUNKS = frozenset({b"caBX"})


def clean_png(data: bytes) -> tuple[bytes, list[str], bool]:
    """Strip privacy metadata from PNG bytes.

    Returns ``(cleaned, removed_labels, provenance_kept)``. Malformed input is
    returned unchanged rather than truncated: a cleaner that corrupts the file
    it was asked to clean is worse than one that declines.
    """
    if not data.startswith(PNG_SIGNATURE):
        return data, [], False

    out = bytearray(PNG_SIGNATURE)
    removed: list[str] = []
    provenance_kept = False
    offset = len(PNG_SIGNATURE)

    while offset + 8 <= len(data):
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        chunk_type = data[offset + 4 : offset + 8]
        end = offset + 12 + length  # length + type + body + crc
        if end > len(data):
            return data, [], False  # truncated; refuse rather than mangle

        if chunk_type in _PNG_PRIVACY_CHUNKS:
            removed.append(f"png.{chunk_type.decode('latin-1')}")
        else:
            if chunk_type in _PNG_PROVENANCE_CHUNKS:
                provenance_kept = True
            out += data[offset:end]

        offset = end
        if chunk_type == b"IEND":
            # Some encoders append bytes after IEND. They are not ours to
            # discard, so copy the remainder verbatim.
            out += data[offset:]
            return bytes(out), removed, provenance_kept

    if offset != len(data):
        # The chunk walk ran out before the data did, so part of the file was
        # never classified. Emitting what we understood would silently truncate
        # it; hand back the original instead.
        return data, [], False
    return bytes(out), removed, provenance_kept


# --- JPEG --------------------------------------------------------------------

#: APP segments and comments carrying user-identifying metadata.
_JPEG_PRIVACY_MARKERS: dict[int, str] = {
    0xE1: "jpeg.APP1",  # EXIF and XMP
    0xE2: "jpeg.APP2",  # ICC / FlashPix
    0xEC: "jpeg.APP12",  # Picture Info
    0xED: "jpeg.APP13",  # Photoshop IRB / IPTC
    0xEE: "jpeg.APP14",  # Adobe
    0xFE: "jpeg.COM",  # free-text comment
}

#: APP11 carries JUMBF, which is where a C2PA manifest lives.
_JPEG_PROVENANCE_MARKER = 0xEB

_JPEG_STANDALONE = frozenset({0xD8, 0xD9, 0x01, *range(0xD0, 0xD8)})


def clean_jpeg(data: bytes) -> tuple[bytes, list[str], bool]:
    """Strip privacy metadata from JPEG bytes.

    Scanning stops at start-of-scan: everything after it is entropy-coded image
    data, and a byte sequence there that happens to look like a marker is not
    one.
    """
    if not data.startswith(JPEG_SIGNATURE):
        return data, [], False

    out = bytearray(JPEG_SIGNATURE)
    removed: list[str] = []
    provenance_kept = False
    offset = 2

    while offset + 2 <= len(data):
        if data[offset] != 0xFF:
            return data, [], False  # not at a marker boundary; refuse
        marker = data[offset + 1]

        if marker == 0xDA:  # start of scan: copy the remainder verbatim
            out += data[offset:]
            return bytes(out), removed, provenance_kept
        if marker in _JPEG_STANDALONE:
            out += data[offset : offset + 2]
            offset += 2
            continue

        if offset + 4 > len(data):
            return data, [], False
        (length,) = struct.unpack(">H", data[offset + 2 : offset + 4])
        end = offset + 2 + length
        if end > len(data):
            return data, [], False

        if marker in _JPEG_PRIVACY_MARKERS:
            removed.append(_JPEG_PRIVACY_MARKERS[marker])
        else:
            if marker == _JPEG_PROVENANCE_MARKER:
                provenance_kept = True
            out += data[offset:end]

        offset = end

    if offset != len(data):
        return data, [], False  # never reached SOS; do not truncate
    return bytes(out), removed, provenance_kept


# --- dispatch ----------------------------------------------------------------

_CLEANERS = {"png": clean_png, "jpeg": clean_jpeg}


def clean_bytes(data: bytes, fmt: str) -> tuple[bytes, Report]:
    """Clean a container of the given format; return ``(bytes, report)``."""
    cleaner = _CLEANERS.get(fmt)
    if cleaner is None:
        report = Report(source=f"<{fmt}>", kind=fmt)
        report.undeterminable.append(
            Undeterminable(
                claim="container metadata removal",
                reason=(
                    f"No metadata cleaner for {fmt!r}. Supported: "
                    f"{', '.join(CLEANABLE)}."
                ),
            )
        )
        return data, report

    cleaned, removed, provenance_kept = cleaner(data)
    report = Report(
        source=f"<{fmt}>",
        kind=fmt,
        metadata={label: "removed" for label in removed},
    )
    report.changed = cleaned != data
    report.removed = len(removed)
    if provenance_kept:
        report.undeterminable.append(
            Undeterminable(
                claim="C2PA provenance manifest removal",
                reason=PROVENANCE_PRESERVED_NOTICE,
            )
        )
    return cleaned, report


def is_valid_zip(data: bytes) -> bool:
    """Whether a zip container is readable, used to guard Office rewriting."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            return archive.testzip() is None
    except (zipfile.BadZipFile, OSError):
        return False
