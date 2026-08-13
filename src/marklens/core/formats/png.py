"""PNG chunk parser (stdlib only).

A PNG is an 8-byte signature followed by length-prefixed chunks. Provenance
and metadata live in ancillary chunks:

``tEXt`` / ``zTXt`` / ``iTXt``
    Textual metadata. Generator software usually announces itself here.
``eXIf``
    An embedded EXIF block.
``caBX``
    The C2PA manifest store (a JUMBF box). This is where Content Credentials
    live in a PNG, and its presence is byte-verifiable.
"""

from __future__ import annotations

import struct
import zlib
from typing import Any

from ._safety import bounded_decompress

__all__ = ["parse_png", "PNG_SIGNATURE"]

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

#: Chunks that carry metadata rather than image data.
_TEXT_CHUNKS = {b"tEXt", b"zTXt", b"iTXt"}
_BINARY_METADATA = {
    b"eXIf": "exif",
    b"caBX": "c2pa_manifest",
    b"iCCP": "icc_profile",
    b"tIME": "modification_time",
}


def _decode_text_chunk(chunk_type: bytes, data: bytes) -> tuple[str, str]:
    """Return ``(keyword, value)`` for a PNG text chunk."""
    if chunk_type == b"tEXt":
        keyword, _, value = data.partition(b"\x00")
        return keyword.decode("latin-1"), value.decode("latin-1", "replace")

    if chunk_type == b"zTXt":
        keyword, _, rest = data.partition(b"\x00")
        # rest[0] is the compression method; the remainder is zlib data.
        try:
            raw, truncated = bounded_decompress(rest[1:])
        except zlib.error:
            return keyword.decode("latin-1"), "<undecompressible>"
        decoded = raw.decode("latin-1", "replace")
        if truncated:
            # Prefixed, not appended: parse_png caps the reported value at 200
            # characters, which would cut a trailing marker off entirely.
            decoded = "<truncated at decompression limit> " + decoded
        return keyword.decode("latin-1"), decoded

    # iTXt: keyword \0 compression_flag compression_method language \0
    #       translated_keyword \0 text
    keyword, _, rest = data.partition(b"\x00")
    if len(rest) < 2:
        return keyword.decode("latin-1"), ""
    compressed = rest[0] == 1
    rest = rest[2:]
    _lang, _, rest = rest.partition(b"\x00")
    _translated, _, text = rest.partition(b"\x00")
    if compressed:
        try:
            inflated, truncated = bounded_decompress(text)
        except zlib.error:
            return keyword.decode("latin-1"), "<undecompressible>"
        text = inflated
        if truncated:
            return keyword.decode("latin-1"), (
                "<truncated at decompression limit> " + text.decode("utf-8", "replace")
            )
    return keyword.decode("latin-1"), text.decode("utf-8", "replace")


def parse_png(data: bytes) -> dict[str, Any]:
    """Extract metadata from PNG bytes.

    Returns a flat mapping of finding name to value. An empty mapping means no
    metadata chunks were present -- which is byte-verifiable, unlike any claim
    about statistical watermarking.
    """
    if not data.startswith(PNG_SIGNATURE):
        return {}

    found: dict[str, Any] = {}
    offset = len(PNG_SIGNATURE)

    while offset + 8 <= len(data):
        (length,) = struct.unpack(">I", data[offset : offset + 4])
        chunk_type = data[offset + 4 : offset + 8]
        body_start = offset + 8
        body_end = body_start + length
        if body_end > len(data):
            break  # truncated file; report what we already have
        body = data[body_start:body_end]

        if chunk_type in _TEXT_CHUNKS:
            keyword, value = _decode_text_chunk(chunk_type, body)
            collapsed = " ".join(value.split())
            if len(collapsed) > 200:
                collapsed = collapsed[:197] + "..."
            found[f"png.{chunk_type.decode()}.{keyword}"] = collapsed
        elif chunk_type in _BINARY_METADATA:
            found[f"png.{_BINARY_METADATA[chunk_type]}"] = f"{length} bytes"

        if chunk_type == b"IEND":
            break
        offset = body_end + 4  # skip the trailing CRC

    return found
