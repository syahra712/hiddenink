"""Container metadata parsers, exercised against synthesised real files.

Fixtures are built byte-by-byte here rather than committed as binaries, so
every assertion is traceable to a structure we constructed on purpose.
"""

from __future__ import annotations

import struct
import zipfile
import zlib
from io import BytesIO

import pytest

from hiddenink.core.formats import detect_format, inspect_file, parse_bytes
from hiddenink.core.formats.jpeg import parse_jpeg
from hiddenink.core.formats.png import PNG_SIGNATURE, parse_png
from hiddenink.core.formats.provenance import C2PA_MANIFEST_UUID

# --- builders ----------------------------------------------------------------


def _png_chunk(kind: bytes, body: bytes) -> bytes:
    return (
        struct.pack(">I", len(body))
        + kind
        + body
        + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    )


def _box(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body) + 8) + kind + body


def build_manifest_store() -> bytes:
    """Small structurally conformant JUMBF C2PA manifest-store fixture."""
    description = _box(b"jumd", C2PA_MANIFEST_UUID + b"\x03c2pa\x00")
    manifest_description = _box(
        b"jumd",
        bytes.fromhex("63326d6100110010800000aa00389b71")
        + b"\x03urn:c2pa:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4\x00",
    )
    manifest = _box(b"jumb", manifest_description + _box(b"cbor", b"\xa0"))
    return _box(b"jumb", description + manifest)


def build_png(*, text: dict[str, str] | None = None, c2pa: bool = False) -> bytes:
    out = [PNG_SIGNATURE]
    out.append(_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)))
    for keyword, value in (text or {}).items():
        out.append(
            _png_chunk(b"tEXt", keyword.encode() + b"\x00" + value.encode("latin-1"))
        )
    if c2pa:
        out.append(_png_chunk(b"caBX", build_manifest_store()))
    out.append(_png_chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff")))
    out.append(_png_chunk(b"IEND", b""))
    return b"".join(out)


def _jpeg_segment(marker: int, body: bytes) -> bytes:
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(body) + 2) + body


def build_jpeg(*, exif: bool = False, xmp: str = "", c2pa: bool = False) -> bytes:
    out = [b"\xff\xd8"]
    if exif:
        out.append(_jpeg_segment(0xE1, b"Exif\x00\x00" + b"MM\x00*" + b"\x00" * 16))
    if xmp:
        out.append(
            _jpeg_segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp.encode("utf-8"))
        )
    if c2pa:
        out.append(
            _jpeg_segment(0xEB, b"JP\x00\x01\x00\x00\x00\x01" + build_manifest_store())
        )
    out.append(_jpeg_segment(0xFE, b"a comment"))
    out.append(_jpeg_segment(0xC0, b"\x08\x00\x01\x00\x01\x01\x01\x11\x00"))
    out.append(b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00")  # SOS
    out.append(b"\xff\xd9")
    return b"".join(out)


def build_docx(title: str = "Quarterly Report", creator: str = "Some Tool") -> bytes:
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        "<cp:coreProperties "
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006'
        '/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f"<dc:title>{title}</dc:title>"
        f"<dc:creator>{creator}</dc:creator>"
        "</cp:coreProperties>"
    )
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("docProps/core.xml", core)
        z.writestr("word/document.xml", "<document/>")
    return buf.getvalue()


SVG_WITH_METADATA = b"""<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
  <title>Generated Chart</title>
  <metadata>c2pa:manifest reference here</metadata>
  <rect width="10" height="10"/>
</svg>"""

PDF_WITH_INFO = (
    b"%PDF-1.7\n"
    b"1 0 obj\n<< /Title (Draft Essay) /Producer (SomeWriter 3.2) >>\nendobj\n"
    b"trailer\n<< /Info 1 0 R >>\n%%EOF\n"
)


# --- detection ---------------------------------------------------------------


class TestDetectFormat:
    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            (build_png(), "png"),
            (build_jpeg(), "jpeg"),
            (build_docx(), "office"),
            (SVG_WITH_METADATA, "svg"),
            (PDF_WITH_INFO, "pdf"),
            (b"just some plain text", None),
        ],
    )
    def test_detects_by_magic_bytes(self, data: bytes, expected: str | None) -> None:
        assert detect_format(data) == expected

    def test_extension_does_not_override_magic_bytes(self) -> None:
        """A PNG named .txt is still a PNG."""
        assert detect_format(build_png(), "notes.txt") == "png"


# --- PNG ---------------------------------------------------------------------


class TestPng:
    def test_reads_text_chunks(self) -> None:
        data = build_png(text={"Software": "Some Generator 1.0", "Author": "nobody"})
        found = parse_png(data)
        assert found["png.tEXt.Software"] == "Some Generator 1.0"
        assert found["png.tEXt.Author"] == "nobody"

    def test_detects_c2pa_manifest_chunk(self) -> None:
        found = parse_png(build_png(c2pa=True))
        assert found["png.c2pa_like"].startswith("caBX")
        assert found["png.c2pa_manifest_store_structurally_parsed"] is True
        assert "unavailable" in found["png.c2pa_credential_verified"]

    def test_bare_png_has_no_metadata(self) -> None:
        found = parse_png(build_png())
        assert found["png.parse_status"] == "complete"
        assert set(found) == {"png.parse_status", "png.coverage"}

    def test_truncated_file_does_not_raise(self) -> None:
        truncated = build_png(text={"Software": "x"})[:40]
        parse_png(truncated)  # must not raise

    def test_non_png_returns_empty(self) -> None:
        assert parse_png(b"not a png")["png.parse_status"] == "malformed"


# --- JPEG --------------------------------------------------------------------


class TestJpeg:
    def test_reads_exif(self) -> None:
        assert "jpeg.exif" in parse_jpeg(build_jpeg(exif=True))

    def test_arbitrary_c2pa_text_in_xmp_is_not_a_manifest(self) -> None:
        found = parse_jpeg(build_jpeg(xmp="<x:xmpmeta>c2pa:soft-binding</x:xmpmeta>"))
        assert "jpeg.xmp" in found
        assert not any(key.startswith("jpeg.c2pa_") for key in found)

    def test_detects_app11_c2pa_manifest(self) -> None:
        found = parse_jpeg(build_jpeg(c2pa=True))
        assert found["jpeg.c2pa_manifest_store_structurally_parsed"] is True
        assert "unavailable" in found["jpeg.c2pa_credential_verified"]

    def test_unrelated_app11_is_not_assumed_to_be_c2pa(self) -> None:
        data = build_jpeg().replace(
            b"\xff\xfe", _jpeg_segment(0xEB, b"not-jumbf") + b"\xff\xfe", 1
        )
        found = parse_jpeg(data)
        assert "jpeg.app11.1" in found
        assert not any(key.startswith("jpeg.c2pa_") for key in found)

    def test_reads_comment(self) -> None:
        assert parse_jpeg(build_jpeg())["jpeg.comment"] == "a comment"

    def test_stops_at_start_of_scan(self) -> None:
        """Entropy-coded image data must not be scanned for markers."""
        data = build_jpeg() + b"\xff\xe1\x00\x08fake"
        assert "jpeg.exif" not in parse_jpeg(data)


# --- documents ---------------------------------------------------------------


class TestDocuments:
    def test_docx_core_properties(self) -> None:
        _, found = parse_bytes(build_docx())
        assert found["office.core.title"] == "Quarterly Report"
        assert found["office.core.creator"] == "Some Tool"

    def test_svg_title_and_c2pa(self) -> None:
        _, found = parse_bytes(SVG_WITH_METADATA)
        assert found["svg.title"] == "Generated Chart"
        assert not any(key.startswith("svg.c2pa_") for key in found)

    def test_pdf_info_dictionary(self) -> None:
        _, found = parse_bytes(PDF_WITH_INFO)
        assert found["pdf.info.Title"] == "Draft Essay"
        assert found["pdf.info.Producer"] == "SomeWriter 3.2"
        assert found["pdf.parse_status"] == "partial"

    def test_malformed_svg_reports_rather_than_raises(self) -> None:
        _, found = parse_bytes(b'<?xml version="1.0"?><svg><unclosed>')
        assert found["svg.parse_status"] == "malformed"
        assert "svg.warning.xml" in found


# --- report integration ------------------------------------------------------


class TestInspectFile:
    def test_soft_binding_caveat_when_no_manifest(self, tmp_path) -> None:
        p = tmp_path / "plain.png"
        p.write_bytes(build_png())
        report = inspect_file(p)
        reasons = " ".join(u.reason for u in report.undeterminable)
        assert "soft-binding" in reasons.lower()

    def test_manifest_structure_does_not_suppress_validation_caveat(
        self, tmp_path
    ) -> None:
        p = tmp_path / "signed.png"
        p.write_bytes(build_png(c2pa=True))
        report = inspect_file(p)
        reasons = " ".join(u.reason for u in report.undeterminable)
        assert "structure was parsed" in reasons
        assert "cryptographically VERIFIED" in reasons

    def test_unknown_format_says_so(self, tmp_path) -> None:
        p = tmp_path / "mystery.bin"
        p.write_bytes(b"\x01\x02\x03\x04 not a known container")
        report = inspect_file(p)
        assert report.kind == "unknown"
        assert any("Unrecognised" in u.reason for u in report.undeterminable)

    def test_binary_report_omits_irrelevant_statistical_text_notice(
        self, tmp_path
    ) -> None:
        p = tmp_path / "x.png"
        p.write_bytes(build_png())
        report = inspect_file(p)
        assert not any(
            "statistical text watermark" in u.claim for u in report.undeterminable
        )
