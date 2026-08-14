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

# --- builders ----------------------------------------------------------------

def _png_chunk(kind: bytes, body: bytes) -> bytes:
    return (
        struct.pack(">I", len(body))
        + kind
        + body
        + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    )


def build_png(*, text: dict[str, str] | None = None, c2pa: bool = False) -> bytes:
    out = [PNG_SIGNATURE]
    out.append(_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)))
    for keyword, value in (text or {}).items():
        out.append(
            _png_chunk(b"tEXt", keyword.encode() + b"\x00" + value.encode("latin-1"))
        )
    if c2pa:
        out.append(_png_chunk(b"caBX", b"\x00\x00\x00\x10jumbc2pa" + b"\x00" * 8))
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
            _jpeg_segment(
                0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp.encode("utf-8")
            )
        )
    if c2pa:
        out.append(_jpeg_segment(0xEB, b"JP\x00\x01c2pa manifest store" + b"\x00" * 8))
    out.append(_jpeg_segment(0xFE, b"a comment"))
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
        assert "png.c2pa_manifest" in found

    def test_bare_png_has_no_metadata(self) -> None:
        assert parse_png(build_png()) == {}

    def test_truncated_file_does_not_raise(self) -> None:
        truncated = build_png(text={"Software": "x"})[:40]
        parse_png(truncated)  # must not raise

    def test_non_png_returns_empty(self) -> None:
        assert parse_png(b"not a png") == {}


# --- JPEG --------------------------------------------------------------------

class TestJpeg:
    def test_reads_exif(self) -> None:
        assert "jpeg.exif" in parse_jpeg(build_jpeg(exif=True))

    def test_reads_xmp_and_flags_c2pa_reference(self) -> None:
        found = parse_jpeg(build_jpeg(xmp="<x:xmpmeta>c2pa:soft-binding</x:xmpmeta>"))
        assert "jpeg.xmp" in found
        assert found["jpeg.xmp.c2pa_reference"] == "present"

    def test_detects_app11_c2pa_manifest(self) -> None:
        found = parse_jpeg(build_jpeg(c2pa=True))
        assert found["jpeg.c2pa_manifest"] == "present"

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
        assert found["svg.c2pa_reference"] == "present"

    def test_pdf_info_dictionary(self) -> None:
        _, found = parse_bytes(PDF_WITH_INFO)
        assert found["pdf.info.Title"] == "Draft Essay"
        assert found["pdf.info.Producer"] == "SomeWriter 3.2"

    def test_malformed_svg_reports_rather_than_raises(self) -> None:
        _, found = parse_bytes(b'<?xml version="1.0"?><svg><unclosed>')
        assert "svg.parse_error" in found


# --- report integration ------------------------------------------------------

class TestInspectFile:
    def test_soft_binding_caveat_when_no_manifest(self, tmp_path) -> None:
        p = tmp_path / "plain.png"
        p.write_bytes(build_png())
        report = inspect_file(p)
        reasons = " ".join(u.reason for u in report.undeterminable)
        assert "soft binding" in reasons.lower()

    def test_no_soft_binding_caveat_when_manifest_present(self, tmp_path) -> None:
        p = tmp_path / "signed.png"
        p.write_bytes(build_png(c2pa=True))
        report = inspect_file(p)
        claims = [u.claim for u in report.undeterminable]
        assert not any("soft binding" in c for c in claims)

    def test_unknown_format_says_so(self, tmp_path) -> None:
        p = tmp_path / "mystery.bin"
        p.write_bytes(b"\x01\x02\x03\x04 not a known container")
        report = inspect_file(p)
        assert report.kind == "unknown"
        assert any("Unrecognised" in u.reason for u in report.undeterminable)

    def test_statistical_notice_always_present(self, tmp_path) -> None:
        p = tmp_path / "x.png"
        p.write_bytes(build_png())
        report = inspect_file(p)
        assert any("NOT EVALUATED" in u.reason for u in report.undeterminable)
