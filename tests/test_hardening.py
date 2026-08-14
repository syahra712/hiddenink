"""Regressions for the defects found in the 2026-08-13 review.

Each test here corresponds to a bug that shipped. They are grouped by the
review's own numbering so a failure points straight back at what it protects.
"""

from __future__ import annotations

import io
import struct
import sys
import time
import zipfile
import zlib

import pytest

from hiddenink.cli import main
from hiddenink.core.clean_text import Profile, clean_text
from hiddenink.core.codepoints import Severity, classify, is_load_bearing
from hiddenink.core.formats import inspect_file
from hiddenink.core.formats._safety import (
    MAX_DECOMPRESSED_BYTES,
    MAX_XML_BYTES,
    UnsafeDocument,
    bounded_decompress,
    safe_fromstring,
)
from hiddenink.core.formats.documents import parse_office, parse_svg
from hiddenink.core.formats.png import PNG_SIGNATURE, parse_png

BILLION_LAUGHS = b"""<?xml version="1.0"?><!DOCTYPE s [
 <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
 <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
 <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]><svg xmlns="http://www.w3.org/2000/svg"><title>&c;</title></svg>"""

XXE = (
    b'<?xml version="1.0"?><!DOCTYPE s ['
    b'<!ENTITY x SYSTEM "file:///etc/passwd">]><svg><title>&x;</title></svg>'
)


def _png_chunk(kind: bytes, body: bytes) -> bytes:
    return (
        struct.pack(">I", len(body))
        + kind
        + body
        + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    )


class TestXmlHardening:
    """P0-2: xml.etree expands entities; both attacks need a declaration."""

    def test_billion_laughs_rejected(self) -> None:
        with pytest.raises(UnsafeDocument):
            safe_fromstring(BILLION_LAUGHS)

    def test_external_entity_rejected(self) -> None:
        with pytest.raises(UnsafeDocument):
            safe_fromstring(XXE)

    def test_parser_reports_rather_than_raising(self) -> None:
        found = parse_svg(BILLION_LAUGHS)
        assert found["svg.parse_status"] == "refused"
        assert "svg.refusal.xml" in found
        assert "svg.warning.xml" in found

    def test_legitimate_svg11_doctype_still_parses(self) -> None:
        """Real SVG 1.1 files carry a DOCTYPE; refusing them would be a bug."""
        doc = (
            b'<?xml version="1.0"?>\n'
            b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
            b'"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n'
            b'<svg xmlns="http://www.w3.org/2000/svg"><title>Chart</title></svg>'
        )
        assert parse_svg(doc)["svg.title"] == "Chart"

    def test_entity_text_in_content_is_not_a_false_positive(self) -> None:
        doc = b"<svg><title>the &lt;!ENTITY declaration</title></svg>"
        assert "svg.unsafe" not in parse_svg(doc)

    @pytest.mark.parametrize(
        "prefix",
        [
            b"<!-- <svg><!ENTITY fake 'x'> -->",
            b"<?processing instruction?>",
            b"<!-- fake <root> --><!-- another -->",
        ],
    )
    def test_comments_and_processing_instructions_do_not_hide_entity(
        self, prefix: bytes
    ) -> None:
        doc = prefix + b"<!DOCTYPE svg [<!ENTITY x 'expanded'>]><svg>&x;</svg>"
        with pytest.raises(UnsafeDocument):
            safe_fromstring(doc)

    @pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
    def test_utf16_entity_declaration_is_rejected(self, encoding: str) -> None:
        text = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x "y">]><svg>&x;</svg>'
        data = text.encode(encoding)
        if encoding == "utf-16-le":
            data = b"\xff\xfe" + data
        elif encoding == "utf-16-be":
            data = b"\xfe\xff" + data
        with pytest.raises(UnsafeDocument):
            safe_fromstring(data)

    def test_parameter_entity_declaration_is_rejected(self) -> None:
        doc = b"<!DOCTYPE svg [<!ENTITY % p 'x'>]><svg/>"
        with pytest.raises(UnsafeDocument):
            safe_fromstring(doc)

    def test_utf16_document_without_entities_parses(self) -> None:
        root = safe_fromstring(
            "<?xml version='1.0'?><svg><title>x</title></svg>".encode("utf-16")
        )
        assert root.tag == "svg"

    def test_xml_byte_limit_precedes_parser(self) -> None:
        with pytest.raises(UnsafeDocument, match="safety limit"):
            safe_fromstring(b"<svg><!--" + b"x" * MAX_XML_BYTES + b"--></svg>")


class TestDecompressionBombs:
    """P0-3: zlib.decompress and ZipFile.read were both unbounded."""

    def test_bounded_decompress_caps_output(self) -> None:
        bomb = zlib.compress(b"\x00" * (64 * 1024 * 1024))
        out, truncated = bounded_decompress(bomb)
        assert len(out) <= MAX_DECOMPRESSED_BYTES
        assert truncated

    def test_bounded_decompress_passes_small_payloads_intact(self) -> None:
        out, truncated = bounded_decompress(zlib.compress(b"hello world"))
        assert out == b"hello world"
        assert not truncated

    def test_png_ztxt_bomb_is_capped_and_fast(self) -> None:
        bomb = zlib.compress(b"\x00" * (64 * 1024 * 1024))
        data = (
            PNG_SIGNATURE
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + _png_chunk(b"zTXt", b"k\x00\x00" + bomb)
            + _png_chunk(b"IEND", b"")
        )
        start = time.monotonic()
        found = parse_png(data)
        assert time.monotonic() - start < 2.0
        assert any("truncated" in str(v) for v in found.values())

    def test_docx_zip_bomb_is_skipped(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("docProps/core.xml", "<a>" + "A" * (32 * 1024 * 1024) + "</a>")
        start = time.monotonic()
        found = parse_office(buf.getvalue())
        assert time.monotonic() - start < 2.0
        assert "office.warning.core.oversized" in found
        assert found["office.parse_status"] == "resource_limit"

    def test_png_aggregate_decompression_budget(self) -> None:
        compressed = zlib.compress(b"A" * MAX_DECOMPRESSED_BYTES)
        chunks = [
            _png_chunk(b"zTXt", f"k{i}".encode() + b"\x00\x00" + compressed)
            for i in range(3)
        ]
        data = (
            PNG_SIGNATURE
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + b"".join(chunks)
            + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
            + _png_chunk(b"IEND", b"")
        )
        found = parse_png(data)
        assert found["png.parse_status"] == "resource_limit"
        assert "png.warning.decompression_limit" in found

    def test_encrypted_office_part_becomes_warning(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("docProps/core.xml", "<a><title>x</title></a>")
        data = bytearray(buf.getvalue())
        local = data.find(b"PK\x03\x04", data.find(b"PK\x03\x04") + 1)
        central = data.find(b"PK\x01\x02", data.find(b"PK\x01\x02") + 1)
        struct.pack_into(
            "<H", data, local + 6, struct.unpack_from("<H", data, local + 6)[0] | 1
        )
        struct.pack_into(
            "<H", data, central + 8, struct.unpack_from("<H", data, central + 8)[0] | 1
        )
        found = parse_office(bytes(data))
        assert "office.warning.core.encrypted" in found
        assert found["office.parse_status"] == "partial"

    def test_unsupported_office_compression_becomes_warning(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("docProps/core.xml", "<a><title>x</title></a>")
        data = bytearray(buf.getvalue())
        local = data.find(b"PK\x03\x04", data.find(b"PK\x03\x04") + 1)
        central = data.find(b"PK\x01\x02", data.find(b"PK\x01\x02") + 1)
        struct.pack_into("<H", data, local + 8, 99)
        struct.pack_into("<H", data, central + 10, 99)
        found = parse_office(bytes(data))
        assert "office.warning.core.read" in found
        assert found["office.parse_status"] == "partial"


class TestTextualContainers:
    """P1-8: SVG is both a container and text; only metadata was scanned."""

    def test_svg_codepoints_are_scanned(self, tmp_path) -> None:
        p = tmp_path / "d.svg"
        p.write_text(
            '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">'
            "<title>Chart</title><text>hel​lo‮</text></svg>",
            encoding="utf-8",
        )
        report = inspect_file(p)
        assert {f.escape for f in report.findings} == {"U+200B", "U+202E"}
        assert report.metadata["svg.title"] == "Chart"  # metadata still read


class TestSurrogateRoundTrip:
    """P0-4: read used surrogatepass, write used strict, so -i crashed."""

    def test_in_place_clean_survives_lone_surrogate(self, tmp_path) -> None:
        p = tmp_path / "s.txt"
        p.write_bytes(b"a\xed\xa0\x80b")
        assert main(["clean", "-i", str(p)]) == 0
        assert p.read_bytes() == b"a\xed\xa0\x80b"


class TestCliSafety:
    """P1-9/10/11: silent data loss and unhelpful failures."""

    def test_refuses_container_it_cannot_clean(self, tmp_path, capsys) -> None:
        """A PDF has no metadata cleaner, so clean points at inspect instead.

        PNG and JPEG *are* cleanable now and take the binary path; see
        tests/test_container_clean.py.
        """
        p = tmp_path / "x.pdf"
        p.write_bytes(b"%PDF-1.7\n<< /Title (t) >>\n%%EOF\n")
        assert main(["clean", str(p)]) == 2
        assert "inspect its supported coverage" in capsys.readouterr().err

    def test_refuses_to_concatenate_multiple_files_to_stdout(
        self, tmp_path, capsys
    ) -> None:
        a, b = tmp_path / "a.md", tmp_path / "b.md"
        a.write_text("one​\n", encoding="utf-8")
        b.write_text("two​\n", encoding="utf-8")
        assert main(["clean", str(a), str(b)]) == 2
        assert "refusing to concatenate" in capsys.readouterr().err

    def test_json_sends_report_to_stderr_and_text_to_stdout(
        self, tmp_path, capsys
    ) -> None:
        p = tmp_path / "t.md"
        # newline="" so the fixture is byte-exact on every platform. Plain
        # write_text translates \n to \r\n on Windows, which would make this
        # assertion about line endings rather than about stream routing.
        with p.open("w", encoding="utf-8", newline="") as handle:
            handle.write("a​b\n")
        assert main(["clean", "--json", str(p)]) == 0
        captured = capsys.readouterr()
        assert captured.out == "ab\n"  # cleaned text, not discarded
        assert '"not_determinable"' in captured.err


class TestLegacyCodepageOutput:
    """The report must not crash on a non-UTF-8 console.

    Windows defaults to a legacy codepage such as cp1252, which cannot encode
    the report's box-drawing characters -- nor arbitrary text lifted out of the
    files being inspected. This reproduces that console on any platform by
    swapping stdout for a cp1252 stream.
    """

    def _cp1252_stdout(self, monkeypatch) -> io.TextIOWrapper:
        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline="")
        monkeypatch.setattr(sys, "stdout", stream)
        return stream

    def test_report_glyphs_do_not_crash(self, tmp_path, monkeypatch) -> None:
        stream = self._cp1252_stdout(monkeypatch)
        p = tmp_path / "f.md"
        p.write_text("a​b—c…", encoding="utf-8")
        assert main(["inspect", str(p)]) == 0
        stream.flush()  # would raise UnicodeEncodeError unencoded

    def test_untrusted_file_metadata_does_not_crash(self, tmp_path, monkeypatch) -> None:
        """A PNG text chunk can hold anything; cp1252 can hold very little."""
        stream = self._cp1252_stdout(monkeypatch)
        p = tmp_path / "f.png"
        p.write_bytes(
            PNG_SIGNATURE
            + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + _png_chunk(b"tEXt", "Software\x00図書館ソフト".encode("latin-1", "replace"))
            + _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
            + _png_chunk(b"IEND", b"")
        )
        assert main(["inspect", str(p)]) == 0
        stream.flush()


class TestLineEndingFidelity:
    """Line endings must survive a clean untouched, on every platform.

    ``clean`` is sold on byte-level diffability, so it may not normalise CRLF
    as a side effect -- neither on read, nor on write, nor through the pipe.
    The ``data`` profile is the single documented exception.
    """

    @pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
    def test_in_place_preserves_line_endings(self, tmp_path, ending: bytes) -> None:
        p = tmp_path / "f.md"
        p.write_bytes(b"a\xe2\x80\x8bb" + ending + b"c" + ending)
        assert main(["clean", "-i", str(p)]) == 0
        assert p.read_bytes() == b"ab" + ending + b"c" + ending

    @pytest.mark.parametrize("ending", ["\n", "\r\n"])
    def test_stdout_preserves_line_endings(self, tmp_path, capsys, ending: str) -> None:
        p = tmp_path / "f.md"
        with p.open("w", encoding="utf-8", newline="") as handle:
            handle.write(f"a​b{ending}")
        assert main(["clean", str(p)]) == 0
        assert capsys.readouterr().out == f"ab{ending}"

    def test_data_profile_normalises_crlf_by_design(self, tmp_path) -> None:
        p = tmp_path / "f.csv"
        p.write_bytes(b"a,b\r\nc,d\r\n")
        assert main(["clean", "-i", str(p)]) == 0
        assert p.read_bytes() == b"a,b\nc,d\n"

    def test_check_exits_nonzero_only_when_changes_needed(self, tmp_path) -> None:
        dirty, clean = tmp_path / "d.md", tmp_path / "c.md"
        dirty.write_text("a​b\n", encoding="utf-8")
        clean.write_text("ab\n", encoding="utf-8")
        assert main(["clean", "--check", str(dirty)]) == 1
        assert main(["clean", "--check", str(clean)]) == 0
        assert dirty.read_text(encoding="utf-8") == "a​b\n"  # unmodified


class TestIdempotenceFuzz:
    """P0-1: the headline guarantee, previously verified only on tame samples.

    A fixed seed keeps CI deterministic while still covering the interactions
    -- invisible characters inside region delimiters, folds that emit
    region-relevant characters -- that the curated cases missed entirely.
    """

    ALPHABET = list("abc XYZ.\n") + [
        "​",
        "‮",
        " ",
        "—",
        "“",
        "”",
        "…",
        "﻿",
        "­",
        "\U000e0041",
        "️",
        "❤",
        "`",
        "```",
        "https://x.com/",
        "⁠",
        "　",
        "'",
    ]

    def _corpus(self, seed: int, count: int, maxlen: int) -> list[str]:
        import random

        rng = random.Random(seed)
        return [
            "".join(rng.choice(self.ALPHABET) for _ in range(rng.randint(0, maxlen)))
            for _ in range(count)
        ]

    @pytest.mark.parametrize("profile", list(Profile))
    @pytest.mark.parametrize(
        ("seed", "count", "maxlen"), [(1337, 400, 60), (99, 400, 140)]
    )
    def test_clean_is_idempotent(
        self, profile: Profile, seed: int, count: int, maxlen: int
    ) -> None:
        for sample in self._corpus(seed, count, maxlen):
            once, _ = clean_text(sample, profile)
            twice, _ = clean_text(once, profile)
            assert once == twice, f"not idempotent under {profile.value}: {sample!r}"

    @pytest.mark.parametrize("profile", list(Profile))
    def test_no_invisible_survives(self, profile: Profile) -> None:
        for sample in self._corpus(7, 400, 100):
            once, _ = clean_text(sample, profile)
            for index, ch in enumerate(once):
                info = classify(ord(ch))
                if info is None or info.severity is not Severity.INVISIBLE:
                    continue
                assert is_load_bearing(once, index), (
                    f"{info.escape} survived clean: {once!r}"
                )
