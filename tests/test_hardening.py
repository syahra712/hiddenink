"""Regressions for the defects found in the 2026-08-13 review.

Each test here corresponds to a bug that shipped. They are grouped by the
review's own numbering so a failure points straight back at what it protects.
"""

from __future__ import annotations

import io
import struct
import time
import zipfile
import zlib

import pytest

from marklens.cli import main
from marklens.core.clean_text import Profile, clean_text
from marklens.core.codepoints import Severity, classify, is_emoji_variation_selector
from marklens.core.formats import inspect_file
from marklens.core.formats._safety import (
    MAX_DECOMPRESSED_BYTES,
    UnsafeDocument,
    bounded_decompress,
    safe_fromstring,
)
from marklens.core.formats.documents import parse_office, parse_svg
from marklens.core.formats.png import PNG_SIGNATURE, parse_png

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
        assert "svg.unsafe" in parse_svg(BILLION_LAUGHS)

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
            z.writestr("docProps/core.xml", "<a>" + "A" * (32 * 1024 * 1024) + "</a>")
        start = time.monotonic()
        found = parse_office(buf.getvalue())
        assert time.monotonic() - start < 2.0
        assert "office.core.oversized" in found


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

    def test_refuses_binary_container(self, tmp_path, capsys) -> None:
        p = tmp_path / "x.png"
        p.write_bytes(PNG_SIGNATURE + _png_chunk(b"IEND", b""))
        assert main(["clean", str(p)]) == 2
        assert "operates on text" in capsys.readouterr().err

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
        p.write_text("a​b\n", encoding="utf-8")
        assert main(["clean", "--json", str(p)]) == 0
        captured = capsys.readouterr()
        assert captured.out == "ab\n"  # cleaned text, not discarded
        assert '"not_determinable"' in captured.err

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
        "​", "‮", " ", "—", "“", "”", "…",
        "﻿", "­", "\U000e0041", "️", "❤", "`", "```",
        "https://x.com/", "⁠", "　", "'",
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
                assert is_emoji_variation_selector(once, index), (
                    f"{info.escape} survived clean: {once!r}"
                )
