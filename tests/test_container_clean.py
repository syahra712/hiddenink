"""Container metadata removal.

The governing rule, and the thing these tests exist to hold in place: remove
metadata that identifies the user, keep metadata that discloses AI involvement.
A PNG loses its text chunks and EXIF and keeps its C2PA manifest.

The other half is refusal. A cleaner that corrupts the file it was asked to
clean is worse than one that declines, so malformed input must round-trip
byte-identical rather than come back truncated to whatever parsed.
"""

from __future__ import annotations

import pytest

from marklens.cli import main
from marklens.core.formats.clean import (
    CLEANABLE,
    clean_bytes,
    clean_jpeg,
    clean_png,
)
from marklens.core.formats.jpeg import parse_jpeg
from marklens.core.formats.png import parse_png
from test_formats import build_jpeg, build_png


class TestPngCleaning:
    def test_text_chunks_are_removed(self) -> None:
        data = build_png(text={"Software": "Gen 1.0", "Author": "someone"})
        cleaned, removed, _ = clean_png(data)
        assert parse_png(cleaned) == {}
        assert len(removed) == 2

    def test_c2pa_manifest_is_preserved(self) -> None:
        data = build_png(text={"Software": "Gen 1.0"}, c2pa=True)
        cleaned, _, provenance_kept = clean_png(data)
        assert provenance_kept
        assert "png.c2pa_manifest" in parse_png(cleaned)
        assert not any(k.startswith("png.tEXt") for k in parse_png(cleaned))

    def test_image_data_survives(self) -> None:
        data = build_png(text={"Software": "x"})
        cleaned, _, _ = clean_png(data)
        assert b"IHDR" in cleaned
        assert b"IDAT" in cleaned
        assert b"IEND" in cleaned

    def test_bare_png_is_unchanged(self) -> None:
        data = build_png()
        assert clean_png(data)[0] == data

    def test_bytes_after_iend_are_preserved(self) -> None:
        """Some encoders append data; discarding it is not ours to do."""
        data = build_png(text={"Software": "x"}) + b"TRAILER"
        cleaned, _, _ = clean_png(data)
        assert cleaned.endswith(b"TRAILER")


class TestJpegCleaning:
    def test_exif_and_xmp_are_removed(self) -> None:
        data = build_jpeg(exif=True, xmp="<x:xmpmeta>gps</x:xmpmeta>")
        cleaned, removed, _ = clean_jpeg(data)
        found = parse_jpeg(cleaned)
        assert "jpeg.exif" not in found
        assert "jpeg.xmp" not in found
        assert removed

    def test_comment_is_removed(self) -> None:
        cleaned, _, _ = clean_jpeg(build_jpeg())
        assert "jpeg.comment" not in parse_jpeg(cleaned)

    def test_app11_jumbf_is_preserved(self) -> None:
        data = build_jpeg(exif=True, c2pa=True)
        cleaned, _, provenance_kept = clean_jpeg(data)
        assert provenance_kept
        assert "jpeg.c2pa_manifest" in parse_jpeg(cleaned)

    def test_scan_data_survives(self) -> None:
        data = build_jpeg(exif=True)
        cleaned, _, _ = clean_jpeg(data)
        assert cleaned.endswith(b"\xff\xd9")
        assert b"\xff\xda" in cleaned


class TestRefusesToCorrupt:
    @pytest.mark.parametrize(
        ("label", "data", "fmt"),
        [
            ("truncated png", build_png(text={"a": "b"})[:40], "png"),
            ("png without IEND", build_png()[:-12], "png"),
            ("not a png", b"hello world", "png"),
            ("empty png", b"", "png"),
            ("garbage jpeg", b"\xff\xd8\xff\xe1\xff\xff", "jpeg"),
            ("jpeg without SOS", build_jpeg(exif=True)[:20], "jpeg"),
            ("not a jpeg", b"hello world", "jpeg"),
        ],
    )
    def test_malformed_input_round_trips_unchanged(
        self, label: str, data: bytes, fmt: str
    ) -> None:
        cleaned, _ = clean_bytes(data, fmt)
        assert cleaned == data, f"{label} was modified"

    def test_unsupported_format_says_so(self) -> None:
        cleaned, report = clean_bytes(b"%PDF-1.7\n", "pdf")
        assert cleaned == b"%PDF-1.7\n"
        assert any("No metadata cleaner" in u.reason for u in report.undeterminable)


class TestIdempotence:
    @pytest.mark.parametrize("fmt", CLEANABLE)
    def test_cleaning_twice_changes_nothing_further(self, fmt: str) -> None:
        data = (
            build_png(text={"Software": "x", "Author": "y"}, c2pa=True)
            if fmt == "png"
            else build_jpeg(exif=True, xmp="<x/>", c2pa=True)
        )
        once, _ = clean_bytes(data, fmt)
        twice, report = clean_bytes(once, fmt)
        assert twice == once
        assert not report.changed


class TestReport:
    def test_provenance_preservation_is_reported_not_silent(self) -> None:
        _, report = clean_bytes(build_png(c2pa=True), "png")
        reasons = " ".join(u.reason for u in report.undeterminable)
        assert "PRESERVED" in reasons
        assert "soft binding" in reasons.lower()

    def test_statistical_notice_still_present(self) -> None:
        _, report = clean_bytes(build_png(), "png")
        assert any("NOT EVALUATED" in u.reason for u in report.undeterminable)

    def test_no_provenance_note_when_there_was_no_manifest(self) -> None:
        _, report = clean_bytes(build_png(text={"a": "b"}), "png")
        assert not any("PRESERVED" in u.reason for u in report.undeterminable)


class TestCli:
    def test_in_place_rewrites_the_file(self, tmp_path) -> None:
        p = tmp_path / "shot.png"
        original = build_png(text={"Software": "Gen", "Author": "me"}, c2pa=True)
        p.write_bytes(original)
        assert main(["clean", "-i", str(p), "--quiet"]) == 0
        cleaned = p.read_bytes()
        assert cleaned != original
        assert "png.c2pa_manifest" in parse_png(cleaned)
        assert not any(k.startswith("png.tEXt") for k in parse_png(cleaned))

    def test_dry_run_leaves_the_file_alone(self, tmp_path) -> None:
        p = tmp_path / "shot.png"
        original = build_png(text={"Software": "Gen"})
        p.write_bytes(original)
        assert main(["clean", "--dry-run", str(p), "--quiet"]) == 0
        assert p.read_bytes() == original

    def test_backup_keeps_the_original(self, tmp_path) -> None:
        p = tmp_path / "shot.png"
        original = build_png(text={"Software": "Gen"})
        p.write_bytes(original)
        assert main(["clean", "-i", "--backup", str(p), "--quiet"]) == 0
        assert (tmp_path / "shot.png.bak").read_bytes() == original

    def test_binary_to_stdout_is_refused(self, tmp_path, capsys) -> None:
        p = tmp_path / "shot.png"
        p.write_bytes(build_png(text={"Software": "Gen"}))
        assert main(["clean", str(p)]) == 2
        assert "rewrites binary data" in capsys.readouterr().err

    def test_check_reports_without_writing(self, tmp_path) -> None:
        p = tmp_path / "shot.png"
        original = build_png(text={"Software": "Gen"})
        p.write_bytes(original)
        assert main(["clean", "--check", str(p), "--quiet"]) == 1
        assert p.read_bytes() == original
