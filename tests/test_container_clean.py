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

from hiddenink.cli import main
from hiddenink.core.formats.clean import (
    CLEANABLE,
    clean_bytes,
    clean_jpeg,
    clean_png,
)
from hiddenink.core.formats.jpeg import parse_jpeg
from hiddenink.core.formats.png import parse_png
from test_formats import build_jpeg, build_png


class TestPngCleaning:
    def test_ambiguous_text_chunks_are_retained(self) -> None:
        data = build_png(text={"Software": "Gen 1.0", "Author": "someone"})
        cleaned, removed, _ = clean_png(data)
        assert cleaned == data
        assert removed == []
        assert parse_png(cleaned)["png.tEXt.Author"] == "someone"

    def test_c2pa_bytes_are_retained_without_validity_claim(self) -> None:
        data = build_png(text={"Software": "Gen 1.0"}, c2pa=True)
        cleaned, _, provenance_kept = clean_png(data)
        assert provenance_kept
        assert cleaned == data
        assert parse_png(cleaned)["png.c2pa_manifest_store_structurally_parsed"] is True

    def test_image_data_survives(self) -> None:
        data = build_png(text={"Software": "x"})
        cleaned, _, _ = clean_png(data)
        assert b"IHDR" in cleaned
        assert b"IDAT" in cleaned
        assert b"IEND" in cleaned

    def test_bare_png_is_unchanged(self) -> None:
        data = build_png()
        assert clean_png(data)[0] == data

    def test_bytes_after_iend_make_mutation_refuse(self) -> None:
        data = build_png(text={"Software": "x"}) + b"TRAILER"
        cleaned, report = clean_bytes(data, "png")
        assert cleaned == data
        assert report.parse_status == "refused"
        assert any("IEND" in reason for reason in report.refusal_reasons)


class TestJpegCleaning:
    def test_exif_and_xmp_are_retained(self) -> None:
        data = build_jpeg(exif=True, xmp="<x:xmpmeta>gps</x:xmpmeta>")
        cleaned, removed, _ = clean_jpeg(data)
        found = parse_jpeg(cleaned)
        assert cleaned == data
        assert "jpeg.exif" in found
        assert "jpeg.xmp" in found
        assert removed == []

    def test_comment_is_retained_as_potential_rights_data(self) -> None:
        cleaned, _, _ = clean_jpeg(build_jpeg())
        assert parse_jpeg(cleaned)["jpeg.comment"] == "a comment"

    def test_app11_jumbf_bytes_are_retained(self) -> None:
        data = build_jpeg(exif=True, c2pa=True)
        cleaned, _, provenance_kept = clean_jpeg(data)
        assert provenance_kept
        assert cleaned == data
        assert parse_jpeg(cleaned)["jpeg.c2pa_manifest_store_structurally_parsed"]

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
            ("png without IDAT", build_png().replace(build_png()[33:-12], b""), "png"),
            ("png bytes after IEND", build_png() + b"trailer", "png"),
            ("not a png", b"hello world", "png"),
            ("empty png", b"", "png"),
            ("garbage jpeg", b"\xff\xd8\xff\xe1\xff\xff", "jpeg"),
            ("jpeg without SOS", build_jpeg(exif=True)[:20], "jpeg"),
            ("jpeg without EOI", build_jpeg(exif=True)[:-2], "jpeg"),
            ("not a jpeg", b"hello world", "jpeg"),
        ],
    )
    def test_malformed_input_round_trips_unchanged(
        self, label: str, data: bytes, fmt: str
    ) -> None:
        cleaned, _ = clean_bytes(data, fmt)
        assert cleaned == data, f"{label} was modified"

    @pytest.mark.parametrize(
        ("data", "fmt"),
        [
            (build_png(text={"Author": "x"})[:-12], "png"),
            (build_jpeg(exif=True)[:-2], "jpeg"),
        ],
    )
    def test_malformed_metadata_container_has_structured_refusal(
        self, data: bytes, fmt: str
    ) -> None:
        _, report = clean_bytes(data, fmt)
        assert report.parse_status == "refused"
        assert report.refusal_reasons
        assert f"{fmt}.refusal.structure" in report.metadata

    def test_unsupported_format_says_so(self) -> None:
        cleaned, report = clean_bytes(b"%PDF-1.7\n", "pdf")
        assert cleaned == b"%PDF-1.7\n"
        assert report.parse_status == "unsupported"
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
    def test_retained_manifest_bytes_are_not_called_preserved_provenance(self) -> None:
        _, report = clean_bytes(build_png(c2pa=True), "png")
        reasons = " ".join(u.reason for u in report.undeterminable)
        assert "PRESERVED" not in reasons
        assert "NOT VERIFIED" in reasons
        assert report.parse_status == "refused"
        assert report.metadata["png.c2pa_manifest_bytes_retained"] is True

    def test_binary_clean_report_omits_statistical_text_notice(self) -> None:
        _, report = clean_bytes(build_png(), "png")
        assert not any(
            "statistical text watermark" in u.claim for u in report.undeterminable
        )

    def test_selective_removal_refusal_when_there_is_no_manifest(self) -> None:
        _, report = clean_bytes(build_png(text={"a": "b"}), "png")
        assert report.parse_status == "refused"
        assert "png.refusal.selective_cleaning" in report.metadata


class TestCli:
    def test_in_place_refuses_ambiguous_metadata(self, tmp_path) -> None:
        p = tmp_path / "shot.png"
        original = build_png(text={"Software": "Gen", "Author": "me"}, c2pa=True)
        p.write_bytes(original)
        assert main(["clean", "-i", str(p), "--quiet"]) == 2
        assert p.read_bytes() == original

    def test_dry_run_leaves_the_file_alone(self, tmp_path) -> None:
        p = tmp_path / "shot.png"
        original = build_png(text={"Software": "Gen"})
        p.write_bytes(original)
        assert main(["clean", "--dry-run", str(p), "--quiet"]) == 2
        assert p.read_bytes() == original

    def test_backup_keeps_the_original(self, tmp_path) -> None:
        p = tmp_path / "shot.png"
        original = build_png(text={"Software": "Gen"})
        p.write_bytes(original)
        assert main(["clean", "-i", "--backup", str(p), "--quiet"]) == 2
        assert not (tmp_path / "shot.png.bak").exists()
        assert p.read_bytes() == original

    def test_binary_to_stdout_is_refused(self, tmp_path, capsys) -> None:
        p = tmp_path / "shot.png"
        p.write_bytes(build_png(text={"Software": "Gen"}))
        assert main(["clean", str(p)]) == 2
        assert "rewrites binary data" in capsys.readouterr().err

    def test_check_reports_without_writing(self, tmp_path) -> None:
        p = tmp_path / "shot.png"
        original = build_png(text={"Software": "Gen"})
        p.write_bytes(original)
        assert main(["clean", "--check", str(p), "--quiet"]) == 2
        assert p.read_bytes() == original


class TestImageFidelity:
    def test_png_pixels_and_profile_survive_refused_clean(self) -> None:
        image_module = pytest.importorskip("PIL.Image")
        png_module = pytest.importorskip("PIL.PngImagePlugin")
        from io import BytesIO

        image = image_module.new("RGB", (2, 2), (12, 34, 56))
        info = png_module.PngInfo()
        info.add_text("Copyright", "Example rights holder")
        stream = BytesIO()
        image.save(stream, format="PNG", pnginfo=info, icc_profile=b"profile-bytes")
        original = stream.getvalue()
        cleaned, report = clean_bytes(original, "png")
        assert report.parse_status == "refused"
        with (
            image_module.open(BytesIO(original)) as before,
            image_module.open(BytesIO(cleaned)) as after,
        ):
            assert list(after.getdata()) == list(before.getdata())
            assert after.info.get("Copyright") == before.info.get("Copyright")
            assert after.info.get("icc_profile") == before.info.get("icc_profile")

    def test_jpeg_orientation_and_pixels_survive_refused_clean(self) -> None:
        image_module = pytest.importorskip("PIL.Image")
        from io import BytesIO

        image = image_module.new("RGB", (3, 2), (90, 80, 70))
        exif = image_module.Exif()
        exif[274] = 6
        stream = BytesIO()
        image.save(stream, format="JPEG", exif=exif)
        original = stream.getvalue()
        cleaned, report = clean_bytes(original, "jpeg")
        assert report.parse_status == "refused"
        with (
            image_module.open(BytesIO(original)) as before,
            image_module.open(BytesIO(cleaned)) as after,
        ):
            assert after.getexif().get(274) == before.getexif().get(274) == 6
            assert list(after.getdata()) == list(before.getdata())
