"""CLI/report regressions for safe repository-scale operation."""

from __future__ import annotations

import json
import os
import stat
import sys
from io import StringIO
from pathlib import Path

import pytest

from hiddenink.cli import _render, _Style, main
from hiddenink.core.formats._safety import MAX_CONTAINER_BYTES
from hiddenink.core.report import Report, Undeterminable


class TestRecursiveTraversal:
    def test_directory_requires_explicit_recursive_flag(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "a.txt").write_text("ok", encoding="utf-8")
        assert main(["inspect", str(tmp_path)]) == 2
        assert "pass --recursive" in capsys.readouterr().err

    def test_recursive_order_is_stable_and_duplicate_paths_are_removed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        nested = tmp_path / "nested"
        nested.mkdir()
        a = tmp_path / "a.txt"
        b = nested / "b.txt"
        a.write_text("a", encoding="utf-8")
        b.write_text("b", encoding="utf-8")

        assert main(["inspect", "-r", str(tmp_path), str(a), "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert [item["source"] for item in payload] == sorted((str(a), str(b)))

    def test_recursive_traversal_skips_named_build_directories(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "ignored").write_bytes(b"\xff")
        visible = tmp_path / "visible.txt"
        visible.write_text("ok", encoding="utf-8")
        assert main(["inspect", "-r", str(tmp_path), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["source"] == str(visible)

    def test_symlink_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "target.txt"
        link = tmp_path / "link.txt"
        target.write_text("a\u200bb", encoding="utf-8")
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks unavailable")
        assert main(["clean", "-i", str(link)]) == 2
        assert target.read_text(encoding="utf-8") == "a\u200bb"

    def test_ignored_name_does_not_hide_a_symlink(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        root = tmp_path / "root"
        outside.mkdir()
        root.mkdir()
        (outside / "payload.txt").write_text("ok", encoding="utf-8")
        try:
            (root / ".git").symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks unavailable")
        assert main(["inspect", "--recursive", str(root)]) == 2

    def test_invalid_unrecognised_bytes_are_an_input_error(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "unknown.bin"
        path.write_bytes(b"\xff\xfe\xfd")
        assert main(["inspect", str(path)]) == 2

    @pytest.mark.parametrize("command", ["inspect", "clean"])
    def test_oversized_file_is_refused_before_reading(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        command: str,
    ) -> None:
        path = tmp_path / "oversized.txt"
        with path.open("wb") as handle:
            handle.truncate(MAX_CONTAINER_BYTES + 1)
        original = Path.read_bytes

        def guarded_read(candidate: Path) -> bytes:
            if candidate == path:
                raise AssertionError("oversized file was read")
            return original(candidate)

        monkeypatch.setattr(Path, "read_bytes", guarded_read)
        assert main([command, str(path)]) == 2

    def test_stdin_is_bounded(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr("hiddenink.cli.MAX_TEXT_CODEPOINTS", 8)
        monkeypatch.setattr("hiddenink.cli._MAX_TEXT_BYTES", 8)
        monkeypatch.setattr(sys, "stdin", StringIO("123456789"))
        assert main(["inspect", "-"]) == 2
        assert "stdin exceeds" in capsys.readouterr().err

    def test_aggregate_input_limit_is_preflighted_before_reads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = tmp_path / "first.txt"
        second = tmp_path / "second.txt"
        for path in (first, second):
            with path.open("wb") as handle:
                handle.truncate(MAX_CONTAINER_BYTES // 2 + 1)

        def forbidden_read(_candidate: Path) -> bytes:
            raise AssertionError("aggregate-limit inputs must not be read")

        monkeypatch.setattr(Path, "read_bytes", forbidden_read)
        assert main(["clean", "--in-place", str(first), str(second)]) == 2

    def test_contextual_severity_has_defined_threshold_order(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "contextual.txt"
        path.write_text("a\ue000b", encoding="utf-8")
        assert main(["inspect", "--fail-on", "contextual", str(path)]) == 1
        assert main(["inspect", "--fail-on", "invisible", str(path)]) == 0


class TestAtomicInPlace:
    def test_svg_cleaning_is_refused_without_changing_visible_content(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "art.svg"
        original = (
            b'<svg xmlns="http://www.w3.org/2000/svg">'
            b'<a href="https://example.com/a\xe2\x80\x94b">'
            b"<text>Visible\xe2\x80\x94text</text></a></svg>"
        )
        path.write_bytes(original)
        assert main(["clean", "--in-place", str(path)]) == 2
        assert path.read_bytes() == original

    def test_replacement_preserves_mode_and_mtime(self, tmp_path: Path) -> None:
        path = tmp_path / "sample.txt"
        path.write_text("a\u200bb", encoding="utf-8")
        path.chmod(0o640)
        timestamp = 1_700_000_000_123_456_789
        os.utime(path, ns=(timestamp, timestamp))
        before = path.stat()

        assert main(["clean", "-i", str(path), "--quiet"]) == 0
        after = path.stat()
        assert path.read_text(encoding="utf-8") == "ab"
        assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
        assert after.st_mtime_ns == before.st_mtime_ns
        if os.name != "nt":
            assert after.st_ino != before.st_ino

    def test_existing_backup_is_not_overwritten_without_authorisation(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "sample.txt"
        backup = tmp_path / "sample.txt.bak"
        path.write_text("a\u200bb", encoding="utf-8")
        backup.write_text("keep me", encoding="utf-8")

        assert main(["clean", "-i", "--backup", str(path)]) == 2
        assert path.read_text(encoding="utf-8") == "a\u200bb"
        assert backup.read_text(encoding="utf-8") == "keep me"

    def test_existing_backup_can_be_replaced_explicitly(self, tmp_path: Path) -> None:
        path = tmp_path / "sample.txt"
        backup = tmp_path / "sample.txt.bak"
        path.write_text("a\u200bb", encoding="utf-8")
        backup.write_text("stale", encoding="utf-8")

        assert (
            main(
                [
                    "clean",
                    "-i",
                    "--backup",
                    "--overwrite-backup",
                    str(path),
                    "--quiet",
                ]
            )
            == 0
        )
        assert path.read_text(encoding="utf-8") == "ab"
        assert backup.read_text(encoding="utf-8") == "a\u200bb"

    def test_backup_path_cannot_also_be_a_selected_target(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "a.txt"
        backup = tmp_path / "a.txt.bak"
        path.write_text("a\u200bb", encoding="utf-8")
        backup.write_text("c\u200bd", encoding="utf-8")

        assert (
            main(
                [
                    "clean",
                    "--in-place",
                    "--backup",
                    "--overwrite-backup",
                    str(path),
                    str(backup),
                ]
            )
            == 2
        )
        assert path.read_text(encoding="utf-8") == "a\u200bb"
        assert backup.read_text(encoding="utf-8") == "c\u200bd"

    def test_preflight_refusal_prevents_partial_multi_file_write(
        self, tmp_path: Path
    ) -> None:
        text = tmp_path / "a.txt"
        pdf = tmp_path / "z.pdf"
        text.write_text("a\u200bb", encoding="utf-8")
        pdf.write_bytes(b"%PDF-1.7\n%%EOF\n")

        assert main(["clean", "-i", str(text), str(pdf)]) == 2
        assert text.read_text(encoding="utf-8") == "a\u200bb"

    def test_failed_replace_leaves_original_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "sample.txt"
        path.write_text("a\u200bb", encoding="utf-8")

        def fail_replace(_source: Path, _destination: Path) -> None:
            raise OSError("synthetic replace failure")

        monkeypatch.setattr(os, "replace", fail_replace)
        assert main(["clean", "-i", str(path)]) == 2
        assert path.read_text(encoding="utf-8") == "a\u200bb"
        assert not list(tmp_path.glob(".*.tmp"))


class TestReportAccuracy:
    @pytest.mark.parametrize(
        "status",
        [
            "complete",
            "partial",
            "unsupported",
            "malformed",
            "refused",
            "resource_limit",
        ],
    )
    def test_public_parser_status_vocabulary(self, status: str) -> None:
        report = Report(source="x.bin", kind="png", parse_status=status)
        serialized = report.to_dict()["verifiable"]["status"]
        assert serialized["parse_status"] == status

    def test_binary_report_has_no_statistical_text_notice(self) -> None:
        report = Report(source="image.png", kind="png")
        assert not report.undeterminable
        assert report.parse_status == "partial"
        assert not report.is_clean
        assert "NOT DETERMINABLE" not in _render(report, _Style(False))

    def test_status_and_separate_transformation_counts_are_serialised(self) -> None:
        report = Report(source="data.csv", kind="text", changed=True)
        report.removed = 1
        report.folded = 2
        report.normalized = 3
        payload = report.to_dict()
        assert payload["verifiable"]["status"]["parse_status"] == "complete"
        assert payload["removed"] == 1
        assert payload["folded"] == 2
        assert payload["normalized"] == 3
        assert payload["transformed"] == 6

    def test_namespaced_parser_diagnostics_are_lifted(self) -> None:
        report = Report(
            source="x.png",
            kind="png",
            metadata={
                "png.parse_status": "refused",
                "png.coverage": "structure only",
                "png.warning.1": "truncated chunk",
                "png.refusal.1": "invalid IEND",
            },
        )
        assert report.parse_status == "refused"
        assert report.coverage == "structure only"
        assert report.warnings == ["truncated chunk"]
        assert report.refusal_reasons == ["invalid IEND"]

    def test_diagnostics_do_not_count_as_found_metadata(self) -> None:
        report = Report(
            source="x.png",
            kind="png",
            metadata={
                "png.parse_status": "complete",
                "png.coverage": "chunks and metadata",
            },
        )
        assert report.is_clean
        assert not report.substantive_metadata

    def test_human_output_escapes_terminal_and_bidi_controls(self) -> None:
        report = Report(
            source="\x1b]0;title\x07.png",
            kind="png",
            metadata={"\x1b[31mkey": "\x1b]52;c;payload\x07\u202e"},
            warnings=["\x1b[2J"],
            undeterminable=[Undeterminable("x", "\x1b]8;;https://bad\x07click")],
        )
        rendered = _render(report, _Style(False))
        assert "\x1b" not in rendered
        assert "\x07" not in rendered
        assert "\u202e" not in rendered
        assert "\\x1b" in rendered
        assert "\\u202e" in rendered

    def test_json_preserves_untrusted_values_safely(self) -> None:
        key = "\x1b[31mkey"
        value = "\x1b]52;c;payload\x07\u202e"
        report = Report(source="x.png", kind="png", metadata={key: value})
        encoded = report.to_json()
        assert "\x1b" not in encoded
        payload = json.loads(encoded)
        assert payload["verifiable"]["metadata"] == {key: value}
