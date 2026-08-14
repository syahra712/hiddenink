"""Executable enforcement of the CHARTER.md rules.

These tests exist so the project's promises are checked by CI rather than by
good intentions. If one fails, the fix is to change the code -- or to amend
the charter in the same pull request, deliberately.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from hiddenink.core.clean_text import Profile, clean_text
from hiddenink.core.inspect_text import inspect_text
from hiddenink.core.report import Report

SRC = Path(__file__).resolve().parent.parent / "src"


class TestRule1NeverClaimTheUndecidable:
    """No user-facing string may claim the statistical layer was handled."""

    BANNED = [
        "watermark removed",
        "watermark is removed",
        "now undetectable",
        "ai-proof",
        "bypasses detection",
        "bypass detection",
        "100% clean",
        "guaranteed removal",
        "undetectable by",
    ]

    @pytest.mark.parametrize("phrase", BANNED)
    def test_phrase_absent_from_source(self, phrase: str) -> None:
        for path in SRC.rglob("*.py"):
            text = path.read_text(encoding="utf-8").lower()
            assert phrase not in text, f"{path.name} contains banned claim: {phrase!r}"

    def test_clean_report_never_says_the_mark_is_gone(self) -> None:
        _, report = clean_text("a​b—c", Profile.CODE)
        blob = report.to_json().lower()
        assert "not evaluated" in blob
        for phrase in self.BANNED:
            assert phrase not in blob

    def test_is_clean_does_not_imply_unmarked(self) -> None:
        """A spotless character layer still carries the statistical caveat."""
        report = inspect_text("Entirely ordinary prose.")
        assert report.is_clean
        assert any("NOT EVALUATED" in u.reason for u in report.undeterminable)


class TestRule2SectionsStaySeparate:
    def test_every_report_has_both_sections(self) -> None:
        for report in (
            inspect_text("x"),
            clean_text("x", Profile.PROSE)[1],
            Report(source="synthetic"),
        ):
            payload = report.to_dict()
            assert "verifiable" in payload
            assert "not_determinable" in payload
            assert payload["not_determinable"], "undeterminable section must be non-empty"

    def test_undeterminable_survives_explicit_empty_construction(self) -> None:
        """The caveat cannot be suppressed by passing an empty list."""
        assert Report(source="s", undeterminable=[]).undeterminable


class TestTransformationCounts:
    def test_removal_folding_and_normalisation_are_separate(self) -> None:
        cleaned, report = clean_text("﻿a—b\r\nc\u200bd", Profile.DATA)
        assert cleaned == "a-b\ncd"
        assert report.removed == 1
        assert report.folded == 1
        assert report.normalized == 2
        assert report.transformed == 4

    def test_data_only_normalisation_is_not_reported_as_zero_changes(self) -> None:
        cleaned, report = clean_text("﻿a\r\n", Profile.DATA)
        assert cleaned == "a\n"
        assert report.changed
        assert report.removed == 0
        assert report.folded == 0
        assert report.normalized == 2


class TestRule4CoreHasNoThirdPartyImports:
    def test_no_third_party_imports(self) -> None:
        """The core and CLI must import nothing outside the standard library."""
        code = (
            "import sys\n"
            "baseline = set(sys.modules)\n"
            "import hiddenink.cli, hiddenink.core, hiddenink.core.formats\n"
            "new = set(sys.modules) - baseline\n"
            "third = {m.split('.')[0] for m in new} "
            "- set(sys.stdlib_module_names) - {'hiddenink'}\n"
            "print(','.join(sorted(third)))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(SRC)},
            check=True,
        )
        leaked = result.stdout.strip()
        assert not leaked, f"core pulled in third-party modules: {leaked}"


class TestRule5ContentAwareRemoval:
    """The correctness traps listed in the charter, as regression tests."""

    def test_emoji_presentation_sequence_preserved(self) -> None:
        for profile in Profile:
            assert clean_text("ok ❤️", profile)[0] == "ok ❤️"

    def test_keycap_sequence_preserved(self) -> None:
        for profile in Profile:
            assert clean_text("1️⃣", profile)[0] == "1️⃣"

    def test_url_punctuation_never_folded(self) -> None:
        for profile in Profile:
            out, _ = clean_text("https://x.com/a—b", profile)
            assert out == "https://x.com/a—b"

    def test_code_fence_folded_under_prose(self) -> None:
        out, _ = clean_text('t “q”\n\n```\nv = “w”\n```\n', Profile.PROSE)
        assert "t “q”" in out  # prose typography preserved
        assert 'v = "w"' in out  # code fence folded

    def test_mid_document_feff_removed(self) -> None:
        assert clean_text("a﻿b", Profile.PROSE)[0] == "ab"

    def test_malformed_container_does_not_raise(self) -> None:
        from hiddenink.core.formats import parse_bytes

        junk_inputs = (
            b"\x89PNG\r\n\x1a\n" + b"\xff" * 9,
            b"%PDF-1.7\n<<",
            b"PK\x03\x04junk",
        )
        for junk in junk_inputs:
            parse_bytes(junk)  # must not raise


class TestRule6AbsenceIsNotAbsence:
    def test_c2pa_capable_file_without_manifest_warns_about_soft_binding(
        self, tmp_path
    ) -> None:
        from hiddenink.core.formats import inspect_file
        from test_formats import build_png

        p = tmp_path / "x.png"
        p.write_bytes(build_png())
        reasons = " ".join(u.reason for u in inspect_file(p).undeterminable).lower()
        assert "soft binding" in reasons.replace("-", " ")
        assert "does not establish the absence" in reasons


class TestEncodingIsAlwaysExplicit:
    """No text file read or write may rely on the platform default encoding.

    The default is cp1252 on Windows, so a bare ``read_text()`` raises on any
    file containing emoji, Devanagari, or Cyrillic -- all of which appear in
    this project's own fixtures and README. This has caused two separate
    failures already: a CLI crash on a Windows console, and then the
    release-integrity tests written to catch released mistakes.

    Checked over the AST rather than by grepping lines, because a line-based
    version reported ``zipfile.open`` (which is binary), calls whose
    ``encoding=`` sat on a later line, and its own source.
    """

    #: Text modes. A mode containing "b" is binary and takes no encoding.
    _TEXT_MODE = re.compile(r"^[rwxa]\+?$")

    def _violations(self, path: Path) -> list[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        found: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(
                node.func, ast.Attribute
            ):
                continue
            name = node.func.attr
            if name not in ("read_text", "write_text", "open"):
                continue
            if any(kw.arg == "encoding" for kw in node.keywords):
                continue
            if name == "open":
                # Only a literal text mode makes this a text stream; anything
                # else (zipfile members, no mode, a variable) is out of scope.
                modes = [
                    a.value
                    for a in node.args
                    if isinstance(a, ast.Constant) and isinstance(a.value, str)
                ]
                if not any(self._TEXT_MODE.match(m) for m in modes):
                    continue
            found.append(f"{path.name}:{node.lineno}: {name}() without encoding=")
        return found

    def test_no_implicit_encoding(self) -> None:
        offenders: list[str] = []
        for path in (*SRC.rglob("*.py"), *Path(__file__).parent.glob("*.py")):
            offenders.extend(self._violations(path))
        assert not offenders, "implicit encoding:\n  " + "\n  ".join(offenders)
