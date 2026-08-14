"""Confusables: detection everywhere, folding only where it is safe.

The governing constraint is that folding a lookalike is destructive when the
character is simply the language. A tool that maps Cyrillic е to Latin e
wherever it appears turns ``привет мир`` into ``пpивeт миp`` -- text that is
*more* confusable than the input, and no longer Russian. Scope, not the size of
the lookalike table, is what makes this safe.
"""

from __future__ import annotations

import pytest

from hiddenink.core.clean_text import Profile, clean_text
from hiddenink.core.codepoints import Category, Severity, classify
from hiddenink.core.confusables import (
    CROSS_SCRIPT_FOLD,
    fold_confusables,
    nfkc_fold,
    script_of,
    scripts_in,
    suspicious_runs,
)
from hiddenink.core.inspect_text import inspect_text


class TestScriptDetection:
    @pytest.mark.parametrize(
        ("char", "script"),
        [
            ("a", "Latin"),
            ("Z", "Latin"),
            ("é", "Latin"),
            ("а", "Cyrillic"),
            ("Ж", "Cyrillic"),
            ("ο", "Greek"),
            ("Ω", "Greek"),
            ("Ꭺ", "Cherokee"),
            ("א", "Hebrew"),
            ("ا", "Arabic"),
            ("中", "Han"),
            ("ひ", "Hiragana"),
            ("カ", "Katakana"),
            ("한", "Hangul"),
            ("1", "Common"),
            (" ", "Common"),
            ("-", "Common"),
        ],
    )
    def test_script_of(self, char: str, script: str) -> None:
        assert script_of(ord(char)) == script

    def test_digits_and_punctuation_are_common(self) -> None:
        assert scripts_in("123 -_.") == frozenset()


class TestMixedScriptDetection:
    @pytest.mark.parametrize(
        "text",
        ["pаypal", "gοogle", "ᎪPPLE", "аpple.com", "micrοsoft"],
    )
    def test_homographs_are_flagged(self, text: str) -> None:
        assert suspicious_runs(text), f"{text!r} should be suspicious"

    @pytest.mark.parametrize(
        "text",
        [
            "paypal.com",
            "привет мир",
            "hello привет",
            "日本語のテキストです",
            "한국어 漢字 텍스트",
            "ρ = m/V",
            "café résumé",
            "",
            "a",
        ],
    )
    def test_legitimate_text_is_not_flagged(self, text: str) -> None:
        assert not suspicious_runs(text), f"{text!r} falsely flagged"

    def test_single_characters_are_not_flagged(self) -> None:
        """Too short to be a meaningful impersonation."""
        assert not suspicious_runs("а")

    def test_run_reports_its_scripts_and_offset(self) -> None:
        runs = suspicious_runs("go to pаypal now")
        assert len(runs) == 1
        assert runs[0].text == "pаypal"
        assert runs[0].offset == 7
        assert (runs[0].span_start, runs[0].span_end) == (6, 12)
        assert runs[0].scripts == frozenset({"Latin", "Cyrillic"})


class TestNfkcFolding:
    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            ("ｈｅｌｌｏ", "hello"),
            ("𝐡𝐞𝐥𝐥𝐨", "hello"),
            ("𝘩𝘦𝘭𝘭𝘰", "hello"),
            ("ⓗⓔⓛⓛⓞ", "hello"),
            ("x²", "x2"),
            ("ﬁle", "file"),
        ],
    )
    def test_compatibility_variants_fold_anywhere(
        self, given: str, expected: str
    ) -> None:
        folded, count = fold_confusables(given)
        assert folded == expected
        assert count > 0

    def test_ascii_is_untouched(self) -> None:
        assert nfkc_fold(ord("a")) is None

    def test_non_ascii_letters_are_not_folded(self) -> None:
        """NFKC must not be used to strip accents or scripts."""
        for char in "éàüñ中ひаο":
            assert nfkc_fold(ord(char)) is None, char


class TestScopedCrossScriptFolding:
    def test_homograph_is_folded(self) -> None:
        assert fold_confusables("pаypal")[0] == "paypal"

    @pytest.mark.parametrize(
        "text", ["привет мир", "ρ = m/V and ν = 3", "hello привет", "Ω = 5"]
    )
    def test_legitimate_non_latin_is_never_folded(self, text: str) -> None:
        folded, count = fold_confusables(text)
        assert folded == text
        assert count == 0

    def test_the_regression_this_prevents(self) -> None:
        """Unscoped folding produces mixed-script mush, not clean text."""
        text = "привет мир"
        unscoped = "".join(CROSS_SCRIPT_FOLD.get(ord(c), c) for c in text)
        assert unscoped != text  # an unscoped table would mangle it
        assert fold_confusables(text)[0] == text  # scoped folding does not


class TestProfileBehaviour:
    def test_code_profile_reports_but_does_not_rewrite_homographs(self) -> None:
        text = "if pаypal_ok:"
        assert clean_text(text, Profile.CODE)[0] == text
        assert suspicious_runs(text)

    def test_prose_profile_reports_but_does_not_fold(self) -> None:
        text = "visit pаypal"
        assert clean_text(text, Profile.PROSE)[0] == text
        findings = inspect_text(text).findings
        assert any(f.category is Category.MIXED_SCRIPT for f in findings)

    def test_urls_are_never_folded_even_under_code(self) -> None:
        """A homograph domain must stay visible, not be silently rewritten."""
        text = "https://pаypal.com"
        assert clean_text(text, Profile.CODE)[0] == text

    def test_code_fences_do_not_rewrite_homographs(self) -> None:
        text = "```\nx = pаypal\n```"
        cleaned, _ = clean_text(text, Profile.PROSE)
        assert cleaned == text

    @pytest.mark.parametrize("profile", list(Profile))
    def test_russian_survives_every_profile(self, profile: Profile) -> None:
        assert clean_text("привет мир", profile)[0] == "привет мир"

    @pytest.mark.parametrize("profile", list(Profile))
    def test_greek_notation_survives_every_profile(self, profile: Profile) -> None:
        assert clean_text("ρ = m/V and ν = 3", profile)[0] == "ρ = m/V and ν = 3"


class TestReporting:
    def test_mixed_script_run_becomes_a_finding(self) -> None:
        findings = inspect_text("go to pаypal now").findings
        mixed = [f for f in findings if f.category is Category.MIXED_SCRIPT]
        assert len(mixed) == 1
        assert mixed[0].severity is Severity.CONFUSABLE
        assert "Cyrillic" in mixed[0].name
        assert mixed[0].codepoint == ord("а")
        assert (mixed[0].line, mixed[0].column) == (1, 8)

    def test_compatibility_variants_are_classified(self) -> None:
        info = classify(ord("ｈ"))
        assert info is not None
        assert info.category is Category.COMPATIBILITY_VARIANT
        assert info.severity is Severity.TYPOGRAPHIC

    def test_clean_text_reports_no_confusables(self) -> None:
        assert inspect_text("ordinary ascii text").findings == []

    def test_findings_are_ordered_by_offset(self) -> None:
        report = inspect_text("pаypal and hel​lo")
        offsets = [f.offset for f in report.findings]
        assert offsets == sorted(offsets)
