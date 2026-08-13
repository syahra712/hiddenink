"""Core classification, inspection, and cleaning behaviour."""

from __future__ import annotations

import pytest

from marklens.core.clean_text import Profile, clean_text, protected_regions
from marklens.core.codepoints import Category, Severity, classify
from marklens.core.inspect_text import inspect_text

ZWSP = "​"
NBSP = " "
RLO = "‮"
TAG_A = "\U000e0041"
SHY = "­"
VS16 = "️"


class TestClassify:
    @pytest.mark.parametrize(
        ("cp", "category"),
        [
            (0x200B, Category.ZERO_WIDTH),
            (0xFEFF, Category.ZERO_WIDTH),
            (0x202E, Category.BIDI_CONTROL),
            (0x2066, Category.BIDI_CONTROL),
            (0x2062, Category.INVISIBLE_OPERATOR),
            (0xE0041, Category.TAG_CHARACTER),
            (0x00AD, Category.SOFT_HYPHEN),
            (0x00A0, Category.EXOTIC_SPACE),
            (0x3000, Category.EXOTIC_SPACE),
            (0x201C, Category.SMART_QUOTE),
            (0x2014, Category.DASH),
            (0x2026, Category.ELLIPSIS),
            (0xE000, Category.PRIVATE_USE),
            (0x0000, Category.CONTROL),
        ],
    )
    def test_known_codepoints(self, cp: int, category: Category) -> None:
        info = classify(cp)
        assert info is not None
        assert info.category is category

    @pytest.mark.parametrize("ch", ["a", "Z", "0", " ", "\n", "\t", "\r", "é", "中", "؟"])
    def test_ordinary_text_is_unremarkable(self, ch: str) -> None:
        assert classify(ord(ch)) is None

    def test_severity_partition(self) -> None:
        assert classify(0x200B).severity is Severity.INVISIBLE
        assert classify(0x00A0).severity is Severity.WHITESPACE
        assert classify(0x2014).severity is Severity.TYPOGRAPHIC


class TestInspect:
    def test_finds_zero_width_at_exact_position(self) -> None:
        report = inspect_text(f"ab{ZWSP}cd")
        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.offset == 2
        assert f.line == 1
        assert f.column == 3
        assert f.escape == "U+200B"

    def test_line_and_column_track_newlines(self) -> None:
        report = inspect_text(f"one\ntwo\nth{ZWSP}ree")
        f = report.findings[0]
        assert (f.line, f.column) == (3, 3)

    def test_emoji_variation_selector_is_not_flagged(self) -> None:
        assert inspect_text(f"heart ❤{VS16} here").findings == []

    def test_keycap_sequence_is_not_flagged(self) -> None:
        assert inspect_text(f"1{VS16}⃣").findings == []

    def test_orphan_variation_selector_is_flagged(self) -> None:
        report = inspect_text(f"plain{VS16}text")
        assert [f.category for f in report.findings] == [Category.VARIATION_SELECTOR]

    def test_clean_text_reports_nothing(self) -> None:
        report = inspect_text("Perfectly ordinary sentence.\n")
        assert report.findings == []
        assert report.is_clean

    def test_report_always_carries_the_undeterminable_section(self) -> None:
        report = inspect_text("anything")
        assert len(report.undeterminable) == 1
        assert "NOT EVALUATED" in report.undeterminable[0].reason

    def test_json_has_both_sections(self) -> None:
        payload = inspect_text(f"x{ZWSP}").to_dict()
        assert "verifiable" in payload
        assert "not_determinable" in payload
        assert payload["verifiable"]["total"] == 1


class TestProtectedRegions:
    def test_detects_fenced_block(self) -> None:
        text = "before\n```py\ncode\n```\nafter\n"
        spans = protected_regions(text)
        assert any(text[s:e].startswith("```") for s, e, _ in spans)

    def test_url_not_double_counted_inside_code(self) -> None:
        text = "`see https://x.com/a`"
        spans = protected_regions(text)
        assert len(spans) == 1


class TestClean:
    def test_removes_all_invisible_categories(self) -> None:
        dirty = f"a{ZWSP}b{RLO}c{TAG_A}d{SHY}e"
        cleaned, report = clean_text(dirty, Profile.PROSE)
        assert cleaned == "abcde"
        assert report.removed == 4
        assert report.changed

    def test_prose_preserves_typography(self) -> None:
        cleaned, _ = clean_text("a—b and “q”…", Profile.PROSE)
        assert cleaned == "a—b and “q”…"

    def test_code_folds_typography(self) -> None:
        cleaned, _ = clean_text("a—b and “q”…", Profile.CODE)
        assert cleaned == "a-b and \"q\"..."

    def test_exotic_space_folded_under_every_profile(self) -> None:
        for profile in Profile:
            cleaned, _ = clean_text(f"a{NBSP}b", profile)
            assert cleaned == "a b", profile

    def test_urls_are_never_folded(self) -> None:
        text = "see https://example.com/a—b now"
        for profile in Profile:
            cleaned, _ = clean_text(text, profile)
            assert "example.com/a—b" in cleaned, profile

    def test_invisible_still_stripped_from_urls(self) -> None:
        cleaned, _ = clean_text(f"https://example.com/{ZWSP}path", Profile.PROSE)
        assert cleaned == "https://example.com/path"

    def test_code_spans_folded_even_under_prose(self) -> None:
        cleaned, _ = clean_text("prose “kept” and `x = “y”`", Profile.PROSE)
        assert "prose “kept”" in cleaned
        assert '`x = "y"`' in cleaned

    def test_fenced_block_folded_even_under_prose(self) -> None:
        text = 'say “hi”\n\n```py\nn = “v”\n```\n'
        cleaned, _ = clean_text(text, Profile.PROSE)
        assert 'say “hi”' in cleaned
        assert 'n = "v"' in cleaned

    def test_emoji_survives_cleaning(self) -> None:
        for profile in Profile:
            cleaned, _ = clean_text(f"hi ❤{VS16} there", profile)
            assert cleaned == f"hi ❤{VS16} there", profile

    def test_data_profile_strips_bom_and_normalises_newlines(self) -> None:
        cleaned, _ = clean_text("﻿a,b\r\nc,d\r\n", Profile.DATA)
        assert cleaned == "a,b\nc,d\n"

    def test_bom_mid_document_is_still_removed(self) -> None:
        cleaned, _ = clean_text("a﻿b", Profile.PROSE)
        assert cleaned == "ab"

    def test_no_change_reports_unchanged(self) -> None:
        cleaned, report = clean_text("ordinary text", Profile.CODE)
        assert cleaned == "ordinary text"
        assert not report.changed
        assert report.removed == 0


class TestIdempotence:
    """clean(clean(x)) == clean(x) for every profile.

    Folding U+2026 to "..." changes length, so idempotence is a real property
    to verify rather than an obvious one.
    """

    SAMPLES = [
        f"a{ZWSP}b{NBSP}c—d…",
        f"`x = “y”` and https://e.com/a—b {TAG_A}",
        "﻿csv,header\r\nv1,v2\r\n",
        f"❤{VS16} 1{VS16}⃣ {RLO}rtl",
        "```\nn = “v”\n```\n",
        "",
    ]

    @pytest.mark.parametrize("profile", list(Profile))
    @pytest.mark.parametrize("sample", SAMPLES)
    def test_idempotent(self, sample: str, profile: Profile) -> None:
        once, _ = clean_text(sample, profile)
        twice, _ = clean_text(once, profile)
        assert once == twice

    @pytest.mark.parametrize("profile", list(Profile))
    @pytest.mark.parametrize("sample", SAMPLES)
    def test_cleaned_output_has_no_invisible_findings(
        self, sample: str, profile: Profile
    ) -> None:
        once, _ = clean_text(sample, profile)
        remaining = [
            f for f in inspect_text(once).findings if f.severity is Severity.INVISIBLE
        ]
        assert remaining == []
