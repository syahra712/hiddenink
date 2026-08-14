"""Regressions for Unicode sequence validity, locations, and linear scaling."""

from __future__ import annotations

import importlib
import time

import pytest

from hiddenink.core.clean_text import Profile, clean_text, protected_regions
from hiddenink.core.codepoints import Category, is_load_bearing, load_bearing_indices
from hiddenink.core.confusables import script_of, suspicious_runs
from hiddenink.core.inspect_text import inspect_text

ZWJ = "\u200d"
ZWNJ = "\u200c"
VS16 = "\ufe0f"
IVS1 = "\U000e0100"
TAG_END = "\U000e007f"
SCOTLAND = "\U0001f3f4" + "".join(chr(0xE0000 + ord(char)) for char in "gbsct") + TAG_END


class TestVariationSequences:
    @pytest.mark.parametrize("profile", list(Profile))
    def test_registered_ideographic_sequence_survives(self, profile: Profile) -> None:
        # Registered in Unicode's IVD (Adobe-Japan1, among other collections).
        text = "\u9089" + IVS1
        assert clean_text(text, profile)[0] == text
        assert inspect_text(text).findings == []

    def test_supplementary_selector_without_ideograph_is_removed(self) -> None:
        assert clean_text("A" + IVS1, Profile.PROSE)[0] == "A"

    def test_standardized_symbol_variant_survives(self) -> None:
        # U+2205 U+FE00 is listed in StandardizedVariants.txt.
        text = "\u2205\ufe00"
        assert clean_text(text, Profile.PROSE)[0] == text

    def test_registered_ascii_standardized_variant_survives(self) -> None:
        # U+0030 U+FE00 is listed in StandardizedVariants.txt.
        text = "0\ufe00"
        assert clean_text(text, Profile.PROSE)[0] == text

    def test_registered_cjk_compatibility_variant_survives(self) -> None:
        # U+4E3D U+FE00 is listed in StandardizedVariants.txt.
        text = "\u4e3d\ufe00"
        assert clean_text(text, Profile.PROSE)[0] == text

    @pytest.mark.parametrize("base", ["\u2b08", "\u219a", "A"])
    def test_non_emoji_block_members_do_not_vouch_for_vs16(self, base: str) -> None:
        assert clean_text(base + VS16, Profile.PROSE)[0] == base

    @pytest.mark.parametrize("base", ["\U0001f100", "\U0001f1e6"])
    def test_non_emoji_supplementary_characters_do_not_vouch_for_invisibles(
        self, base: str
    ) -> None:
        assert clean_text(base + VS16, Profile.PROSE)[0] == base
        assert clean_text(f"{base}{ZWJ}{base}", Profile.PROSE)[0] == base * 2


class TestJoinerAndTagValidity:
    @pytest.mark.parametrize(
        "text",
        [f"A{ZWJ}ب", f"ب{ZWJ}A", f"A{ZWJ}١", f"١{ZWNJ}ب"],
    )
    def test_one_sided_or_non_letter_script_context_is_not_enough(
        self, text: str
    ) -> None:
        assert ZWJ not in clean_text(text, Profile.PROSE)[0]
        assert ZWNJ not in clean_text(text, Profile.PROSE)[0]

    def test_joining_family_spans_unicode_blocks(self) -> None:
        text = f"ب{ZWJ}\u0750"
        assert clean_text(text, Profile.PROSE)[0] == text

    @pytest.mark.parametrize("joiner", [ZWJ, ZWNJ])
    def test_non_joining_arabic_letters_do_not_vouch_for_joiner(
        self, joiner: str
    ) -> None:
        # Arabic HAMZA is Joining_Type=Non_Joining despite being a letter.
        assert clean_text(f"ء{joiner}ء", Profile.PROSE)[0] == "ءء"

    def test_non_emoji_symbol_does_not_form_zwj_sequence(self) -> None:
        text = f"\u2b08{ZWJ}\u2b08"
        assert clean_text(text, Profile.PROSE)[0] == "\u2b08\u2b08"

    def test_emoji_modifier_zwj_sequence_survives(self) -> None:
        text = f"\U0001f469\U0001f3fd{ZWJ}\U0001f4bb"
        assert clean_text(text, Profile.PROSE)[0] == text

    def test_only_supported_subdivision_tag_payload_is_preserved(self) -> None:
        assert clean_text(SCOTLAND, Profile.PROSE)[0] == SCOTLAND
        for payload in ("", "A", "abc", "gbscttoolong"):
            tagged = (
                "\U0001f3f4"
                + "".join(chr(0xE0000 + ord(char)) for char in payload)
                + TAG_END
            )
            assert clean_text(tagged, Profile.PROSE)[0] == "\U0001f3f4"


class TestMixedScriptActionability:
    @pytest.mark.parametrize("text", ["English-русский", "hello.привет"])
    def test_bilingual_punctuation_does_not_merge_runs(self, text: str) -> None:
        assert suspicious_runs(text) == []
        assert clean_text(text, Profile.CODE)[0] == text

    def test_newer_cyrillic_block_is_detected(self) -> None:
        text = "p\U0001e030ypal"
        assert script_of(0x1E030) == "Cyrillic"
        assert suspicious_runs(text)

    def test_finding_points_at_actual_outlier(self) -> None:
        text = "go pаypal"
        finding = next(
            finding
            for finding in inspect_text(text).findings
            if finding.category is Category.MIXED_SCRIPT
        )
        assert finding.offset == text.index("а")
        assert finding.codepoint == ord("а")
        assert finding.context.startswith("go p[U+0430]")

    def test_finding_uses_the_majority_script_as_context(self) -> None:
        text = "русскийa"
        finding = next(
            finding
            for finding in inspect_text(text).findings
            if finding.category is Category.MIXED_SCRIPT
        )
        assert finding.offset == len(text) - 1
        assert finding.codepoint == ord("a")
        assert finding.context.endswith("[U+0061]")


class TestHeuristicRegions:
    @pytest.mark.parametrize(
        "url",
        [
            "example.com/a—b",
            "www.example.com/a—b",
            "https://example.com/O'Reilly—notes",
            "person@example.com/a—b",
            "mailto:person@example.com?subject=a—b",
            "https://example.com/a_(b)—c",
        ],
    )
    def test_url_forms_preserve_punctuation_under_code(self, url: str) -> None:
        assert clean_text(url, Profile.CODE)[0] == url

    def test_trailing_prose_punctuation_is_outside_url(self) -> None:
        text = "see (https://example.com/a—b)."
        assert clean_text(text, Profile.CODE)[0] == text

    @pytest.mark.parametrize(
        ("text", "needle"),
        [
            ("``code\nwith “quote”``", 'with "quote"'),
            ("````\n“quote”\n````", '"quote"'),
            ("~~~lang\n“quote”", '"quote"'),
            ("before `code with `` inside and “quote”` after", '"quote"'),
        ],
    )
    def test_multiline_long_and_unclosed_code_regions(
        self, text: str, needle: str
    ) -> None:
        cleaned, _ = clean_text(text, Profile.PROSE)
        assert needle in cleaned

    def test_backtick_in_backtick_fence_info_is_not_an_opener(self) -> None:
        text = "```bad`info\n“quote”"
        assert protected_regions(text) == []
        assert clean_text(text, Profile.PROSE)[0] == text


def _best_time(text: str) -> float:
    elapsed: list[float] = []
    for _ in range(2):
        started = time.perf_counter()
        inspect_text(text)
        clean_text(text, Profile.PROSE)
        elapsed.append(time.perf_counter() - started)
    return min(elapsed)


@pytest.mark.parametrize(
    "unit",
    [ZWJ, ZWNJ, "\U000e0061", IVS1],
    ids=["zwj", "zwnj", "tag", "variation-selector"],
)
def test_adversarial_invisible_runs_scale_linearly(unit: str) -> None:
    small = _best_time(unit * 1_000)
    large = _best_time(unit * 4_000)
    # Four times the input gets a generous 8x budget plus scheduler noise.
    # The former quadratic implementation was roughly 16x and took seconds
    # for only a few hundred joiners.
    assert large < small * 8 + 0.15
    assert large < 3.0


def test_domain_like_url_path_scales_linearly() -> None:
    short = "https://root.example/" + "a.com/" * 1_000
    long = "https://root.example/" + "a.com/" * 4_000
    small = _best_time(short)
    large = _best_time(long)
    assert large < small * 8 + 0.15
    assert large < 3.0


@pytest.mark.parametrize("profile", list(Profile))
def test_sequence_cleaning_is_idempotent(profile: Profile) -> None:
    sample = "\u9089" + IVS1 + SCOTLAND + f" क्\u200b{ZWNJ}ष example.com/a—b `“code”`"
    once = clean_text(sample, profile)[0]
    assert clean_text(once, profile)[0] == once


def test_is_load_bearing_public_helper_uses_same_analysis() -> None:
    selector_index = 1
    assert is_load_bearing("\u9089" + IVS1, selector_index)
    assert not is_load_bearing("A" + IVS1, selector_index)


def test_is_load_bearing_repeated_calls_do_not_rescan_text() -> None:
    def elapsed(size: int) -> float:
        text = ZWJ * size
        load_bearing_indices.cache_clear()
        started = time.perf_counter()
        for index in range(size):
            is_load_bearing(text, index)
        return time.perf_counter() - started

    small = elapsed(200)
    large = elapsed(800)
    assert large < small * 8 + 0.05


def test_data_normalization_runs_after_invisible_removal() -> None:
    text = "a\r\u200b\nb"
    cleaned, report = clean_text(text, Profile.DATA)
    assert cleaned == "a\nb"
    assert (report.removed, report.folded, report.normalized) == (1, 0, 1)
    twice, second_report = clean_text(cleaned, Profile.DATA)
    assert twice == cleaned
    assert not second_report.changed


def test_text_and_finding_resource_limits_are_structured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspect_module = importlib.import_module("hiddenink.core.inspect_text")
    monkeypatch.setattr(inspect_module, "MAX_TEXT_CODEPOINTS", 4)
    oversized = inspect_text("abcde")
    assert oversized.parse_status == "resource_limit"
    assert oversized.findings == []

    monkeypatch.setattr(inspect_module, "MAX_TEXT_CODEPOINTS", 100)
    monkeypatch.setattr(inspect_module, "MAX_TEXT_FINDINGS", 3)
    truncated = inspect_text("\u200b" * 6)
    assert truncated.parse_status == "resource_limit"
    assert len(truncated.findings) == 3

    clean_module = importlib.import_module("hiddenink.core.clean_text")
    monkeypatch.setattr(clean_module, "MAX_TEXT_CODEPOINTS", 4)
    original = "a\u200bbcde"
    cleaned, clean_report = clean_text(original)
    assert cleaned == original
    assert clean_report.parse_status == "resource_limit"
    assert not clean_report.changed
