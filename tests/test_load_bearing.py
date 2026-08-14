"""Load-bearing invisibles: the same codepoint, decided per occurrence.

A zero-width joiner between two Latin letters is a hidden mark. The same
codepoint between two emoji is what makes a family one glyph, and between two
Devanagari letters it is spelling. Stripping by codepoint identity alone either
corrupts every Indic, Arabic, and emoji document, or leaves every hidden joiner
in place. Neither is acceptable, so the decision is made from context.

The parametrised pairs below are the point of this module: each codepoint
appears in both a load-bearing and a contraband position, so a regression that
collapses the distinction fails rather than half-passing.
"""

from __future__ import annotations

import pytest

from hiddenink.core.clean_text import Profile, clean_text
from hiddenink.core.codepoints import classify, is_load_bearing
from hiddenink.core.inspect_text import inspect_text

# Emoji and script samples, written as escapes so the intent survives editors
# that normalise or strip the invisible characters.
ZWJ, ZWNJ, ZWSP, VS16, RLO, CGJ = (
    "‍", "‌", "​", "️", "‮", "͏",
)
FAMILY = f"\U0001f468{ZWJ}\U0001f469{ZWJ}\U0001f467"
SCOTLAND = "\U0001f3f4" + "".join(
    chr(c) for c in (0xE0067, 0xE0062, 0xE0073, 0xE0063, 0xE0074, 0xE007F)
)

PRESERVE = [
    ("emoji zwj sequence", FAMILY),
    ("subdivision flag tag sequence", SCOTLAND),
    ("devanagari zwnj", f"क्{ZWNJ}ष"),
    ("urdu zwnj", f"ہے{ZWNJ}نا"),
    ("persian zwnj", f"می{ZWNJ}رود"),
    ("arabic zwj", f"ا{ZWJ}ب"),
    ("emoji presentation selector", f"heart ❤{VS16}"),
    ("keycap sequence", f"1{VS16}⃣"),
    ("hangul choseong filler", "ᄀᅟᅡ"),
    ("khmer inherent vowel", "ក឴ខ"),
    ("mongolian free variation selector", "ᠠ᠋ᠡ"),
]

STRIP = [
    ("zero width space in latin", f"hel{ZWSP}lo", "hello"),
    ("zwj between latin letters", f"he{ZWJ}llo", "hello"),
    ("zwnj between latin letters", f"he{ZWNJ}llo", "hello"),
    ("tag character outside a flag", "tag\U000e0041chars", "tagchars"),
    ("bidi override", f"a{RLO}b", "ab"),
    ("combining grapheme joiner", f"a{CGJ}b", "ab"),
    ("orphan variation selector", f"plain{VS16}text", "plaintext"),
    ("mongolian fvs without mongolian", "a᠋b", "ab"),
    ("hangul filler without hangul", "aᅟb", "ab"),
    ("truncated flag sequence", "\U0001f3f4\U000e0067", "\U0001f3f4"),
]


class TestPreserved:
    @pytest.mark.parametrize(("name", "text"), PRESERVE, ids=[n for n, _ in PRESERVE])
    @pytest.mark.parametrize("profile", list(Profile))
    def test_clean_leaves_it_alone(self, name: str, text: str, profile: Profile) -> None:
        assert clean_text(text, profile)[0] == text

    @pytest.mark.parametrize(("name", "text"), PRESERVE, ids=[n for n, _ in PRESERVE])
    def test_inspect_does_not_flag_it(self, name: str, text: str) -> None:
        """Reporting content as contraband invites the user to corrupt it."""
        assert inspect_text(text).findings == []


class TestStripped:
    @pytest.mark.parametrize(
        ("name", "text", "expected"), STRIP, ids=[n for n, _, _ in STRIP]
    )
    @pytest.mark.parametrize("profile", list(Profile))
    def test_clean_removes_it(
        self, name: str, text: str, expected: str, profile: Profile
    ) -> None:
        assert clean_text(text, profile)[0] == expected

    @pytest.mark.parametrize(
        ("name", "text", "expected"), STRIP, ids=[n for n, _, _ in STRIP]
    )
    def test_inspect_flags_it(self, name: str, text: str, expected: str) -> None:
        assert inspect_text(text).findings != []


class TestSameCodepointBothWays:
    """The discrimination itself, not just each side of it."""

    @pytest.mark.parametrize(
        ("codepoint", "bearing", "hidden"),
        [
            (ZWJ, FAMILY, f"he{ZWJ}llo"),
            (ZWNJ, f"क्{ZWNJ}ष", f"he{ZWNJ}llo"),
            (VS16, f"❤{VS16}", f"plain{VS16}text"),
            ("\U000e0067", SCOTLAND, "tag\U000e0067chars"),
            ("᠋", "ᠠ᠋ᠡ", "a᠋b"),
        ],
        ids=["zwj", "zwnj", "vs16", "tag", "mongolian-fvs"],
    )
    def test_kept_in_one_context_and_dropped_in_the_other(
        self, codepoint: str, bearing: str, hidden: str
    ) -> None:
        assert codepoint in clean_text(bearing, Profile.PROSE)[0]
        assert codepoint not in clean_text(hidden, Profile.PROSE)[0]


class TestNeighbourResolution:
    """An intervening invisible must not change who governs a mark.

    U+180B..U+180E sit inside the Mongolian block, so a naive neighbour lookup
    lets one free variation selector vouch for the next: a run of two keeps one
    and drops one, and the following pass drops the survivor. Fuzzing found
    this; these pin it.
    """

    def test_run_of_mongolian_selectors_is_stable(self) -> None:
        text = "ᠠ᠋᠋ᠡ"
        once, _ = clean_text(text, Profile.PROSE)
        assert clean_text(once, Profile.PROSE)[0] == once

    def test_selector_run_without_mongolian_is_fully_removed(self) -> None:
        assert clean_text("a᠋᠋b", Profile.PROSE)[0] == "ab"

    def test_orthography_survives_an_injected_zero_width_space(self) -> None:
        """The ZWNJ is still doing its job; the ZWSP still has to go."""
        cleaned, _ = clean_text(f"क्{ZWSP}{ZWNJ}ष", Profile.PROSE)
        assert cleaned == f"क्{ZWNJ}ष"

    def test_load_bearing_is_position_dependent(self) -> None:
        text = f"{FAMILY} and he{ZWJ}llo"
        flags = [
            is_load_bearing(text, i)
            for i, ch in enumerate(text)
            if ch == ZWJ
        ]
        assert flags == [True, True, False]


class TestScriptInvisibleCoverage:
    """Mn/Lo invisibles are not Cf, so the format fallback never sees them."""

    @pytest.mark.parametrize(
        "codepoint",
        [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180E],
    )
    def test_is_classified(self, codepoint: int) -> None:
        info = classify(codepoint)
        assert info is not None, f"U+{codepoint:04X} is not classified at all"
