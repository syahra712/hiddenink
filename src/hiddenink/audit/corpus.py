"""A conformance corpus for AI-provenance-mark cleaners.

Every tool in this category claims to remove invisible marks. None of them
publishes what "correct" means, so the claims cannot be compared and users
cannot tell a cleaner from a corrupter. This corpus is an attempt to fix that:
it states the expected output for each input and the reason, so any tool --
including this one -- can be scored rather than described.

Cases are split into two tiers, and the distinction is the point:

``CORRECTNESS``
    There is a right answer. Either the input contains a hidden mark that has
    to go, or it contains a codepoint that is load-bearing content and must
    survive. A tool that fails one of these is either leaving contraband in
    place or corrupting the user's document.

``POLICY``
    Reasonable tools disagree. Whether an em dash in prose becomes a hyphen is
    a style decision, not a defect. These are reported so differences are
    visible, and deliberately not scored, because scoring them would just
    encode this project's preferences as everyone else's bugs.

Adding a case means committing to a claim about correctness. Cite the reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["Tier", "Case", "CORPUS", "correctness_cases", "policy_cases"]


class Tier(str, Enum):
    CORRECTNESS = "correctness"
    POLICY = "policy"


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    tier: Tier
    given: str
    expect: str
    why: str
    group: str = ""

    @property
    def is_removal(self) -> bool:
        """True if the case is about taking something out."""
        return self.expect != self.given


def _c(name: str, given: str, expect: str, why: str, group: str) -> Case:
    return Case(name, Tier.CORRECTNESS, given, expect, why, group)


def _p(name: str, given: str, expect: str, why: str, group: str) -> Case:
    return Case(name, Tier.POLICY, given, expect, why, group)


# Written as literals rather than chr() calls so the corpus stays readable, but
# named here so the intent survives an editor that eats invisible characters.
ZWSP, ZWNJ, ZWJ, VS16, VS15 = "​", "‌", "‍", "️", "︎"
RLO, LRO, PDF_ = "‮", "‭", "‬"
CGJ, SHY, NBSP, WJ = "͏", "­", " ", "⁠"

FAMILY = f"\U0001f468{ZWJ}\U0001f469{ZWJ}\U0001f467"
REGISTERED_IVS = "\u9089\U000e0100"
SCOTLAND = "\U0001f3f4" + "".join(
    chr(c) for c in (0xE0067, 0xE0062, 0xE0073, 0xE0063, 0xE0074, 0xE007F)
)

CORPUS: tuple[Case, ...] = (
    # --- contraband: hidden marks that must be removed --------------------
    _c(
        "zero-width space",
        f"hel{ZWSP}lo",
        "hello",
        "U+200B between Latin letters carries no linguistic information",
        "contraband",
    ),
    _p(
        "word joiner",
        f"hel{WJ}lo",
        f"hel{WJ}lo",
        "U+2060 controls line breaking; removing it can change layout",
        "context-dependent",
    ),
    _p(
        "soft hyphen",
        f"soft{SHY}hyphen",
        f"soft{SHY}hyphen",
        "U+00AD is a discretionary break with legitimate typography uses",
        "context-dependent",
    ),
    _c(
        "bidi override",
        f"a{RLO}b",
        "ab",
        "Trojan Source (CVE-2021-42574): reorders rendering without changing bytes",
        "contraband",
    ),
    _c(
        "bidi override run",
        f"a{LRO}b{PDF_}c",
        "abc",
        "the whole override sequence is contraband, not just the opener",
        "contraband",
    ),
    _p(
        "combining grapheme joiner",
        f"a{CGJ}b",
        f"a{CGJ}b",
        "U+034F blocks canonical reordering and can carry normalization semantics",
        "context-dependent",
    ),
    _c(
        "tag character outside a flag",
        "tag\U000e0041chars",
        "tagchars",
        "the tag block is a full invisible ASCII alphabet, the most efficient "
        "steganographic channel in Unicode",
        "contraband",
    ),
    _c(
        "orphan variation selector",
        f"plain{VS16}text",
        "plaintext",
        "VS16 after a non-emoji base requests nothing and renders nothing",
        "contraband",
    ),
    _c(
        "text-presentation selector orphan",
        f"plain{VS15}text",
        "plaintext",
        "same as VS16: no emoji base, no effect",
        "contraband",
    ),
    _c(
        "invisible times",
        "a⁢b",
        "ab",
        "mathematical invisible operators are not text",
        "contraband",
    ),
    _c(
        "interlinear annotation",
        "a￹b",
        "ab",
        "U+FFF9..U+FFFB are deprecated annotation controls",
        "contraband",
    ),
    _p(
        "private use",
        "ab",
        "ab",
        "private-use semantics are application-defined and may be visible content",
        "context-dependent",
    ),
    _c(
        "byte-order mark mid-document",
        "a﻿b",
        "ab",
        "U+FEFF away from offset 0 is ZWNBSP, not a BOM",
        "contraband",
    ),
    _c(
        "deprecated format character",
        "a⁪b",
        "ab",
        "U+206A..U+206F are deprecated shaping controls",
        "contraband",
    ),
    _c(
        "zwj between Latin letters",
        f"he{ZWJ}llo",
        "hello",
        "Latin has no joining behaviour, so U+200D here is hidden, not spelling",
        "contraband",
    ),
    _c(
        "zwnj between Latin letters",
        f"he{ZWNJ}llo",
        "hello",
        "Latin has no cursive joining to suppress",
        "contraband",
    ),
    _c(
        "one-sided Arabic joiner",
        f"A{ZWJ}ب",
        "Aب",
        "UAX #31 joining-control contexts do not permit one Arabic-side block "
        "neighbor to vouch for a joiner",
        "contraband",
    ),
    _c(
        "mongolian selector without Mongolian",
        "a᠋b",
        "ab",
        "a free variation selector with no Mongolian letter to modify",
        "contraband",
    ),
    _c(
        "hangul filler without Hangul",
        "aᅟb",
        "ab",
        "a choseong filler outside a Hangul syllable block",
        "contraband",
    ),
    _c(
        "truncated flag sequence",
        "\U0001f3f4\U000e0067",
        "\U0001f3f4",
        "an unterminated tag sequence is not a flag; the tag bytes are payload",
        "contraband",
    ),
    _c(
        "invalid subdivision tag sequence",
        "\U0001f3f4\U000e0061\U000e0062\U000e0063\U000e007f",
        "\U0001f3f4",
        "UTS #51 requires a CLDR-valid subdivision tag payload, not arbitrary "
        "lowercase tag letters",
        "contraband",
    ),
    # --- load-bearing: content that must survive --------------------------
    _c(
        "emoji zwj sequence",
        FAMILY,
        FAMILY,
        "U+200D is what fuses the family into one grapheme; removing it yields "
        "three separate people",
        "load-bearing",
    ),
    _c(
        "subdivision flag",
        SCOTLAND,
        SCOTLAND,
        "the tag characters spell the region code; removing them destroys the flag",
        "load-bearing",
    ),
    _c(
        "emoji presentation selector",
        f"heart {chr(0x2764)}{VS16}",
        f"heart {chr(0x2764)}{VS16}",
        "U+FE0F selects emoji presentation for a dual-presentation base",
        "load-bearing",
    ),
    _c(
        "keycap sequence",
        f"1{VS16}⃣",
        f"1{VS16}⃣",
        "digit + VS16 + U+20E3 is a single keycap grapheme",
        "load-bearing",
    ),
    _c(
        "devanagari zwnj",
        f"क्{ZWNJ}ष",
        f"क्{ZWNJ}ष",
        "U+200C suppresses the conjunct ligature; removing it changes the spelling",
        "load-bearing",
    ),
    _c(
        "urdu zwnj",
        f"ہے{ZWNJ}نا",
        f"ہے{ZWNJ}نا",
        "U+200C marks a word boundary inside Urdu compounds",
        "load-bearing",
    ),
    _c(
        "persian zwnj",
        f"می{ZWNJ}رود",
        f"می{ZWNJ}رود",
        "Persian verb prefixes are separated by U+200C, not by a space",
        "load-bearing",
    ),
    _c(
        "arabic zwj",
        f"ا{ZWJ}ب",
        f"ا{ZWJ}ب",
        "U+200D forces cursive joining, which is orthographic in Arabic",
        "load-bearing",
    ),
    _c(
        "mongolian free variation selector",
        "ᠠ᠋ᠡ",
        "ᠠ᠋ᠡ",
        "selects a positional glyph variant of the preceding Mongolian letter",
        "load-bearing",
    ),
    _c(
        "khmer inherent vowel",
        "ក឴ខ",
        "ក឴ខ",
        "U+17B4 is a Khmer vowel, invisible but phonemic",
        "load-bearing",
    ),
    _c(
        "hangul filler in syllable block",
        "ᄀᅟᅡ",
        "ᄀᅟᅡ",
        "fillers hold positions in a partial Hangul syllable",
        "load-bearing",
    ),
    _c(
        "registered ideographic variation sequence",
        REGISTERED_IVS,
        REGISTERED_IVS,
        "U+9089 U+E0100 is registered in Unicode's Ideographic Variation "
        "Database and requests a specific glyph",
        "load-bearing",
    ),
    # --- fidelity: must not be collateral damage --------------------------
    _c(
        "url with em dash",
        "see https://example.com/a—b now",
        "see https://example.com/a—b now",
        "folding punctuation inside a URL breaks the link",
        "fidelity",
    ),
    _c(
        "lf line endings",
        "one\ntwo\n",
        "one\ntwo\n",
        "a cleaner must not normalise line endings as a side effect",
        "fidelity",
    ),
    _c(
        "crlf line endings",
        "one\r\ntwo\r\n",
        "one\r\ntwo\r\n",
        "same, in the other direction",
        "fidelity",
    ),
    _c(
        "tabs preserved",
        "a\tb",
        "a\tb",
        "tab is legitimate whitespace, not an invisible mark",
        "fidelity",
    ),
    _c(
        "cjk text untouched",
        "图书館",
        "图书館",
        "non-Latin text is not suspicious merely for being non-ASCII",
        "fidelity",
    ),
    _c(
        "combining accents preserved",
        "é",
        "é",
        "U+0301 is a visible diacritic, not a hidden mark",
        "fidelity",
    ),
    _c(
        "russian prose untouched",
        "привет мир",
        "привет мир",
        "Cyrillic letters inside a Cyrillic word are the language, not an "
        "impersonation; folding them to Latin corrupts the text",
        "fidelity",
    ),
    _c(
        "greek notation untouched",
        "ρ = m/V and ν = 3",
        "ρ = m/V and ν = 3",
        "lowercase Greek is mathematical notation; folding rho to p would "
        "corrupt any physics or statistics document",
        "fidelity",
    ),
    _c(
        "bilingual sentence untouched",
        "hello привет",
        "hello привет",
        "two scripts in a sentence is ordinary bilingual text; only a single "
        "word mixing scripts is suspicious",
        "fidelity",
    ),
    _c(
        "hyphenated bilingual text untouched",
        "English-русский",
        "English-русский",
        "a hyphen separates words; it does not create one mixed-script identifier",
        "fidelity",
    ),
    _c(
        "japanese untouched",
        "日本語のテキスト",
        "日本語のテキスト",
        "Han with kana is how Japanese is written, not a script-mixing attack",
        "fidelity",
    ),
    # --- policy: defensible either way, reported but not scored ------------
    _p(
        "nbsp in prose",
        f"10{NBSP}km",
        "10 km",
        "an invisible indentation hazard, but sometimes intentional typography",
        "whitespace",
    ),
    _p(
        "ideographic space",
        "a　b",
        "a b",
        "as above, in CJK text where it may be deliberate",
        "whitespace",
    ),
    _p(
        "em dash in prose",
        "clear—truly",
        "clear—truly",
        "legitimate prose typography; folding it is cosmetic damage, not cleaning",
        "typography",
    ),
    _p(
        "curly quotes in prose",
        "she said “hi”",
        "she said “hi”",
        "as above",
        "typography",
    ),
    _p("ellipsis in prose", "wait…", "wait…", "as above", "typography"),
    _p(
        "curly quotes in a code span",
        "run `x = “y”` now",
        'run `x = "y"` now',
        "a curly quote inside code is a syntax error even in a prose document",
        "typography",
    ),
    _p(
        "curly quotes in a fenced block",
        "```\nn = “v”\n```",
        '```\nn = "v"\n```',
        "as above",
        "typography",
    ),
    _p(
        "homograph in prose",
        "visit pаypal.com",
        "visit pаypal.com",
        "hiddenink reports this and leaves it alone in prose, because the "
        "reader needs to see the impersonation; rewriting requires explicit "
        "use of the folding API",
        "confusables",
    ),
    _p(
        "fullwidth text",
        "ｈｅｌｌｏ",
        "ｈｅｌｌｏ",
        "NFKC folding is explicit policy because compatibility normalization "
        "can be lossy",
        "confusables",
    ),
    _p("mathematical bold", "𝐡𝐞𝐥𝐥𝐨", "𝐡𝐞𝐥𝐥𝐨", "as above", "confusables"),
)


def correctness_cases() -> tuple[Case, ...]:
    return tuple(c for c in CORPUS if c.tier is Tier.CORRECTNESS)


def policy_cases() -> tuple[Case, ...]:
    return tuple(c for c in CORPUS if c.tier is Tier.POLICY)
