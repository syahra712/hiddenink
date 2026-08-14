"""Codepoint taxonomy for AI provenance marks and text-hygiene hazards.

Zero dependencies. Everything here is deterministic and byte-verifiable: a
codepoint is either present in the input or it is not. Nothing in this module
makes a claim about statistical watermarking.

The taxonomy is deliberately finer-grained than the blanket "strip weird
characters" approach taken by most removal tools, because the categories have
genuinely different removal semantics:

* INVISIBLE   never legitimate in user-authored text -> always safe to remove
* WHITESPACE  visible as space, sometimes intentional -> profile-dependent
* TYPOGRAPHIC visible glyphs, usually legitimate     -> profile-dependent

Conflating the third group with the first is what produces the "AI watermark
remover" that merely converts your em dashes to hyphens.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from enum import Enum
from functools import lru_cache
from typing import NamedTuple

from .confusables import nfkc_fold

__all__ = [
    "Category",
    "Severity",
    "CodepointInfo",
    "classify",
    "is_emoji_variation_selector",
    "is_load_bearing",
    "SCRIPT_INVISIBLE",
    "ASCII_FOLD",
]


class Severity(str, Enum):
    """How confident we are that a codepoint is unwanted."""

    #: Never legitimate in authored text. Removal cannot change rendering.
    INVISIBLE = "invisible"
    #: Renders as whitespace. Removal may be intentional-content-destroying.
    WHITESPACE = "whitespace"
    #: A visible glyph. Removal changes what the reader sees.
    TYPOGRAPHIC = "typographic"
    #: A visible glyph impersonating a different one. A security signal rather
    #: than a style preference: the risk is that a reader cannot tell.
    CONFUSABLE = "confusable"


class Category(str, Enum):
    """Fine-grained reason a codepoint was flagged."""

    ZERO_WIDTH = "zero_width"
    BIDI_CONTROL = "bidi_control"
    INVISIBLE_OPERATOR = "invisible_operator"
    TAG_CHARACTER = "tag_character"
    VARIATION_SELECTOR = "variation_selector"
    DEPRECATED_FORMAT = "deprecated_format"
    OTHER_FORMAT = "other_format"
    PRIVATE_USE = "private_use"
    CONTROL = "control"
    SOFT_HYPHEN = "soft_hyphen"
    SCRIPT_INVISIBLE = "script_invisible"
    EXOTIC_SPACE = "exotic_space"
    SMART_QUOTE = "smart_quote"
    DASH = "dash"
    ELLIPSIS = "ellipsis"
    COMPATIBILITY_VARIANT = "compatibility_variant"
    CONFUSABLE = "confusable"
    MIXED_SCRIPT = "mixed_script"


_SEVERITY_OF: dict[Category, Severity] = {
    Category.ZERO_WIDTH: Severity.INVISIBLE,
    Category.BIDI_CONTROL: Severity.INVISIBLE,
    Category.INVISIBLE_OPERATOR: Severity.INVISIBLE,
    Category.TAG_CHARACTER: Severity.INVISIBLE,
    Category.VARIATION_SELECTOR: Severity.INVISIBLE,
    Category.DEPRECATED_FORMAT: Severity.INVISIBLE,
    Category.OTHER_FORMAT: Severity.INVISIBLE,
    Category.PRIVATE_USE: Severity.INVISIBLE,
    Category.CONTROL: Severity.INVISIBLE,
    Category.SOFT_HYPHEN: Severity.INVISIBLE,
    Category.SCRIPT_INVISIBLE: Severity.INVISIBLE,
    Category.EXOTIC_SPACE: Severity.WHITESPACE,
    Category.SMART_QUOTE: Severity.TYPOGRAPHIC,
    Category.DASH: Severity.TYPOGRAPHIC,
    Category.ELLIPSIS: Severity.TYPOGRAPHIC,
    Category.COMPATIBILITY_VARIANT: Severity.TYPOGRAPHIC,
    Category.CONFUSABLE: Severity.CONFUSABLE,
    Category.MIXED_SCRIPT: Severity.CONFUSABLE,
}

# --- explicit codepoint sets -------------------------------------------------

#: Width-zero characters. U+FEFF is both BOM and ZERO WIDTH NO-BREAK SPACE.
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF})

#: Directional overrides. The Trojan Source (CVE-2021-42574) hazard class:
#: these reorder rendered text without changing the underlying bytes, so
#: source code can display differently from how it compiles.
BIDI_CONTROL = frozenset(
    {0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
)

#: Mathematical invisible operators.
INVISIBLE_OPERATOR = frozenset(range(0x2061, 0x2065))

#: Deprecated format characters (symmetric/shaping overrides).
DEPRECATED_FORMAT = frozenset(range(0x206A, 0x2070))

#: Spaces that are not U+0020 but render as horizontal whitespace.
EXOTIC_SPACE = frozenset(
    {
        0x00A0,  # NO-BREAK SPACE
        0x1680,  # OGHAM SPACE MARK
        *range(0x2000, 0x200B),  # EN QUAD .. HAIR SPACE
        0x202F,  # NARROW NO-BREAK SPACE
        0x205F,  # MEDIUM MATHEMATICAL SPACE
        0x3000,  # IDEOGRAPHIC SPACE
    }
)

SMART_QUOTE = frozenset({0x2018, 0x2019, 0x201A, 0x201B, 0x201C, 0x201D, 0x201E, 0x201F})
DASH = frozenset({0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015})
ELLIPSIS = frozenset({0x2026})

#: Tag characters (U+E0000..U+E007F). A full ASCII alphabet in invisible form:
#: the single most efficient text-steganography channel in Unicode.
TAG_BLOCK = range(0xE0000, 0xE0080)

#: Variation selectors. VS1-16 plus the supplement.
VARIATION_SELECTORS = frozenset({*range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)})

#: Control characters we tolerate: tab, newline, carriage return.
_ALLOWED_CONTROLS = frozenset({0x09, 0x0A, 0x0D})

#: Invisible characters belonging to specific scripts. These are ``Mn`` or
#: ``Lo`` in general category, not ``Cf``, so the format-character fallback
#: never sees them -- they have to be named explicitly.
SCRIPT_INVISIBLE = frozenset(
    {
        0x034F,  # COMBINING GRAPHEME JOINER
        0x115F,  # HANGUL CHOSEONG FILLER
        0x1160,  # HANGUL JUNGSEONG FILLER
        0x17B4,  # KHMER VOWEL INHERENT AQ
        0x17B5,  # KHMER VOWEL INHERENT AA
        *range(0x180B, 0x180F),  # MONGOLIAN FREE VARIATION SELECTORS + separator
    }
)

#: Zero-width joiners. Contraband when hiding between Latin letters, essential
#: when doing orthographic or emoji work -- see :func:`is_load_bearing`.
ZWJ = 0x200D
ZWNJ = 0x200C

#: Folding table used by the ``code`` and ``data`` clean profiles, where a
#: smart quote is a syntax error rather than typography.
ASCII_FOLD: dict[int, str] = {
    **{cp: "'" for cp in (0x2018, 0x2019, 0x201A, 0x201B)},
    **{cp: '"' for cp in (0x201C, 0x201D, 0x201E, 0x201F)},
    **{cp: "-" for cp in DASH},
    0x2026: "...",
    **{cp: " " for cp in EXOTIC_SPACE},
}


# --- emoji-aware variation selector handling ---------------------------------

# Ranges whose members legitimately take U+FE0F to request emoji presentation.
# Stripping VS16 from these mangles the emoji, which is a real correctness bug
# in tools that blanket-remove the whole U+FE00..U+FE0F block.
_EMOJI_BASE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00A9, 0x00A9),  # (c)
    (0x00AE, 0x00AE),  # (R)
    (0x203C, 0x203C),
    (0x2049, 0x2049),
    (0x2122, 0x2122),
    (0x2139, 0x2139),
    (0x2190, 0x21FF),
    (0x2300, 0x23FF),
    (0x24C2, 0x24C2),
    (0x25A0, 0x27BF),
    (0x2934, 0x2935),
    (0x2B00, 0x2BFF),
    (0x3030, 0x3030),
    (0x303D, 0x303D),
    (0x3297, 0x3299),
    (0x1F000, 0x1FAFF),
)


def _is_emoji_base(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in _EMOJI_BASE_RANGES)


def is_emoji_variation_selector(text: str, index: int) -> bool:
    """True if ``text[index]`` is a variation selector serving an emoji.

    Emoji presentation sequences (base + U+FE0F) are legitimate content. A
    keycap sequence such as ``1<U+FE0F><U+20E3>`` is also preserved by looking
    through the selector to the combining keycap.
    """
    cp = ord(text[index])
    if cp not in (0xFE0E, 0xFE0F):
        return False
    if index == 0:
        return False
    if _is_emoji_base(ord(text[index - 1])):
        return True
    # Keycap: ASCII digit / '#' / '*' + VS16 + U+20E3
    nxt = ord(text[index + 1]) if index + 1 < len(text) else -1
    return nxt == 0x20E3


# --- load-bearing invisibles --------------------------------------------------

#: Scripts in which U+200C/U+200D are orthography rather than contraband.
#: Removing a ZWNJ from Devanagari or Persian changes how a word is spelled and
#: can change what it means, so a cleaner that strips them unconditionally
#: corrupts every document written in these scripts.
_JOINING_SCRIPT_RANGES: tuple[tuple[int, int], ...] = (
    (0x0590, 0x05FF),  # Hebrew
    (0x0600, 0x06FF),  # Arabic
    (0x0700, 0x074F),  # Syriac
    (0x0750, 0x077F),  # Arabic Supplement
    (0x0780, 0x07BF),  # Thaana
    (0x07C0, 0x07FF),  # NKo
    (0x0800, 0x083F),  # Samaritan
    (0x0840, 0x085F),  # Mandaic
    (0x0860, 0x08FF),  # Syriac Sup., Arabic Ext.
    (0x0900, 0x0DFF),  # Devanagari through Sinhala (all Indic)
    (0x0E00, 0x0EFF),  # Thai, Lao
    (0x0F00, 0x0FFF),  # Tibetan
    (0x1000, 0x109F),  # Myanmar
    (0x1780, 0x17FF),  # Khmer
    (0x1800, 0x18AF),  # Mongolian
    (0x1B80, 0x1BBF),  # Sundanese
    (0xA980, 0xA9DF),  # Javanese
    (0xFB1D, 0xFDFF),  # Hebrew/Arabic presentation forms
    (0xFE70, 0xFEFE),  # Arabic presentation forms-B
    (0x10D00, 0x10D3F),  # Hanifi Rohingya
    (0x1E900, 0x1E95F),  # Adlam
)

_SCRIPT_NEIGHBOUR_RANGES: dict[int, tuple[tuple[int, int], ...]] = {
    0x115F: ((0x1100, 0x11FF), (0xAC00, 0xD7AF), (0x3130, 0x318F)),  # Hangul
    0x1160: ((0x1100, 0x11FF), (0xAC00, 0xD7AF), (0x3130, 0x318F)),
    0x17B4: ((0x1780, 0x17FF),),  # Khmer
    0x17B5: ((0x1780, 0x17FF),),
}

#: The base of an emoji tag sequence (currently only subdivision flags).
_TAG_SEQUENCE_BASE = 0x1F3F4
_TAG_TERMINATOR = 0xE007F


def _in_ranges(cp: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(lo <= cp <= hi for lo, hi in ranges)


def _neighbour(text: str, index: int, step: int) -> int:
    """The nearest *visible* codepoint beside ``index``.

    Every invisible character is skipped, not just variation selectors, because
    the question being asked is which letter governs this mark -- and the answer
    must not change when a neighbouring invisible is removed.

    Skipping only some of them makes cleaning non-idempotent, and the failure is
    subtle: U+180B..U+180E sit *inside* the Mongolian block, so one Mongolian
    free variation selector would vouch for the next. A run of two would keep
    one and drop one, and the next pass would drop the survivor.
    """
    position = index + step
    while 0 <= position < len(text):
        info = classify(ord(text[position]))
        if info is None or info.severity is not Severity.INVISIBLE:
            return ord(text[position])
        position += step
    return -1


def _joins_emoji(text: str, index: int) -> bool:
    """True if a ZWJ at ``index`` glues two emoji into one grapheme."""
    return _is_emoji_base(_neighbour(text, index, -1)) and _is_emoji_base(
        _neighbour(text, index, 1)
    )


def _joins_complex_script(text: str, index: int) -> bool:
    """True if a ZWJ/ZWNJ at ``index`` is orthographic rather than hidden."""
    return _in_ranges(_neighbour(text, index, -1), _JOINING_SCRIPT_RANGES) or _in_ranges(
        _neighbour(text, index, 1), _JOINING_SCRIPT_RANGES
    )


def _in_emoji_tag_sequence(text: str, index: int) -> bool:
    """True if a tag character at ``index`` spells out a subdivision flag.

    An emoji tag sequence is U+1F3F4 followed by tag letters and closed by
    U+E007F. Tag characters anywhere else are the most efficient
    steganographic channel in Unicode and are always contraband.
    """
    position = index - 1
    while position >= 0 and ord(text[position]) in TAG_BLOCK:
        position -= 1
    if position < 0 or ord(text[position]) != _TAG_SEQUENCE_BASE:
        return False
    # Must be terminated, or it is a truncated/forged sequence.
    position = index
    while position < len(text) and ord(text[position]) in TAG_BLOCK:
        if ord(text[position]) == _TAG_TERMINATOR:
            return True
        position += 1
    return False


def is_load_bearing(text: str, index: int) -> bool:
    """True if the invisible codepoint at ``index`` is doing real work.

    The same codepoint can be contraband or essential depending only on what
    surrounds it. A U+200D between two Latin letters is a hidden mark; the same
    U+200D between two emoji is what makes a family a single glyph, and between
    two Devanagari letters it is spelling.

    Deciding this per occurrence is what separates cleaning from corruption.
    Tools that expose it as one global switch have to choose between mangling
    every Indic and Arabic document or leaving every hidden joiner in place.
    """
    cp = ord(text[index])

    if cp in (0xFE0E, 0xFE0F):
        return is_emoji_variation_selector(text, index)
    if cp == ZWJ:
        return _joins_emoji(text, index) or _joins_complex_script(text, index)
    if cp == ZWNJ:
        return _joins_complex_script(text, index)
    if cp in TAG_BLOCK:
        return _in_emoji_tag_sequence(text, index)
    if cp in _SCRIPT_NEIGHBOUR_RANGES:
        ranges = _SCRIPT_NEIGHBOUR_RANGES[cp]
        return _in_ranges(_neighbour(text, index, -1), ranges) or _in_ranges(
            _neighbour(text, index, 1), ranges
        )
    if 0x180B <= cp <= 0x180D:  # Mongolian free variation selectors
        return _in_ranges(_neighbour(text, index, -1), ((0x1800, 0x18AF),))
    return False


# --- classification ----------------------------------------------------------


class CodepointInfo(NamedTuple):
    """The classification of a single flagged codepoint."""

    codepoint: int
    category: Category
    severity: Severity
    name: str

    @property
    def escape(self) -> str:
        """The ``U+XXXX`` form."""
        return f"U+{self.codepoint:04X}"


def _unicode_name(cp: int) -> str:
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        # Unnamed: private use, unassigned, and the C0/C1 control blocks.
        general = unicodedata.category(chr(cp))
        return {
            "Cc": "<control>",
            "Co": "<private use>",
            "Cn": "<unassigned>",
            "Cs": "<surrogate>",
        }.get(general, "<unnamed>")


def _category_of(cp: int) -> Category | None:
    """Map a codepoint to a Category, or None if it is unremarkable."""
    # Fast path. Text is overwhelmingly ASCII, and the only ASCII codepoints
    # of interest are the C0 controls. Short-circuiting here avoids a
    # ``unicodedata.category`` call per character, which dominates the scan.
    if cp < 0x80:
        if cp < 0x20 or cp == 0x7F:
            return None if cp in _ALLOWED_CONTROLS else Category.CONTROL
        return None

    if cp in ZERO_WIDTH:
        return Category.ZERO_WIDTH
    if cp in BIDI_CONTROL:
        return Category.BIDI_CONTROL
    if cp in INVISIBLE_OPERATOR:
        return Category.INVISIBLE_OPERATOR
    if cp in DEPRECATED_FORMAT:
        return Category.DEPRECATED_FORMAT
    if cp in TAG_BLOCK:
        return Category.TAG_CHARACTER
    if cp in VARIATION_SELECTORS:
        return Category.VARIATION_SELECTOR
    if cp == 0x00AD:
        return Category.SOFT_HYPHEN
    if cp in SCRIPT_INVISIBLE:
        return Category.SCRIPT_INVISIBLE
    if cp in EXOTIC_SPACE:
        return Category.EXOTIC_SPACE
    if cp in SMART_QUOTE:
        return Category.SMART_QUOTE
    if cp in DASH:
        return Category.DASH
    if cp in ELLIPSIS:
        return Category.ELLIPSIS

    if nfkc_fold(cp) is not None:
        # A decorative encoding of ASCII: fullwidth, mathematical, circled.
        return Category.COMPATIBILITY_VARIANT

    general = unicodedata.category(chr(cp))
    if general == "Cc" and cp not in _ALLOWED_CONTROLS:
        return Category.CONTROL
    if general == "Co":
        return Category.PRIVATE_USE
    if general == "Cf":
        # Any remaining format character we have not named explicitly.
        return Category.OTHER_FORMAT
    return None


@lru_cache(maxsize=8192)
def classify(cp: int) -> CodepointInfo | None:
    """Classify a codepoint, or return None if it is unremarkable.

    Cached: a document draws on few distinct codepoints, so this collapses to
    a dict hit after the first occurrence of each. The cache is safe because
    the function is pure and :class:`CodepointInfo` is immutable, and it keeps
    ``unicodedata`` as the authority on general category rather than freezing
    a table against one Unicode version.

    >>> classify(0x200B).category
    <Category.ZERO_WIDTH: 'zero_width'>
    >>> classify(ord("a")) is None
    True
    """
    category = _category_of(cp)
    if category is None:
        return None
    return CodepointInfo(
        codepoint=cp,
        category=category,
        severity=_SEVERITY_OF[category],
        name=_unicode_name(cp),
    )


def categories_for_severities(severities: Iterable[Severity]) -> frozenset[Category]:
    """All categories whose severity is in ``severities``."""
    wanted = set(severities)
    return frozenset(c for c, s in _SEVERITY_OF.items() if s in wanted)
