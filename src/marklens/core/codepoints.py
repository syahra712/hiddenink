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
from typing import NamedTuple

__all__ = [
    "Category",
    "Severity",
    "CodepointInfo",
    "classify",
    "is_emoji_variation_selector",
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
    EXOTIC_SPACE = "exotic_space"
    SMART_QUOTE = "smart_quote"
    DASH = "dash"
    ELLIPSIS = "ellipsis"


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
    Category.EXOTIC_SPACE: Severity.WHITESPACE,
    Category.SMART_QUOTE: Severity.TYPOGRAPHIC,
    Category.DASH: Severity.TYPOGRAPHIC,
    Category.ELLIPSIS: Severity.TYPOGRAPHIC,
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
    if cp in EXOTIC_SPACE:
        return Category.EXOTIC_SPACE
    if cp in SMART_QUOTE:
        return Category.SMART_QUOTE
    if cp in DASH:
        return Category.DASH
    if cp in ELLIPSIS:
        return Category.ELLIPSIS

    general = unicodedata.category(chr(cp))
    if general == "Cc" and cp not in _ALLOWED_CONTROLS:
        return Category.CONTROL
    if general == "Co":
        return Category.PRIVATE_USE
    if general == "Cf":
        # Any remaining format character we have not named explicitly.
        return Category.OTHER_FORMAT
    return None


def classify(cp: int) -> CodepointInfo | None:
    """Classify a codepoint, or return None if it is unremarkable.

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
