"""Codepoint taxonomy for AI provenance marks and text-hygiene hazards.

Zero dependencies. Everything here is deterministic and byte-verifiable: a
codepoint is either present in the input or it is not. Nothing in this module
makes a claim about statistical watermarking.

The taxonomy is deliberately finer-grained than the blanket "strip weird
characters" approach taken by most removal tools, because the categories have
genuinely different removal semantics:

* INVISIBLE   prohibited or malformed in the observed context -> remove
* CONTEXTUAL  format/implementation-defined and potentially meaningful -> report
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
    "load_bearing_indices",
    "MAX_TEXT_CODEPOINTS",
    "SCRIPT_INVISIBLE",
    "ASCII_FOLD",
]


class Severity(str, Enum):
    """How confident we are that a codepoint is unwanted."""

    #: Prohibited or malformed in the observed context. Safe to remove.
    INVISIBLE = "invisible"
    #: Renders as whitespace. Removal may be intentional-content-destroying.
    WHITESPACE = "whitespace"
    #: A visible glyph. Removal changes what the reader sees.
    TYPOGRAPHIC = "typographic"
    #: A visible glyph impersonating a different one. A security signal rather
    #: than a style preference: the risk is that a reader cannot tell.
    CONFUSABLE = "confusable"
    #: Invisible or implementation-defined content with legitimate uses.
    #: Report it, but do not delete it under a default cleaning profile.
    CONTEXTUAL = "contextual"


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
    WORD_JOINER = "word_joiner"
    NORMALIZATION_CONTROL = "normalization_control"
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
    Category.PRIVATE_USE: Severity.CONTEXTUAL,
    Category.CONTROL: Severity.INVISIBLE,
    Category.SOFT_HYPHEN: Severity.CONTEXTUAL,
    Category.WORD_JOINER: Severity.CONTEXTUAL,
    Category.NORMALIZATION_CONTROL: Severity.CONTEXTUAL,
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
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0xFEFF})

#: Directional overrides. The Trojan Source (CVE-2021-42574) hazard class:
#: these reorder rendered text without changing the underlying bytes, so
#: source code can display differently from how it compiles.
BIDI_CONTROL = frozenset({0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)})

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

# Public text APIs reject larger inputs before allocating their context-index
# arrays. Container inputs have separate byte and member limits.
MAX_TEXT_CODEPOINTS = 1_000_000


# --- emoji-aware variation selector handling ---------------------------------

# A conservative subset of the Emoji/Extended_Pictographic repertoire used by
# Unicode emoji sequences.  The old implementation admitted whole blocks such
# as U+2190..U+21FF and U+2300..U+23FF.  Those blocks contain many ordinary
# symbols which are not emoji bases, so they could make an unrelated ZWJ look
# load-bearing.  These ranges follow the actual allocations in Unicode Emoji
# rather than block boundaries.  The supplementary pictographic blocks are
# intentionally kept as ranges: Extended_Pictographic reserves their holes for
# future emoji so that grapheme segmentation remains forward compatible. The
# supplementary ranges are the compressed Unicode 17 Extended_Pictographic
# property; notably they exclude regional indicators and U+1F100.
_EMOJI_BMP_BASE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00A9, 0x00A9),  # (c)
    (0x00AE, 0x00AE),  # (R)
    (0x203C, 0x203C),
    (0x2049, 0x2049),
    (0x2122, 0x2122),
    (0x2139, 0x2139),
    (0x2194, 0x2199),
    (0x21A9, 0x21AA),
    (0x231A, 0x231B),
    (0x2328, 0x2328),
    (0x23CF, 0x23CF),
    (0x23E9, 0x23F3),
    (0x23F8, 0x23FA),
    (0x24C2, 0x24C2),
    (0x25AA, 0x25AB),
    (0x25B6, 0x25B6),
    (0x25C0, 0x25C0),
    (0x25FB, 0x25FE),
    (0x2600, 0x2604),
    (0x260E, 0x260E),
    (0x2611, 0x2611),
    (0x2614, 0x2615),
    (0x2618, 0x2618),
    (0x261D, 0x261D),
    (0x2620, 0x2620),
    (0x2622, 0x2623),
    (0x2626, 0x2626),
    (0x262A, 0x262A),
    (0x262E, 0x262F),
    (0x2638, 0x263A),
    (0x2640, 0x2640),
    (0x2642, 0x2642),
    (0x2648, 0x2653),
    (0x265F, 0x2660),
    (0x2663, 0x2663),
    (0x2665, 0x2666),
    (0x2668, 0x2668),
    (0x267B, 0x267B),
    (0x267E, 0x267F),
    (0x2692, 0x2697),
    (0x2699, 0x2699),
    (0x269B, 0x269C),
    (0x26A0, 0x26A1),
    (0x26A7, 0x26A7),
    (0x26AA, 0x26AB),
    (0x26B0, 0x26B1),
    (0x26BD, 0x26BE),
    (0x26C4, 0x26C5),
    (0x26C8, 0x26C8),
    (0x26CE, 0x26CF),
    (0x26D1, 0x26D1),
    (0x26D3, 0x26D4),
    (0x26E9, 0x26EA),
    (0x26F0, 0x26F5),
    (0x26F7, 0x26FA),
    (0x26FD, 0x26FD),
    (0x2702, 0x2702),
    (0x2705, 0x2705),
    (0x2708, 0x270D),
    (0x270F, 0x270F),
    (0x2712, 0x2712),
    (0x2714, 0x2714),
    (0x2716, 0x2716),
    (0x271D, 0x271D),
    (0x2721, 0x2721),
    (0x2728, 0x2728),
    (0x2733, 0x2734),
    (0x2744, 0x2744),
    (0x2747, 0x2747),
    (0x274C, 0x274C),
    (0x274E, 0x274E),
    (0x2753, 0x2755),
    (0x2757, 0x2757),
    (0x2763, 0x2764),
    (0x2795, 0x2797),
    (0x27A1, 0x27A1),
    (0x27B0, 0x27B0),
    (0x27BF, 0x27BF),
    (0x2934, 0x2935),
    (0x2B05, 0x2B07),
    (0x2B1B, 0x2B1C),
    (0x2B50, 0x2B50),
    (0x2B55, 0x2B55),
    (0x3030, 0x3030),
    (0x303D, 0x303D),
    (0x3297, 0x3297),
    (0x3299, 0x3299),
)

_EMOJI_BASE_RANGES: tuple[tuple[int, int], ...] = (
    *_EMOJI_BMP_BASE_RANGES,
    (0x1F004, 0x1F004),
    (0x1F02C, 0x1F02F),
    (0x1F094, 0x1F09F),
    (0x1F0AF, 0x1F0B0),
    (0x1F0C0, 0x1F0C0),
    (0x1F0CF, 0x1F0D0),
    (0x1F0F6, 0x1F0FF),
    (0x1F170, 0x1F171),
    (0x1F17E, 0x1F17F),
    (0x1F18E, 0x1F18E),
    (0x1F191, 0x1F19A),
    (0x1F1AE, 0x1F1E5),
    (0x1F201, 0x1F20F),
    (0x1F21A, 0x1F21A),
    (0x1F22F, 0x1F22F),
    (0x1F232, 0x1F23A),
    (0x1F23C, 0x1F23F),
    (0x1F249, 0x1F25F),
    (0x1F266, 0x1F321),
    (0x1F324, 0x1F393),
    (0x1F396, 0x1F397),
    (0x1F399, 0x1F39B),
    (0x1F39E, 0x1F3F0),
    (0x1F3F3, 0x1F3F5),
    (0x1F3F7, 0x1F3FA),
    (0x1F400, 0x1F4FD),
    (0x1F4FF, 0x1F53D),
    (0x1F549, 0x1F54E),
    (0x1F550, 0x1F567),
    (0x1F56F, 0x1F570),
    (0x1F573, 0x1F57A),
    (0x1F587, 0x1F587),
    (0x1F58A, 0x1F58D),
    (0x1F590, 0x1F590),
    (0x1F595, 0x1F596),
    (0x1F5A4, 0x1F5A5),
    (0x1F5A8, 0x1F5A8),
    (0x1F5B1, 0x1F5B2),
    (0x1F5BC, 0x1F5BC),
    (0x1F5C2, 0x1F5C4),
    (0x1F5D1, 0x1F5D3),
    (0x1F5DC, 0x1F5DE),
    (0x1F5E1, 0x1F5E1),
    (0x1F5E3, 0x1F5E3),
    (0x1F5E8, 0x1F5E8),
    (0x1F5EF, 0x1F5EF),
    (0x1F5F3, 0x1F5F3),
    (0x1F5FA, 0x1F64F),
    (0x1F680, 0x1F6C5),
    (0x1F6CB, 0x1F6D2),
    (0x1F6D5, 0x1F6E5),
    (0x1F6E9, 0x1F6E9),
    (0x1F6EB, 0x1F6F0),
    (0x1F6F3, 0x1F6FF),
    (0x1F7DA, 0x1F7FF),
    (0x1F80C, 0x1F80F),
    (0x1F848, 0x1F84F),
    (0x1F85A, 0x1F85F),
    (0x1F888, 0x1F88F),
    (0x1F8AE, 0x1F8AF),
    (0x1F8BC, 0x1F8BF),
    (0x1F8C2, 0x1F8CF),
    (0x1F8D9, 0x1F8FF),
    (0x1F90C, 0x1F93A),
    (0x1F93C, 0x1F945),
    (0x1F947, 0x1F9FF),
    (0x1FA58, 0x1FA5F),
    (0x1FA6E, 0x1FAFF),
    (0x1FC00, 0x1FFFD),
)

# Unicode 17 emoji-variation-sequences.txt. The BMP entries coincide with the
# ranges above; this list adds the exact supplementary bases and ASCII keycap
# bases rather than treating every pictograph as a valid VS15/VS16 base.
_EMOJI_VARIATION_BASE_RANGES: tuple[tuple[int, int], ...] = (
    (0x0023, 0x0023),
    (0x002A, 0x002A),
    (0x0030, 0x0039),
    *_EMOJI_BMP_BASE_RANGES,
    (0x1F004, 0x1F004),
    (0x1F170, 0x1F171),
    (0x1F17E, 0x1F17F),
    (0x1F202, 0x1F202),
    (0x1F21A, 0x1F21A),
    (0x1F22F, 0x1F22F),
    (0x1F237, 0x1F237),
    (0x1F30D, 0x1F30F),
    (0x1F315, 0x1F315),
    (0x1F31C, 0x1F31C),
    (0x1F321, 0x1F321),
    (0x1F324, 0x1F32C),
    (0x1F336, 0x1F336),
    (0x1F378, 0x1F378),
    (0x1F37D, 0x1F37D),
    (0x1F393, 0x1F393),
    (0x1F396, 0x1F397),
    (0x1F399, 0x1F39B),
    (0x1F39E, 0x1F39F),
    (0x1F3A7, 0x1F3A7),
    (0x1F3AC, 0x1F3AE),
    (0x1F3C2, 0x1F3C2),
    (0x1F3C4, 0x1F3C4),
    (0x1F3C6, 0x1F3C6),
    (0x1F3CA, 0x1F3CE),
    (0x1F3D4, 0x1F3E0),
    (0x1F3ED, 0x1F3ED),
    (0x1F3F3, 0x1F3F3),
    (0x1F3F5, 0x1F3F5),
    (0x1F3F7, 0x1F3F7),
    (0x1F408, 0x1F408),
    (0x1F415, 0x1F415),
    (0x1F41F, 0x1F41F),
    (0x1F426, 0x1F426),
    (0x1F43F, 0x1F43F),
    (0x1F441, 0x1F442),
    (0x1F446, 0x1F449),
    (0x1F44D, 0x1F44E),
    (0x1F453, 0x1F453),
    (0x1F46A, 0x1F46A),
    (0x1F47D, 0x1F47D),
    (0x1F4A3, 0x1F4A3),
    (0x1F4B0, 0x1F4B0),
    (0x1F4B3, 0x1F4B3),
    (0x1F4BB, 0x1F4BB),
    (0x1F4BF, 0x1F4BF),
    (0x1F4CB, 0x1F4CB),
    (0x1F4DA, 0x1F4DA),
    (0x1F4DF, 0x1F4DF),
    (0x1F4E4, 0x1F4E6),
    (0x1F4EA, 0x1F4ED),
    (0x1F4F7, 0x1F4F7),
    (0x1F4F9, 0x1F4FB),
    (0x1F4FD, 0x1F4FD),
    (0x1F508, 0x1F508),
    (0x1F50D, 0x1F50D),
    (0x1F512, 0x1F513),
    (0x1F549, 0x1F54A),
    (0x1F550, 0x1F567),
    (0x1F56F, 0x1F570),
    (0x1F573, 0x1F579),
    (0x1F587, 0x1F587),
    (0x1F58A, 0x1F58D),
    (0x1F590, 0x1F590),
    (0x1F5A5, 0x1F5A5),
    (0x1F5A8, 0x1F5A8),
    (0x1F5B1, 0x1F5B2),
    (0x1F5BC, 0x1F5BC),
    (0x1F5C2, 0x1F5C4),
    (0x1F5D1, 0x1F5D3),
    (0x1F5DC, 0x1F5DE),
    (0x1F5E1, 0x1F5E1),
    (0x1F5E3, 0x1F5E3),
    (0x1F5E8, 0x1F5E8),
    (0x1F5EF, 0x1F5EF),
    (0x1F5F3, 0x1F5F3),
    (0x1F5FA, 0x1F5FA),
    (0x1F610, 0x1F610),
    (0x1F687, 0x1F687),
    (0x1F68D, 0x1F68D),
    (0x1F691, 0x1F691),
    (0x1F694, 0x1F694),
    (0x1F698, 0x1F698),
    (0x1F6AD, 0x1F6AD),
    (0x1F6B2, 0x1F6B2),
    (0x1F6B9, 0x1F6BA),
    (0x1F6BC, 0x1F6BC),
    (0x1F6CB, 0x1F6CB),
    (0x1F6CD, 0x1F6CF),
    (0x1F6E0, 0x1F6E5),
    (0x1F6E9, 0x1F6E9),
    (0x1F6F0, 0x1F6F0),
    (0x1F6F3, 0x1F6F3),
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
    if _in_ranges(ord(text[index - 1]), _EMOJI_VARIATION_BASE_RANGES):
        return True
    # Keycap: ASCII digit / '#' / '*' + VS16 + U+20E3.  VS15 is not
    # permitted in an emoji keycap sequence (UTS #51 ED-14c).
    nxt = ord(text[index + 1]) if index + 1 < len(text) else -1
    return cp == 0xFE0F and text[index - 1] in "0123456789#*" and nxt == 0x20E3


# --- load-bearing invisibles --------------------------------------------------

#: Scripts in which U+200C/U+200D are orthography rather than contraband.
#: Removing a ZWNJ from Devanagari or Persian changes how a word is spelled and
#: can change what it means, so a cleaner that strips them unconditionally
#: corrupts every document written in these scripts.
_JOINING_SCRIPT_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x0590, 0x05FF, "Hebrew"),
    (0x0600, 0x06FF, "Arabic"),
    (0x0700, 0x074F, "Syriac"),
    (0x0750, 0x077F, "Arabic"),
    (0x0780, 0x07BF, "Thaana"),
    (0x07C0, 0x07FF, "NKo"),
    (0x0800, 0x083F, "Samaritan"),
    (0x0840, 0x085F, "Mandaic"),
    (0x0860, 0x086F, "Syriac"),
    (0x0870, 0x08FF, "Arabic"),
    (0x0900, 0x097F, "Devanagari"),
    (0x0980, 0x09FF, "Bengali"),
    (0x0A00, 0x0A7F, "Gurmukhi"),
    (0x0A80, 0x0AFF, "Gujarati"),
    (0x0B00, 0x0B7F, "Oriya"),
    (0x0B80, 0x0BFF, "Tamil"),
    (0x0C00, 0x0C7F, "Telugu"),
    (0x0C80, 0x0CFF, "Kannada"),
    (0x0D00, 0x0D7F, "Malayalam"),
    (0x0D80, 0x0DFF, "Sinhala"),
    (0x0E00, 0x0E7F, "Thai"),
    (0x0E80, 0x0EFF, "Lao"),
    (0x0F00, 0x0FFF, "Tibetan"),
    (0x1000, 0x109F, "Myanmar"),
    (0x1780, 0x17FF, "Khmer"),
    (0x1800, 0x18AF, "Mongolian"),
    (0x1B80, 0x1BBF, "Sundanese"),
    (0xA980, 0xA9DF, "Javanese"),
    (0xFB1D, 0xFB4F, "Hebrew"),
    (0xFB50, 0xFDFF, "Arabic"),
    (0xFE70, 0xFEFE, "Arabic"),
    (0x10D00, 0x10D3F, "Hanifi Rohingya"),
    (0x1E900, 0x1E95F, "Adlam"),
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

# The RGI subdivision flags in Unicode Emoji 17.  UTS #51 permits additional
# CLDR-valid subdivisions, but validating that open-ended registry would need
# bundled CLDR data.  Preserving this explicit, interoperable set is safer than
# accepting arbitrary invisible tag payloads after a black flag.
_RGI_FLAG_TAG_SPECS = frozenset({"gbeng", "gbsct", "gbwls"})

# Conservative base families for non-emoji standardized variants.  Unicode's
# StandardizedVariants.txt is the normative registry.  Keeping a registered-
# looking sequence from these families can retain an unsupported sequence, but
# cannot destroy a legitimate glyph request; stripping outside them remains the
# steganography-safe default.  Ideographic sequences are handled separately.
_STANDARDIZED_VARIANT_BASE_RANGES: tuple[tuple[int, int], ...] = (
    (0x0030, 0x0030),  # short diagonal stroke form
    (0x1000, 0x109F),  # Myanmar
    (0x2018, 0x201D),  # East Asian punctuation variants
    (0x2100, 0x2AFF),  # mathematical/symbol variants
    (0x3000, 0x303F),  # CJK punctuation
    (0x3400, 0x4DBF),  # CJK compatibility variation sequences
    (0x4E00, 0x9FFF),
    (0xA840, 0xA87F),  # Phags-pa
    (0xAA60, 0xAA7F),  # Myanmar Extended-A
    (0xFF00, 0xFFEF),  # fullwidth forms
    (0x10AC0, 0x10AFF),  # Manichaean
    (0x13000, 0x143FF),  # Egyptian hieroglyph rotations
    (0x1D400, 0x1D7FF),  # mathematical alphanumeric symbols
    (0x20000, 0x2EE5F),  # supplementary CJK compatibility sequences
    (0x30000, 0x3347F),
)

# Ideographic Variation Database bases are unified/compatibility ideographs.
# The ranges include the Unicode 17 unified ideograph extensions.  We
# deliberately preserve any base+VS17..VS256 pair in these ranges rather than
# freezing a 1.3 MB registry into the dependency-free core: this is a stated
# conservative rule, not a claim that every retained pair is registered.
_IDEOGRAPH_RANGES: tuple[tuple[int, int], ...] = (
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xF900, 0xFAFF),
    (0x20000, 0x2EE5F),
    (0x30000, 0x3347F),
)

_CURSIVE_JOINING_FAMILIES = frozenset(
    {
        "Arabic",
        "Syriac",
        "Thaana",
        "NKo",
        "Samaritan",
        "Mandaic",
        "Mongolian",
        "Hanifi Rohingya",
        "Adlam",
    }
)

# Unicode 17 DerivedJoiningType.txt, compressed to characters with L/D and D/R
# joining capability. For natural text we conservatively retain a join control
# when both same-script cursive neighbours have some joining capability. This
# deliberately admits script-specific contexts beyond UTS #39 A1 while still
# rejecting block-mates such as Arabic HAMZA U+0621, whose Joining_Type is
# Non_Joining. Indic virama contexts are handled separately below.
_CAN_JOIN_FORWARD: tuple[tuple[int, int], ...] = (
    (0x0620, 0x0620),
    (0x0626, 0x0626),
    (0x0628, 0x0628),
    (0x062A, 0x062E),
    (0x0633, 0x063F),
    (0x0641, 0x0647),
    (0x0649, 0x064A),
    (0x066E, 0x066F),
    (0x0678, 0x0687),
    (0x069A, 0x06BF),
    (0x06C1, 0x06C2),
    (0x06CC, 0x06CC),
    (0x06CE, 0x06CE),
    (0x06D0, 0x06D1),
    (0x06FA, 0x06FC),
    (0x06FF, 0x06FF),
    (0x0712, 0x0714),
    (0x071A, 0x071D),
    (0x071F, 0x0727),
    (0x0729, 0x0729),
    (0x072B, 0x072B),
    (0x072D, 0x072E),
    (0x074E, 0x0758),
    (0x075C, 0x076A),
    (0x076D, 0x0770),
    (0x0772, 0x0772),
    (0x0775, 0x0777),
    (0x077A, 0x077F),
    (0x07CA, 0x07EA),
    (0x0841, 0x0845),
    (0x0848, 0x0848),
    (0x084A, 0x0853),
    (0x0855, 0x0855),
    (0x0860, 0x0860),
    (0x0862, 0x0865),
    (0x0868, 0x0868),
    (0x0886, 0x0886),
    (0x0889, 0x088D),
    (0x088F, 0x088F),
    (0x08A0, 0x08A9),
    (0x08AF, 0x08B0),
    (0x08B3, 0x08B8),
    (0x08BA, 0x08C8),
    (0x1807, 0x1807),
    (0x1820, 0x1878),
    (0x1887, 0x18A8),
    (0x18AA, 0x18AA),
    (0xA840, 0xA872),
    (0x10AC0, 0x10AC4),
    (0x10ACD, 0x10ACD),
    (0x10AD3, 0x10ADC),
    (0x10ADE, 0x10AE0),
    (0x10AEB, 0x10AEE),
    (0x10B80, 0x10B80),
    (0x10B82, 0x10B82),
    (0x10B86, 0x10B88),
    (0x10B8A, 0x10B8B),
    (0x10B8D, 0x10B8D),
    (0x10B90, 0x10B90),
    (0x10BAD, 0x10BAE),
    (0x10D00, 0x10D21),
    (0x10D23, 0x10D23),
    (0x10EC3, 0x10EC4),
    (0x10EC6, 0x10EC7),
    (0x10F30, 0x10F32),
    (0x10F34, 0x10F44),
    (0x10F51, 0x10F53),
    (0x10F70, 0x10F73),
    (0x10F76, 0x10F81),
    (0x10FB0, 0x10FB0),
    (0x10FB2, 0x10FB3),
    (0x10FB8, 0x10FB8),
    (0x10FBB, 0x10FBC),
    (0x10FBE, 0x10FBF),
    (0x10FC1, 0x10FC1),
    (0x10FC4, 0x10FC4),
    (0x10FCA, 0x10FCB),
    (0x1E900, 0x1E943),
)

_CAN_JOIN_BACKWARD: tuple[tuple[int, int], ...] = (
    (0x0620, 0x0620),
    (0x0622, 0x063F),
    (0x0641, 0x064A),
    (0x066E, 0x066F),
    (0x0671, 0x0673),
    (0x0675, 0x06D3),
    (0x06D5, 0x06D5),
    (0x06EE, 0x06EF),
    (0x06FA, 0x06FC),
    (0x06FF, 0x06FF),
    (0x0710, 0x0710),
    (0x0712, 0x072F),
    (0x074D, 0x077F),
    (0x07CA, 0x07EA),
    (0x0840, 0x0858),
    (0x0860, 0x0860),
    (0x0862, 0x0865),
    (0x0867, 0x086A),
    (0x0870, 0x0882),
    (0x0886, 0x0886),
    (0x0889, 0x088F),
    (0x08A0, 0x08AC),
    (0x08AE, 0x08C8),
    (0x1807, 0x1807),
    (0x1820, 0x1878),
    (0x1887, 0x18A8),
    (0x18AA, 0x18AA),
    (0xA840, 0xA871),
    (0x10AC0, 0x10AC5),
    (0x10AC7, 0x10AC7),
    (0x10AC9, 0x10ACA),
    (0x10ACE, 0x10AD6),
    (0x10AD8, 0x10AE1),
    (0x10AE4, 0x10AE4),
    (0x10AEB, 0x10AEF),
    (0x10B80, 0x10B91),
    (0x10BA9, 0x10BAE),
    (0x10D01, 0x10D23),
    (0x10EC2, 0x10EC4),
    (0x10EC6, 0x10EC7),
    (0x10F30, 0x10F44),
    (0x10F51, 0x10F54),
    (0x10F70, 0x10F81),
    (0x10FB0, 0x10FB0),
    (0x10FB2, 0x10FB6),
    (0x10FB8, 0x10FBF),
    (0x10FC1, 0x10FC4),
    (0x10FC9, 0x10FCA),
    (0x1E900, 0x1E943),
)

# A conservative subset of Indic_Syllabic_Category=Virama used by the scripts
# represented in _JOINING_SCRIPT_RANGES.  In Indic text, UAX #31 permits join
# controls in a virama context; merely sitting between two block-mates is not
# sufficient.
_VIRAMAS = frozenset(
    {
        0x094D,
        0x09CD,
        0x0A4D,
        0x0ACD,
        0x0B4D,
        0x0BCD,
        0x0C4D,
        0x0CCD,
        0x0D3B,
        0x0D3C,
        0x0D4D,
        0x0DCA,
        0x1039,
        0x17D2,
        0xA9C0,
    }
)


def _in_ranges(cp: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(lo <= cp <= hi for lo, hi in ranges)


def _has_joining_type(cp: int) -> bool:
    return _in_ranges(cp, _CAN_JOIN_FORWARD) or _in_ranges(cp, _CAN_JOIN_BACKWARD)


def _joining_script(cp: int) -> str | None:
    """Return a joining-script family for a letter/mark, else ``None``.

    Block membership alone is insufficient: Arabic-script blocks also contain
    digits and punctuation.  Requiring letter/mark semantics on *both* sides is
    a conservative subset of the UAX #31 joining-control contexts.
    """
    if cp < 0 or not unicodedata.category(chr(cp)).startswith(("L", "M")):
        return None
    for low, high, script in _JOINING_SCRIPT_RANGES:
        if low <= cp <= high:
            return script
    return None


def _is_context_barrier(cp: int) -> bool:
    """Whether ``cp`` must stop joiner neighbour resolution.

    Contraband such as an injected ZWSP is skipped so cleaning remains a fixed
    point, but another joiner is a barrier.  This prevents a long ZWJ run from
    letting distant script letters or emoji vouch for every character.
    """
    if cp in (ZWJ, ZWNJ):
        return True
    # Emoji modifiers extend the pictograph to their left and do not replace
    # it as the base of a following ZWJ sequence.
    if 0x1F3FB <= cp <= 0x1F3FF:
        return False
    info = classify(cp)
    return info is None or info.severity is not Severity.INVISIBLE


def _valid_tag_run(text: str, start: int, end: int) -> bool:
    """Validate one complete RGI black-flag tag run ``[start, end)``."""
    if start == 0 or ord(text[start - 1]) != _TAG_SEQUENCE_BASE:
        return False
    values = [ord(ch) for ch in text[start:end]]
    if len(values) < 2 or len(values) + 1 > 32 or values[-1] != _TAG_TERMINATOR:
        return False
    payload = values[:-1]
    if not all(0xE0061 <= cp <= 0xE007A for cp in payload):
        return False
    spec = "".join(chr(cp - 0xE0000) for cp in payload)
    return spec in _RGI_FLAG_TAG_SPECS


@lru_cache(maxsize=1)
def load_bearing_indices(text: str) -> frozenset[int]:
    """Return every context-dependent invisible that must be preserved.

    This is a pair of linear sweeps plus a single forward scan.  Earlier code
    searched outward from every invisible and rescanned every tag suffix, which
    made a run of ``n`` ZWJs or tags O(n²).  Centralising the analysis also
    guarantees inspection and cleaning make the same per-occurrence decision.
    """
    if text.isascii():
        return frozenset()

    size = len(text)
    previous = [-1] * size
    last = -1
    for index, ch in enumerate(text):
        previous[index] = last
        if _is_context_barrier(ord(ch)):
            last = index
    following = [-1] * size
    last = -1
    for index in range(size - 1, -1, -1):
        following[index] = last
        if _is_context_barrier(ord(text[index])):
            last = index

    bearing: set[int] = set()
    index = 0
    while index < size:
        cp = ord(text[index])

        if cp in TAG_BLOCK:
            end = index + 1
            while end < size and ord(text[end]) in TAG_BLOCK:
                end += 1
            if _valid_tag_run(text, index, end):
                bearing.update(range(index, end))
            index = end
            continue

        if cp in VARIATION_SELECTORS:
            if index > 0:
                base = ord(text[index - 1])
                if cp in (0xFE0E, 0xFE0F):
                    if is_emoji_variation_selector(text, index):
                        bearing.add(index)
                elif (
                    0xFE00 <= cp <= 0xFE0D
                    and _in_ranges(base, _STANDARDIZED_VARIANT_BASE_RANGES)
                    or 0xE0100 <= cp <= 0xE01EF
                    and _in_ranges(base, _IDEOGRAPH_RANGES)
                ):
                    bearing.add(index)
            index += 1
            continue

        if cp in (ZWJ, ZWNJ):
            left_i, right_i = previous[index], following[index]
            left = ord(text[left_i]) if left_i >= 0 else -1
            right = ord(text[right_i]) if right_i >= 0 else -1
            if cp == ZWJ and _is_emoji_base(left) and _is_emoji_base(right):
                bearing.add(index)
            else:
                left_script = _joining_script(left)
                if (
                    left_script is not None
                    and left_script == _joining_script(right)
                    and (
                        left in _VIRAMAS
                        or left_script in _CURSIVE_JOINING_FAMILIES
                        and _has_joining_type(left)
                        and _has_joining_type(right)
                    )
                ):
                    bearing.add(index)
            index += 1
            continue

        ranges = _SCRIPT_NEIGHBOUR_RANGES.get(cp)
        if ranges is not None:
            left_i, right_i = previous[index], following[index]
            left = ord(text[left_i]) if left_i >= 0 else -1
            right = ord(text[right_i]) if right_i >= 0 else -1
            if _in_ranges(left, ranges) and _in_ranges(right, ranges):
                bearing.add(index)
        elif 0x180B <= cp <= 0x180D:
            # Mongolian FVS follows the base it modifies.  Looking on either
            # side admitted selector runs and unrelated following letters.
            if index > 0:
                base = ord(text[index - 1])
                if 0x1800 <= base <= 0x18AF and unicodedata.category(
                    text[index - 1]
                ).startswith("L"):
                    bearing.add(index)
        index += 1

    return frozenset(bearing)


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
    return index in load_bearing_indices(text)


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
    if cp == 0x2060:
        return Category.WORD_JOINER
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
    if cp == 0x034F:
        return Category.NORMALIZATION_CONTROL
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
