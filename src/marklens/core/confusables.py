"""Confusable and mixed-script detection.

The usual approach is a hand-written lookalike table: Cyrillic а maps to Latin
a, and so on for a few dozen entries. That catches yesterday's substitutions
and nothing else -- Unicode has thousands of confusable pairs and gains more
every release.

Two mechanisms here instead, because the problem has two halves:

**Compatibility variants** -- fullwidth ``ｈｅｌｌｏ``, mathematical bold
``𝐡𝐞𝐥𝐥𝐨``, circled ``ⓗⓔⓛⓛⓞ``, and the rest -- already have a canonical ASCII
form recorded in Unicode itself. Folding them with NFKC covers thousands of
codepoints with no table to maintain and no version to fall behind.

**Cross-script lookalikes** -- Cyrillic а, Greek ο, Cherokee Ꭺ -- are genuinely
different letters, so NFKC leaves them alone by design. These need a table, but
the table is not the interesting part: the interesting part is that a *word*
mixing Latin and Cyrillic is almost certainly an attack regardless of which
specific pair was used. Mixed-script analysis (the approach of Unicode TR39)
catches substitutions no table lists, including ones invented tomorrow.

Both are reported. Neither is folded by default in prose, because a document
that legitimately contains Cyrillic is not an attack -- see
:func:`suspicious_runs` for how the two are told apart.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from functools import lru_cache

__all__ = [
    "Script",
    "SuspiciousRun",
    "script_of",
    "scripts_in",
    "suspicious_runs",
    "nfkc_fold",
    "CROSS_SCRIPT_FOLD",
    "fold_confusables",
]


class Script(str):
    """A script name. A plain string subclass; no registry to keep in sync."""

    __slots__ = ()


COMMON = Script("Common")
LATIN = Script("Latin")

#: Script ranges, restricted to what matters for confusability. Anything not
#: listed resolves to ``Common``, which never triggers a mixed-script finding.
_SCRIPT_RANGES: tuple[tuple[int, int, Script], ...] = (
    (0x0041, 0x005A, LATIN),
    (0x0061, 0x007A, LATIN),
    (0x00C0, 0x024F, LATIN),
    (0x1E00, 0x1EFF, LATIN),
    (0x0370, 0x03FF, Script("Greek")),
    (0x1F00, 0x1FFF, Script("Greek")),
    (0x0400, 0x052F, Script("Cyrillic")),
    (0x2DE0, 0x2DFF, Script("Cyrillic")),
    (0xA640, 0xA69F, Script("Cyrillic")),
    (0x0530, 0x058F, Script("Armenian")),
    (0x0590, 0x05FF, Script("Hebrew")),
    (0x0600, 0x06FF, Script("Arabic")),
    (0x0750, 0x077F, Script("Arabic")),
    (0x0700, 0x074F, Script("Syriac")),
    (0x0900, 0x097F, Script("Devanagari")),
    (0x0980, 0x09FF, Script("Bengali")),
    (0x0A00, 0x0A7F, Script("Gurmukhi")),
    (0x0A80, 0x0AFF, Script("Gujarati")),
    (0x0B00, 0x0B7F, Script("Oriya")),
    (0x0B80, 0x0BFF, Script("Tamil")),
    (0x0C00, 0x0C7F, Script("Telugu")),
    (0x0C80, 0x0CFF, Script("Kannada")),
    (0x0D00, 0x0D7F, Script("Malayalam")),
    (0x0D80, 0x0DFF, Script("Sinhala")),
    (0x0E00, 0x0E7F, Script("Thai")),
    (0x10A0, 0x10FF, Script("Georgian")),
    (0x13A0, 0x13FF, Script("Cherokee")),
    (0xAB70, 0xABBF, Script("Cherokee")),
    (0x3040, 0x309F, Script("Hiragana")),
    (0x30A0, 0x30FF, Script("Katakana")),
    (0x31F0, 0x31FF, Script("Katakana")),
    (0x1100, 0x11FF, Script("Hangul")),
    (0x3130, 0x318F, Script("Hangul")),
    (0xAC00, 0xD7AF, Script("Hangul")),
    (0x2E80, 0x2FDF, Script("Han")),
    (0x3400, 0x4DBF, Script("Han")),
    (0x4E00, 0x9FFF, Script("Han")),
    (0xF900, 0xFAFF, Script("Han")),
)

#: Script sets that co-occur legitimately and must not be flagged. Japanese
#: mixes Han with both kana; Korean mixes Han with Hangul. Flagging these would
#: make the check useless for CJK documents.
_LEGITIMATE_COMBINATIONS: tuple[frozenset[Script], ...] = (
    frozenset({Script("Han"), Script("Hiragana"), Script("Katakana")}),
    frozenset({Script("Han"), Script("Hangul")}),
    frozenset({Script("Han"), Script("Hiragana")}),
    frozenset({Script("Han"), Script("Katakana")}),
)


@lru_cache(maxsize=4096)
def script_of(codepoint: int) -> Script:
    """The script a codepoint belongs to, or ``Common``."""
    for low, high, script in _SCRIPT_RANGES:
        if low <= codepoint <= high:
            return script
    return COMMON


def scripts_in(text: str) -> frozenset[Script]:
    """Every non-``Common`` script appearing in ``text``."""
    return frozenset(
        script
        for script in (script_of(ord(ch)) for ch in text)
        if script is not COMMON
    )


@dataclass(frozen=True, slots=True)
class SuspiciousRun:
    """A word-like run of text that mixes scripts."""

    text: str
    offset: int
    scripts: frozenset[Script]

    @property
    def description(self) -> str:
        names = ", ".join(sorted(self.scripts))
        return f"{self.text!r} mixes {names}"


def _is_word_character(ch: str) -> bool:
    return ch.isalnum() or ch in "_-."


def suspicious_runs(text: str, minimum_length: int = 2) -> list[SuspiciousRun]:
    """Find word-like runs that mix scripts.

    A document containing both Latin and Cyrillic is perfectly ordinary -- a
    Russian-English glossary, for instance. A single *word* containing both is
    not: that is the shape of a homograph substitution, and it is what this
    reports.

    Known-good combinations (Japanese Han + kana, Korean Han + Hangul) are
    excluded, so the check stays usable on CJK text.
    """
    runs: list[SuspiciousRun] = []
    start: int | None = None

    def flush(end: int) -> None:
        if start is None:
            return
        word = text[start:end]
        if len(word) < minimum_length:
            return
        found = scripts_in(word)
        if len(found) < 2:
            return
        if any(found <= combination for combination in _LEGITIMATE_COMBINATIONS):
            return
        runs.append(SuspiciousRun(text=word, offset=start, scripts=found))

    for index, ch in enumerate(text):
        if _is_word_character(ch):
            if start is None:
                start = index
        else:
            flush(index)
            start = None
    flush(len(text))
    return runs


# --- folding -----------------------------------------------------------------

#: Cross-script lookalikes that NFKC will never fold, because they are
#: genuinely different letters.
#:
#: Deliberately conservative, for two reasons learned the hard way.
#:
#: First, a hand-written table is easy to get wrong. An earlier version of this
#: one mapped Cherokee U+13AA to ``L`` and U+13A0 to ``A``, turning ``ᎪPPLE``
#: into ``LPPLE``. Cherokee, Armenian, and Georgian are omitted entirely now:
#: :func:`suspicious_runs` still *detects* homographs built from them, which is
#: what actually protects the user, and a wrong fold is worse than no fold.
#:
#: Second, lowercase Greek is mathematical notation. Folding rho to ``p`` or nu
#: to ``v`` would corrupt any physics or statistics document. Only omicron is
#: listed, because it is visually identical to ``o`` and is never used as a
#: variable name.
CROSS_SCRIPT_FOLD: dict[int, str] = {
    # Cyrillic uppercase -- shares ancestry with Latin, so these are identical
    # glyphs in essentially every font.
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x0417: "3", 0x041A: "K",
    0x041C: "M", 0x041D: "H", 0x041E: "O", 0x0420: "P", 0x0421: "C",
    0x0422: "T", 0x0423: "Y", 0x0425: "X",
    0x0405: "S", 0x0406: "I", 0x0408: "J", 0x04C0: "I",
    # Cyrillic lowercase
    0x0430: "a", 0x0435: "e", 0x043A: "k", 0x043C: "m", 0x043E: "o",
    0x0440: "p", 0x0441: "c", 0x0443: "y", 0x0445: "x",
    0x0455: "s", 0x0456: "i", 0x0458: "j",
    # Greek uppercase -- likewise identical to Latin
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H",
    0x0399: "I", 0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O",
    0x03A1: "P", 0x03A4: "T", 0x03A5: "Y", 0x03A7: "X",
    # Greek lowercase: omicron only. See the note above.
    0x03BF: "o",
}


@lru_cache(maxsize=8192)
def nfkc_fold(codepoint: int) -> str | None:
    """The ASCII form of a compatibility variant, if it has one.

    Covers fullwidth, mathematical alphanumeric, circled, parenthesised, and
    every other block Unicode records a compatibility decomposition for --
    thousands of codepoints, no table.
    """
    ch = chr(codepoint)
    if ch.isascii():
        return None
    folded = unicodedata.normalize("NFKC", ch)
    if folded == ch or not folded.isascii() or not folded.isprintable():
        return None
    return folded


def fold_confusables(text: str) -> tuple[str, int]:
    """Fold confusable characters to ASCII; return ``(text, changed_count)``.

    The two mechanisms have different blast radii, so they get different scope.

    **Compatibility variants** (fullwidth, mathematical, circled) are folded
    everywhere. They are decorative encodings of ASCII, so recovering the ASCII
    cannot lose information.

    **Cross-script lookalikes** are folded *only inside a mixed-script run*.
    This matters enormously: folding Cyrillic а to ``a`` wherever it appears
    would turn ``привет`` into ``pривet``, corrupting every Russian document it
    touched. Inside ``pаypal`` the same character is an impersonation and the
    fold is exactly right. Scope, not the table, is what makes this safe --
    which is why a blanket "aggressive homoglyphs" switch is the wrong shape for
    this problem.
    """
    folded_runs = {
        offset
        for run in suspicious_runs(text)
        for offset in range(run.offset, run.offset + len(run.text))
    }

    out: list[str] = []
    changed = 0
    for index, ch in enumerate(text):
        codepoint = ord(ch)
        replacement = nfkc_fold(codepoint)
        if replacement is None and index in folded_runs:
            replacement = CROSS_SCRIPT_FOLD.get(codepoint)
        if replacement is not None and replacement != ch:
            out.append(replacement)
            changed += 1
        else:
            out.append(ch)
    return "".join(out), changed
