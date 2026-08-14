"""Deterministic removal of invisible and hazardous codepoints.

This is the part of "watermark removal" that is real: the characters either
survive into the output or they do not, and ``diff`` will show you which.
Nothing here touches -- or claims to touch -- model-level statistical
watermarking.

Three profiles, because the right answer differs by content type:

``prose``
    Strip invisible characters. Fold exotic spaces to U+0020. **Preserve**
    typography: em dashes and curly quotes are legitimate writing, and a tool
    that mangles them is doing cosmetic damage, not cleaning.

``code``
    Strip invisible characters. Fold exotic spaces *and* typography to ASCII,
    because a curly quote in source is a syntax error and a non-breaking space
    is an invisible indentation bug.

``data``
    ``code`` plus: drop a leading byte-order mark and normalise CRLF to LF,
    the two things that most often corrupt CSV and JSON pipelines.

Region awareness, applied under every profile:

* **URLs** are only ever stripped of invisible characters. Folding a dash or
  quote inside a URL silently breaks the link.
* **Code spans and fenced blocks** are always folded to ASCII, even under
  ``prose``. A curly quote inside a Markdown code fence is still a bug.

Cleaning runs in two phases, and the order is load-bearing:

1. **Strip invisibles.** These are removed everywhere under every profile, so
   the decision needs no region context.
2. **Compute regions on the stripped text, then fold.**

Doing it the other way round breaks idempotence. Removing an invisible
character shifts the text, which can change which regions the delimiters
form -- a zero-width space between two backticks makes ``` `<ZWSP>` ``` a code
span on the first pass but not on the second. Computing regions *after* the
strip means pass two sees exactly the regions pass one folded against.
"""

from __future__ import annotations

import re
from enum import Enum

from .codepoints import (
    ASCII_FOLD,
    EXOTIC_SPACE,
    Severity,
    classify,
    is_load_bearing,
)
from .confusables import fold_confusables
from .report import Report

__all__ = ["Profile", "clean_text", "protected_regions"]


class Profile(str, Enum):
    PROSE = "prose"
    CODE = "code"
    DATA = "data"


class _Mode(str, Enum):
    """How a span of text should be treated."""

    DEFAULT = "default"
    #: Invisible removal only; never fold. Used for URLs.
    LITERAL = "literal"
    #: Invisible removal plus ASCII folding, regardless of profile.
    SOURCE = "source"


_FENCED = re.compile(r"^[ \t]*(`{3,}|~{3,})[^\n]*\n.*?^[ \t]*\1[^\n]*$", re.S | re.M)
_INLINE_CODE = re.compile(r"`[^`\n]+`")
_URL = re.compile(r"""(?:https?|ftp|mailto):[^\s<>"'`\])]+""")

#: Ordered by precedence: an earlier pattern wins any overlap.
_PATTERNS: tuple[tuple[re.Pattern[str], _Mode], ...] = (
    (_FENCED, _Mode.SOURCE),
    (_INLINE_CODE, _Mode.SOURCE),
    (_URL, _Mode.LITERAL),
)

# --- translation tables ------------------------------------------------------
# ``str.translate`` runs in C, so folding a whole segment costs one pass with
# no per-character Python overhead.

_FOLD_ALL: dict[int, str] = dict(ASCII_FOLD)
_FOLD_WHITESPACE_ONLY: dict[int, str] = {cp: " " for cp in EXOTIC_SPACE}
_FOLD_NONE: dict[int, str] = {}

#: ASCII control characters that are never legitimate (tab/LF/CR excluded).
_ASCII_CONTROL_DELETE: dict[int, None] = {
    **{cp: None for cp in range(0x20) if cp not in (0x09, 0x0A, 0x0D)},
    0x7F: None,
}


def _default_table(profile: Profile) -> dict[int, str]:
    """Folding applied outside any protected region."""
    if profile is Profile.PROSE:
        # Exotic spaces are invisible bugs in every context, including prose;
        # typography is legitimate writing and is left alone.
        return _FOLD_WHITESPACE_ONLY
    return _FOLD_ALL


_MODE_TABLE: dict[_Mode, dict[int, str]] = {
    _Mode.SOURCE: _FOLD_ALL,
    _Mode.LITERAL: _FOLD_NONE,
}


def protected_regions(text: str) -> list[tuple[int, int, _Mode]]:
    """Find spans needing treatment other than the ambient profile.

    Returns non-overlapping ``(start, end, mode)`` tuples in document order.
    Resolved by a single positional sweep in O(n log n); earlier patterns in
    :data:`_PATTERNS` win, so a URL inside a code fence stays ``SOURCE``.
    """
    candidates: list[tuple[int, int, int, _Mode]] = []
    for priority, (pattern, mode) in enumerate(_PATTERNS):
        for m in pattern.finditer(text):
            candidates.append((m.start(), priority, m.end(), mode))

    candidates.sort()

    spans: list[tuple[int, int, _Mode]] = []
    covered_to = 0
    for start, _priority, end, mode in candidates:
        if start >= covered_to:
            spans.append((start, end, mode))
            covered_to = end
    return spans


def _strip_invisible(text: str) -> tuple[str, int]:
    """Phase 1: remove every invisible codepoint that is not load-bearing.

    Load-bearing invisibles survive: emoji presentation sequences, the ZWJ that
    fuses a family emoji, the ZWNJ that spells a Devanagari or Persian word, and
    the tag characters inside a subdivision flag. Stripping those is not
    cleaning, it is corruption -- and unlike a global opt-out flag, the decision
    is made per occurrence, so a hidden joiner between two Latin letters still
    goes.
    """
    if text.isascii():
        # The only invisibles reachable in ASCII are the C0 controls, and no
        # load-bearing exception can apply, so this is a single C-level pass.
        out = text.translate(_ASCII_CONTROL_DELETE)
        return out, len(text) - len(out)

    kept: list[str] = []
    removed = 0
    for index, ch in enumerate(text):
        info = classify(ord(ch))
        contraband = (
            info is not None
            and info.severity is Severity.INVISIBLE
            and not is_load_bearing(text, index)
        )
        if contraband:
            removed += 1
        else:
            kept.append(ch)
    return "".join(kept), removed


def _fold_segment(
    segment: str, table: dict[int, str], confusables: bool = False
) -> tuple[str, int]:
    """Apply a translation table, counting how many characters it touched.

    ``confusables`` additionally folds impersonating characters to ASCII. It is
    off for prose and off inside URLs: a Cyrillic letter in running text is
    somebody's language, and rewriting a URL's characters changes where it
    points.
    """
    changed = 0
    if table and segment:
        out = segment.translate(table)
        if out != segment:
            # Only pay for the Python-level count when something changed.
            changed += sum(1 for ch in segment if ord(ch) in table)
            segment = out
    if confusables and not segment.isascii():
        segment, folded = fold_confusables(segment)
        changed += folded
    return segment, changed


def _fold(text: str, profile: Profile) -> tuple[str, int]:
    """Phase 2: fold visible-but-flagged characters, respecting regions."""
    default_table = _default_table(profile)
    # A confusable in source or structured data is unambiguously a defect: an
    # identifier that reads as `paypal` but is not. In prose it is reported and
    # left alone, because the same character may simply be the language.
    fold_lookalikes = profile in (Profile.CODE, Profile.DATA)
    spans = protected_regions(text)
    if not spans:
        return _fold_segment(text, default_table, fold_lookalikes)

    pieces: list[str] = []
    folded = 0
    position = 0
    for start, end, mode in spans:
        if start > position:
            out, n = _fold_segment(
                text[position:start], default_table, fold_lookalikes
            )
            pieces.append(out)
            folded += n
        # SOURCE regions fold like code even under prose; LITERAL (URLs) never
        # fold at all, because changing a URL's characters changes where it
        # points -- and a homograph domain is precisely what you want to still
        # be able to see in the report.
        if mode is _Mode.LITERAL:
            pieces.append(text[start:end])
        else:
            out, n = _fold_segment(text[start:end], _MODE_TABLE[mode], True)
            pieces.append(out)
            folded += n
        position = end
    if position < len(text):
        out, n = _fold_segment(text[position:], default_table, fold_lookalikes)
        pieces.append(out)
        folded += n
    return "".join(pieces), folded


#: Folding cannot introduce a new foldable character -- every replacement is
#: ASCII and no ASCII codepoint is a key in the fold tables -- so each round
#: strictly reduces the number of foldable characters and convergence is
#: guaranteed. This bound only exists to make a logic error loud instead of
#: infinite.
_MAX_FOLD_ROUNDS = 8


def _fold_stable(text: str, profile: Profile) -> tuple[str, int]:
    """Fold repeatedly until the text stops changing.

    A single fold pass is not idempotent on its own. Folding emits ``"``,
    ``'`` and spaces, and those characters are exactly what the URL and fenced
    -block patterns are sensitive to, so one pass can move a region boundary
    and leave the next pass with different work to do. Converging here means
    :func:`clean_text` returns a fixed point, which is what makes running it
    twice a no-op.
    """
    total = 0
    for _ in range(_MAX_FOLD_ROUNDS):
        folded, n = _fold(text, profile)
        total += n
        if folded == text:
            return text, total
        text = folded
    raise RuntimeError(  # pragma: no cover - unreachable; see _MAX_FOLD_ROUNDS
        f"folding failed to converge after {_MAX_FOLD_ROUNDS} rounds"
    )


def clean_text(
    text: str,
    profile: Profile | str = Profile.PROSE,
    source: str = "<text>",
) -> tuple[str, Report]:
    """Clean ``text``; return ``(cleaned, report)``.

    Idempotent for every profile: ``clean_text(clean_text(x)[0])[0]`` equals
    ``clean_text(x)[0]``. This is verified by a fuzz test, not by inspection --
    folding ``U+2026`` to ``...`` changes length, and phase ordering matters.
    """
    profile = Profile(profile)
    original = text

    if profile is Profile.DATA:
        if text.startswith("﻿"):
            text = text[1:]
        text = text.replace("\r\n", "\n")

    stripped, removed = _strip_invisible(text)
    cleaned, folded = _fold_stable(stripped, profile)

    from .inspect_text import inspect_text  # local import: avoids a cycle

    report = inspect_text(original, source=source)
    report.changed = cleaned != original
    report.removed = removed + folded
    return cleaned, report
