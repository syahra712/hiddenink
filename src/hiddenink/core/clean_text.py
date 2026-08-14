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
* **Heuristically recognized Markdown code spans and fenced blocks** are always
  folded to ASCII, even under ``prose``. This is intentionally not a complete
  CommonMark parser.

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
    MAX_TEXT_CODEPOINTS,
    Severity,
    classify,
    load_bearing_indices,
)
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


_FENCE_OPEN = re.compile(r"^( {0,3})(`{3,}|~{3,})([^\r\n]*)")
_URL_START = re.compile(
    r"""(?ix)
    (?<![\w@])
    (?:
        (?:https?|ftp)://
      | mailto:
      | www\.
      | [\w.!#$%&'*+/=?^_{}|~-]+@
        (?:[\w](?:[\w-]{0,61}[\w])?\.)+[\w]{2,63}
      | (?:[\w](?:[\w-]{0,61}[\w])?\.)+[\w]{2,63}
        (?=[:/?#]|[^\w-]|$)
    )
    """
)
_URL_STOP = frozenset('<>"`')


def _fenced_regions(text: str) -> list[tuple[int, int]]:
    """Return heuristic CommonMark-style fenced code blocks.

    Supports up to three leading spaces, longer delimiters, closing delimiters
    at least as long as the opener, and unclosed fences extending to EOF.  It
    intentionally does not claim to be a complete CommonMark parser.
    """
    lines = text.splitlines(keepends=True)
    spans: list[tuple[int, int]] = []
    offsets: list[int] = []
    offset = 0
    for line in lines:
        offsets.append(offset)
        offset += len(line)

    line_index = 0
    while line_index < len(lines):
        line = lines[line_index].rstrip("\r\n")
        match = _FENCE_OPEN.match(line)
        if match is None:
            line_index += 1
            continue
        marker = match.group(2)
        if marker[0] == "`" and "`" in match.group(3):
            line_index += 1
            continue
        close = re.compile(rf"^ {{0,3}}{re.escape(marker[0])}{{{len(marker)},}}[ \t]*$")
        end_line = line_index + 1
        while end_line < len(lines):
            candidate = lines[end_line].rstrip("\r\n")
            if close.match(candidate):
                end_line += 1
                break
            end_line += 1
        end = offsets[end_line] if end_line < len(offsets) else len(text)
        spans.append((offsets[line_index], end))
        line_index = end_line
    return spans


def _inline_code_regions(text: str) -> list[tuple[int, int]]:
    """Pair equal-length backtick runs, including multiline code spans."""
    opened: dict[int, int] = {}
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        if text[index] != "`":
            index += 1
            continue
        end = index + 1
        while end < len(text) and text[end] == "`":
            end += 1
        width = end - index
        start = opened.pop(width, None)
        if start is None:
            opened[width] = index
        else:
            spans.append((start, end))
        index = end
    return spans


def _trim_url_end(text: str, start: int, end: int) -> int:
    """Drop prose punctuation that cannot belong to this URL occurrence."""
    counts = {char: 0 for char in "()[]{}"}
    for char in text[start:end]:
        if char in counts:
            counts[char] += 1
    while end > start and text[end - 1] in ".,;:!?":
        end -= 1
    pairs = {")": "(", "]": "[", "}": "{"}
    while end > start and text[end - 1] in pairs:
        closing = text[end - 1]
        if counts[closing] <= counts[pairs[closing]]:
            break
        counts[closing] -= 1
        end -= 1
    return end


def _url_regions(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    cursor = 0
    while match := _URL_START.search(text, cursor):
        end = match.end()
        while (
            end < len(text)
            and not text[end].isspace()
            and text[end] not in _URL_STOP
            and ord(text[end]) >= 0x20
        ):
            end += 1
        scanned_end = end
        trimmed_end = _trim_url_end(text, match.start(), end)
        if trimmed_end > match.start():
            spans.append((match.start(), trimmed_end))
        # Do not let domain-looking components inside one long URL start a new
        # suffix scan.  Advancing to the scanned end makes this pass linear.
        cursor = max(scanned_end, match.end())
    return spans


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
    Resolved by a single positional sweep in O(n log n). Finder order is the
    tie-breaker at a shared start; a URL found inside a surrounding code region
    stays ``SOURCE``.
    """
    candidates: list[tuple[int, int, int, _Mode]] = []
    for priority, (finder, mode) in enumerate(
        (
            (_fenced_regions, _Mode.SOURCE),
            (_inline_code_regions, _Mode.SOURCE),
            (_url_regions, _Mode.LITERAL),
        )
    ):
        for start, end in finder(text):
            candidates.append((start, priority, end, mode))

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
    bearing = load_bearing_indices(text)
    for index, ch in enumerate(text):
        info = classify(ord(ch))
        contraband = (
            info is not None
            and info.severity is Severity.INVISIBLE
            and index not in bearing
        )
        if contraband:
            removed += 1
        else:
            kept.append(ch)
    return "".join(kept), removed


def _fold_segment(segment: str, table: dict[int, str]) -> tuple[str, int]:
    """Apply a translation table, counting how many characters it touched.

    Mixed-script and compatibility findings are deliberately detection-only.
    Without a language-specific parser, rewriting them can corrupt strings,
    comments, mathematical notation, and multilingual identifiers.  Callers
    that explicitly accept that policy can use ``fold_confusables`` directly.
    """
    changed = 0
    if table and segment:
        out = segment.translate(table)
        if out != segment:
            # Only pay for the Python-level count when something changed.
            changed += sum(1 for ch in segment if ord(ch) in table)
            segment = out
    return segment, changed


def _fold(text: str, profile: Profile) -> tuple[str, int]:
    """Phase 2: fold visible-but-flagged characters, respecting regions."""
    default_table = _default_table(profile)
    spans = protected_regions(text)
    if not spans:
        return _fold_segment(text, default_table)

    pieces: list[str] = []
    folded = 0
    position = 0
    for start, end, mode in spans:
        if start > position:
            out, n = _fold_segment(text[position:start], default_table)
            pieces.append(out)
            folded += n
        # SOURCE regions fold like code even under prose; LITERAL (URLs) never
        # fold at all, because changing a URL's characters changes where it
        # points -- and a homograph domain is precisely what you want to still
        # be able to see in the report.
        if mode is _Mode.LITERAL:
            pieces.append(text[start:end])
        else:
            out, n = _fold_segment(text[start:end], _MODE_TABLE[mode])
            pieces.append(out)
            folded += n
        position = end
    if position < len(text):
        out, n = _fold_segment(text[position:], default_table)
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
    normalized = 0

    if len(text) > MAX_TEXT_CODEPOINTS:
        return text, Report(
            source=source,
            kind="text",
            parse_status="resource_limit",
            warnings=[
                f"text has {len(text)} codepoints; limit is {MAX_TEXT_CODEPOINTS}"
            ],
        )

    if profile is Profile.DATA and text.startswith("﻿"):
        text = text[1:]
        normalized += 1

    removed = 0
    folded = 0
    cleaned = text
    for _ in range(_MAX_FOLD_ROUNDS):
        stripped, stripped_count = _strip_invisible(cleaned)
        if profile is Profile.DATA:
            normalized_count = stripped.count("\r\n")
            normalized += normalized_count
            stripped = stripped.replace("\r\n", "\n")
        cleaned_next, folded_count = _fold_stable(stripped, profile)
        removed += stripped_count
        folded += folded_count
        if cleaned_next == cleaned:
            cleaned = cleaned_next
            break
        cleaned = cleaned_next
    else:  # pragma: no cover - every round removes or folds a finite character
        raise RuntimeError(f"cleaning failed to converge after {_MAX_FOLD_ROUNDS} rounds")

    from .inspect_text import inspect_text  # local import: avoids a cycle

    report = inspect_text(original, source=source)
    report.changed = cleaned != original
    report.removed = removed
    report.folded = folded
    report.normalized = normalized
    return cleaned, report
