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
"""

from __future__ import annotations

import re
from enum import Enum

from .codepoints import ASCII_FOLD, Severity, classify, is_emoji_variation_selector
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


def protected_regions(text: str) -> list[tuple[int, int, _Mode]]:
    """Find spans needing treatment other than the ambient profile.

    Returns non-overlapping ``(start, end, mode)`` tuples in document order.
    Earlier matchers win: a URL inside a code fence stays SOURCE.
    """
    spans: list[tuple[int, int, _Mode]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < e and s < end for s, e, _ in spans)

    for pattern, mode in (
        (_FENCED, _Mode.SOURCE),
        (_INLINE_CODE, _Mode.SOURCE),
        (_URL, _Mode.LITERAL),
    ):
        for m in pattern.finditer(text):
            if not overlaps(m.start(), m.end()):
                spans.append((m.start(), m.end(), mode))

    spans.sort()
    return spans


def _mode_map(text: str) -> list[_Mode]:
    """Per-character mode lookup."""
    modes = [_Mode.DEFAULT] * len(text)
    for start, end, mode in protected_regions(text):
        for i in range(start, end):
            modes[i] = mode
    return modes


def _should_fold(severity: Severity, profile: Profile, mode: _Mode) -> bool:
    """Whether a visible-but-flagged character gets folded to ASCII."""
    if mode is _Mode.LITERAL:
        return False
    if mode is _Mode.SOURCE:
        return True
    if severity is Severity.WHITESPACE:
        # Exotic spaces are folded under every profile: they are invisible
        # bugs in every context, including prose.
        return True
    return profile in (Profile.CODE, Profile.DATA)


def clean_text(
    text: str,
    profile: Profile | str = Profile.PROSE,
    source: str = "<text>",
) -> tuple[str, Report]:
    """Clean ``text``; return ``(cleaned, report)``.

    Guaranteed idempotent: ``clean_text(clean_text(x)[0])[0] == clean_text(x)[0]``.
    """
    profile = Profile(profile)

    if profile is Profile.DATA:
        if text.startswith("﻿"):
            text = text[1:]
        text = text.replace("\r\n", "\n")

    modes = _mode_map(text)
    out: list[str] = []
    removed = 0

    for index, ch in enumerate(text):
        cp = ord(ch)
        info = classify(cp)

        if info is None:
            out.append(ch)
            continue

        # Emoji presentation sequences are content, not contraband.
        if cp in (0xFE0E, 0xFE0F) and is_emoji_variation_selector(text, index):
            out.append(ch)
            continue

        if info.severity is Severity.INVISIBLE:
            removed += 1
            continue

        if _should_fold(info.severity, profile, modes[index]):
            replacement = ASCII_FOLD.get(cp)
            if replacement is not None:
                out.append(replacement)
                removed += 1
                continue

        out.append(ch)

    cleaned = "".join(out)

    from .inspect_text import inspect_text  # local import: avoids a cycle

    report = inspect_text(text, source=source)
    report.changed = cleaned != text
    report.removed = removed
    return cleaned, report
