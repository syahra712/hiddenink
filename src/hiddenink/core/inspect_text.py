"""Text inspection: a byte-verifiable inventory of flagged codepoints.

Reports position as ``line:column`` as well as absolute offset, so findings
are actionable in an editor rather than merely countable.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterator
from itertools import islice

from .codepoints import (
    MAX_TEXT_CODEPOINTS,
    Category,
    Severity,
    classify,
    load_bearing_indices,
)
from .confusables import suspicious_runs
from .report import Finding, Report

__all__ = [
    "inspect_text",
    "iter_findings",
    "iter_mixed_script_findings",
    "render_context",
    "MAX_TEXT_FINDINGS",
]

_DEFAULT_CONTEXT = 24
MAX_TEXT_FINDINGS = 10_000

#: A superset of every codepoint :func:`classify` can flag, expressed as a
#: character class so the scan runs in C rather than one Python call per
#: character. Correctness rests on a simple invariant: ``classify`` returns
#: ``None`` for all of printable ASCII plus tab/LF/CR, so anything it flags is
#: either a C0/C1 control or non-ASCII -- exactly what this matches. On
#: ordinary ASCII source files it yields no candidates at all.
_CANDIDATE = re.compile(r"[^\t\n\r\x20-\x7e]")


def _line_starts(text: str) -> list[int]:
    """Offsets at which each line begins, for O(log n) position lookup."""
    starts = [0]
    position = text.find("\n")
    while position != -1:
        starts.append(position + 1)
        position = text.find("\n", position + 1)
    return starts


def render_context(
    text: str,
    index: int,
    width: int = _DEFAULT_CONTEXT,
    *,
    _bearing: frozenset[int] | None = None,
) -> str:
    """Return text around ``index`` with non-printing characters escaped.

    The flagged character itself is always shown as its ``U+XXXX`` form so the
    context is legible in a terminal; other invisible characters in the window
    are shown as ``·`` so they do not silently distort the excerpt.
    """
    if _bearing is None:
        _bearing = load_bearing_indices(text)
    start = max(0, index - width)
    end = min(len(text), index + width + 1)
    out: list[str] = []
    for i in range(start, end):
        ch = text[i]
        cp = ord(ch)
        if i == index:
            out.append(f"[U+{cp:04X}]")
            continue
        if ch in "\n\r\t":
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
            continue
        if 0x20 <= cp < 0x7F:
            out.append(ch)  # printable ASCII is never hidden
            continue
        info = classify(cp)
        hidden = (
            info is not None and info.severity is Severity.INVISIBLE and i not in _bearing
        )
        out.append("·" if hidden else ch)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{''.join(out)}{suffix}"


def iter_findings(
    text: str,
    context_width: int = _DEFAULT_CONTEXT,
    *,
    _bearing: frozenset[int] | None = None,
) -> Iterator[Finding]:
    """Yield a :class:`Finding` for every flagged codepoint in ``text``.

    Load-bearing invisibles are not flagged. An emoji presentation sequence, a
    ZWJ gluing a family emoji together, a ZWNJ spelling a Devanagari word, the
    tag characters inside a subdivision flag -- all of these are content, and
    reporting them as contraband would invite the user to corrupt their own
    document. See :func:`~hiddenink.core.codepoints.is_load_bearing`.
    """
    starts: list[int] | None = None
    if _bearing is None:
        _bearing = load_bearing_indices(text)

    for match in _CANDIDATE.finditer(text):
        index = match.start()

        info = classify(ord(text[index]))
        if info is None:
            continue
        if info.severity is Severity.INVISIBLE and index in _bearing:
            continue

        # Built once, and only if the document actually has a finding.
        if starts is None:
            starts = _line_starts(text)
        line = bisect_right(starts, index)

        yield Finding.from_info(
            info,
            offset=index,
            line=line,
            column=index - starts[line - 1] + 1,
            context=render_context(text, index, context_width, _bearing=_bearing),
        )


def iter_mixed_script_findings(
    text: str,
    context_width: int = _DEFAULT_CONTEXT,
    *,
    _bearing: frozenset[int] | None = None,
    _limit: int | None = None,
) -> Iterator[Finding]:
    """Yield a finding per word-like run that mixes scripts.

    Reported separately from codepoint findings because the defect is a property
    of the *run*, not of any single character: every character in ``pаypal`` is
    individually unremarkable. Known-good combinations -- Japanese Han with
    kana, Korean Han with Hangul -- are excluded upstream.
    """
    runs = suspicious_runs(text, limit=_limit)
    if not runs:
        return
    starts = _line_starts(text)
    if _bearing is None:
        _bearing = load_bearing_indices(text)
    for run in runs:
        line = bisect_right(starts, run.offset)
        yield Finding(
            codepoint=ord(text[run.offset]),
            category=Category.MIXED_SCRIPT,
            severity=Severity.CONFUSABLE,
            name=run.description,
            offset=run.offset,
            line=line,
            column=run.offset - starts[line - 1] + 1,
            context=render_context(text, run.offset, context_width, _bearing=_bearing),
        )


def inspect_text(
    text: str,
    source: str = "<text>",
    context_width: int = _DEFAULT_CONTEXT,
) -> Report:
    """Inspect ``text`` and return a :class:`Report`.

    The report's ``verifiable`` section is complete and reproducible. Its
    ``not_determinable`` section records that the statistical watermark layer
    was not evaluated, because it cannot be.
    """
    if len(text) > MAX_TEXT_CODEPOINTS:
        return Report(
            source=source,
            kind="text",
            parse_status="resource_limit",
            warnings=[
                f"text has {len(text)} codepoints; limit is {MAX_TEXT_CODEPOINTS}"
            ],
        )

    bearing = load_bearing_indices(text)
    findings = list(
        islice(
            iter_findings(text, context_width, _bearing=bearing),
            MAX_TEXT_FINDINGS + 1,
        )
    )
    truncated = len(findings) > MAX_TEXT_FINDINGS
    if truncated:
        findings = findings[:MAX_TEXT_FINDINGS]
    else:
        remaining = MAX_TEXT_FINDINGS - len(findings)
        mixed = list(
            iter_mixed_script_findings(
                text,
                context_width,
                _bearing=bearing,
                _limit=remaining + 1,
            )
        )
        truncated = len(mixed) > remaining
        findings.extend(mixed[:remaining])
    findings.sort(key=lambda f: (f.offset, f.category.value))
    return Report(
        source=source,
        kind="text",
        findings=findings,
        parse_status="resource_limit" if truncated else "complete",
        warnings=(
            [f"finding output truncated at {MAX_TEXT_FINDINGS} occurrences"]
            if truncated
            else []
        ),
    )
