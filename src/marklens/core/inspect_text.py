"""Text inspection: a byte-verifiable inventory of flagged codepoints.

Reports position as ``line:column`` as well as absolute offset, so findings
are actionable in an editor rather than merely countable.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterator

from .codepoints import Severity, classify, is_load_bearing
from .report import Finding, Report

__all__ = ["inspect_text", "iter_findings", "render_context"]

_DEFAULT_CONTEXT = 24

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


def render_context(text: str, index: int, width: int = _DEFAULT_CONTEXT) -> str:
    """Return text around ``index`` with non-printing characters escaped.

    The flagged character itself is always shown as its ``U+XXXX`` form so the
    context is legible in a terminal; other invisible characters in the window
    are shown as ``·`` so they do not silently distort the excerpt.
    """
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
            info is not None
            and info.severity is Severity.INVISIBLE
            and not is_load_bearing(text, i)
        )
        out.append("·" if hidden else ch)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{''.join(out)}{suffix}"


def iter_findings(
    text: str, context_width: int = _DEFAULT_CONTEXT
) -> Iterator[Finding]:
    """Yield a :class:`Finding` for every flagged codepoint in ``text``.

    Load-bearing invisibles are not flagged. An emoji presentation sequence, a
    ZWJ gluing a family emoji together, a ZWNJ spelling a Devanagari word, the
    tag characters inside a subdivision flag -- all of these are content, and
    reporting them as contraband would invite the user to corrupt their own
    document. See :func:`~marklens.core.codepoints.is_load_bearing`.
    """
    starts: list[int] | None = None

    for match in _CANDIDATE.finditer(text):
        index = match.start()

        info = classify(ord(text[index]))
        if info is None:
            continue
        if info.severity is Severity.INVISIBLE and is_load_bearing(text, index):
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
            context=render_context(text, index, context_width),
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
    return Report(
        source=source,
        kind="text",
        findings=list(iter_findings(text, context_width)),
    )
