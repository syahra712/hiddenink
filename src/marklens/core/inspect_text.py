"""Text inspection: a byte-verifiable inventory of flagged codepoints.

Reports position as ``line:column`` as well as absolute offset, so findings
are actionable in an editor rather than merely countable.
"""

from __future__ import annotations

from .codepoints import Severity, classify, is_emoji_variation_selector
from .report import Finding, Report

__all__ = ["inspect_text", "iter_findings", "render_context"]

_DEFAULT_CONTEXT = 24


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
        info = classify(cp)
        hidden = info is not None and info.severity is Severity.INVISIBLE
        if hidden and cp in (0xFE0E, 0xFE0F) and is_emoji_variation_selector(text, i):
            hidden = False  # part of an emoji, not contraband
        out.append("·" if hidden else ch)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return f"{prefix}{''.join(out)}{suffix}"


def iter_findings(text: str, context_width: int = _DEFAULT_CONTEXT):
    """Yield a :class:`Finding` for every flagged codepoint in ``text``.

    Legitimate emoji presentation sequences are not flagged: stripping the
    variation selector out of an emoji corrupts it, so treating every
    U+FE00..U+FE0F as contraband is a correctness bug, not caution.
    """
    line = 1
    column = 1
    for index, ch in enumerate(text):
        cp = ord(ch)

        info = classify(cp)
        if info is not None and not (
            cp in (0xFE0E, 0xFE0F) and is_emoji_variation_selector(text, index)
        ):
            yield Finding.from_info(
                info,
                offset=index,
                line=line,
                column=column,
                context=render_context(text, index, context_width),
            )

        if ch == "\n":
            line += 1
            column = 1
        else:
            column += 1


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
