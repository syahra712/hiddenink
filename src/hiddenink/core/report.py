"""The report model, and the honesty contract it enforces.

Every ``hiddenink`` result is split into two sections:

``verifiable``
    Claims that are decidable from the bytes in front of us. An invisible
    codepoint is present at offset N, or it is not. A C2PA manifest is
    embedded, or it is not. These claims are reproducible by anyone.

``not_determinable``
    Claims that cannot be decided with the information publicly available.
    As of 2026-08-13 this includes every statement about the presence,
    absence, or removal of a model-level statistical text watermark:
    Anthropic has published neither the scheme nor a detector, so no tool --
    including this one -- can evaluate it.

The split is machine-readable on purpose. A tool that reports "watermark
removed" without being able to check is not reporting a result, it is
reporting a hope. Keeping the undecidable claims in a named section makes the
boundary auditable rather than rhetorical.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .codepoints import Category, CodepointInfo, Severity

__all__ = ["Finding", "Undeterminable", "Report", "STATISTICAL_WATERMARK_NOTICE"]


#: Attached to every text report. The wording is deliberate: we do not say
#: "no watermark found", because absence of evidence is not available to us.
STATISTICAL_WATERMARK_NOTICE = (
    "Model-level statistical text watermark: NOT EVALUATED. Anthropic has "
    "published no detector or scheme specification, so its presence, absence, "
    "and removal are all undecidable by any third-party tool at this time."
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One byte-verifiable occurrence of a flagged codepoint."""

    codepoint: int
    category: Category
    severity: Severity
    name: str
    offset: int
    """Zero-based index into the decoded string (not the byte stream)."""
    line: int
    """One-based line number."""
    column: int
    """One-based column, counted in codepoints."""
    context: str = ""
    """Surrounding text with the flagged character rendered as its escape."""

    @property
    def escape(self) -> str:
        return f"U+{self.codepoint:04X}"

    @classmethod
    def from_info(
        cls,
        info: CodepointInfo,
        offset: int,
        line: int,
        column: int,
        context: str = "",
    ) -> Finding:
        return cls(
            codepoint=info.codepoint,
            category=info.category,
            severity=info.severity,
            name=info.name,
            offset=offset,
            line=line,
            column=column,
            context=context,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "codepoint": self.escape,
            "category": self.category.value,
            "severity": self.severity.value,
            "name": self.name,
            "offset": self.offset,
            "line": self.line,
            "column": self.column,
            "context": self.context,
        }


@dataclass(frozen=True, slots=True)
class Undeterminable:
    """A question this tool is structurally unable to answer, and why."""

    claim: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"claim": self.claim, "reason": self.reason}


@dataclass
class Report:
    """The result of inspecting or cleaning one source."""

    source: str
    kind: str = "text"
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    """Byte-verifiable container metadata (C2PA, EXIF, XMP, doc properties)."""
    undeterminable: list[Undeterminable] = field(default_factory=list)
    changed: bool = False
    """Set by ``clean`` when the output differs from the input."""
    removed: int = 0
    """Count of codepoints actually removed or folded by ``clean``."""

    def __post_init__(self) -> None:
        if not self.undeterminable:
            self.undeterminable = [
                Undeterminable(
                    claim="statistical text watermark present / absent / removed",
                    reason=STATISTICAL_WATERMARK_NOTICE,
                )
            ]

    # -- aggregation ---------------------------------------------------------

    def counts_by_category(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category.value] = out.get(f.category.value, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    def counts_by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return out

    @property
    def is_clean(self) -> bool:
        """True if nothing byte-verifiable was flagged.

        Note the scope: this says the *character and metadata layers* are
        clean. It says nothing about the statistical layer, which is listed
        under ``undeterminable`` precisely because it cannot be checked.
        """
        return not self.findings and not self.metadata

    # -- serialisation -------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "verifiable": {
                "findings": [f.to_dict() for f in self.findings],
                "counts_by_category": self.counts_by_category(),
                "counts_by_severity": self.counts_by_severity(),
                "metadata": self.metadata,
                "total": len(self.findings),
            },
            "not_determinable": [u.to_dict() for u in self.undeterminable],
            "changed": self.changed,
            "removed": self.removed,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
