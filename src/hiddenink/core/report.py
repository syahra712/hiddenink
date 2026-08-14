"""The report model, and the honesty contract it enforces.

Every ``hiddenink`` result is split into two sections:

``verifiable``
    Claims that are decidable from the bytes in front of us. An invisible
    codepoint is present at offset N, or it is not. A supported container
    structure is present at a byte range, or it is not. These claims are
    reproducible; credential validity remains a separate question.

``not_determinable``
    Claims that this inspection did not evaluate. For text, that includes the
    presence, absence, or removal of any model-level statistical watermark:
    this package has no vendor detector or model-specific scheme information.

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
    "Model-level statistical text watermark: NOT EVALUATED. hiddenink has no "
    "vendor detector or model-specific scheme information, so this report makes "
    "no claim about its presence, absence, or removal."
)


_DEFAULT_COVERAGE = {
    "text": "Unicode codepoint scan and heuristic mixed-script detection",
    "png": "PNG structure and supported metadata chunks",
    "jpeg": "JPEG marker structure and supported metadata segments",
    "svg": "SVG metadata elements and decoded XML text",
    "office": (
        "document properties only; body text, comments, revisions, cells, and "
        "slides are not scanned"
    ),
    "pdf": (
        "shallow lexical metadata scan; compressed objects and unsupported "
        "encodings may not be visible"
    ),
    "unknown": "no parser selected",
}


def _is_diagnostic_metadata(key: str) -> bool:
    suffix = key.rsplit(".", 1)[-1]
    return (
        suffix
        in {
            "parse_status",
            "coverage",
            "warning",
            "warnings",
            "refusal",
            "refusal_reason",
        }
        or ".warning." in key
        or ".refusal." in key
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
    """Parser results for supported container structures and metadata."""
    undeterminable: list[Undeterminable] = field(default_factory=list)
    changed: bool = False
    """Set by ``clean`` when the output differs from the input."""
    removed: int = 0
    """Count of codepoints actually removed by ``clean``."""
    folded: int = 0
    """Count of characters replaced by a profile-specific fold."""
    normalized: int = 0
    """Count of other normalisations, such as BOM or CRLF handling."""
    parse_status: str = ""
    """Parser outcome, including ``complete``, ``partial``, or a refusal state."""
    coverage: str = ""
    """Plain-language statement of what the selected parser examined."""
    warnings: list[str] = field(default_factory=list)
    refusal_reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Container parsers use namespaced metadata keys so old API consumers
        # can still see every parser result. Lift their status into a stable,
        # structured report contract as well.
        for key, value in self.metadata.items():
            suffix = key.rsplit(".", 1)[-1]
            if suffix == "parse_status" and not self.parse_status:
                self.parse_status = str(value)
            elif suffix == "coverage" and not self.coverage:
                self.coverage = str(value)
            elif suffix in {"warning", "warnings"} or ".warning." in key:
                values = value if isinstance(value, list) else [value]
                self.warnings.extend(str(item) for item in values)
            elif (
                suffix in {"refusal", "refusal_reason"}
                or ".refusal." in key
            ):
                self.refusal_reasons.append(str(value))

        if not self.parse_status:
            if self.kind == "text":
                self.parse_status = "complete"
            elif self.kind == "unknown":
                self.parse_status = "unsupported"
            else:
                # Container readers vary in depth. Until a parser explicitly
                # declares complete coverage, partial is the honest default.
                self.parse_status = "partial"
        if not self.coverage:
            self.coverage = _DEFAULT_COVERAGE.get(self.kind, "limited inspection")

        # A statistical *text* watermark caveat is useful for text, but is
        # irrelevant noise on a binary metadata report.
        if self.kind == "text" and not self.undeterminable:
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
        """True if a complete declared scan produced no finding or warning.

        This is always relative to :attr:`coverage`; it makes no statement
        about unimplemented parsing or any statistical watermark layer.
        """
        return (
            self.parse_status == "complete"
            and not self.findings
            and not self.substantive_metadata
            and not self.warnings
            and not self.refusal_reasons
        )

    @property
    def substantive_metadata(self) -> dict[str, Any]:
        """Parsed metadata excluding status/warning transport keys."""
        return {
            key: value
            for key, value in self.metadata.items()
            if not _is_diagnostic_metadata(key)
        }

    @property
    def transformed(self) -> int:
        """Total number of explicitly counted transformations."""
        return self.removed + self.folded + self.normalized

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
                "status": {
                    "parse_status": self.parse_status,
                    "coverage": self.coverage,
                    "warnings": self.warnings,
                    "refusal_reasons": self.refusal_reasons,
                },
            },
            "not_determinable": [u.to_dict() for u in self.undeterminable],
            "changed": self.changed,
            "removed": self.removed,
            "folded": self.folded,
            "normalized": self.normalized,
            "transformed": self.transformed,
        }

    def to_json(self, indent: int = 2) -> str:
        # ASCII-only JSON prevents bidi/C1 terminal effects when users inspect
        # the raw machine output; decoding reconstructs the original values.
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=True)
