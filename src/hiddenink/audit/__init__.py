"""Conformance auditing for AI-provenance-mark cleaners.

Run with ``python -m hiddenink.audit [NAME=COMMAND ...]``. With no arguments it
scores this package alone; each extra argument adds another tool, driven by
piping text through its stdin.
"""

from .corpus import CORPUS, Case, Tier, correctness_cases, policy_cases
from .report import render
from .runner import (
    Outcome,
    ToolResult,
    external_adapter,
    hiddenink_adapter,
    run_tool,
    to_json,
)

__all__ = [
    "CORPUS",
    "Case",
    "Outcome",
    "Tier",
    "ToolResult",
    "correctness_cases",
    "external_adapter",
    "hiddenink_adapter",
    "policy_cases",
    "render",
    "run_tool",
    "to_json",
]
