"""Score a cleaner against the conformance corpus.

Tools are driven the way a user would drive them: text in on stdin, cleaned
text out on stdout. That keeps the harness honest about what a tool actually
does rather than about what its internals look like, and it means a competing
implementation in any language can be measured without adapting to us.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..core.clean_text import Profile, clean_text
from .corpus import CORPUS, Case, Tier

__all__ = ["Outcome", "ToolResult", "run_tool", "marklens_adapter", "external_adapter"]

#: Trailing-newline differences are a stdout convention, not a cleaning
#: decision, so they are normalised away before comparing. Everything else is
#: compared byte for byte.
_TRAILING = "\n\r"


@dataclass(frozen=True, slots=True)
class Outcome:
    case: Case
    produced: str
    error: str = ""

    @property
    def passed(self) -> bool:
        if self.error:
            return False
        return self.produced.rstrip(_TRAILING) == self.case.expect.rstrip(_TRAILING)

    @property
    def corrupted(self) -> bool:
        """Failed a load-bearing case: the tool damaged real content."""
        return not self.passed and self.case.group == "load-bearing"

    @property
    def leaked(self) -> bool:
        """Failed a contraband case: the tool left a hidden mark in place."""
        return not self.passed and self.case.group == "contraband"

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.name,
            "tier": self.case.tier.value,
            "group": self.case.group,
            "passed": self.passed,
            "given": self.case.given,
            "expected": self.case.expect,
            "produced": self.produced,
            "error": self.error,
            "why": self.case.why,
        }


@dataclass
class ToolResult:
    tool: str
    outcomes: list[Outcome] = field(default_factory=list)

    def _of_tier(self, tier: Tier) -> list[Outcome]:
        return [o for o in self.outcomes if o.case.tier is tier]

    @property
    def correctness(self) -> tuple[int, int]:
        scored = self._of_tier(Tier.CORRECTNESS)
        return sum(o.passed for o in scored), len(scored)

    @property
    def corruptions(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.corrupted]

    @property
    def leaks(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.leaked]

    def to_dict(self) -> dict[str, Any]:
        passed, total = self.correctness
        return {
            "tool": self.tool,
            "correctness_passed": passed,
            "correctness_total": total,
            "corruptions": [o.case.name for o in self.corruptions],
            "leaks": [o.case.name for o in self.leaks],
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


#: A cleaner: text in, text out. Raise to report a tool-level failure.
Adapter = Callable[[str], str]


def marklens_adapter(profile: Profile = Profile.PROSE) -> Adapter:
    """Run this package in-process, with no subprocess overhead."""

    def clean(text: str) -> str:
        return clean_text(text, profile)[0]

    return clean


def external_adapter(command: str, timeout: float = 30.0) -> Adapter:
    """Run another tool as a subprocess, piping text through stdin/stdout.

    ``command`` is a shell-style argv template. ``{}`` is replaced by ``-`` so
    tools that need an explicit stdin marker can ask for one; otherwise the
    marker is appended.
    """
    argv = shlex.split(command)
    argv = [("-" if part == "{}" else part) for part in argv]
    if "-" not in argv:
        argv.append("-")

    def clean(text: str) -> str:
        completed = subprocess.run(
            argv,
            input=text.encode("utf-8", "surrogatepass"),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace").strip()
            raise RuntimeError(f"exit {completed.returncode}: {detail[:200]}")
        return completed.stdout.decode("utf-8", "surrogatepass")

    return clean


def run_tool(name: str, adapter: Adapter, cases: tuple[Case, ...] = CORPUS) -> ToolResult:
    """Run ``adapter`` over ``cases`` and collect outcomes.

    A tool that crashes on one case is recorded as failing that case and the
    run continues: refusing to report the other 40 results because one input
    was fatal would hide more than it protects.
    """
    result = ToolResult(tool=name)
    for case in cases:
        try:
            produced = adapter(case.given)
            result.outcomes.append(Outcome(case=case, produced=produced))
        except Exception as exc:  # noqa: BLE001 - any failure is a failed case
            result.outcomes.append(
                Outcome(case=case, produced="", error=f"{type(exc).__name__}: {exc}")
            )
    return result


def to_json(results: list[ToolResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin wrapper
    from .report import render

    args = list(sys.argv[1:] if argv is None else argv)
    tools: list[tuple[str, Adapter]] = [("marklens", marklens_adapter())]
    for spec in args:
        if "=" not in spec:
            print(f"audit: expected NAME=COMMAND, got {spec!r}", file=sys.stderr)
            return 2
        name, command = spec.split("=", 1)
        tools.append((name, external_adapter(command)))

    results = [run_tool(name, adapter) for name, adapter in tools]
    print(render(results))
    return 0
