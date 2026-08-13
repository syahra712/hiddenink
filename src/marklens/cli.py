"""Command-line interface.

Exit codes:
    0  success, nothing exceeded the ``--fail-on`` threshold
    1  findings at or above the ``--fail-on`` severity were present
    2  usage or I/O error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core.clean_text import Profile, clean_text
from .core.codepoints import Severity
from .core.inspect_text import inspect_text
from .core.report import Report

_SEVERITY_ORDER = {
    Severity.TYPOGRAPHIC: 1,
    Severity.WHITESPACE: 2,
    Severity.INVISIBLE: 3,
}

_PROFILE_BY_SUFFIX = {
    ".md": Profile.PROSE,
    ".markdown": Profile.PROSE,
    ".txt": Profile.PROSE,
    ".rst": Profile.PROSE,
    ".csv": Profile.DATA,
    ".tsv": Profile.DATA,
    ".json": Profile.DATA,
    ".jsonl": Profile.DATA,
}


def _use_colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str:
        return self(t, "1")

    def dim(self, t: str) -> str:
        return self(t, "2")

    def red(self, t: str) -> str:
        return self(t, "31")

    def yellow(self, t: str) -> str:
        return self(t, "33")

    def green(self, t: str) -> str:
        return self(t, "32")

    def cyan(self, t: str) -> str:
        return self(t, "36")


def _render(report: Report, style: _Style, show_findings: bool = True) -> str:
    """Human-readable report, always showing both sections."""
    lines: list[str] = []
    lines.append(style.bold(f"── {report.source}"))

    total = len(report.findings)
    lines.append(style.bold("VERIFIABLE") + style.dim("  (decidable from the bytes)"))

    if total == 0 and not report.metadata:
        lines.append("  " + style.green("no flagged codepoints, no container metadata"))
    else:
        by_sev = report.counts_by_severity()
        parts = []
        for sev, colour in (
            (Severity.INVISIBLE, style.red),
            (Severity.WHITESPACE, style.yellow),
            (Severity.TYPOGRAPHIC, style.cyan),
        ):
            n = by_sev.get(sev.value, 0)
            if n:
                parts.append(colour(f"{n} {sev.value}"))
        if parts:
            lines.append(f"  {total} flagged codepoints: " + ", ".join(parts))
        for cat, n in report.counts_by_category().items():
            lines.append(f"    {style.dim('·')} {cat:<20} {n}")
        for key, value in report.metadata.items():
            lines.append(f"  {style.dim('metadata')} {key}: {value}")

        if show_findings and report.findings:
            lines.append(style.dim("  ── occurrences"))
            for f in report.findings[:40]:
                loc = f"{f.line}:{f.column}"
                lines.append(
                    f"    {style.dim(loc.ljust(9))}{f.escape:<9} "
                    f"{f.name[:38]:<38} {style.dim(f.context)}"
                )
            if len(report.findings) > 40:
                lines.append(
                    style.dim(f"    … {len(report.findings) - 40} more (use --json)")
                )

    if report.changed:
        lines.append(f"  {style.green('removed/folded')}: {report.removed}")

    lines.append(
        style.bold("NOT DETERMINABLE") + style.dim("  (no tool can decide these)")
    )
    for u in report.undeterminable:
        lines.append(f"  {style.dim('·')} {u.reason}")

    return "\n".join(lines)


def _read(path: str) -> tuple[str, str]:
    if path == "-":
        return sys.stdin.read(), "<stdin>"
    p = Path(path)
    return p.read_text(encoding="utf-8", errors="surrogatepass"), str(p)


def _exceeds(report: Report, threshold: Severity | None) -> bool:
    if threshold is None:
        return False
    want = _SEVERITY_ORDER[threshold]
    return any(_SEVERITY_ORDER[f.severity] >= want for f in report.findings)


def _emit(reports: list[Report], args, style: _Style) -> None:
    if args.json:
        payload = [r.to_dict() for r in reports]
        print(json.dumps(payload if len(payload) != 1 else payload[0], indent=2,
                         ensure_ascii=False))
    else:
        print("\n\n".join(_render(r, style, show_findings=not args.quiet)
                          for r in reports))


def cmd_inspect(args) -> int:
    style = _Style(_use_colour(sys.stdout) and not args.json)
    reports: list[Report] = []
    for path in args.paths:
        text, name = _read(path)
        reports.append(inspect_text(text, source=name, context_width=args.context))
    _emit(reports, args, style)
    return 1 if any(_exceeds(r, args.fail_on) for r in reports) else 0


def cmd_clean(args) -> int:
    style = _Style(_use_colour(sys.stderr) and not args.json)
    reports: list[Report] = []
    for path in args.paths:
        text, name = _read(path)

        profile = args.profile
        if profile is None:
            suffix = Path(name).suffix.lower()
            profile = _PROFILE_BY_SUFFIX.get(suffix, Profile.CODE)

        cleaned, report = clean_text(text, profile=profile, source=name)
        reports.append(report)

        if args.in_place and path != "-":
            if args.dry_run:
                continue
            p = Path(path)
            if args.backup:
                p.with_suffix(p.suffix + ".bak").write_text(text, encoding="utf-8")
            p.write_text(cleaned, encoding="utf-8")
        elif not args.dry_run and not args.json:
            sys.stdout.write(cleaned)

    if args.in_place or args.dry_run or args.json:
        _emit(reports, args, style)
    else:
        print("\n\n".join(_render(r, style, show_findings=False) for r in reports),
              file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="marklens",
        description=(
            "Inspect and clean AI provenance marks. Removes what is provably "
            "removable; never claims to remove what cannot be verified."
        ),
        epilog=(
            "marklens does not remove, defeat, or detect model-level statistical "
            "watermarking. No public tool can: no detector has been published."
        ),
    )
    parser.add_argument("--version", action="version", version=f"marklens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("paths", nargs="*", default=["-"],
                        help="files to process, or - for stdin (default: -)")
    common.add_argument("--json", action="store_true", help="machine-readable output")

    p_inspect = sub.add_parser("inspect", parents=[common],
                               help="report flagged codepoints without changing anything")
    p_inspect.add_argument("--context", type=int, default=24,
                           help="characters of context around each finding (default: 24)")
    p_inspect.add_argument("--fail-on", type=Severity, choices=list(Severity),
                           default=None,
                           help="exit 1 if findings at this severity or above exist")
    p_inspect.add_argument("-q", "--quiet", action="store_true",
                           help="counts only, omit individual occurrences")
    p_inspect.set_defaults(func=cmd_inspect)

    p_clean = sub.add_parser("clean", parents=[common],
                             help="remove invisible codepoints; fold per profile")
    p_clean.add_argument("--profile", type=Profile, choices=list(Profile), default=None,
                         help="prose|code|data (default: inferred from file extension)")
    p_clean.add_argument("--dry-run", action="store_true",
                         help="report what would change without writing")
    p_clean.add_argument("-i", "--in-place", action="store_true",
                         help="rewrite files instead of writing to stdout")
    p_clean.add_argument("--backup", action="store_true",
                         help="with --in-place, keep a .bak copy")
    p_clean.add_argument("-q", "--quiet", action="store_true",
                         help="counts only, omit individual occurrences")
    p_clean.set_defaults(func=cmd_clean)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.paths:
        args.paths = ["-"]
    try:
        return args.func(args)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"marklens: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
