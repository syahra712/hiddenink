"""Command-line interface.

Exit codes:
    0  success, nothing exceeded the ``--fail-on`` threshold
    1  findings at or above the ``--fail-on`` severity were present
    2  usage or I/O error
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .core.clean_text import Profile, clean_text
from .core.codepoints import Severity
from .core.formats import detect_format, inspect_file
from .core.formats.clean import CLEANABLE, clean_bytes
from .core.inspect_text import inspect_text
from .core.report import Report

_SEVERITY_ORDER = {
    Severity.TYPOGRAPHIC: 1,
    Severity.WHITESPACE: 2,
    Severity.CONFUSABLE: 3,
    Severity.INVISIBLE: 4,
}

#: Containers that are text underneath, so ``clean`` can run the text pipeline
#: over them directly. Binary containers listed in ``CLEANABLE`` get their
#: metadata rewritten instead; anything in neither set is refused with a
#: pointer to ``inspect``.
_CLEANABLE_CONTAINERS = {"svg"}

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


def _use_colour(stream: Any) -> bool:
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
            (Severity.CONFUSABLE, style.yellow),
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
    # newline="" keeps line endings exactly as they are on disk; without it
    # Python translates them on read and again on write, so a tool that
    # promises byte-level diffs would silently rewrite every line on Windows.
    with p.open("r", encoding="utf-8", errors="surrogatepass", newline="") as handle:
        return handle.read(), str(p)


def _write(path: Path, text: str) -> None:
    """Write text back, preserving what :func:`_read` was able to accept.

    Both the encoding error handler and the newline policy have to match the
    read side. ``surrogatepass`` in particular: without it, any file
    containing a lone surrogate can be read and inspected but explodes on
    write, which turns ``--in-place`` into a crash on exactly the malformed
    input this tool exists to examine.
    """
    with path.open("w", encoding="utf-8", errors="surrogatepass", newline="") as handle:
        handle.write(text)


def _inspect_path(path: str, context: int) -> Report:
    """Dispatch to the container parser or the text inspector.

    Detection is by magic bytes, so a ``.txt`` that is really a PNG is still
    read as a PNG.
    """
    if path != "-":
        data = Path(path).read_bytes()
        if detect_format(data, path) is not None:
            return inspect_file(path)
    text, name = _read(path)
    return inspect_text(text, source=name, context_width=context)


def _exceeds(report: Report, threshold: Severity | None) -> bool:
    if threshold is None:
        return False
    want = _SEVERITY_ORDER[threshold]
    return any(_SEVERITY_ORDER[f.severity] >= want for f in report.findings)


def _emit(
    reports: list[Report],
    args: argparse.Namespace,
    style: _Style,
    stream: Any = None,
) -> None:
    stream = stream or sys.stdout
    if args.json:
        payload = [r.to_dict() for r in reports]
        print(json.dumps(payload if len(payload) != 1 else payload[0], indent=2,
                         ensure_ascii=False), file=stream)
    else:
        print("\n\n".join(_render(r, style, show_findings=not args.quiet)
                          for r in reports), file=stream)


def cmd_inspect(args: argparse.Namespace) -> int:
    style = _Style(_use_colour(sys.stdout) and not args.json)
    reports = [_inspect_path(path, args.context) for path in args.paths]
    _emit(reports, args, style)
    return 1 if any(_exceeds(r, args.fail_on) for r in reports) else 0


def cmd_clean(args: argparse.Namespace) -> int:
    # When cleaned text goes to stdout the report must not, or the two get
    # interleaved into a file the user then saves.
    to_stdout = not (args.in_place or args.dry_run or args.check)
    style = _Style(_use_colour(sys.stderr if to_stdout else sys.stdout)
                   and not args.json)

    if to_stdout and len(args.paths) > 1:
        print(
            f"hiddenink: refusing to concatenate {len(args.paths)} files to stdout "
            "(the result could not be split back apart). Use --in-place, or pass "
            "one file at a time.",
            file=sys.stderr,
        )
        return 2

    reports: list[Report] = []
    for path in args.paths:
        if path != "-":
            container = detect_format(Path(path).read_bytes(), path)

            if container in CLEANABLE:
                # Binary container: rewrite bytes, never route through the text
                # pipeline. Writing image bytes to stdout is a footgun (and the
                # stream is a UTF-8 text stream), so this needs an explicit
                # destination.
                if to_stdout:
                    print(
                        f"hiddenink: {path} is a {container}; cleaning it rewrites "
                        "binary data. Use --in-place, or --dry-run to see what "
                        "would be removed.",
                        file=sys.stderr,
                    )
                    return 2
                data = Path(path).read_bytes()
                cleaned_bytes, report = clean_bytes(data, container)
                report.source = path
                reports.append(report)
                if args.in_place and not (args.dry_run or args.check):
                    if args.backup:
                        Path(f"{path}.bak").write_bytes(data)
                    Path(path).write_bytes(cleaned_bytes)
                continue

            if container is not None and container not in _CLEANABLE_CONTAINERS:
                print(
                    f"hiddenink: {path} is a {container} container; clean operates on "
                    f"text. Use 'hiddenink inspect {path}' to read its metadata.",
                    file=sys.stderr,
                )
                return 2

        text, name = _read(path)

        profile = args.profile
        if profile is None:
            suffix = Path(name).suffix.lower()
            profile = _PROFILE_BY_SUFFIX.get(suffix, Profile.CODE)

        cleaned, report = clean_text(text, profile=profile, source=name)
        reports.append(report)

        if args.in_place and path != "-":
            if args.dry_run or args.check or not report.changed:
                continue
            p = Path(path)
            if args.backup:
                _write(p.with_suffix(p.suffix + ".bak"), text)
            _write(p, cleaned)
        elif to_stdout:
            sys.stdout.write(cleaned)

    _emit(reports, args, style, stream=sys.stderr if to_stdout else sys.stdout)

    if args.check and any(r.changed for r in reports):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hiddenink",
        description=(
            "Inspect and clean AI provenance marks. Removes what is provably "
            "removable; never claims to remove what cannot be verified."
        ),
        epilog=(
            "hiddenink does not remove, defeat, or detect model-level statistical "
            "watermarking. No public tool can: no detector has been published."
        ),
    )
    parser.add_argument("--version", action="version", version=f"hiddenink {__version__}")
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
    p_clean.add_argument("--check", action="store_true",
                         help="exit 1 if any file would change; writes nothing")
    p_clean.add_argument("-i", "--in-place", action="store_true",
                         help="rewrite files instead of writing to stdout")
    p_clean.add_argument("--backup", action="store_true",
                         help="with --in-place, keep a .bak copy")
    p_clean.add_argument("-q", "--quiet", action="store_true",
                         help="counts only, omit individual occurrences")
    p_clean.set_defaults(func=cmd_clean)

    return parser


def _configure_streams() -> None:
    """Make stdout safe for both file content and report glyphs.

    Two Windows-specific hazards, and they pull in opposite directions:

    *Newline translation.* A text stream opened with ``newline=None``
    translates every ``\\n`` on the way out, so ``clean f.md > out.md`` would
    rewrite the line endings of the file it was asked to preserve -- and on a
    CRLF input the surviving ``\\r`` would make it ``\\r\\r\\n``.

    *Encoding.* The default console encoding is a legacy codepage such as
    cp1252, which cannot represent the report's box-drawing characters. It
    also cannot represent whatever happens to be inside the files being
    inspected: a PNG text chunk holding CJK would crash the process just as
    readily. UTF-8 covers both.

    stdout gets real UTF-8 rather than a replacing error handler, because it
    carries cleaned file content and a lossy substitution there would be
    silent data corruption. stderr carries only human-readable text, so it can
    afford ``backslashreplace`` as a last resort.
    """
    stdout_reconfigure = getattr(sys.stdout, "reconfigure", None)
    if stdout_reconfigure is not None:
        # Detached, non-seekable, or already-wrapped streams refuse. The write
        # still succeeds afterwards; it just keeps the platform default.
        with contextlib.suppress(ValueError, OSError, LookupError):
            stdout_reconfigure(encoding="utf-8", newline="")

    stderr_reconfigure = getattr(sys.stderr, "reconfigure", None)
    if stderr_reconfigure is not None:
        with contextlib.suppress(ValueError, OSError, LookupError):
            stderr_reconfigure(encoding="utf-8", errors="backslashreplace")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_streams()
    if not args.paths:
        args.paths = ["-"]
    try:
        return int(args.func(args))
    except (OSError, UnicodeDecodeError) as exc:
        print(f"hiddenink: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
