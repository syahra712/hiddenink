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
import os
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .core.clean_text import Profile, clean_text
from .core.codepoints import MAX_TEXT_CODEPOINTS, Severity
from .core.formats import detect_format, inspect_file
from .core.formats._safety import MAX_CONTAINER_BYTES, MAX_CONTAINER_ITEMS
from .core.formats.clean import CLEANABLE, clean_bytes
from .core.inspect_text import inspect_text
from .core.report import Report

_SEVERITY_ORDER = {
    Severity.TYPOGRAPHIC: 1,
    Severity.CONTEXTUAL: 2,
    Severity.WHITESPACE: 3,
    Severity.CONFUSABLE: 4,
    Severity.INVISIBLE: 5,
}

#: Text containers that may safely use the generic text cleaner. SVG is
#: intentionally absent: its visible text, URLs, attributes, and Unicode
#: sequences affect rendering, and the generic CODE profile is not SVG-aware.
_CLEANABLE_CONTAINERS: frozenset[str] = frozenset()

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

_IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
)
_MAX_TEXT_BYTES = MAX_TEXT_CODEPOINTS * 4


class CliError(Exception):
    """An expected command-line refusal, rendered without a traceback."""


@dataclass(frozen=True, slots=True)
class _PreparedClean:
    argument: str
    path: Path | None
    data: bytes
    text: str | None
    container: str | None
    profile: Profile | None
    original_stat: os.stat_result | None


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
    lines.append(style.bold(f"── {_terminal_safe(report.source)}"))

    total = len(report.findings)
    lines.append(style.bold("VERIFIABLE") + style.dim("  (decidable from the bytes)"))

    lines.append(
        f"  {style.dim('status')} {_terminal_safe(report.parse_status)}; "
        f"{_terminal_safe(report.coverage)}"
    )
    for warning in report.warnings:
        lines.append(f"  {style.yellow('warning')} {_terminal_safe(warning)}")
    for reason in report.refusal_reasons:
        lines.append(f"  {style.red('refused')} {_terminal_safe(reason)}")

    if total == 0 and not report.substantive_metadata:
        if report.parse_status == "complete":
            lines.append("  " + style.green("no findings in the stated coverage"))
        else:
            lines.append("  no findings in the portion that was examined")
    else:
        by_sev = report.counts_by_severity()
        parts = []
        for sev, colour in (
            (Severity.INVISIBLE, style.red),
            (Severity.CONTEXTUAL, style.yellow),
            (Severity.WHITESPACE, style.yellow),
            (Severity.CONFUSABLE, style.yellow),
            (Severity.TYPOGRAPHIC, style.cyan),
        ):
            n = by_sev.get(sev.value, 0)
            if n:
                parts.append(colour(f"{n} {sev.value}"))
        if parts:
            lines.append(f"  {total} findings: " + ", ".join(parts))
        for cat, n in report.counts_by_category().items():
            lines.append(f"    {style.dim('·')} {cat:<20} {n}")
        for key, value in report.substantive_metadata.items():
            lines.append(
                f"  {style.dim('metadata')} {_terminal_safe(str(key))}: "
                f"{_terminal_safe(str(value))}"
            )

        if show_findings and report.findings:
            lines.append(style.dim("  ── occurrences"))
            for f in report.findings[:40]:
                loc = f"{f.line}:{f.column}"
                lines.append(
                    f"    {style.dim(loc.ljust(9))}{f.escape:<9} "
                    f"{_terminal_safe(f.name[:38]):<38} "
                    f"{style.dim(_terminal_safe(f.context))}"
                )
            if len(report.findings) > 40:
                lines.append(
                    style.dim(f"    … {len(report.findings) - 40} more (use --json)")
                )

    if report.changed:
        lines.append(
            "  transformations: "
            f"{style.green(str(report.removed))} removed, "
            f"{style.green(str(report.folded))} folded, "
            f"{style.green(str(report.normalized))} normalized"
        )

    if report.undeterminable:
        lines.append(
            style.bold("NOT DETERMINABLE")
            + style.dim("  (outside this inspection's capabilities)")
        )
        for u in report.undeterminable:
            lines.append(f"  {style.dim('·')} {_terminal_safe(u.reason)}")

    return "\n".join(lines)


def _terminal_safe(value: str) -> str:
    """Escape terminal controls while leaving ordinary Unicode readable.

    JSON output intentionally bypasses this function: JSON escaping already
    protects its syntax and machine consumers should receive the original
    values. Human output must also neutralise ANSI/OSC and bidi controls.
    """
    out: list[str] = []
    bidi = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
    for char in value:
        codepoint = ord(char)
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            out.append(f"\\x{codepoint:02x}")
        elif codepoint in bidi:
            out.append(f"\\u{codepoint:04x}")
        else:
            out.append(char)
    return "".join(out)


def _read(path: str) -> tuple[str, str]:
    if path == "-":
        binary = getattr(sys.stdin, "buffer", None)
        if binary is not None:
            data = binary.read(_MAX_TEXT_BYTES + 1)
            if len(data) > _MAX_TEXT_BYTES:
                raise CliError(f"stdin exceeds the {_MAX_TEXT_BYTES}-byte text limit")
            text = data.decode("utf-8", "surrogatepass")
            if len(text) > MAX_TEXT_CODEPOINTS:
                raise CliError(
                    "stdin exceeds the "
                    f"{MAX_TEXT_CODEPOINTS}-codepoint text limit"
                )
            return text, "<stdin>"
        # StringIO and other test/application-provided streams may have no
        # binary buffer. Their read is still bounded; the encoded-size check
        # enforces the same byte contract.
        text = sys.stdin.read(MAX_TEXT_CODEPOINTS + 1)
        if len(text) > MAX_TEXT_CODEPOINTS:
            raise CliError(
                f"stdin exceeds the {MAX_TEXT_CODEPOINTS}-codepoint text limit"
            )
        return text, "<stdin>"
    p = Path(path)
    # newline="" keeps line endings exactly as they are on disk; without it
    # Python translates them on read and again on write, so a tool that
    # promises byte-level diffs would silently rewrite every line on Windows.
    with p.open("r", encoding="utf-8", errors="surrogatepass", newline="") as handle:
        return handle.read(), str(p)


def _encoded(text: str) -> bytes:
    return text.encode("utf-8", "surrogatepass")


def _write_temp(path: Path, data: bytes, source: Path) -> Path:
    """Write and sync a same-directory temporary copy with source metadata."""
    descriptor, raw_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        shutil.copystat(source, temporary, follow_symlinks=False)
        return temporary
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def _same_file(path: Path, expected: os.stat_result) -> bool:
    current = path.lstat()
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_dev == expected.st_dev
        and current.st_ino == expected.st_ino
        and current.st_size == expected.st_size
        and current.st_mtime_ns == expected.st_mtime_ns
    )


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_replace(
    path: Path, data: bytes, source: Path, expected: os.stat_result
) -> None:
    """Atomically replace ``path`` after detecting symlink/TOCTOU changes."""
    if path.is_symlink() or not _same_file(path, expected):
        raise CliError(f"refusing changed or non-regular target: {path}")
    temporary = _write_temp(path, data, source)
    try:
        # Re-check after preparing the temporary file, immediately before the
        # destructive operation.
        if path.is_symlink() or not _same_file(path, expected):
            raise CliError(f"refusing target changed during cleaning: {path}")
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _atomic_backup(path: Path, data: bytes, overwrite: bool) -> None:
    """Create a complete backup without ever silently replacing one."""
    source = path
    backup = path.with_name(path.name + ".bak")
    temporary = _write_temp(backup, data, source)
    try:
        if overwrite:
            if backup.is_symlink():
                raise CliError(f"refusing symlink backup target: {backup}")
            if backup.exists():
                expected = backup.lstat()
                if not stat.S_ISREG(expected.st_mode):
                    raise CliError(f"refusing non-regular backup target: {backup}")
                if not _same_file(backup, expected):
                    raise CliError(f"backup changed during cleaning: {backup}")
                os.replace(temporary, backup)
            else:
                os.link(temporary, backup)
        else:
            try:
                os.link(temporary, backup)
            except FileExistsError as exc:
                raise CliError(
                    f"backup already exists: {backup}; pass --overwrite-backup "
                    "to replace it explicitly"
                ) from exc
        _sync_directory(path.parent)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _inspect_path(path: str, context: int) -> Report:
    """Dispatch to the container parser or the text inspector.

    Detection is by magic bytes, so a ``.txt`` that is really a PNG is still
    read as a PNG.
    """
    if path != "-":
        file_path = Path(path)
        size = file_path.stat().st_size
        with file_path.open("rb") as handle:
            head = handle.read(4096)
        if detect_format(head, path) is not None:
            return inspect_file(path)
        if size > _MAX_TEXT_BYTES:
            return Report(
                source=str(file_path),
                kind="text",
                parse_status="resource_limit",
                warnings=[
                    f"text input exceeds the {_MAX_TEXT_BYTES}-byte preflight limit"
                ],
            )
    text, name = _read(path)
    return inspect_text(text, source=name, context_width=context)


def _walk_directory(root: Path) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    errors: list[str] = []
    limit_reached = False

    def visit(directory: Path) -> None:
        nonlocal limit_reached
        if limit_reached:
            return
        try:
            entries = sorted(directory.iterdir(), key=lambda item: str(item))
        except OSError as exc:
            errors.append(f"{directory}: {exc}")
            return
        for entry in entries:
            if entry.is_symlink():
                errors.append(f"refusing symlink encountered recursively: {entry}")
            elif entry.name in _IGNORED_DIRECTORY_NAMES and entry.is_dir():
                continue
            elif entry.is_dir():
                visit(entry)
            elif entry.is_file():
                if len(files) >= MAX_CONTAINER_ITEMS:
                    errors.append(
                        f"{root}: recursive file-count limit of "
                        f"{MAX_CONTAINER_ITEMS} exceeded"
                    )
                    limit_reached = True
                    return
                files.append(entry)
            else:
                errors.append(f"refusing non-regular target: {entry}")

    visit(root)
    return files, errors


def _expand_paths(arguments: list[str], recursive: bool) -> list[str]:
    """Expand directory arguments deterministically, refusing symlinks."""
    expanded: list[str] = []
    errors: list[str] = []
    for argument in arguments:
        if argument == "-":
            expanded.append(argument)
            continue
        path = Path(argument)
        if path.is_symlink():
            errors.append(f"refusing symlink target: {path}")
        elif not path.exists():
            errors.append(f"path does not exist: {path}")
        elif path.is_dir():
            if not recursive:
                errors.append(f"{path} is a directory; pass --recursive to traverse it")
            else:
                files, walk_errors = _walk_directory(path)
                expanded.extend(str(item) for item in files)
                errors.extend(walk_errors)
        elif path.is_file():
            expanded.append(str(path))
        else:
            errors.append(f"refusing non-regular target: {path}")

    # A path named twice (or reached through overlapping directories) is
    # processed once. Resolve only after symlinks have been rejected.
    unique: dict[tuple[int, int] | str, str] = {}
    for argument in expanded:
        if argument == "-":
            key: tuple[int, int] | str = "<stdin>"
        else:
            info = Path(argument).stat()
            key = (info.st_dev, info.st_ino)
        unique.setdefault(key, argument)
    result = sorted(unique.values(), key=lambda item: (item == "-", item))
    if len(result) > MAX_CONTAINER_ITEMS:
        errors.append(
            f"operation has {len(result)} files; limit is {MAX_CONTAINER_ITEMS}"
        )
    aggregate_bytes = 0
    for argument in result:
        if argument == "-":
            continue
        try:
            aggregate_bytes += Path(argument).stat().st_size
        except OSError as exc:
            errors.append(f"{argument}: {exc}")
            continue
        if aggregate_bytes > MAX_CONTAINER_BYTES and len(result) > 1:
            errors.append(
                "operation input exceeds the aggregate "
                f"{MAX_CONTAINER_BYTES}-byte limit"
            )
            break
    if errors:
        raise CliError("\n".join(errors))
    if not result:
        raise CliError("no regular files to process")
    return result


def _prepare_clean(paths: list[str], args: argparse.Namespace) -> list[_PreparedClean]:
    """Read and classify every clean target before any mutation occurs."""
    prepared: list[_PreparedClean] = []
    errors: list[str] = []
    for argument in paths:
        if argument == "-":
            if args.in_place:
                errors.append("cannot use --in-place with stdin")
                continue
            try:
                stdin_text, _name = _read("-")
            except (UnicodeDecodeError, CliError) as exc:
                errors.append(str(exc))
                continue
            prepared.append(
                _PreparedClean(
                    "-",
                    None,
                    _encoded(stdin_text),
                    stdin_text,
                    None,
                    args.profile,
                    None,
                )
            )
            continue

        path = Path(argument)
        try:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise CliError(f"refusing changed or non-regular target: {path}")
            with path.open("rb") as handle:
                head = handle.read(4096)
            container_hint = detect_format(head, str(path))
            input_limit = (
                MAX_CONTAINER_BYTES if container_hint is not None else _MAX_TEXT_BYTES
            )
            if info.st_size > input_limit:
                raise CliError(
                    f"exceeds the {input_limit}-byte input limit"
                )
            data = path.read_bytes()
            container = detect_format(data, str(path))
            if container in CLEANABLE:
                text = None
                profile = None
            elif container is not None and container not in _CLEANABLE_CONTAINERS:
                errors.append(
                    f"{path} is a {container} container; clean operates on text "
                    "files or an explicitly supported safe binary path, and no safe "
                    f"{container} cleaner is available. Use 'hiddenink inspect "
                    f"{path}' to inspect its supported coverage."
                )
                continue
            else:
                text = data.decode("utf-8", "surrogatepass")
                profile = args.profile
                if profile is None:
                    profile = _PROFILE_BY_SUFFIX.get(path.suffix.lower(), Profile.CODE)
            prepared.append(
                _PreparedClean(argument, path, data, text, container, profile, info)
            )
        except (OSError, UnicodeDecodeError, CliError) as exc:
            errors.append(f"{path}: {exc}")

    if args.backup and not args.in_place:
        errors.append("--backup requires --in-place")
    if args.overwrite_backup and not args.backup:
        errors.append("--overwrite-backup requires --backup")
    if errors:
        raise CliError("\n".join(errors))
    return prepared


def _preflight_backups(
    changed: list[tuple[_PreparedClean, bytes, Report]],
    overwrite: bool,
    targets: list[tuple[_PreparedClean, bytes, Report]],
) -> None:
    errors: list[str] = []
    selected_paths = {
        os.path.abspath(item.path)
        for item, _output, _report in targets
        if item.path is not None
    }
    selected_files = {
        (item.original_stat.st_dev, item.original_stat.st_ino)
        for item, _output, _report in targets
        if item.original_stat is not None
    }
    for item, _output, _report in changed:
        assert item.path is not None
        backup = item.path.with_name(item.path.name + ".bak")
        backup_path = os.path.abspath(backup)
        if backup_path in selected_paths:
            errors.append(f"backup path is also a selected target: {backup}")
        elif backup.is_symlink():
            errors.append(f"refusing symlink backup target: {backup}")
        elif backup.exists() and not backup.is_file():
            errors.append(f"refusing non-regular backup target: {backup}")
        elif backup.exists() and (
            (backup.lstat().st_dev, backup.lstat().st_ino) in selected_files
        ):
            errors.append(f"backup aliases a selected target: {backup}")
        elif backup.exists() and not overwrite:
            errors.append(
                f"backup already exists: {backup}; pass --overwrite-backup "
                "to replace it explicitly"
            )
    if errors:
        raise CliError("\n".join(errors))


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
        print(
            json.dumps(
                payload if len(payload) != 1 else payload[0],
                indent=2,
                ensure_ascii=True,
            ),
            file=stream,
        )
    else:
        print("\n\n".join(_render(r, style, show_findings=not args.quiet)
                          for r in reports), file=stream)


def cmd_inspect(args: argparse.Namespace) -> int:
    style = _Style(_use_colour(sys.stdout) and not args.json)
    paths = _expand_paths(args.paths, args.recursive)
    reports: list[Report] = []
    errors: list[str] = []
    for path in paths:
        try:
            reports.append(_inspect_path(path, args.context))
        except (OSError, UnicodeDecodeError, CliError) as exc:
            errors.append(f"{path}: {exc}")
    _emit(reports, args, style)
    if errors:
        for error in errors:
            print(f"hiddenink: {error}", file=sys.stderr)
        return 2
    if any(
        r.parse_status
        in {"unsupported", "malformed", "unsafe", "refused", "resource_limit"}
        for r in reports
    ):
        return 2
    return 1 if any(_exceeds(r, args.fail_on) for r in reports) else 0


def cmd_clean(args: argparse.Namespace) -> int:
    # When cleaned text goes to stdout the report must not, or the two get
    # interleaved into a file the user then saves.
    to_stdout = not (args.in_place or args.dry_run or args.check)
    style = _Style(_use_colour(sys.stderr if to_stdout else sys.stdout)
                   and not args.json)

    paths = _expand_paths(args.paths, args.recursive)
    if to_stdout and len(paths) > 1:
        print(
            f"hiddenink: refusing to concatenate {len(paths)} files to stdout "
            "(the result could not be split back apart). Use --in-place, or pass "
            "one file at a time.",
            file=sys.stderr,
        )
        return 2

    prepared = _prepare_clean(paths, args)
    reports: list[Report] = []
    outputs: list[tuple[_PreparedClean, bytes, Report]] = []
    for item in prepared:
        if item.container in CLEANABLE:
            if to_stdout:
                raise CliError(
                    f"{item.argument} is a {item.container}; cleaning it rewrites "
                    "binary data. Use --in-place, or --dry-run to see what would "
                    "change."
                )
            cleaned_bytes, report = clean_bytes(item.data, item.container)
            report.source = item.argument
        else:
            assert item.text is not None and item.profile is not None
            cleaned, report = clean_text(
                item.text,
                profile=item.profile,
                source=item.argument if item.path else "<stdin>",
            )
            cleaned_bytes = _encoded(cleaned)
        reports.append(report)
        outputs.append((item, cleaned_bytes, report))
        if to_stdout:
            sys.stdout.write(cleaned_bytes.decode("utf-8", "surrogatepass"))

    if any(
        r.parse_status
        in {"unsupported", "malformed", "unsafe", "refused", "resource_limit"}
        for r in reports
    ):
        _emit(reports, args, style, stream=sys.stderr if to_stdout else sys.stdout)
        return 2

    if args.in_place and not (args.dry_run or args.check):
        changed = [entry for entry in outputs if entry[2].changed]
        if args.backup:
            _preflight_backups(changed, args.overwrite_backup, outputs)
        # Revalidate the complete target set before the first mutation.
        for item, _output, _report in changed:
            assert item.path is not None and item.original_stat is not None
            if item.path.is_symlink() or not _same_file(item.path, item.original_stat):
                raise CliError(f"target changed during preflight: {item.path}")
        if args.backup:
            for item, _output, _report in changed:
                assert item.path is not None
                _atomic_backup(item.path, item.data, args.overwrite_backup)
        for item, output, _report in changed:
            assert item.path is not None and item.original_stat is not None
            _atomic_replace(item.path, output, item.path, item.original_stat)

    _emit(reports, args, style, stream=sys.stderr if to_stdout else sys.stdout)

    if args.check and any(r.changed for r in reports):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hiddenink",
        description=(
            "Inspect hidden Unicode and supported file metadata; clean only "
            "where the selected policy has a defined, reportable result."
        ),
        epilog=(
            "hiddenink does not evaluate or claim to remove model-level statistical "
            "watermarks. Container reports state parser coverage explicitly."
        ),
    )
    parser.add_argument("--version", action="version", version=f"hiddenink {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("paths", nargs="*", default=["-"],
                        help="files to process, or - for stdin (default: -)")
    common.add_argument("--json", action="store_true", help="machine-readable output")
    common.add_argument(
        "-r", "--recursive", action="store_true",
        help="traverse directory arguments in deterministic path order",
    )

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
    p_clean.add_argument(
        "--overwrite-backup", action="store_true",
        help="with --backup, explicitly replace an existing regular .bak file",
    )
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
    except (OSError, UnicodeDecodeError, CliError) as exc:
        print(f"hiddenink: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
