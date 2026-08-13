"""Container-metadata readers, dispatched on magic bytes.

Every parser here is stdlib-only and read-only. Nothing shells out to
``exiftool``: a tool that silently reports "no metadata" because an optional
binary is missing is worse than one that cannot read the format at all, and
the whole point of this project is that reports mean what they say.

Detection is by magic bytes rather than file extension, so a mislabelled file
is still read correctly.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..report import Report, Undeterminable
from .documents import parse_office, parse_pdf, parse_svg
from .jpeg import JPEG_SIGNATURE, parse_jpeg
from .png import PNG_SIGNATURE, parse_png

__all__ = ["inspect_file", "detect_format", "parse_bytes", "SUPPORTED"]

SUPPORTED = ("png", "jpeg", "svg", "office", "pdf")

_PARSERS: dict[str, Callable[[bytes], dict[str, Any]]] = {
    "png": parse_png,
    "jpeg": parse_jpeg,
    "svg": parse_svg,
    "office": parse_office,
    "pdf": parse_pdf,
}

#: Formats that can carry a C2PA manifest, so their absence of one is
#: meaningful rather than merely unexamined.
_C2PA_CAPABLE = {"png", "jpeg", "svg", "pdf"}


def detect_format(data: bytes, path: str | None = None) -> str | None:
    """Identify a container from its magic bytes."""
    if data.startswith(PNG_SIGNATURE):
        return "png"
    if data.startswith(JPEG_SIGNATURE):
        return "jpeg"
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "office"
    head = data[:512].lstrip()
    if head.startswith((b"<?xml", b"<svg")) and b"<svg" in data[:4096]:
        return "svg"
    if path and Path(path).suffix.lower() == ".svg":
        return "svg"
    return None


def parse_bytes(
    data: bytes, path: str | None = None
) -> tuple[str | None, dict[str, Any]]:
    """Return ``(format_name, metadata)`` for a byte string."""
    fmt = detect_format(data, path)
    if fmt is None:
        return None, {}
    return fmt, _PARSERS[fmt](data)


#: Containers that are themselves text, and so can carry invisible codepoints
#: in their markup as well as metadata in their structure. Reporting only the
#: metadata for these would miss half of what the user asked about.
_TEXTUAL_CONTAINERS = {"svg"}


def inspect_file(path: str | Path) -> Report:
    """Inspect a container and report its embedded metadata.

    For text-based containers the codepoint scan runs too, so a single call
    covers both layers.
    """
    p = Path(path)
    data = p.read_bytes()
    fmt, metadata = parse_bytes(data, str(p))

    report = Report(source=str(p), kind=fmt or "unknown", metadata=metadata)

    if fmt in _TEXTUAL_CONTAINERS:
        from ..inspect_text import iter_findings

        report.findings = list(iter_findings(data.decode("utf-8", "replace")))

    if fmt is None:
        report.undeterminable.append(
            Undeterminable(
                claim="embedded container metadata",
                reason=(
                    "Unrecognised container format; no metadata parser applied. "
                    f"Supported: {', '.join(SUPPORTED)}."
                ),
            )
        )
    elif fmt in _C2PA_CAPABLE and not any("c2pa" in k for k in metadata):
        report.undeterminable.append(
            Undeterminable(
                claim="C2PA soft binding (durable content credentials)",
                reason=(
                    "No hard-bound C2PA manifest found in the container. This does "
                    "NOT establish the absence of provenance: C2PA soft bindings "
                    "are carried in the pixels themselves and can re-link a remote "
                    "manifest after all metadata is stripped. Reading them requires "
                    "the C2PA soft-binding algorithms, which marklens does not "
                    "implement."
                ),
            )
        )

    return report
