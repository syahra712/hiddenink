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

from ..report import STATISTICAL_WATERMARK_NOTICE, Report, Undeterminable
from ._safety import MAX_CONTAINER_BYTES
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
    head = data[:4096]
    stripped = head.lstrip()
    if stripped.startswith((b"<?xml", b"<svg")) and b"<svg" in head:
        return "svg"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            xml_head = head.decode("utf-16")
        except UnicodeError:
            pass
        else:
            if "<svg" in xml_head:
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
    try:
        size = p.stat().st_size
    except OSError:
        raise
    if size > MAX_CONTAINER_BYTES:
        with p.open("rb") as handle:
            head = handle.read(4096)
        fmt = detect_format(head, str(p))
        prefix = fmt or "container"
        return Report(
            source=str(p),
            kind=fmt or "unknown",
            metadata={
                f"{prefix}.parse_status": "resource_limit",
                f"{prefix}.warning.container_limit": (
                    f"{size} bytes exceeds the {MAX_CONTAINER_BYTES}-byte limit"
                ),
            },
            undeterminable=[
                Undeterminable(
                    claim="container parsing completeness",
                    reason=(
                        "Parsing REFUSED because the container exceeds the byte limit."
                    ),
                )
            ],
        )
    data = p.read_bytes()
    fmt, metadata = parse_bytes(data, str(p))

    notices: list[Undeterminable] = []
    if fmt in _TEXTUAL_CONTAINERS:
        notices.append(
            Undeterminable(
                claim="statistical text watermark present / absent / removed",
                reason=STATISTICAL_WATERMARK_NOTICE,
            )
        )
    report = Report(
        source=str(p), kind=fmt or "unknown", metadata=metadata, undeterminable=notices
    )

    if fmt in _TEXTUAL_CONTAINERS:
        from ..inspect_text import iter_findings

        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16", "replace")
        else:
            text = data.decode("utf-8", "replace")
        report.findings = list(iter_findings(text))

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
    elif fmt in _C2PA_CAPABLE:
        structural = (
            metadata.get(f"{fmt}.c2pa_manifest_store_structurally_parsed") is True
        )
        detected = any(key.endswith(".c2pa_like") for key in metadata)
        if structural:
            prefix = "A C2PA manifest-store structure was parsed, but"
        elif detected:
            prefix = "C2PA-like container bytes were detected, but"
        else:
            prefix = "No embedded C2PA manifest store was structurally parsed, and"
        report.undeterminable.append(
            Undeterminable(
                claim="C2PA credential and hard-binding validity",
                reason=(
                    f"{prefix} no hard-bound credential was cryptographically VERIFIED. "
                    "The dependency-free parser does not validate claims, signatures, "
                    "trust, or asset hashes. This also does NOT establish the absence "
                    "of provenance or remote/soft-binding discovery mechanisms."
                ),
            )
        )

    if fmt is not None:
        status = metadata.get(f"{fmt}.parse_status")
        if status not in (None, "complete"):
            coverage = metadata.get(f"{fmt}.coverage", "parser coverage is limited")
            report.undeterminable.append(
                Undeterminable(
                    claim="container parsing completeness",
                    reason=f"Parser status is {status!r}; {coverage}.",
                )
            )

    return report
