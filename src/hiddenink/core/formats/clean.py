"""Rendering- and provenance-safe container cleaning.

PNG and JPEG metadata classes mix privacy fields with orientation, colour,
accessibility, copyright, licensing, and provenance.  The dependency-free core
does not have a trustworthy semantic rewriter for EXIF, XMP, ICC, IPTC, or C2PA.
Accordingly the default path validates the container and then refuses ambiguous
mutations instead of deleting whole marker/chunk classes.
"""

from __future__ import annotations

import zipfile
import zlib
from collections.abc import Callable
from io import BytesIO
from typing import Any

from ..report import Report, Undeterminable
from .jpeg import parse_jpeg
from .png import parse_png

__all__ = ["CLEANABLE", "clean_png", "clean_jpeg", "clean_bytes", "is_valid_zip"]

CLEANABLE = ("png", "jpeg")

_C2PA_VALIDATION_BOUNDARY = (
    "C2PA credential validity was NOT VERIFIED. The dependency-free parser can "
    "recognise an embedded manifest-store structure, but it does not parse claims, "
    "verify signatures or trust, or validate the asset hard binding."
)


def clean_png(data: bytes) -> tuple[bytes, list[str], bool]:
    """Validate and conservatively retain all PNG bytes.

    The boolean means only that a structurally recognised C2PA manifest-store
    chunk remains byte-identical.  It says nothing about credential validity.
    """
    parsed = parse_png(data)
    retained = parsed.get("png.c2pa_manifest_store_structurally_parsed") is True
    return data, [], retained


def clean_jpeg(data: bytes) -> tuple[bytes, list[str], bool]:
    """Validate and conservatively retain all JPEG bytes; see :func:`clean_png`."""
    parsed = parse_jpeg(data)
    retained = parsed.get("jpeg.c2pa_manifest_store_structurally_parsed") is True
    return data, [], retained


_PARSERS: dict[str, Callable[[bytes], dict[str, Any]]] = {
    "png": parse_png,
    "jpeg": parse_jpeg,
}


def _has_user_metadata(fmt: str, metadata: dict[str, object]) -> bool:
    administrative = (
        f"{fmt}.parse_status",
        f"{fmt}.coverage",
        f"{fmt}.warning.",
        f"{fmt}.refusal.",
    )
    return any(not key.startswith(administrative) for key in metadata)


def clean_bytes(data: bytes, fmt: str) -> tuple[bytes, Report]:
    """Safely assess a requested container cleanup.

    Malformed inputs and semantically ambiguous metadata are returned
    byte-identical with a namespaced refusal reason.  No report says provenance
    is preserved merely because the manifest bytes were retained.
    """
    parser = _PARSERS.get(fmt)
    if parser is None:
        report = Report(
            source=f"<{fmt}>",
            kind=fmt,
            metadata={f"{fmt}.refusal.unsupported": "no container cleaner available"},
            undeterminable=[
                Undeterminable(
                    claim="container metadata removal",
                    reason=(
                        f"No metadata cleaner for {fmt!r}. Supported: "
                        f"{', '.join(CLEANABLE)}."
                    ),
                )
            ],
            parse_status="unsupported",
            coverage="no container cleaning implementation",
        )
        return data, report

    metadata = parser(data)
    parser_status = str(metadata.get(f"{fmt}.parse_status", "partial"))
    parser_reason = str(
        metadata.get(f"{fmt}.warning.structure", "container parsing was incomplete")
    )
    undeterminable = [
        Undeterminable(
            claim="C2PA credential cryptographic validity",
            reason=_C2PA_VALIDATION_BOUNDARY,
        )
    ]
    refused = False
    if parser_status != "complete":
        refused = True
        metadata[f"{fmt}.refusal.structure"] = (
            f"container mutation refused: {parser_reason}"
        )
        undeterminable.append(
            Undeterminable(
                claim="container metadata removal",
                reason=(
                    f"Mutation REFUSED because parsing was {parser_status}: "
                    f"{parser_reason}"
                ),
            )
        )
    elif any("c2pa_like" in key for key in metadata):
        refused = True
        metadata[f"{fmt}.c2pa_manifest_bytes_retained"] = True
        metadata[f"{fmt}.refusal.provenance"] = (
            "mutation refused: an embedded C2PA/JUMBF structure may bind to "
            "other asset bytes"
        )
        undeterminable.append(
            Undeterminable(
                claim="valid provenance after cleaning",
                reason=(
                    "Mutation REFUSED. Retaining manifest bytes while changing "
                    "other asset bytes could invalidate a hard binding, and this "
                    "core cannot re-sign or re-validate the credential."
                ),
            )
        )
    elif _has_user_metadata(fmt, metadata):
        refused = True
        metadata[f"{fmt}.refusal.selective_cleaning"] = (
            "mutation refused: metadata classes mix privacy with rendering, "
            "rights, and accessibility semantics"
        )
        undeterminable.append(
            Undeterminable(
                claim="safe selective metadata removal",
                reason=(
                    "Mutation REFUSED. The default cleaner will not delete whole "
                    "PNG chunks or JPEG marker classes that can carry colour, "
                    "orientation, rights, accessibility, or provenance information."
                ),
            )
        )

    report = Report(
        source=f"<{fmt}>",
        kind=fmt,
        metadata=metadata,
        undeterminable=undeterminable,
        changed=False,
        removed=0,
        parse_status="refused" if refused else parser_status,
        coverage=str(metadata.get(f"{fmt}.coverage", "validated container structure")),
    )
    return data, report


def is_valid_zip(data: bytes) -> bool:
    """Whether a zip container is readable without unsupported member features."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            return archive.testzip() is None
    except (
        EOFError,
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ):
        return False
