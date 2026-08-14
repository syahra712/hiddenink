"""Bounded JPEG marker and metadata parser (stdlib only)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from ._safety import MAX_CONTAINER_BYTES, MAX_CONTAINER_ITEMS, MAX_METADATA_BYTES
from .provenance import (
    C2PA_MANIFEST_UUID,
    inspect_jumbf_manifest_store,
    reassemble_jpeg_app11,
)

__all__ = ["JPEG_SIGNATURE", "JpegSegment", "JpegScan", "parse_jpeg", "scan_jpeg"]

JPEG_SIGNATURE = b"\xff\xd8"

_XMP_ID = b"http://ns.adobe.com/xap/1.0/\x00"
_EXIF_ID = b"Exif\x00\x00"
_ICC_ID = b"ICC_PROFILE\x00"
_SOF_MARKERS = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)
_STANDALONE = frozenset({0x01, *range(0xD0, 0xD8), 0xD8, 0xD9})


@dataclass(frozen=True, slots=True)
class JpegSegment:
    """One bounds-checked marker segment."""

    marker: int
    offset: int
    body_start: int
    body_end: int
    end: int

    @property
    def length(self) -> int:
        return self.body_end - self.body_start


@dataclass(frozen=True, slots=True)
class JpegScan:
    segments: tuple[JpegSegment, ...]
    status: str
    reason: str

    @property
    def complete(self) -> bool:
        return self.status == "complete"


def _invalid(
    segments: list[JpegSegment], reason: str, status: str = "malformed"
) -> JpegScan:
    return JpegScan(tuple(segments), status, reason)


def _next_entropy_marker(data: bytes, offset: int) -> int | None:
    """Find the next real marker, skipping stuffed bytes and restart markers."""
    while offset < len(data):
        marker_start = data.find(b"\xff", offset)
        if marker_start < 0:
            return None
        cursor = marker_start + 1
        while cursor < len(data) and data[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(data):
            return None
        marker = data[cursor]
        if marker == 0x00 or 0xD0 <= marker <= 0xD7:
            offset = cursor + 1
            continue
        return marker_start
    return None


def scan_jpeg(data: bytes) -> JpegScan:
    """Validate JPEG marker lengths and require SOF, SOS, and terminal EOI."""
    segments: list[JpegSegment] = []
    if len(data) > MAX_CONTAINER_BYTES:
        return _invalid(segments, "container exceeds the byte limit", "resource_limit")
    if not data.startswith(JPEG_SIGNATURE):
        return _invalid(segments, "JPEG SOI signature is missing")

    offset = 2
    in_scan = False
    seen_sof = False
    seen_sos = False
    while offset < len(data):
        if len(segments) >= MAX_CONTAINER_ITEMS:
            return _invalid(
                segments, "JPEG segment-count limit exceeded", "resource_limit"
            )
        if in_scan:
            marker_offset = _next_entropy_marker(data, offset)
            if marker_offset is None:
                return _invalid(segments, "entropy-coded data has no terminal marker")
            offset = marker_offset
            in_scan = False
        if data[offset] != 0xFF:
            return _invalid(segments, "expected a JPEG marker boundary")
        marker_start = offset
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return _invalid(segments, "truncated JPEG marker")
        marker = data[offset]
        offset += 1
        if marker == 0x00:
            return _invalid(segments, "stuffed zero byte appears outside scan data")
        if marker == 0xD9:
            if not seen_sof or not seen_sos:
                return _invalid(segments, "JPEG ended before a frame and scan")
            if offset != len(data):
                return _invalid(segments, "bytes follow the JPEG EOI marker")
            return JpegScan(tuple(segments), "complete", "complete marker structure")
        if marker == 0xD8:
            return _invalid(segments, "unexpected second JPEG SOI marker")
        if marker in _STANDALONE:
            if 0xD0 <= marker <= 0xD7:
                return _invalid(segments, "restart marker appears outside scan data")
            continue
        if len(data) - offset < 2:
            return _invalid(segments, "truncated JPEG segment length")
        length = struct.unpack_from(">H", data, offset)[0]
        if length < 2:
            return _invalid(segments, "JPEG segment length is smaller than its header")
        body_start = offset + 2
        body_end = body_start + length - 2
        if body_end > len(data):
            return _invalid(segments, "JPEG segment length exceeds available bytes")
        segment = JpegSegment(marker, marker_start, body_start, body_end, body_end)
        segments.append(segment)
        if marker in _SOF_MARKERS:
            if segment.length < 6:
                return _invalid(segments, "JPEG frame header is truncated")
            seen_sof = True
        if marker == 0xDA:
            if not seen_sof:
                return _invalid(segments, "JPEG scan appears before a frame header")
            if segment.length < 6:
                return _invalid(segments, "JPEG scan header is truncated")
            seen_sos = True
            in_scan = True
        offset = body_end
    return _invalid(segments, "JPEG has no EOI marker")


def _c2pa_runs(segments: tuple[JpegSegment, ...]) -> list[list[JpegSegment]]:
    runs: list[list[JpegSegment]] = []
    current: list[JpegSegment] = []
    for segment in segments:
        if segment.marker == 0xEB:
            current.append(segment)
        elif current:
            runs.append(current)
            current = []
    if current:
        runs.append(current)
    return runs


def parse_jpeg(data: bytes) -> dict[str, Any]:
    """Inspect JPEG metadata with explicit structure and coverage status."""
    scan = scan_jpeg(data)
    found: dict[str, Any] = {
        "jpeg.parse_status": scan.status,
        "jpeg.coverage": (
            "complete marker framing; selected APP/COM metadata only; pixels not decoded"
        ),
    }
    if not scan.complete:
        found["jpeg.warning.structure"] = scan.reason

    metadata_bytes = 0
    app11_seen = 0
    for segment in scan.segments:
        marker = segment.marker
        if marker not in {0xE1, 0xE2, 0xEB, 0xED, 0xEE, 0xFE}:
            continue
        metadata_bytes += segment.length
        if metadata_bytes > MAX_METADATA_BYTES:
            found["jpeg.warning.metadata_limit"] = (
                "aggregate metadata byte limit exceeded"
            )
            found["jpeg.parse_status"] = "resource_limit"
            break
        body = data[segment.body_start : segment.body_end]
        if marker == 0xE1:
            if body.startswith(_EXIF_ID):
                found["jpeg.exif"] = f"{len(body) - len(_EXIF_ID)} bytes"
            elif body.startswith(_XMP_ID):
                found["jpeg.xmp"] = f"{len(body) - len(_XMP_ID)} bytes"
        elif marker == 0xE2 and body.startswith(_ICC_ID):
            found["jpeg.icc_profile"] = f"{len(body) - len(_ICC_ID)} bytes"
        elif marker == 0xEB:
            app11_seen += 1
            found[f"jpeg.app11.{app11_seen}"] = f"{len(body)} bytes (not assumed C2PA)"
        elif marker == 0xED:
            found["jpeg.photoshop_irb_iptc"] = f"{len(body)} bytes"
        elif marker == 0xEE and body.startswith(b"Adobe"):
            found["jpeg.adobe_color_transform"] = "present"
        elif marker == 0xFE:
            found["jpeg.comment"] = body.decode("utf-8", "replace")[:200]

    # A resource-limited scan must stop. In particular, do not make a second
    # pass over APP11 after the aggregate metadata ceiling has been crossed.
    if found["jpeg.parse_status"] == "resource_limit":
        return found

    for run_number, run in enumerate(_c2pa_runs(scan.segments), 1):
        run_size = sum(segment.length for segment in run)
        if run_size > MAX_METADATA_BYTES:
            found[f"jpeg.warning.c2pa_structure.{run_number}"] = (
                "APP11 run exceeds metadata limit"
            )
            continue
        bodies = [data[s.body_start : s.body_end] for s in run]
        payload, reason = reassemble_jpeg_app11(bodies)
        if payload is None:
            header_sample = b"".join(body[:256] for body in bodies)
            jpeg_xt = any(body.startswith(b"JP") for body in bodies)
            if jpeg_xt and (
                b"jumb" in header_sample or C2PA_MANIFEST_UUID in header_sample
            ):
                found["jpeg.c2pa_like"] = (
                    "malformed JPEG XT APP11 sequence contains JUMBF/C2PA identifiers"
                )
                found[f"jpeg.warning.c2pa_structure.{run_number}"] = reason
                found["jpeg.c2pa_credential_verified"] = (
                    "unavailable: malformed structure was not cryptographically validated"
                )
            continue
        status = inspect_jumbf_manifest_store(payload)
        plausible = (
            status.looks_like_jumbf
            or payload[4:8] == b"jumb"
            or C2PA_MANIFEST_UUID in payload[:256]
        )
        if not plausible:
            continue
        found["jpeg.c2pa_like"] = (
            f"JPEG XT APP11 JUMBF sequence present ({len(run)} segment(s))"
        )
        if status.manifest_store_parsed:
            found["jpeg.c2pa_manifest_store_structurally_parsed"] = True
        else:
            found[f"jpeg.warning.c2pa_structure.{run_number}"] = status.reason or reason
        found["jpeg.c2pa_credential_verified"] = (
            "unavailable: the dependency-free parser performs no cryptographic validation"
        )
    return found
