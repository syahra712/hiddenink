"""Bounded PNG structure and metadata parser (stdlib only)."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Any

from ._safety import (
    MAX_CONTAINER_BYTES,
    MAX_CONTAINER_ITEMS,
    MAX_DECOMPRESSED_BYTES,
    MAX_METADATA_BYTES,
    MAX_TOTAL_DECOMPRESSED_BYTES,
    bounded_decompress,
)
from .provenance import inspect_jumbf_manifest_store

__all__ = ["PNG_SIGNATURE", "PngChunk", "PngScan", "parse_png", "scan_png"]

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

_TEXT_CHUNKS = frozenset({b"tEXt", b"zTXt", b"iTXt"})
_BINARY_METADATA = {
    b"eXIf": "exif",
    b"iCCP": "icc_profile",
    b"tIME": "modification_time",
}
_KNOWN_CRITICAL = frozenset({b"IHDR", b"PLTE", b"IDAT", b"IEND"})
_VALID_DEPTHS = {
    0: frozenset({1, 2, 4, 8, 16}),
    2: frozenset({8, 16}),
    3: frozenset({1, 2, 4, 8}),
    4: frozenset({8, 16}),
    6: frozenset({8, 16}),
}


@dataclass(frozen=True, slots=True)
class PngChunk:
    """One bounds- and CRC-checked PNG chunk without copying its payload."""

    kind: bytes
    offset: int
    body_start: int
    body_end: int
    end: int

    @property
    def length(self) -> int:
        return self.body_end - self.body_start


@dataclass(frozen=True, slots=True)
class PngScan:
    """Structural coverage result used by both inspection and cleaning."""

    chunks: tuple[PngChunk, ...]
    status: str
    reason: str

    @property
    def complete(self) -> bool:
        return self.status == "complete"


def _invalid(chunks: list[PngChunk], reason: str, status: str = "malformed") -> PngScan:
    return PngScan(tuple(chunks), status, reason)


def scan_png(data: bytes) -> PngScan:
    """Validate PNG framing, CRCs, required chunks, and critical ordering."""
    chunks: list[PngChunk] = []
    if len(data) > MAX_CONTAINER_BYTES:
        return _invalid(chunks, "container exceeds the byte limit", "resource_limit")
    if not data.startswith(PNG_SIGNATURE):
        return _invalid(chunks, "PNG signature is missing")

    offset = len(PNG_SIGNATURE)
    seen_ihdr = False
    seen_plte = False
    seen_idat = False
    idat_ended = False
    colour_type: int | None = None

    while offset < len(data):
        if len(chunks) >= MAX_CONTAINER_ITEMS:
            return _invalid(chunks, "PNG chunk-count limit exceeded", "resource_limit")
        if len(data) - offset < 12:
            return _invalid(chunks, "truncated PNG chunk")
        length = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4 : offset + 8]
        body_start = offset + 8
        body_end = body_start + length
        end = body_end + 4
        if end > len(data):
            return _invalid(chunks, "PNG chunk length exceeds available bytes")
        if not all(65 <= byte <= 90 or 97 <= byte <= 122 for byte in kind):
            return _invalid(chunks, "PNG chunk type contains a non-letter byte")
        expected_crc = struct.unpack_from(">I", data, body_end)[0]
        actual_crc = zlib.crc32(kind)
        # ``memoryview`` avoids duplicating a potentially very large IDAT body
        # merely to validate its CRC.
        actual_crc = zlib.crc32(memoryview(data)[body_start:body_end], actual_crc)
        actual_crc &= 0xFFFFFFFF
        if expected_crc != actual_crc:
            return _invalid(chunks, f"CRC mismatch in {kind.decode('ascii')} chunk")

        chunk = PngChunk(kind, offset, body_start, body_end, end)
        chunks.append(chunk)

        if not seen_ihdr:
            if kind != b"IHDR":
                return _invalid(chunks, "IHDR is not the first PNG chunk")
            if length != 13:
                return _invalid(chunks, "IHDR length is not 13 bytes")
            width, height, depth, colour_type, compression, filtering, interlace = (
                struct.unpack_from(">IIBBBBB", data, body_start)
            )
            if width == 0 or height == 0:
                return _invalid(chunks, "IHDR dimensions must be non-zero")
            if depth not in _VALID_DEPTHS.get(colour_type, frozenset()):
                return _invalid(chunks, "IHDR bit depth and colour type are invalid")
            if compression != 0 or filtering != 0 or interlace not in (0, 1):
                return _invalid(chunks, "IHDR method fields are unsupported or invalid")
            seen_ihdr = True
        elif kind == b"IHDR":
            return _invalid(chunks, "multiple IHDR chunks are not permitted")
        elif kind == b"PLTE":
            if seen_plte or seen_idat or length == 0 or length % 3 or length > 768:
                return _invalid(
                    chunks, "PLTE length, multiplicity, or ordering is invalid"
                )
            if colour_type in (0, 4):
                return _invalid(chunks, "PLTE is forbidden for this colour type")
            seen_plte = True
        elif kind == b"IDAT":
            if idat_ended:
                return _invalid(chunks, "IDAT chunks are not consecutive")
            if colour_type == 3 and not seen_plte:
                return _invalid(chunks, "indexed-colour PNG is missing PLTE before IDAT")
            seen_idat = True
        elif seen_idat:
            idat_ended = True

        if kind[0] & 0x20 == 0 and kind not in _KNOWN_CRITICAL:
            return _invalid(chunks, "unknown critical PNG chunk")
        if kind == b"IEND":
            if length != 0:
                return _invalid(chunks, "IEND chunk must be empty")
            if not seen_idat:
                return _invalid(chunks, "PNG has no IDAT chunk")
            if end != len(data):
                return _invalid(chunks, "bytes follow the IEND chunk")
            return PngScan(tuple(chunks), "complete", "complete PNG chunk structure")
        offset = end

    return _invalid(chunks, "PNG has no IEND chunk")


def _decode_text_chunk(
    chunk_type: bytes, data: bytes, limit: int
) -> tuple[str, str, int, bool]:
    """Return keyword, value, inflated bytes consumed, and truncation state."""
    keyword, separator, rest = data.partition(b"\x00")
    key = keyword.decode("latin-1", "replace")
    if not separator:
        return key, "<malformed text chunk>", 0, False
    if chunk_type == b"tEXt":
        return key, rest.decode("latin-1", "replace"), 0, False
    if chunk_type == b"zTXt":
        if len(rest) < 2 or rest[0] != 0:
            return key, "<unsupported or malformed compression method>", 0, False
        try:
            raw, truncated = bounded_decompress(
                rest[1:], min(limit, MAX_DECOMPRESSED_BYTES)
            )
        except zlib.error:
            return key, "<undecompressible>", 0, False
        return key, raw.decode("latin-1", "replace"), len(raw), truncated

    if len(rest) < 2 or rest[1] != 0 or rest[0] not in (0, 1):
        return key, "<unsupported or malformed iTXt header>", 0, False
    compressed = rest[0] == 1
    language, separator, rest = rest[2:].partition(b"\x00")
    if not separator or any(byte >= 0x80 for byte in language):
        return key, "<malformed iTXt language tag>", 0, False
    _translated, separator, text = rest.partition(b"\x00")
    if not separator:
        return key, "<malformed iTXt translated keyword>", 0, False
    if not compressed:
        return key, text.decode("utf-8", "replace"), 0, False
    try:
        raw, truncated = bounded_decompress(text, min(limit, MAX_DECOMPRESSED_BYTES))
    except zlib.error:
        return key, "<undecompressible>", 0, False
    return key, raw.decode("utf-8", "replace"), len(raw), truncated


def parse_png(data: bytes) -> dict[str, Any]:
    """Inspect PNG metadata with explicit structure and coverage status."""
    scan = scan_png(data)
    found: dict[str, Any] = {
        "png.parse_status": scan.status,
        "png.coverage": (
            "complete chunk framing; selected text/profile/EXIF/time/C2PA metadata "
            "only; pixel data not decoded"
        ),
    }
    if not scan.complete:
        found["png.warning.structure"] = scan.reason

    metadata_bytes = 0
    decompressed_bytes = 0
    ca_count = 0
    text_count = 0
    for chunk in scan.chunks:
        if (
            chunk.kind not in _TEXT_CHUNKS
            and chunk.kind not in _BINARY_METADATA
            and chunk.kind != b"caBX"
        ):
            continue
        metadata_bytes += chunk.length
        if metadata_bytes > MAX_METADATA_BYTES:
            found["png.warning.metadata_limit"] = "aggregate metadata byte limit exceeded"
            found["png.parse_status"] = "resource_limit"
            break
        body = data[chunk.body_start : chunk.body_end]
        if chunk.kind in _TEXT_CHUNKS:
            text_count += 1
            remaining = MAX_TOTAL_DECOMPRESSED_BYTES - decompressed_bytes
            if remaining <= 0:
                found["png.warning.decompression_limit"] = (
                    "aggregate metadata decompression limit exceeded"
                )
                found["png.parse_status"] = "resource_limit"
                continue
            keyword, value, consumed, truncated = _decode_text_chunk(
                chunk.kind, body, remaining
            )
            decompressed_bytes += consumed
            if value.startswith(("<unsupported", "<malformed", "<undecompressible")):
                found[f"png.warning.text.{text_count}"] = value.strip("<>")
                if found["png.parse_status"] == "complete":
                    found["png.parse_status"] = "partial"
            if truncated:
                value = "<truncated at decompression limit> " + value
                found["png.warning.decompression_limit"] = (
                    "compressed metadata was truncated at a resource limit"
                )
                found["png.parse_status"] = "resource_limit"
            if len(value) > 200:
                value = value[:197] + "..."
            key = f"png.{chunk.kind.decode('ascii')}.{keyword}"
            if key in found:
                key = f"{key}.{text_count}"
            found[key] = value
        elif chunk.kind == b"caBX":
            ca_count += 1
            if ca_count > 1:
                found["png.warning.c2pa_multiplicity"] = (
                    "multiple caBX chunks prevent unambiguous manifest-store handling"
                )
                if found["png.parse_status"] == "complete":
                    found["png.parse_status"] = "partial"
            found["png.c2pa_like"] = f"caBX chunk present ({chunk.length} bytes)"
            status = inspect_jumbf_manifest_store(body)
            if status.manifest_store_parsed:
                found["png.c2pa_manifest_store_structurally_parsed"] = True
            else:
                found[f"png.warning.c2pa_structure.{ca_count}"] = status.reason
            found["png.c2pa_credential_verified"] = (
                "unavailable: the dependency-free parser performs no "
                "cryptographic validation"
            )
        else:
            found[f"png.{_BINARY_METADATA[chunk.kind]}"] = f"{chunk.length} bytes"
    return found
