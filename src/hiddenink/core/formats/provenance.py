"""Minimal, non-cryptographic C2PA/JUMBF structure recognition.

This module deliberately stops well before credential validation.  The C2PA
specification identifies a manifest store as a JUMBF superbox whose first child
is a description box with both the C2PA UUID and the label ``c2pa``.  Recognising
that structure is useful, but it does not parse claims, verify signatures, apply
trust policy, or validate the asset's hard binding.

Keeping those states separate prevents a byte-pattern match from being reported
as valid provenance.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

__all__ = [
    "C2PA_MANIFEST_UUID",
    "JumbfStatus",
    "inspect_jumbf_manifest_store",
    "reassemble_jpeg_app11",
]


C2PA_MANIFEST_UUID = bytes.fromhex("6332706100110010800000aa00389b71")
_C2PA_MANIFEST_TYPES = frozenset(
    {
        bytes.fromhex("63326d6100110010800000aa00389b71"),  # c2ma
        bytes.fromhex("6332636d00110010800000aa00389b71"),  # c2cm
        bytes.fromhex("6332756d00110010800000aa00389b71"),  # c2um
        bytes.fromhex("63326d6400110010800000aa00389b71"),  # c2md (legacy)
    }
)


@dataclass(frozen=True, slots=True)
class JumbfStatus:
    """Result of bounded JUMBF manifest-store recognition."""

    looks_like_jumbf: bool
    manifest_store_parsed: bool
    reason: str


def _box(data: bytes, offset: int = 0) -> tuple[bytes, bytes, int] | None:
    """Return ``(type, payload, end)`` for one complete ISO-style box."""
    if offset < 0 or len(data) - offset < 8:
        return None
    size = struct.unpack_from(">I", data, offset)[0]
    kind = data[offset + 4 : offset + 8]
    header = 8
    if size == 1:
        if len(data) - offset < 16:
            return None
        size = struct.unpack_from(">Q", data, offset + 8)[0]
        header = 16
    elif size == 0:
        size = len(data) - offset
    if size < header or size > len(data) - offset:
        return None
    end = offset + size
    return kind, data[offset + header : end], end


def _description_identity(payload: bytes) -> tuple[bytes, bytes, int] | None:
    """Return a JUMBF description's UUID, label, and end offset."""
    description = _box(payload)
    if description is None:
        return None
    kind, body, description_end = description
    if kind != b"jumd" or len(body) < 17:
        return None
    toggles = body[16]
    if toggles & 0x03 != 0x03:
        return None
    label, separator, _rest = body[17:].partition(b"\x00")
    if not separator:
        return None
    return body[:16], label, description_end


def _has_complete_content_box(payload: bytes, offset: int) -> bool:
    """Validate that at least one complete content box follows a description."""
    if offset == len(payload):
        return False
    while offset < len(payload):
        child = _box(payload, offset)
        if child is None:
            return False
        _kind, _body, offset = child
    return True


def inspect_jumbf_manifest_store(data: bytes) -> JumbfStatus:
    """Recognise the C2PA manifest-store JUMBF superbox.

    A successful result is *structural only*.  It must never be treated as a
    parsed claim or a cryptographically verified credential.
    """
    outer = _box(data)
    if outer is None:
        return JumbfStatus(False, False, "not a complete box")
    outer_kind, outer_payload, outer_end = outer
    if outer_kind != b"jumb":
        return JumbfStatus(False, False, "outer box is not a JUMBF superbox")
    if outer_end != len(data):
        return JumbfStatus(True, False, "bytes follow the JUMBF superbox")

    identity = _description_identity(outer_payload)
    if identity is None:
        return JumbfStatus(True, False, "missing complete JUMBF description box")
    content_uuid, label, description_end = identity
    if content_uuid != C2PA_MANIFEST_UUID:
        return JumbfStatus(True, False, "JUMBF content UUID is not C2PA")
    if label != b"c2pa":
        return JumbfStatus(True, False, "C2PA JUMBF label is missing or invalid")

    if description_end == len(outer_payload):
        return JumbfStatus(True, False, "manifest store has no content boxes")
    content_offset = description_end
    manifest_found = False
    while content_offset < len(outer_payload):
        content = _box(outer_payload, content_offset)
        if content is None:
            return JumbfStatus(True, False, "manifest-store content box is truncated")
        content_kind, content_payload, content_offset = content
        if content_kind != b"jumb":
            continue
        manifest_identity = _description_identity(content_payload)
        if manifest_identity is None:
            continue
        manifest_uuid, manifest_label, manifest_description_end = manifest_identity
        if (
            manifest_uuid in _C2PA_MANIFEST_TYPES
            and manifest_label.startswith(b"urn:c2pa:")
            and len(manifest_label) > len(b"urn:c2pa:")
            and _has_complete_content_box(content_payload, manifest_description_end)
        ):
            manifest_found = True
    if not manifest_found:
        return JumbfStatus(
            True,
            False,
            "manifest store contains no C2PA Manifest superbox with a urn:c2pa label",
        )
    return JumbfStatus(True, True, "C2PA manifest-store structure recognised")


def reassemble_jpeg_app11(bodies: list[bytes]) -> tuple[bytes | None, str]:
    """Reassemble one contiguous JPEG XT APP11 box instance.

    Each segment body is ``JP`` + a two-byte box-instance number + a four-byte
    packet sequence number + payload.  The function is strict about the common
    identifier, instance, and contiguous sequence numbers, because APP11 is used
    by standards other than C2PA.
    """
    if not bodies:
        return None, "no APP11 segments"
    instance: bytes | None = None
    expected_sequence: int | None = None
    payloads: list[bytes] = []
    for body in bodies:
        if len(body) < 8 or body[:2] != b"JP":
            return None, "APP11 segment is not a JPEG XT box segment"
        if instance is None:
            instance = body[2:4]
        elif body[2:4] != instance:
            return None, "APP11 box-instance numbers differ"
        sequence = struct.unpack_from(">I", body, 4)[0]
        if expected_sequence is None:
            expected_sequence = sequence
        if sequence != expected_sequence:
            return None, "APP11 packet sequence is not contiguous"
        expected_sequence += 1
        payloads.append(body[8:])
    return b"".join(payloads), "JPEG XT APP11 sequence reassembled"
