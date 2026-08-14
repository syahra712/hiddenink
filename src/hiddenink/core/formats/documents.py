"""Bounded SVG, document-property ZIP, and shallow PDF metadata readers."""

from __future__ import annotations

import base64
import binascii
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib
from io import BytesIO
from typing import Any

from ._safety import (
    MAX_CONTAINER_BYTES,
    MAX_CONTAINER_ITEMS,
    MAX_DECOMPRESSED_BYTES,
    MAX_METADATA_BYTES,
    MAX_TOTAL_DECOMPRESSED_BYTES,
    ResourceLimitExceeded,
    UnsafeDocument,
    safe_fromstring,
)
from .provenance import inspect_jumbf_manifest_store

__all__ = ["parse_svg", "parse_office", "parse_pdf"]

_SVG_METADATA_TAGS = {"metadata", "title", "desc"}
_C2PA_NS = "http://c2pa.org/manifest"


def parse_svg(data: bytes) -> dict[str, Any]:
    """Extract SVG metadata without resolving or expanding XML entities."""
    found: dict[str, Any] = {
        "svg.parse_status": "complete",
        "svg.coverage": (
            "complete XML structure and metadata elements; rendering not evaluated"
        ),
    }
    try:
        root = safe_fromstring(data)
    except ResourceLimitExceeded as exc:
        found["svg.parse_status"] = "resource_limit"
        found["svg.warning.xml_resource_limit"] = str(exc)
        return found
    except UnsafeDocument as exc:
        found["svg.parse_status"] = "refused"
        found["svg.refusal.xml"] = "security policy refused XML parsing"
        found["svg.warning.xml"] = str(exc)
        return found
    except ET.ParseError as exc:
        found["svg.parse_status"] = "malformed"
        found["svg.warning.xml"] = f"document is not well-formed XML: {exc}"
        return found

    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag in _SVG_METADATA_TAGS:
            text = " ".join(element.itertext())
            collapsed = " ".join(text.split())
            if collapsed:
                found[f"svg.{tag}"] = collapsed[:200]
            elif tag == "metadata":
                found["svg.metadata"] = "<present, no text>"

        if element.tag != f"{{{_C2PA_NS}}}manifest":
            continue
        encoded = "".join(element.itertext()).strip()
        found["svg.c2pa_like"] = "c2pa:manifest element present"
        if len(encoded) > (MAX_METADATA_BYTES * 4 // 3 + 8):
            found["svg.warning.c2pa_structure"] = "Base64 manifest exceeds metadata limit"
        else:
            try:
                manifest = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                found["svg.warning.c2pa_structure"] = "manifest is not valid Base64"
            else:
                status = inspect_jumbf_manifest_store(manifest)
                if status.manifest_store_parsed:
                    found["svg.c2pa_manifest_store_structurally_parsed"] = True
                else:
                    found["svg.warning.c2pa_structure"] = status.reason
        found["svg.c2pa_credential_verified"] = (
            "unavailable: the dependency-free parser performs no cryptographic validation"
        )
    return found


_OOXML_PARTS = {
    "docProps/core.xml": "core",
    "docProps/app.xml": "app",
    "docProps/custom.xml": "custom",
}
_ODF_PARTS = {"meta.xml": "meta"}

_ZIP_EXCEPTIONS = (
    EOFError,
    NotImplementedError,
    OSError,
    RuntimeError,
    ValueError,
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    zlib.error,
)

_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_CENTRAL_FILE_SIGNATURE = b"PK\x01\x02"
_CENTRAL_DIGITAL_SIGNATURE = b"PK\x05\x05"
_EOCD_SIZE = 22
_MAX_ZIP_COMMENT = 65_535


def _find_eocd(data: bytes) -> int:
    """Locate an EOCD whose declared comment ends exactly at EOF."""
    lower = max(0, len(data) - _EOCD_SIZE - _MAX_ZIP_COMMENT)
    cursor = len(data)
    while True:
        offset = data.rfind(_EOCD_SIGNATURE, lower, cursor)
        if offset < 0:
            raise zipfile.BadZipFile("end-of-central-directory record not found")
        if len(data) - offset >= _EOCD_SIZE:
            comment_length = struct.unpack_from("<H", data, offset + 20)[0]
            if offset + _EOCD_SIZE + comment_length == len(data):
                return offset
        cursor = offset


def _zip64_directory(data: bytes, eocd_offset: int) -> tuple[int, int, int, int]:
    """Return ZIP64 entry count, directory size/offset, and record position."""
    locator_offset = eocd_offset - 20
    if (
        locator_offset < 0
        or data[locator_offset : locator_offset + 4] != _ZIP64_LOCATOR_SIGNATURE
    ):
        raise zipfile.BadZipFile("ZIP64 end-of-central-directory locator is missing")
    disk, record_offset, disks = struct.unpack_from("<IQI", data, locator_offset + 4)
    if disk != 0 or disks != 1:
        raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")
    if (
        record_offset > locator_offset - 56
        or data[record_offset : record_offset + 4] != _ZIP64_EOCD_SIGNATURE
    ):
        raise zipfile.BadZipFile("ZIP64 end-of-central-directory record is invalid")
    record_size = struct.unpack_from("<Q", data, record_offset + 4)[0]
    if record_size < 44 or record_offset + 12 + record_size != locator_offset:
        raise zipfile.BadZipFile("ZIP64 end-of-central-directory size is invalid")
    disk_number, directory_disk = struct.unpack_from("<II", data, record_offset + 16)
    entries_on_disk, entries_total, directory_size, directory_offset = (
        struct.unpack_from("<QQQQ", data, record_offset + 24)
    )
    if disk_number != 0 or directory_disk != 0 or entries_on_disk != entries_total:
        raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")
    return entries_total, directory_size, directory_offset, record_offset


def _preflight_zip_directory(data: bytes) -> None:
    """Bound and validate the central directory before ``ZipFile`` allocates."""
    eocd_offset = _find_eocd(data)
    (
        disk_number,
        directory_disk,
        entries_on_disk,
        entries_total,
        directory_size,
        directory_offset,
        _comment_length,
    ) = struct.unpack_from("<4H2IH", data, eocd_offset + 4)
    if disk_number not in (0, 0xFFFF) or directory_disk not in (0, 0xFFFF):
        raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")

    sentinel = (
        entries_on_disk == 0xFFFF
        or entries_total == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    )
    directory_end = eocd_offset
    if sentinel:
        entries_total, directory_size, directory_offset, directory_end = (
            _zip64_directory(data, eocd_offset)
        )
    elif entries_on_disk != entries_total:
        raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")

    if entries_total > MAX_CONTAINER_ITEMS:
        raise ResourceLimitExceeded(
            f"ZIP has {entries_total} members; limit is {MAX_CONTAINER_ITEMS}"
        )
    if directory_size > directory_end or directory_offset > directory_end:
        raise zipfile.BadZipFile("central directory bounds are invalid")

    # ZIP offsets omit any prefix prepended to an otherwise valid archive. Infer
    # that prefix without constructing a ZipInfo for every hostile member.
    prefix = directory_end - directory_size - directory_offset
    if prefix < 0:
        raise zipfile.BadZipFile("central directory offset is invalid")
    cursor = directory_offset + prefix
    expected_end = cursor + directory_size
    actual_entries = 0
    while cursor < expected_end:
        signature = data[cursor : cursor + 4]
        if signature == _CENTRAL_FILE_SIGNATURE:
            if expected_end - cursor < 46:
                raise zipfile.BadZipFile("truncated central-directory member")
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH", data, cursor + 28
            )
            cursor += 46 + name_length + extra_length + comment_length
            if cursor > expected_end:
                raise zipfile.BadZipFile("central-directory member exceeds bounds")
            actual_entries += 1
            if actual_entries > MAX_CONTAINER_ITEMS:
                raise ResourceLimitExceeded(
                    f"ZIP has more than {MAX_CONTAINER_ITEMS} members"
                )
        elif signature == _CENTRAL_DIGITAL_SIGNATURE:
            if expected_end - cursor < 6:
                raise zipfile.BadZipFile("truncated central-directory signature")
            signature_length = struct.unpack_from("<H", data, cursor + 4)[0]
            cursor += 6 + signature_length
            if cursor > expected_end:
                raise zipfile.BadZipFile("central-directory signature exceeds bounds")
        else:
            raise zipfile.BadZipFile("invalid central-directory member signature")
    if actual_entries != entries_total:
        raise zipfile.BadZipFile("central-directory member count is inconsistent")


def parse_office(data: bytes) -> dict[str, Any]:
    """Inspect only OOXML/ODF document-property XML parts.

    Body text, comments, revisions, cells, slides, and embedded images are not
    scanned by this API; the coverage field makes that limitation explicit.
    """
    found: dict[str, Any] = {
        "office.parse_status": "complete",
        "office.coverage": (
            "document properties only; body text, comments, revisions, cells, slides, "
            "and embedded images not inspected"
        ),
    }
    if len(data) > MAX_CONTAINER_BYTES:
        found["office.parse_status"] = "resource_limit"
        found["office.warning.container_limit"] = "container exceeds byte limit"
        return found
    try:
        _preflight_zip_directory(data)
        archive = zipfile.ZipFile(BytesIO(data))
    except ResourceLimitExceeded as exc:
        found["office.parse_status"] = "resource_limit"
        found["office.warning.member_limit"] = str(exc)
        return found
    except _ZIP_EXCEPTIONS as exc:
        found["office.parse_status"] = "malformed"
        found["office.warning.zip"] = f"ZIP could not be opened: {type(exc).__name__}"
        return found

    try:
        infos = archive.infolist()
        if len(infos) > MAX_CONTAINER_ITEMS:
            found["office.parse_status"] = "resource_limit"
            found["office.warning.member_limit"] = (
                f"ZIP has {len(infos)} members; limit is {MAX_CONTAINER_ITEMS}"
            )
            return found

        selected: dict[str, zipfile.ZipInfo] = {}
        package_marker = False
        for info in infos:
            if info.filename in ("[Content_Types].xml", "mimetype"):
                package_marker = True
            if info.filename in _OOXML_PARTS or info.filename in _ODF_PARTS:
                if info.filename in selected:
                    found["office.parse_status"] = "malformed"
                    found["office.warning.duplicate_part"] = (
                        f"duplicate metadata part: {info.filename}"
                    )
                    return found
                selected[info.filename] = info
        if not package_marker:
            found["office.parse_status"] = "unsupported"
            found["office.warning.package"] = "ZIP is not identified as OOXML or ODF"
            return found

        total_declared = 0
        total_read = 0
        all_parts_ok = True
        security_refused = False
        resource_limited = False
        for part, label in {**_OOXML_PARTS, **_ODF_PARTS}.items():
            selected_info = selected.get(part)
            if selected_info is None:
                continue
            if selected_info.flag_bits & 0x1:
                found[f"office.warning.{label}.encrypted"] = "encrypted part was not read"
                all_parts_ok = False
                continue
            if selected_info.file_size > MAX_DECOMPRESSED_BYTES:
                found[f"office.warning.{label}.oversized"] = (
                    f"{selected_info.file_size} declared bytes, skipped"
                )
                all_parts_ok = False
                resource_limited = True
                continue
            total_declared += selected_info.file_size
            if total_declared > MAX_TOTAL_DECOMPRESSED_BYTES:
                found["office.warning.decompression_limit"] = (
                    "aggregate declared metadata size limit exceeded"
                )
                all_parts_ok = False
                resource_limited = True
                break
            try:
                with archive.open(selected_info) as handle:
                    raw = handle.read(MAX_DECOMPRESSED_BYTES + 1)
            except _ZIP_EXCEPTIONS as exc:
                found[f"office.warning.{label}.read"] = (
                    f"part could not be read: {type(exc).__name__}"
                )
                all_parts_ok = False
                continue
            total_read += len(raw)
            if (
                len(raw) > MAX_DECOMPRESSED_BYTES
                or total_read > MAX_TOTAL_DECOMPRESSED_BYTES
            ):
                found[f"office.warning.{label}.oversized"] = "actual data exceeded limit"
                all_parts_ok = False
                resource_limited = True
                continue
            try:
                root = safe_fromstring(raw)
            except ResourceLimitExceeded as exc:
                found[f"office.warning.{label}.resource_limit"] = str(exc)
                all_parts_ok = False
                resource_limited = True
                continue
            except UnsafeDocument as exc:
                found[f"office.warning.{label}.unsafe"] = str(exc)
                found[f"office.refusal.{label}.xml"] = (
                    "security policy refused XML parsing"
                )
                all_parts_ok = False
                security_refused = True
                continue
            except ET.ParseError as exc:
                found[f"office.warning.{label}.xml"] = f"malformed XML: {exc}"
                all_parts_ok = False
                continue
            for element in root.iter():
                tag = element.tag.rsplit("}", 1)[-1]
                text = (element.text or "").strip()
                if text and tag not in ("coreProperties", "Properties", "meta"):
                    found[f"office.{label}.{tag}"] = text[:200]
        if security_refused:
            found["office.parse_status"] = "refused"
        elif resource_limited:
            found["office.parse_status"] = "resource_limit"
        elif not all_parts_ok:
            found["office.parse_status"] = "partial"
        return found
    finally:
        archive.close()


_PDF_INFO_KEYS = (
    "Title",
    "Author",
    "Subject",
    "Keywords",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
)


def parse_pdf(data: bytes) -> dict[str, Any]:
    """Perform a bounded lexical PDF metadata scan with explicit partial status."""
    found: dict[str, Any] = {
        "pdf.parse_status": "partial",
        "pdf.coverage": (
            "bounded lexical Info/XMP scan only; object streams, filters, xref, "
            "signatures, and page content not fully parsed"
        ),
    }
    if len(data) > MAX_CONTAINER_BYTES:
        found["pdf.parse_status"] = "resource_limit"
        found["pdf.warning.container_limit"] = "container exceeds byte limit"
        return found
    if not data.startswith(b"%PDF"):
        found["pdf.parse_status"] = "malformed"
        found["pdf.warning.structure"] = "PDF header is missing"
        return found
    if b"%%EOF" not in data[-2048:]:
        found["pdf.parse_status"] = "malformed"
        found["pdf.warning.structure"] = "terminal PDF EOF marker was not found"
    if re.search(rb"/Encrypt\b", data[:MAX_METADATA_BYTES]):
        found["pdf.warning.encryption"] = "encrypted PDF content was not parsed"

    scan = data[:MAX_METADATA_BYTES]
    if len(data) > len(scan):
        found["pdf.warning.scan_limit"] = "only the leading metadata budget was scanned"
    for key in _PDF_INFO_KEYS:
        pattern = (
            rb"/"
            + key.encode()
            + rb"\s*(?:\((.{0,4096}?)(?<!\\)\)|<([0-9A-Fa-f\s]{1,8192})>)"
        )
        match = re.search(pattern, scan, re.S)
        if not match:
            continue
        if match.group(1) is not None:
            value = match.group(1).decode("latin-1", "replace")
        else:
            hexed = re.sub(rb"\s", b"", match.group(2))
            try:
                value = bytes.fromhex(hexed.decode("ascii")).decode(
                    "utf-16-be", "replace"
                )
            except (UnicodeError, ValueError):
                found[f"pdf.warning.info.{key}"] = "malformed hexadecimal string"
                continue
        value = " ".join(value.split())
        if value:
            found[f"pdf.info.{key}"] = value[:200]

    start = scan.find(b"<x:xmpmeta")
    if start >= 0:
        end = scan.find(b"</x:xmpmeta>", start)
        if end >= 0:
            found["pdf.xmp"] = f"{end + len(b'</x:xmpmeta>') - start} bytes"
        else:
            found["pdf.warning.xmp"] = "unterminated XMP packet"
    return found
