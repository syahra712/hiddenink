"""SVG, Office (DOCX/ODT/XLSX/PPTX), and PDF metadata readers (stdlib only)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from io import BytesIO
from typing import Any

__all__ = ["parse_svg", "parse_office", "parse_pdf"]


# --- SVG ---------------------------------------------------------------------

_SVG_METADATA_TAGS = {"metadata", "title", "desc"}


def parse_svg(data: bytes) -> dict[str, Any]:
    """Extract metadata elements from an SVG document."""
    found: dict[str, Any] = {}
    try:
        root = ET.fromstring(data.decode("utf-8", "replace"))
    except ET.ParseError:
        return {"svg.parse_error": "document is not well-formed XML"}

    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]  # drop the namespace
        if tag in _SVG_METADATA_TAGS:
            text = " ".join(element.itertext())
            collapsed = " ".join(text.split())
            if collapsed:
                found[f"svg.{tag}"] = collapsed[:200]
            elif tag == "metadata":
                found["svg.metadata"] = "<present, no text>"

    blob = data.decode("utf-8", "replace").lower()
    if "c2pa" in blob:
        found["svg.c2pa_reference"] = "present"
    if "xmpmeta" in blob:
        found["svg.xmp"] = "present"
    return found


# --- Office (OOXML / ODF) ----------------------------------------------------

_OOXML_PARTS = {
    "docProps/core.xml": "core",
    "docProps/app.xml": "app",
    "docProps/custom.xml": "custom",
}
_ODF_PARTS = {"meta.xml": "meta"}


def parse_office(data: bytes) -> dict[str, Any]:
    """Extract document properties from a zip-container document.

    Covers OOXML (.docx/.xlsx/.pptx) and ODF (.odt/.ods/.odp), which are both
    just zip archives with an XML metadata part.
    """
    found: dict[str, Any] = {}
    try:
        archive = zipfile.ZipFile(BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return {}

    names = set(archive.namelist())
    for part, label in {**_OOXML_PARTS, **_ODF_PARTS}.items():
        if part not in names:
            continue
        try:
            root = ET.fromstring(archive.read(part).decode("utf-8", "replace"))
        except (ET.ParseError, KeyError, OSError):
            continue
        for element in root.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            text = (element.text or "").strip()
            if text and tag not in ("coreProperties", "Properties", "meta"):
                found[f"office.{label}.{tag}"] = text[:200]

    if any(n.startswith("c2pa") or "c2pa" in n.lower() for n in names):
        found["office.c2pa_part"] = "present"
    return found


# --- PDF ---------------------------------------------------------------------

_PDF_INFO_KEYS = (
    "Title", "Author", "Subject", "Keywords", "Creator", "Producer",
    "CreationDate", "ModDate",
)
_XMP_PACKET = re.compile(rb"<x:xmpmeta.*?</x:xmpmeta>", re.S)


def parse_pdf(data: bytes) -> dict[str, Any]:
    """Extract the Info dictionary and XMP packet from a PDF.

    This is a deliberately shallow scan rather than a full PDF parse: it finds
    the metadata that generators actually write, without pulling in a
    dependency. Values inside object streams compressed with an unsupported
    filter will not be visible, and the report says so by omission.
    """
    if not data.startswith(b"%PDF"):
        return {}

    found: dict[str, Any] = {}
    for key in _PDF_INFO_KEYS:
        # /Key (literal string) or /Key <hex string>
        pattern = rb"/" + key.encode() + rb"\s*(?:\((.*?)(?<!\\)\)|<([0-9A-Fa-f\s]+)>)"
        match = re.search(pattern, data, re.S)
        if not match:
            continue
        if match.group(1) is not None:
            value = match.group(1).decode("latin-1", "replace")
        else:
            hexed = re.sub(rb"\s", b"", match.group(2))
            try:
                value = bytes.fromhex(hexed.decode()).decode("utf-16-be", "replace")
            except ValueError:
                continue
        value = " ".join(value.split())
        if value:
            found[f"pdf.info.{key}"] = value[:200]

    packet = _XMP_PACKET.search(data)
    if packet:
        found["pdf.xmp"] = f"{len(packet.group(0))} bytes"
        if b"c2pa" in packet.group(0).lower():
            found["pdf.xmp.c2pa_reference"] = "present"
    return found
