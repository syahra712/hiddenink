"""JPEG APPn segment parser (stdlib only).

A JPEG is SOI (``FFD8``) followed by marker segments. Metadata lives in the
application segments:

``APP1``  EXIF (``Exif\\0\\0``) or XMP (``http://ns.adobe.com/xap/1.0/\\0``)
``APP11`` JUMBF -- the container C2PA uses for Content Credentials in JPEG
``APP13`` Photoshop IRB / IPTC
"""

from __future__ import annotations

import struct
from typing import Any

__all__ = ["parse_jpeg", "JPEG_SIGNATURE"]

JPEG_SIGNATURE = b"\xff\xd8"

_XMP_ID = b"http://ns.adobe.com/xap/1.0/\x00"
_EXIF_ID = b"Exif\x00\x00"

#: Markers with no length field.
_STANDALONE = {0xD8, 0xD9, *range(0xD0, 0xD8), 0x01}


def parse_jpeg(data: bytes) -> dict[str, Any]:
    """Extract metadata from JPEG bytes."""
    if not data.startswith(JPEG_SIGNATURE):
        return {}

    found: dict[str, Any] = {}
    offset = 2

    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            break
        marker = data[offset + 1]

        if marker == 0xDA:  # start of scan: image data follows, no more metadata
            break
        if marker in _STANDALONE:
            offset += 2
            continue

        (length,) = struct.unpack(">H", data[offset + 2 : offset + 4])
        body = data[offset + 4 : offset + 2 + length]

        if marker == 0xE1:
            if body.startswith(_EXIF_ID):
                found["jpeg.exif"] = f"{len(body) - len(_EXIF_ID)} bytes"
            elif body.startswith(_XMP_ID):
                xmp = body[len(_XMP_ID) :].decode("utf-8", "replace")
                found["jpeg.xmp"] = f"{len(xmp)} chars"
                if "c2pa" in xmp.lower():
                    found["jpeg.xmp.c2pa_reference"] = "present"
        elif marker == 0xEB:
            # APP11 carries JUMBF; C2PA manifests are JUMBF superboxes.
            found["jpeg.app11_jumbf"] = f"{len(body)} bytes"
            if b"c2pa" in body[:256].lower():
                found["jpeg.c2pa_manifest"] = "present"
        elif marker == 0xED:
            found["jpeg.photoshop_irb"] = f"{len(body)} bytes"
        elif marker == 0xFE:
            found["jpeg.comment"] = body.decode("utf-8", "replace")[:200]

        offset += 2 + length

    return found
