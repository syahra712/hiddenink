"""Resource limits and a hardened XML parser for untrusted input.

Every parser in this package reads files the user did not create -- that is
the entire use case. Container formats give an attacker two cheap amplification
primitives, and the standard library defends against neither by default:

* **Decompression bombs.** A 200 KB PNG ``zTXt`` chunk expands to 200 MB
  through ``zlib.decompress``; an 80 KB ``.docx`` part expands to 80 MB
  through ``ZipFile.read``. Truncating the *result* does not help, because
  the expansion has already happened in memory.
* **Entity expansion.** ``xml.etree.ElementTree`` expands internal entities,
  so the classic "billion laughs" DTD costs an attacker a few hundred bytes
  and costs the parser gigabytes.

Rather than take a dependency on ``defusedxml``, which would break the core's
zero-dependency guarantee, this module installs expat handlers that refuse
entity declarations outright and caps every decompression.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zlib

__all__ = [
    "MAX_DECOMPRESSED_BYTES",
    "MAX_CONTAINER_BYTES",
    "UnsafeDocument",
    "bounded_decompress",
    "safe_fromstring",
]

#: Cap on any single decompressed member (PNG text chunk, zip part).
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024

#: Cap on a whole container we are willing to read into memory.
MAX_CONTAINER_BYTES = 256 * 1024 * 1024


class UnsafeDocument(ValueError):
    """Raised when input trips a resource limit or a hardening rule."""


def bounded_decompress(
    data: bytes, limit: int = MAX_DECOMPRESSED_BYTES
) -> tuple[bytes, bool]:
    """Inflate ``data``, stopping at ``limit`` bytes.

    Returns ``(output, truncated)``. Uses ``decompressobj`` with ``max_length``
    so the bomb is never materialised -- unlike ``zlib.decompress``, which
    expands fully and only then lets the caller discard the result.
    """
    engine = zlib.decompressobj()
    out = engine.decompress(data, limit)
    truncated = bool(engine.unconsumed_tail) or not engine.eof
    return out, truncated


#: Matches an entity declaration anywhere in the document prolog. Both the
#: billion-laughs and the XXE attack require one: recursive expansion needs
#: internal ``<!ENTITY>`` definitions, and external references need an
#: ``<!ENTITY ... SYSTEM ...>`` declaration to name the target.
_ENTITY_DECL = re.compile(rb"<!ENTITY", re.IGNORECASE)

#: The first element start tag, which terminates the prolog.
_ELEMENT_START = re.compile(rb"<[A-Za-z_:]")


def safe_fromstring(text: str | bytes) -> ET.Element:
    """``ET.fromstring`` with entity declarations refused.

    Raises :class:`UnsafeDocument` if the prolog declares any entity. A plain
    ``<!DOCTYPE svg PUBLIC ...>`` is still accepted, because real SVG 1.1
    files carry one and it cannot expand to anything on its own -- CPython's
    parser installs no external-entity handler, so an external DTD subset is
    never fetched.

    The declaration is refused rather than merely left unexpanded so the
    caller learns the document is hostile instead of silently getting a
    document with holes in it.
    """
    data = text.encode("utf-8", "surrogatepass") if isinstance(text, str) else text

    # The root element is the first '<' followed by a name character. The XML
    # declaration, comments, and the DOCTYPE all begin '<?' or '<!', so
    # everything before that point is the prolog -- the only place an entity
    # declaration can legally appear.
    root = _ELEMENT_START.search(data)
    prolog = data[: root.start()] if root else data

    if _ENTITY_DECL.search(prolog):
        raise UnsafeDocument("XML entity declarations are not permitted")

    return ET.fromstring(data)  # noqa: S314 - entity declarations refused above
