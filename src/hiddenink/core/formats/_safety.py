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

import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
import zlib

__all__ = [
    "MAX_DECOMPRESSED_BYTES",
    "MAX_CONTAINER_BYTES",
    "MAX_CONTAINER_ITEMS",
    "MAX_METADATA_BYTES",
    "MAX_TOTAL_DECOMPRESSED_BYTES",
    "MAX_XML_BYTES",
    "ResourceLimitExceeded",
    "UnsafeDocument",
    "bounded_decompress",
    "safe_fromstring",
]

#: Cap on any single decompressed member (PNG text chunk, zip part).
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024

#: Cap on a whole container we are willing to read into memory.
MAX_CONTAINER_BYTES = 256 * 1024 * 1024

#: Maximum number of chunks, JPEG segments, or ZIP members examined.
MAX_CONTAINER_ITEMS = 10_000

#: Aggregate compressed/uncompressed metadata accepted from one container.
MAX_METADATA_BYTES = 16 * 1024 * 1024

#: Aggregate inflated metadata accepted from one container.
MAX_TOTAL_DECOMPRESSED_BYTES = 16 * 1024 * 1024

#: XML is parsed twice (security gate, then tree building).  Keep the ceiling
#: intentionally lower than the general member limit, especially because some
#: supported Python builds still bundle Expat versions affected by large-token
#: denial-of-service issues.
MAX_XML_BYTES = 2 * 1024 * 1024


class UnsafeDocument(ValueError):
    """Raised when input trips a hardening rule."""


class ResourceLimitExceeded(UnsafeDocument):
    """Raised when safe parsing stops at an explicit resource ceiling."""


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


def safe_fromstring(text: str | bytes) -> ET.Element:
    """``ET.fromstring`` with entity declarations refused.

    Raises :class:`UnsafeDocument` if the prolog declares any entity. A plain
    ``<!DOCTYPE svg PUBLIC ...>`` is still accepted, because real SVG 1.1
    files carry one and it cannot expand to anything on its own. Parameter
    entities are disabled, external references hit a rejecting handler, and no
    resolver capable of file or network access is installed.

    The declaration is refused rather than merely left unexpanded so the
    caller learns the document is hostile instead of silently getting a
    document with holes in it.
    """
    data = text.encode("utf-8", "surrogatepass") if isinstance(text, str) else text
    if len(data) > MAX_XML_BYTES:
        raise ResourceLimitExceeded(
            f"XML exceeds the {MAX_XML_BYTES}-byte safety limit"
        )

    # Do not try to recognise declarations with a byte regular expression.
    # Expat performs XML's own encoding detection (including UTF-16), skips
    # comments and processing instructions correctly, and invokes this handler
    # only for an actual grammar-level entity declaration.
    gate = expat.ParserCreate()

    def reject_entity(*_args: object) -> None:
        raise UnsafeDocument("XML entity declarations are not permitted")

    def reject_external(*_args: object) -> int:
        raise UnsafeDocument("external XML entities are not permitted")

    gate.EntityDeclHandler = reject_entity
    gate.ExternalEntityRefHandler = reject_external
    gate.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    depth = 0
    elements = 0

    def start_element(_name: str, _attrs: dict[str, str]) -> None:
        nonlocal depth, elements
        depth += 1
        elements += 1
        if depth > 256 or elements > MAX_CONTAINER_ITEMS:
            raise ResourceLimitExceeded(
                "XML nesting or element-count limit exceeded"
            )

    def end_element(_name: str) -> None:
        nonlocal depth
        depth -= 1

    gate.StartElementHandler = start_element
    gate.EndElementHandler = end_element
    try:
        gate.Parse(data, True)
    except UnsafeDocument:
        raise
    except expat.ExpatError as exc:
        raise ET.ParseError(str(exc)) from exc

    # The security gate above has already interpreted the real XML grammar and
    # refused all declarations.  ElementTree is used only to build the result.
    return ET.fromstring(data)  # noqa: S314 - declarations refused by Expat gate
