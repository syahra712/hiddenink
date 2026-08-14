"""hiddenink -- inspect and clean AI provenance marks in text and files.

Removes what is provably removable (invisible codepoints, container metadata)
and says so precisely. Does not claim to remove, defeat, or detect model-level
statistical watermarking, which no public tool can currently evaluate.
"""

from .core import (
    STATISTICAL_WATERMARK_NOTICE,
    Category,
    Finding,
    Profile,
    Report,
    Severity,
    clean_text,
    inspect_text,
)

__version__ = "0.1.2"

__all__ = [
    "Category",
    "Finding",
    "Profile",
    "Report",
    "STATISTICAL_WATERMARK_NOTICE",
    "Severity",
    "__version__",
    "clean_text",
    "inspect_text",
]
