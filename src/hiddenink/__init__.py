"""hiddenink -- inspect and conservatively clean text and file metadata.

Reports what was examined, what changed, and what was outside parser coverage.
Does not claim to remove, defeat, or detect model-level statistical watermarking.
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

__version__ = "0.2.1"

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
