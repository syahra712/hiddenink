"""Zero-dependency core: classification, inspection, and deterministic cleaning."""

from .clean_text import Profile, clean_text
from .codepoints import Category, CodepointInfo, Severity, classify
from .inspect_text import inspect_text, iter_findings
from .report import STATISTICAL_WATERMARK_NOTICE, Finding, Report, Undeterminable

__all__ = [
    "Category",
    "CodepointInfo",
    "Finding",
    "Profile",
    "Report",
    "STATISTICAL_WATERMARK_NOTICE",
    "Severity",
    "Undeterminable",
    "classify",
    "clean_text",
    "inspect_text",
    "iter_findings",
]
