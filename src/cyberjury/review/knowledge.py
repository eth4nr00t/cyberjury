"""The one language-independent security kernel bound to every review unit."""

from __future__ import annotations

from cyberjury.review.contract import SECURITY_KERNEL_FILE, SEVERITY_RUBRIC_FILE


def load_review_brief() -> str:
    """Load the language-independent security kernel, the only security knowledge given to a model judgment."""
    return f"# Security Reasoning Kernel\n{SECURITY_KERNEL_FILE.read_text(encoding='utf-8')}"


def load_severity_rubric() -> str:
    """Load the severity rubric shared by every finder judgment."""
    return SEVERITY_RUBRIC_FILE.read_text(encoding="utf-8")
