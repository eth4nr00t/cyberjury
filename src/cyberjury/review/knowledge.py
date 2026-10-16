"""Bind one language-independent security kernel to every review unit."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cyberjury.review.contract import SECURITY_KERNEL_FILE, SEVERITY_RUBRIC_FILE


@dataclass(frozen=True, slots=True, kw_only=True)
class ReviewBrief:
    """The same general security reasoning contract for every language and framework."""

    kernel: str

    def __post_init__(self) -> None:
        """Reject an empty judgment contract."""
        if not isinstance(self.kernel, str) or not self.kernel.strip():
            raise ValueError("security kernel must be nonempty")

    @property
    def content_sha256(self) -> str:
        """Identify the exact prompt content."""
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()

    def render(self) -> str:
        """Give every judgment the complete, compact kernel."""
        return f"# Security Reasoning Kernel\n{self.kernel}"


def load_review_brief(*, kernel_file: str | Path = SECURITY_KERNEL_FILE) -> ReviewBrief:
    """Load the only security knowledge given to a model judgment."""
    source = Path(kernel_file)
    try:
        kernel = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"security kernel file {source} could not be loaded: {exc}") from exc
    return ReviewBrief(kernel=kernel)


def load_severity_rubric() -> str:
    """Load the severity rubric shared by every finder judgment."""
    return SEVERITY_RUBRIC_FILE.read_text(encoding="utf-8")
