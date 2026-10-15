"""Bind one language-independent security kernel to every review unit."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True, kw_only=True)
class ReviewBrief:
    """The same general security reasoning contract for every language and framework."""

    kernel: str

    def __post_init__(self) -> None:
        """Reject an empty judgment contract."""
        if not isinstance(self.kernel, str) or not self.kernel.strip():
            raise ValueError("security kernel must be nonempty")

    @property
    def label(self) -> str:
        """Name the shared prompt content."""
        return "security kernel"

    @property
    def content_sha256(self) -> str:
        """Identify the exact prompt content."""
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()

    def render(self) -> str:
        """Give every judgment the complete, compact kernel."""
        return f"# Security Reasoning Kernel\n{self.kernel}"

    def canonicalize_category(self, category: str) -> str:
        """Normalize a model supplied class without treating qualifiers as new classes."""
        raw = category.strip()
        broad_class = re.sub(r"(?:[\s_-]*\([^()]*\))+$", "", raw).strip() or raw
        return broad_class.lower().replace(" ", "-").replace("_", "-")


def load_review_brief(*, kernel_file: str | Path) -> ReviewBrief:
    """Load the only security knowledge given to a model judgment."""
    source = Path(kernel_file)
    try:
        kernel = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"security kernel file {source} could not be loaded: {exc}") from exc
    return ReviewBrief(kernel=kernel)
