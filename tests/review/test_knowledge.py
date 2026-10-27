"""The review brief binds one general security kernel to every unit."""

from cyberjury.review.contract import SECURITY_KERNEL_FILE
from cyberjury.review.knowledge import load_review_brief


def test_brief_renders_the_kernel_once_under_its_heading():
    """The brief is the shipped kernel text under the kernel heading."""
    brief = load_review_brief()

    assert brief == f"# Security Reasoning Kernel\n{SECURITY_KERNEL_FILE.read_text(encoding='utf-8')}"
