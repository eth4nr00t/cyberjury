"""The review brief binds one general security kernel to every unit."""

import pytest

from cyberjury.review.knowledge import ReviewBrief, load_review_brief


def test_brief_loads_only_the_kernel(tmp_path):
    """A brief built from one kernel file renders its text once under the kernel heading."""
    kernel = tmp_path / "security-kernel.md"
    kernel.write_text("Trace actor, input, boundary, effect, and control.\n", encoding="utf-8")

    brief = load_review_brief(kernel_file=kernel)

    assert brief.render().count("Trace actor") == 1
    assert brief.render().startswith("# Security Reasoning Kernel\n")


def test_brief_rejects_missing_or_empty_kernel(tmp_path):
    """A missing kernel file raises "could not be loaded" and a whitespace-only kernel raises "nonempty"."""
    with pytest.raises(ValueError, match="could not be loaded"):
        load_review_brief(kernel_file=tmp_path / "missing.md")
    with pytest.raises(ValueError, match="nonempty"):
        ReviewBrief(kernel=" ")
