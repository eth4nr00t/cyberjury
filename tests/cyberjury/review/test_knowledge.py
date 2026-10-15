"""The review brief binds one general security kernel to every unit."""

import pytest

from cyberjury.review.knowledge import ReviewBrief, load_review_brief


def test_brief_loads_only_the_kernel(tmp_path):
    kernel = tmp_path / "security-kernel.md"
    kernel.write_text("Trace actor, input, boundary, effect, and control.\n", encoding="utf-8")

    brief = load_review_brief(kernel_file=kernel)

    assert brief.render().count("Trace actor") == 1
    assert len(brief.content_sha256) == 64


def test_brief_rejects_missing_or_empty_kernel(tmp_path):
    with pytest.raises(ValueError, match="could not be loaded"):
        load_review_brief(kernel_file=tmp_path / "missing.md")
    with pytest.raises(ValueError, match="nonempty"):
        ReviewBrief(kernel=" ")


def test_category_qualifiers_do_not_create_new_vulnerability_classes():
    brief = ReviewBrief(kernel="Review the evidence")

    assert brief.canonicalize_category("Authorization Bypass (IDOR)") == "authorization-bypass"
    assert brief.canonicalize_category("authorization-bypass-(ownership check)") == "authorization-bypass"
    assert brief.canonicalize_category("race-condition") == "race-condition"
    assert brief.canonicalize_category("(unknown)") == "(unknown)"
