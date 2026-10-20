"""Source fences remain intact, and every target sends one user message envelope."""

import pytest

from cyberjury.review.context import EvidencePromptContext, GroundingContext, SourceEvidence, SourceSpan
from cyberjury.review.prompts import PromptPlan, fenced_source, inline_source, one_line_source


def test_fenced_source_preserves_the_common_prompt_shape():
    """Plain source gets a bare triple-backtick fence, and a "diff" tag follows the opening fence."""
    assert fenced_source("value = 1") == "```\nvalue = 1\n```"
    assert fenced_source("+value = 1", "diff") == "```diff\n+value = 1\n```"


def test_fenced_source_uses_a_delimiter_absent_from_the_source():
    """Source containing backtick fences switches to tildes, and nested fences get a longer backtick run."""
    assert fenced_source('value = "```"') == '~~~\nvalue = "```"\n~~~'
    assert fenced_source("first\n```\nsecond") == "~~~\nfirst\n```\nsecond\n~~~"
    assert fenced_source('value = "~~~"') == '```\nvalue = "~~~"\n```'
    assert fenced_source("````\n~~~~", "diff") == "`````diff\n````\n~~~~\n`````"


def test_inline_source_and_labels_cannot_break_their_prompt_line():
    """Embedded backticks get double-backtick padding, and newline, CR, and U+2028 are escaped literally."""
    assert inline_source("plain") == "`plain`"
    assert inline_source("part`next") == "`` part`next ``"
    assert inline_source("`leading") == "`` `leading ``"
    assert one_line_source("first\nsecond\rthird\u2028fourth") == "first\\nsecond\\rthird\\u2028fourth"


def test_every_target_sends_seed_notices_delivered_source_hints_then_catalog_before_the_controls():
    """The stable prefix orders seed, notices, initial source, then hints, and the suffix is the follow-up."""
    delivered = SourceEvidence(
        id="src-000000000001",
        identity="lib.py:helper:0:9",
        text="# file: lib.py lines 1-1\n1 | helper()",
        source_span=SourceSpan(file="lib.py", start_line=1, end_line=1),
    )
    context = GroundingContext(
        text="NOTICES AND CALL CANDIDATES",
        seed="SEED",
        syntax_hints="HINTS",
        source_evidence=(delivered,),
    )
    prompt = context.prompt
    plan = prompt.plan

    assert plan.stable_prefix.index("SEED") < plan.stable_prefix.index("NOTICES AND CALL CANDIDATES")
    assert plan.stable_prefix.index("NOTICES") < plan.stable_prefix.index("Initial source `src-000000000001`")
    assert plan.stable_prefix.index("Initial source") < plan.stable_prefix.index("HINTS")
    assert plan.stable_prefix.endswith("HINTS\n\n")
    assert plan.dynamic_suffix == prompt.followup


def test_delivered_exchanges_are_the_cache_segments_that_lead_the_follow_up():
    """Two delivered exchanges before the budget become two segments, and text equals prefix, segments, rest."""
    plan = EvidencePromptContext(source="SEED", delivered=("FIRST", "SECOND"), budget="BUDGET").plan

    assert plan.cache_segments == ("FIRST\n\n", "SECOND\n\n")
    assert plan.text == "SEED\n\nFIRST\n\nSECOND\n\nBUDGET"
    assert EvidencePromptContext(source="SEED", delivered=("ONLY",)).plan.cache_segments == ()


def test_prompt_plan_rejects_segments_that_do_not_lead_the_suffix():
    """Segments that are not the start of the dynamic suffix raise ValueError."""
    with pytest.raises(ValueError, match="lead the dynamic suffix"):
        PromptPlan(stable_prefix="SEED", dynamic_suffix="BUDGET", cache_segments=("FIRST",))
