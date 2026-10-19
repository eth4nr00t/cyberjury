"""Source fences remain intact, and every target sends one user message envelope."""

from cyberjury.review.context import GroundingContext, SourceEvidence, SourceSpan
from cyberjury.review.prompts import fenced_source, inline_source, one_line_source


def test_fenced_source_preserves_the_common_prompt_shape():
    assert fenced_source("value = 1") == "```\nvalue = 1\n```"
    assert fenced_source("+value = 1", "diff") == "```diff\n+value = 1\n```"


def test_fenced_source_uses_a_delimiter_absent_from_the_source():
    assert fenced_source('value = "```"') == '~~~\nvalue = "```"\n~~~'
    assert fenced_source("first\n```\nsecond") == "~~~\nfirst\n```\nsecond\n~~~"
    assert fenced_source('value = "~~~"') == '```\nvalue = "~~~"\n```'
    assert fenced_source("````\n~~~~", "diff") == "`````diff\n````\n~~~~\n`````"


def test_inline_source_and_labels_cannot_break_their_prompt_line():
    assert inline_source("plain") == "`plain`"
    assert inline_source("part`next") == "`` part`next ``"
    assert inline_source("`leading") == "`` `leading ``"
    assert one_line_source("first\nsecond\rthird\u2028fourth") == "first\\nsecond\\rthird\\u2028fourth"


def test_every_target_sends_seed_notices_delivered_source_hints_then_catalog_before_the_controls():
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
