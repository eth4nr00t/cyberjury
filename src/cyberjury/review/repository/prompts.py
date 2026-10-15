"""Finder contract and prompt plan for repository review units."""

from __future__ import annotations

import json

from cyberjury.review.prompts import CATEGORY_FIELD, SEVERITY_FIELD, PromptPlan, finder_system
from cyberjury.review.schemas import closed_object, finder_response_schema, string_array

REPOSITORY_FINDING_SCHEMA = closed_object(
    {
        "title": {"type": "string"},
        "category": {"type": "string"},
        "symbol": {"type": "string"},
        "endpoint": {"type": "string"},
        "file": {"type": "string"},
        "line": {"type": "integer"},
        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "attack_path": {"type": "string"},
        "evidence": {"type": "string"},
        "evidence_refs": string_array(),
    }
)
FINDER_RESPONSE_SCHEMA = finder_response_schema("repository_finder_reply", REPOSITORY_FINDING_SCHEMA)

_REPOSITORY_SCOPE = """The user message contains one repository review unit: its source, syntax hints, delivered \
source, an evidence catalog, and findings already recorded for this repository. Review the unit's code. Other \
repository source is context for tracing inputs, controls, and effects."""

_REPOSITORY_FIELDS = f"""- `findings`: one entry per reported vulnerability; empty when there is none.
- `title`: a short name for the vulnerability.
{CATEGORY_FIELD}
- `symbol`: the function or method that contains `file` and `line`, or empty.
- `endpoint`: the attacker-reachable route or operation where the exploit path starts, or empty when there is none.
- `file`, `line`: where the fix must be applied, inside source covered by a cited evidence id.
{SEVERITY_FIELD}
- `attack_path`: the concrete steps from attacker input to impact.
- `evidence`: the delivered source facts, cited by evidence id, that establish the missing or broken control and \
the implementation flaw.
- `evidence_refs`: the evidence ids that establish the exploit path, including one whose source covers `file` and \
`line`."""


def repository_finder_system(*, review_brief: str, severity_rubric: str, navigation: str) -> str:
    """Render the repository finder contract shared by every unit of one run."""
    return finder_system(
        target="one repository review unit",
        scope=_REPOSITORY_SCOPE,
        output_fields=_REPOSITORY_FIELDS,
        review_brief=review_brief,
        severity_rubric=severity_rubric,
        navigation=navigation,
    )


def known_findings_block(known: list[dict]) -> str:
    """Render findings recorded before this unit with only the fields that identify them."""
    if not known:
        return ""
    records = [{field: item.get(field) for field in ("title", "category", "file", "line")} for item in known]
    return (
        "Already recorded; do not report them again. Report only vulnerabilities that need a different fix:\n"
        f"{json.dumps(records, ensure_ascii=False)}"
    )


def repository_prompt_plan(evidence: str, *, known: list[dict], catalog: str = "", followup: str = "") -> PromptPlan:
    """Keep one unit's evidence and known findings ahead of the controls that change between calls."""
    blocks = [evidence.strip(), known_findings_block(known), catalog]
    stable_prefix = "\n\n".join(block for block in blocks if block) + "\n\n"
    return PromptPlan(stable_prefix=stable_prefix, dynamic_suffix=followup)
