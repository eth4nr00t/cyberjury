"""Prompt plans and judgment blocks shared by every review target."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class PromptPlan:
    """One reusable evidence prefix followed by one changing judgment task."""

    stable_prefix: str
    judgment_suffix: str

    @property
    def text(self) -> str:
        """Preserve the exact prefix while exposing the provider's string input."""
        return f"{self.stable_prefix}{self.judgment_suffix}"


REVIEW_SYSTEM = (
    "You are a senior application security engineer. Report only real, exploitable, "
    "high-confidence vulnerabilities supported by the evidence. Every finding must have "
    "a precise location and a concrete end-to-end exploit path. Do not report style notes, "
    "generic hardening advice, or speculation. Respond with a single JSON object and nothing else."
)

FINDER_SYSTEM = (
    REVIEW_SYSTEM + " As the finding reviewer, examine every assigned vulnerability class and every "
    "plausible attack path in the evidence. Do not omit a candidate because the context is "
    "incomplete, but report it only when the evidence supports a concrete exploit path."
)

CHALLENGER_SYSTEM = (
    REVIEW_SYSTEM + " As the challenging reviewer, rebut a candidate only when the evidence shows the "
    "controlling safety fact. Independently scan the same evidence for real issues the finder "
    "missed. Preserve a candidate when safety cannot be established from the available evidence."
)

JUDGE_SYSTEM = (
    REVIEW_SYSTEM + " As the final security judge, weigh each candidate against the available evidence. "
    "Keep every finding supported by a concrete exploit path, and dismiss or downgrade only "
    "when the evidence shows why it is safe or less severe. Do not invent missing context."
)


def finder_task(scope: str) -> str:
    """Keep Finder instructions identical across review paths."""
    return (
        f"Find every exploitable vulnerability in this {scope}. Examine every assigned "
        "vulnerability class and plausible attack path. Do not omit a candidate because "
        "context is incomplete, but report it only when the evidence supports a concrete "
        "exploit path.\n\n"
    )


def challenger_task(scope: str) -> str:
    """Keep Challenger instructions identical across review paths."""
    return (
        f"Two tasks for this {scope}.\n"
        "1. Rebut a reported finding only when the evidence shows the controlling safety "
        "fact, such as a parameterized sink, containment check, allowlist, validation, or "
        "constant or trusted value. Do not dismiss a dangerous sink because the input "
        "origin is not shown.\n"
        "2. Independently scan the same evidence for real issues the Finder missed. Preserve "
        "a candidate when safety cannot be established from the available evidence.\n\n"
    )


def judge_task(scope: str) -> str:
    """Keep Judge instructions identical across review paths."""
    return (
        f"Rule on each candidate finding from the independent reviews of this {scope}.\n"
        "Keep every finding supported by a concrete exploit path. Dismiss or downgrade only "
        "when the evidence shows the controlling safety fact or a lower impact. Do not invent "
        "missing context.\n\n"
    )


def knowledge_judgment(
    categories: tuple[str, ...],
    body: str,
    *,
    selected_categories: tuple[str, ...] = (),
) -> str:
    """Assign one knowledge pack without suppressing compelling incidental findings."""
    if not categories:
        guidance = f"Relevant class guidance:\n{body}\n\n" if body else ""
        return f"Review the evidence for every real, high-impact vulnerability in scope.\n\n{guidance}"
    other_selected = tuple(category for category in selected_categories if category not in categories)
    division = (
        "The following selected classes also have assigned judgments:\n"
        + ", ".join(other_selected)
        + "\nReport any real vulnerability already established by this evidence even when another judgment "
        "also covers its class. Deterministic union handles duplicates.\n"
        if other_selected
        else "Report any compelling incidental vulnerability outside this assigned pack.\n"
    )
    return (
        "Exhaustively review the evidence for this assigned vulnerability class pack:\n"
        + ", ".join(categories)
        + "\n"
        + division
        + "An assignment does not prove a finding. Report an assigned class only when the "
        "evidence supports a concrete exploit path.\n\n" + f"Class guidance:\n{body}\n\n"
    )
