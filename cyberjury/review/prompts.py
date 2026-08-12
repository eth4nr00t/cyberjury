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
        "The following selected classes belong to other assigned judgments. Do not report "
        "them here:\n"
        + ", ".join(other_selected)
        + "\nA compelling vulnerability outside the complete selected class set may still be "
        "reported as an incidental finding.\n"
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
