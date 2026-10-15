"""Named settings that shape review coverage, cost, and execution.

Fields prefixed with ``max`` are strict bounds. Fields prefixed with ``target`` are
packing goals that selected evidence may exceed. Defaults remain at their baseline values
until a two arm backtest supports changing them.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True, kw_only=True)
class DiffReviewSettings:
    """Patch packing, retrieval, and context settings for Diff Review."""

    target_patch_chars_per_unit: int = 60_000
    target_repository_context_chars_per_unit: int = 24_000
    max_full_source_chars_per_context_file: int = 12_000
    max_changed_source_prefix_chars: int = 3_000
    max_facts_chars_per_context_file: int = 1_200
    related_context_first_min_changed_files: int = 5
    target_definition_context_chars_per_file: int = 6_000
    max_caller_definition_chars: int = 6_000
    max_related_context_fraction: float = 0.5
    hunk_context_lines_per_side: int = 5
    max_relationship_chars_per_unit: int = 60_000
    max_definition_evidence_items_per_unit: int = 64
    default_batch_concurrency: int = 4


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryReviewSettings:
    """Discovery, unit construction, and context settings for Repository Review."""

    max_source_chars_per_unit: int = 24_000
    hard_split_overlap_chars: int = 2_000
    max_relationship_chars_per_unit: int = 60_000
    max_facts_chars_per_unit: int = 16_000


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationSettings:
    """Source and model output settings for shared verification work."""

    max_source_chars_per_finding: int = 40_000
    skeptic_max_output_tokens: int = 2_048
    confirmer_max_output_tokens: int = 1_024


@dataclass(frozen=True, slots=True, kw_only=True)
class ReviewExecutionSettings:
    """Cross target execution defaults exposed by public review interfaces."""

    reviewer_max_output_tokens: int = 4_096
    default_model_call_concurrency: int = 8
    target_evidence_request_chars: int = 48_000
    max_source_navigation_followups: int = 8


@dataclass(frozen=True, slots=True, kw_only=True)
class ReviewSettings:
    """The complete discoverable settings surface owned by the review engine."""

    diff: DiffReviewSettings = field(default_factory=DiffReviewSettings)
    repository: RepositoryReviewSettings = field(default_factory=RepositoryReviewSettings)
    verification: VerificationSettings = field(default_factory=VerificationSettings)
    execution: ReviewExecutionSettings = field(default_factory=ReviewExecutionSettings)


DEFAULT_REVIEW_SETTINGS = ReviewSettings()


def positive_concurrency(value: object, label: str) -> int:
    """Return a strict positive worker count or reject it before any work starts."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be positive")
    return value
