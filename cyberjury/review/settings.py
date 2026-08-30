"""Named settings that shape review coverage, cost, and execution.

Fields prefixed with ``max`` are strict bounds. Fields prefixed with ``target`` are
packing goals that selected evidence may exceed. Defaults remain at their baseline values
until a two arm backtest supports changing them.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from math import isfinite


def _field_values(settings: object) -> dict[str, int | float]:
    return {item.name: getattr(settings, item.name) for item in fields(settings)}


def _require_positive_ints(**values: int) -> None:
    invalid = [
        name for name, value in values.items() if isinstance(value, bool) or not isinstance(value, int) or value <= 0
    ]
    if invalid:
        raise ValueError(f"review integer settings must be positive integers: {', '.join(invalid)}")


def _require_positive_numbers(**values: float) -> None:
    invalid = [
        name
        for name, value in values.items()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or value <= 0
    ]
    if invalid:
        raise ValueError(f"review numeric settings must be positive and finite: {', '.join(invalid)}")


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeSettings:
    """Packing settings for selected vulnerability knowledge."""

    target_chars_per_judgment: int = 6_000
    max_classes_per_judgment: int = 4

    def __post_init__(self) -> None:
        """Prevent an empty budget from dropping selected knowledge classes."""
        _require_positive_ints(**_field_values(self))


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
    max_diff_grounding_chars_per_review: int = 8_000
    max_relationship_chars_per_unit: int = 60_000
    default_batch_concurrency: int = 1

    def __post_init__(self) -> None:
        """Keep changed code inside the prompt budget and every limit usable."""
        values = _field_values(self)
        _require_positive_numbers(max_related_context_fraction=values.pop("max_related_context_fraction"))
        _require_positive_ints(**values)
        if self.max_related_context_fraction > 1:
            raise ValueError("max_related_context_fraction cannot exceed 1")
        if self.max_changed_source_prefix_chars > self.target_repository_context_chars_per_unit:
            raise ValueError("max_changed_source_prefix_chars cannot exceed the context limit")


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryReviewSettings:
    """Discovery, unit construction, and context settings for Repository Review."""

    max_source_chars_per_unit: int = 24_000
    hard_split_overlap_chars: int = 2_000
    max_secondary_source_chars_per_file: int = 24_000
    target_gathered_source_chars_per_unit: int = 120_000
    max_relationship_chars_per_unit: int = 60_000
    max_facts_chars_per_unit: int = 16_000
    max_related_files_per_unit: int = 20
    import_closure_depth: int = 2
    max_scanned_source_bytes_per_file: int = 2_000_000
    default_max_rounds: int = 24
    min_adversarial_rounds: int = 2

    def __post_init__(self) -> None:
        """Guarantee source windows advance and configured rounds can finish."""
        _require_positive_ints(**_field_values(self))
        if self.hard_split_overlap_chars >= self.max_source_chars_per_unit:
            raise ValueError("hard_split_overlap_chars must be smaller than the source unit limit")
        if self.min_adversarial_rounds > self.default_max_rounds:
            raise ValueError("repository minimum rounds cannot exceed its library maximum")


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationSettings:
    """Source and model output settings for shared verification work."""

    max_source_chars_per_finding: int = 40_000
    skeptic_max_output_tokens: int = 2_048
    confirmer_max_output_tokens: int = 1_024

    def __post_init__(self) -> None:
        """Prevent zero budgets from disabling a verification step."""
        _require_positive_ints(**_field_values(self))


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingDeduplicationSettings:
    """Recall sensitive thresholds for collapsing repeated repository evidence."""

    min_evidence_chars_for_similarity: int = 120
    near_duplicate_similarity_threshold: float = 0.92

    def __post_init__(self) -> None:
        """Keep fuzzy matching meaningful without exceeding exact similarity."""
        values = _field_values(self)
        _require_positive_numbers(near_duplicate_similarity_threshold=values.pop("near_duplicate_similarity_threshold"))
        _require_positive_ints(**values)
        if self.near_duplicate_similarity_threshold > 1:
            raise ValueError("near_duplicate_similarity_threshold cannot exceed 1")


@dataclass(frozen=True, slots=True, kw_only=True)
class ReviewExecutionSettings:
    """Cross target execution defaults exposed by public review interfaces."""

    reviewer_max_output_tokens: int = 4_096
    default_adversarial_rounds: int = 3
    clean_rounds_to_converge: int = 2
    default_model_call_concurrency: int = 8
    verification_votes_required: int = 1
    target_evidence_request_chars: int = 48_000
    max_source_navigation_followups: int = 8

    def __post_init__(self) -> None:
        """Prevent zero defaults from silently skipping review work."""
        _require_positive_ints(**_field_values(self))


@dataclass(frozen=True, slots=True, kw_only=True)
class ReviewSettings:
    """The complete discoverable settings surface owned by the review engine."""

    knowledge: KnowledgeSettings = field(default_factory=KnowledgeSettings)
    diff: DiffReviewSettings = field(default_factory=DiffReviewSettings)
    repository: RepositoryReviewSettings = field(default_factory=RepositoryReviewSettings)
    verification: VerificationSettings = field(default_factory=VerificationSettings)
    deduplication: FindingDeduplicationSettings = field(default_factory=FindingDeduplicationSettings)
    execution: ReviewExecutionSettings = field(default_factory=ReviewExecutionSettings)


DEFAULT_REVIEW_SETTINGS = ReviewSettings()
