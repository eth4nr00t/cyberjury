"""Shared context envelope used by diff review and repository review."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from cyberjury.numbering import numbered_source, split_lines
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.facts import FactLimitation, render_fact_limitations
from cyberjury.review.paths import normalized_location_path
from cyberjury.review.prompts import PromptPlan, fenced_source, inline_source, one_line_source
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

if TYPE_CHECKING:
    from cyberjury.review.navigation import SourceNavigator


_EXECUTION = DEFAULT_REVIEW_SETTINGS.execution
_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_EVIDENCE_ID_CHARS = 128


@dataclass(frozen=True, kw_only=True)
class GroundingCoverage:
    """The evidence one judgment holds, what it could not resolve, and the fact limitations it saw."""

    included: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the coverage record."""
        return {
            "included": list(self.included),
            "unresolved": list(self.unresolved),
            "limitations": list(self.limitations),
            "references": list(self.references),
        }

    @property
    def complete(self) -> bool:
        """Require every evidence need to be resolved, while fact limitations stay advisory."""
        return not self.unresolved

    @property
    def failure_reason(self) -> str:
        """Explain why this grounding cannot support a complete judgment."""
        return (
            f"grounding incomplete, unresolved required evidence: {', '.join(self.unresolved)}"
            if self.unresolved
            else ""
        )


@dataclass(frozen=True, kw_only=True)
class SourceSpan:
    """The source lines covered by one delivered fragment."""

    file: str
    start_line: int
    end_line: int

    def to_dict(self) -> dict[str, object]:
        """Return one exact source line range."""
        return {"file": self.file, "range": [self.start_line, self.end_line]}


def numbered_source_range(file: str, source: str, start: int, end: int) -> tuple[str, SourceSpan]:
    """Number one exact character range of a file and record the lines it covers."""
    selected = source[start:end]
    first_line = source.count("\n", 0, start) + 1
    return numbered_source(file, selected, first_line), SourceSpan(
        file=file,
        start_line=first_line,
        end_line=first_line + max(1, len(split_lines(selected))) - 1,
    )


def source_id(identity: str) -> str:
    """Return the one published id of an exact named source range, whoever publishes it."""
    return f"src-{hashlib.sha256(identity.encode()).hexdigest()[:12]}"


@dataclass(frozen=True, kw_only=True)
class EvidenceItem:
    """One exact source fragment available through a bounded evidence request."""

    id: str
    identity: str
    label: str
    text: str
    preview: str = ""
    source_span: SourceSpan | None = None

    @classmethod
    def create(
        cls,
        *,
        identity: str,
        label: str,
        text: str,
        preview: str = "",
        source_span: SourceSpan | None = None,
    ) -> EvidenceItem:
        """Publish one exact source range under its source id."""
        return cls(
            id=source_id(identity),
            identity=identity,
            label=label,
            text=text,
            preview=preview,
            source_span=source_span,
        )


@dataclass(frozen=True, kw_only=True)
class SourceEvidence:
    """One exact source range delivered to the model under its receipt id and span."""

    id: str
    identity: str
    text: str
    source_span: SourceSpan | None = None


@dataclass(frozen=True, kw_only=True)
class EvidenceSelection:
    """Validated evidence returned for one model request."""

    text: str
    coverage: GroundingCoverage


class EvidenceRequestError(RuntimeError):
    """A model requested evidence outside the published catalog or budget."""


class EvidenceBudgetError(EvidenceRequestError):
    """One evidence exchange exceeds its published character target."""


class UnknownEvidenceRequest(EvidenceRequestError):
    """A model requested evidence identifiers absent from the current catalog."""

    def __init__(self, ids: tuple[str, ...]) -> None:
        """Retain unknown ids for one bounded response correction."""
        self.ids = ids
        super().__init__(f"evidence request contains unknown ids: {', '.join(ids)}")


def publish_evidence(
    existing: tuple[EvidenceItem, ...],
    items: tuple[EvidenceItem, ...],
) -> tuple[EvidenceItem, ...]:
    """Add retrievable evidence to a catalog, keeping the first item of each id."""
    by_id = {item.id: item for item in existing}
    for item in items:
        by_id.setdefault(item.id, item)
    return tuple(by_id.values())


def evidence_index(items: tuple[EvidenceItem, ...]) -> str:
    """Render the exact evidence ids a reviewer may request."""
    if not items:
        return ""
    lines = ["Evidence catalog (source is delivered only on request):"]
    lines.extend(
        f"- `{item.id}` [{len(item.text)} chars] {one_line_source(item.label)}"
        + (f" | declaration: {inline_source(item.preview)}" if item.preview else "")
        for item in items
    )
    return "\n".join(lines)


def select_evidence(
    items: tuple[EvidenceItem, ...],
    requested: Iterable[str],
) -> EvidenceSelection:
    """Render the published evidence of the given distinct ids, which the caller checked against the catalog."""
    catalog = {item.id: item for item in items}
    selected = tuple(catalog[item] for item in requested)
    return EvidenceSelection(
        text="\n\n".join(
            f"Read evidence `{item.id}` {one_line_source(item.label)}:\n{fenced_source(item.text)}" for item in selected
        ),
        coverage=GroundingCoverage(included=tuple(item.identity for item in selected)),
    )


def is_evidence_id(value: str) -> bool:
    """Report whether one value has the published evidence id format."""
    return len(value) <= _MAX_EVIDENCE_ID_CHARS and _EVIDENCE_ID.fullmatch(value) is not None


def evidence_request_ids(requested: list[str]) -> tuple[str, ...]:
    """Validate one exact request batch and collapse semantically identical ids."""
    if len(requested) > _EXECUTION.max_evidence_requests_per_batch:
        raise EvidenceRequestError(
            f"evidence_requests cannot contain more than {_EXECUTION.max_evidence_requests_per_batch} ids"
        )
    if any(len(item) > _MAX_EVIDENCE_ID_CHARS for item in requested):
        raise EvidenceRequestError("evidence_requests contain an oversized evidence id")
    if any(not _EVIDENCE_ID.fullmatch(item) for item in requested):
        raise EvidenceRequestError("evidence_requests contain a malformed evidence id")
    return tuple(dict.fromkeys(requested))


def merge_grounding_coverage(values: tuple[GroundingCoverage, ...]) -> GroundingCoverage:
    """Merge coverage receipts without losing any incomplete obligation."""

    def unique(items: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(items))

    included = unique(tuple(item for value in values for item in value.included))
    delivered = set(included)
    return GroundingCoverage(
        included=included,
        unresolved=tuple(
            item
            for item in unique(tuple(item for value in values for item in value.unresolved))
            if item not in delivered
        ),
        limitations=unique(tuple(item for value in values for item in value.limitations)),
        references=unique(tuple(item for value in values for item in value.references)),
    )


def definition_plan_source_files(plan: DefinitionUnitPlan | None) -> tuple[str, ...]:
    """Return every source published by one definition plan."""
    if plan is None:
        return ()
    return tuple(dict.fromkeys((*(seed.source.path for seed in plan.seeds), *plan.seed_files)))


def files_without_seed_definitions(plan: DefinitionUnitPlan | None, files: Iterable[str]) -> tuple[str, ...]:
    """Return the files a unit reviews without any seed definition other than the whole file."""
    seeded = {seed.source.path for seed in plan.seeds if seed.kind != "file"} if plan is not None else set()
    return tuple(file for file in dict.fromkeys(files) if file not in seeded)


def syntax_hints(
    plan: DefinitionUnitPlan | None,
    files: Iterable[str],
    by_file: Mapping[str, str],
    *,
    max_chars_per_file: int,
) -> str:
    """Render bounded syntax hints, one labeled block per unit file without a seed definition."""
    blocks = []
    for file in files_without_seed_definitions(plan, files):
        hints = by_file.get(file) or ""
        if not hints:
            continue
        truncated = f", first {max_chars_per_file} characters" if len(hints) > max_chars_per_file else ""
        blocks.append(
            f"{one_line_source(file)}: syntax hints (unverified, cite only delivered source){truncated}:\n"
            f"{fenced_source(hints[:max_chars_per_file])}"
        )
    return "\n\n".join(blocks)


def with_scoped_fact_limitations(
    context: GroundingContext,
    limitations: tuple[FactLimitation, ...],
    *,
    source_files: tuple[str, ...],
) -> GroundingContext:
    """Attach only source limitations published by one grounding unit."""
    scope = set(source_files)
    scoped = tuple(limitation for limitation in limitations if limitation.source in scope)
    if not scoped:
        return context
    limitation_text = render_fact_limitations(scoped)
    return replace(
        context,
        text="\n\n".join(part for part in (limitation_text, context.text) if part),
        coverage=merge_grounding_coverage(
            (
                context.coverage,
                GroundingCoverage(limitations=tuple(limitation.identity for limitation in scoped)),
            )
        ),
    )


@dataclass(frozen=True, kw_only=True)
class GroundingContext:
    """Prompt context with an explicit source boundary and reviewed files."""

    text: str
    seed: str = ""
    syntax_hints: str = ""
    files: tuple[str, ...] = ()
    coverage: GroundingCoverage = field(default_factory=GroundingCoverage)
    evidence: tuple[EvidenceItem, ...] = ()
    source_spans: tuple[SourceSpan, ...] = ()
    source_evidence: tuple[SourceEvidence, ...] = ()
    navigator: SourceNavigator | None = None
    snapshot_files: tuple[str, ...] = ()

    @property
    def prompt(self) -> EvidencePromptContext:
        """Separate stable unit evidence from engine owned controls."""
        blocks = (
            self.seed,
            self.text,
            *(delivered_source_block(item) for item in self.source_evidence),
            self.syntax_hints,
        )
        source = "\n\n".join(block for block in blocks if block)
        return EvidencePromptContext(
            source=source,
            catalog=evidence_index(self.evidence),
            navigation_available=self.navigator is not None,
        )


def delivered_source_block(item: SourceEvidence) -> str:
    """Label source the review agent delivered before the model requested anything."""
    return f"Initial source `{item.id}`, delivered by the review agent:\n{fenced_source(item.text)}"


def cited_location_file(
    *,
    file: str,
    line: int,
    evidence_refs: tuple[str, ...],
    seed_spans: tuple[SourceSpan, ...],
    source_evidence: tuple[SourceEvidence, ...],
) -> str | None:
    """Return the canonical path of the first cited source span that covers one exact location."""
    requested = normalized_location_path(file)
    spans = cited_source_spans(evidence_refs, seed_spans=seed_spans, source_evidence=source_evidence)
    return next(
        (span.file for span in spans if span.file == requested and span.start_line <= line <= span.end_line), None
    )


def cited_source_spans(
    evidence_refs: tuple[str, ...],
    *,
    seed_spans: tuple[SourceSpan, ...],
    source_evidence: tuple[SourceEvidence, ...],
) -> tuple[SourceSpan, ...]:
    """Return the distinct source spans that one finding's evidence refs cite, in canonical path form."""
    cited = set(evidence_refs)
    spans = (
        *(seed_spans if "seed" in cited else ()),
        *(item.source_span for item in source_evidence if item.id in cited and item.source_span is not None),
    )
    return tuple(dict.fromkeys(replace(span, file=normalized_location_path(span.file)) for span in spans))


@dataclass(frozen=True, kw_only=True)
class EvidencePromptContext:
    """Stable unit evidence followed by the engine controls of one model call."""

    source: str
    catalog: str = ""
    delivered: tuple[str, ...] = ()
    correction: str = ""
    provisional: str = ""
    budget: str = ""
    navigation_available: bool = False

    @property
    def followup(self) -> str:
        """Render delivered exchanges, then the one current correction, provisional findings, and budget."""
        return "\n\n".join(self._followup_parts)

    @property
    def _followup_parts(self) -> list[str]:
        return [part for part in (*self.delivered, self.correction, self.provisional, self.budget) if part]

    @property
    def controls(self) -> str:
        """Render everything after the unit source, in prompt order."""
        return "\n\n".join(part for part in (self.catalog, self.followup) if part)

    @property
    def plan(self) -> PromptPlan:
        """Keep the unit evidence and catalog ahead of the controls that change between calls."""
        stable = "\n\n".join(part for part in (self.source, self.catalog) if part)
        parts = self._followup_parts
        delivered = sum(1 for part in self.delivered if part)
        segments = tuple(f"{part}\n\n" for part in parts[: min(delivered, len(parts) - 1)])
        return PromptPlan(stable_prefix=f"{stable}\n\n", dynamic_suffix=self.followup, cache_segments=segments)
