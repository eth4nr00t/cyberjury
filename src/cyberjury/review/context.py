"""Shared context envelope used by Diff Review and Repository Review."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from cyberjury.canonical import normalized_repository_path
from cyberjury.numbering import numbered_source, split_lines
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.facts import FactLimitation, render_fact_limitations
from cyberjury.review.paths import normalized_location_path
from cyberjury.review.prompts import PromptPlan, fenced_source, inline_source, one_line_source

if TYPE_CHECKING:
    from cyberjury.review.navigation import SourceNavigator
    from cyberjury.sources.snapshot import SourceSnapshot


_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_EVIDENCE_REQUESTS_PER_BATCH = 64
_MAX_EVIDENCE_ID_CHARS = 128


def _unique_strings(values: tuple[str, ...], label: str) -> None:
    if not isinstance(values, tuple) or not all(isinstance(value, str) and value for value in values):
        raise ValueError(f"grounding {label} must be a tuple of nonempty strings")
    if len(values) != len(set(values)):
        raise ValueError(f"grounding {label} must not contain duplicates")


@dataclass(frozen=True, kw_only=True)
class GroundingCoverage:
    """Evidence obligations and the subset available to one judgment."""

    required: tuple[str, ...] = ()
    included: tuple[str, ...] = ()
    omitted: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require canonical evidence obligation sets."""
        for label, values in (
            ("required identities", self.required),
            ("included identities", self.included),
            ("omitted identities", self.omitted),
            ("unresolved identities", self.unresolved),
            ("limitation identities", self.limitations),
            ("reference ids", self.references),
        ):
            _unique_strings(values, label)

    def to_dict(self) -> dict[str, object]:
        """Return the strict coverage record."""
        return {
            "required": list(self.required),
            "included": list(self.included),
            "omitted": list(self.omitted),
            "unresolved": list(self.unresolved),
            "limitations": list(self.limitations),
            "references": list(self.references),
        }

    @property
    def missing(self) -> tuple[str, ...]:
        """Return every required evidence identity absent from the prompt."""
        absent = set(self.required).difference(self.included)
        return tuple(dict.fromkeys((*self.omitted, *sorted(absent))))

    @property
    def complete(self) -> bool:
        """Require every known obligation to be resolved and included, while fact limitations stay advisory."""
        return not self.missing and not self.unresolved

    @property
    def failure_reason(self) -> str:
        """Explain why this grounding cannot support a complete judgment."""
        reasons: list[str] = []
        if self.missing:
            reasons.append(f"omitted required evidence: {', '.join(self.missing)}")
        if self.unresolved:
            reasons.append(f"unresolved required evidence: {', '.join(self.unresolved)}")
        return f"grounding incomplete, {'; '.join(reasons)}" if reasons else ""


@dataclass(frozen=True, kw_only=True)
class SourceSpan:
    """Record the source lines covered by one delivered fragment."""

    file: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        """Reject unsafe paths and invalid line ranges."""
        normalized_repository_path(self.file, "grounding source path")
        if (
            isinstance(self.start_line, bool)
            or not isinstance(self.start_line, int)
            or isinstance(self.end_line, bool)
            or not isinstance(self.end_line, int)
            or self.start_line < 1
            or self.end_line < self.start_line
        ):
            raise ValueError("grounding source span must have a valid line range")

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
        if not (identity and label and text):
            raise ValueError("evidence item identity, label, and text must be nonempty strings")
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
    """One exact source range read through a verified source provider."""

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
    """Add retrievable evidence to a catalog without letting one id change identity or content."""
    by_id = {item.id: item for item in existing}
    for item in items:
        prior = by_id.get(item.id)
        if prior is not None and (prior.identity != item.identity or prior.text != item.text):
            raise ValueError(f"candidate evidence id {item.id} changed identity or content")
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
    *,
    target_chars: int,
) -> EvidenceSelection:
    """Resolve ids validated by `evidence_request_ids` against the catalog, failing on any unpublished id."""
    ids = tuple(dict.fromkeys(requested))
    catalog = {item.id: item for item in items}
    unknown = tuple(item for item in ids if item not in catalog)
    if unknown:
        raise UnknownEvidenceRequest(unknown)
    selected = tuple(catalog[item] for item in ids)
    if len(selected) > 1 and sum(len(item.text) for item in selected) > target_chars:
        raise EvidenceBudgetError(f"evidence request exceeds the {target_chars} character target")
    return EvidenceSelection(
        text="\n\n".join(
            f"Read evidence `{item.id}` {one_line_source(item.label)}:\n{fenced_source(item.text)}" for item in selected
        ),
        coverage=GroundingCoverage(
            required=tuple(item.identity for item in selected),
            included=tuple(item.identity for item in selected),
        ),
    )


def is_evidence_id(value: str) -> bool:
    """Report whether one value has the published evidence id format."""
    return len(value) <= _MAX_EVIDENCE_ID_CHARS and _EVIDENCE_ID.fullmatch(value) is not None


def evidence_request_ids(requested: object) -> tuple[str, ...]:
    """Validate one exact request batch and collapse semantically identical ids."""
    if not isinstance(requested, list) or not all(isinstance(item, str) for item in requested):
        raise EvidenceRequestError("evidence_requests must be a list of evidence ids")
    if len(requested) > MAX_EVIDENCE_REQUESTS_PER_BATCH:
        raise EvidenceRequestError(f"evidence_requests cannot contain more than {MAX_EVIDENCE_REQUESTS_PER_BATCH} ids")
    if any(not item or item != item.strip() for item in requested):
        raise EvidenceRequestError("evidence_requests must contain nonempty exact evidence ids")
    if any(len(item) > _MAX_EVIDENCE_ID_CHARS for item in requested):
        raise EvidenceRequestError("evidence_requests contain an oversized evidence id")
    if any(not _EVIDENCE_ID.fullmatch(item) for item in requested):
        raise EvidenceRequestError("evidence_requests contain a malformed evidence id")
    return tuple(dict.fromkeys(requested))


def merge_grounding_coverage(values: tuple[GroundingCoverage, ...]) -> GroundingCoverage:
    """Merge coverage receipts without losing any incomplete obligation."""

    def unique(items: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(items))

    required = unique(tuple(item for value in values for item in value.required))
    included = unique(tuple(item for value in values for item in value.included))
    delivered = set(included)
    return GroundingCoverage(
        required=required,
        included=included,
        omitted=tuple(
            item for item in unique(tuple(item for value in values for item in value.omitted)) if item not in delivered
        ),
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
    source_snapshot: SourceSnapshot | None = None
    snapshot_files: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject ambiguous initial evidence."""
        for label, paths in (("files", self.files), ("snapshot files", self.snapshot_files)):
            _unique_strings(paths, label)
            for path in paths:
                normalized_repository_path(path, "grounding source path")
        for label, items in (("evidence catalog", self.evidence), ("source evidence", self.source_evidence)):
            if len({item.id for item in items}) != len(items):
                raise ValueError(f"grounding context {label} ids must be unique")
            if label == "evidence catalog" and len({item.identity for item in items}) != len(items):
                raise ValueError(f"grounding context {label} identities must be unique")
        source_by_identity: dict[str, SourceEvidence] = {}
        for item in self.source_evidence:
            existing = source_by_identity.get(item.identity)
            if existing is not None and (existing.text != item.text or existing.source_span != item.source_span):
                raise ValueError("grounding source evidence aliases must bind identical source")
            source_by_identity[item.identity] = item
        catalog = {item.id: item for item in self.evidence}
        for delivered in self.source_evidence:
            published = catalog.get(delivered.id)
            if published is not None and (delivered.identity != published.identity or delivered.text != published.text):
                raise ValueError("grounding context delivered evidence differs from its catalog entry")

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


def with_source_evidence(
    context: GroundingContext,
    evidence: tuple[SourceEvidence, ...],
) -> GroundingContext:
    """Extend one unit with exact source read by its navigation session."""
    by_id = {item.id: item for item in context.source_evidence}
    delivered_by_id: dict[str, SourceEvidence] = {}
    for item in evidence:
        existing = delivered_by_id.get(item.id) or by_id.get(item.id)
        if existing is not None and existing != item:
            raise ValueError(f"source evidence id {item.id} changed identity or content")
        delivered_by_id[item.id] = item
        by_id[item.id] = item
    delivered_items = tuple(delivered_by_id.values())
    identities = tuple(dict.fromkeys(item.identity for item in delivered_items))
    delivered = GroundingCoverage(
        required=identities,
        included=identities,
        references=tuple(item.id for item in delivered_items),
    )
    snapshot_files = context.snapshot_files
    if snapshot_files:
        snapshot_files = tuple(
            dict.fromkeys(
                (*snapshot_files, *(item.source_span.file for item in delivered_items if item.source_span is not None))
            )
        )
    return replace(
        context,
        source_evidence=tuple(by_id.values()),
        coverage=merge_grounding_coverage((context.coverage, delivered)),
        snapshot_files=snapshot_files,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceLocationReceipt:
    """One canonical source location bound to the evidence that exposed it."""

    file: str
    line: int
    evidence_ref: str


def source_location_receipt(
    *,
    file: str,
    line: int,
    evidence_refs: tuple[str, ...],
    seed_spans: tuple[SourceSpan, ...] = (),
    source_evidence: tuple[SourceEvidence, ...] = (),
) -> SourceLocationReceipt | None:
    """Return the first cited source span that covers one exact location."""
    if not isinstance(file, str) or not file.strip():
        return None
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None
    if not isinstance(evidence_refs, tuple) or not all(isinstance(item, str) and item for item in evidence_refs):
        return None
    requested = normalized_location_path(file)
    for evidence_ref, span in _cited_spans(evidence_refs, seed_spans, source_evidence):
        canonical = normalized_location_path(span.file)
        if canonical == requested and span.start_line <= line <= span.end_line:
            return SourceLocationReceipt(file=canonical, line=line, evidence_ref=evidence_ref)
    return None


def cited_source_spans(
    evidence_refs: tuple[str, ...],
    *,
    seed_spans: tuple[SourceSpan, ...] = (),
    source_evidence: tuple[SourceEvidence, ...] = (),
) -> tuple[SourceSpan, ...]:
    """Return the distinct source spans that one finding's evidence refs cite, in canonical path form."""
    return tuple(
        dict.fromkeys(
            replace(span, file=normalized_location_path(span.file))
            for _evidence_ref, span in _cited_spans(evidence_refs, seed_spans, source_evidence)
        )
    )


def _cited_spans(
    evidence_refs: tuple[str, ...],
    seed_spans: tuple[SourceSpan, ...],
    source_evidence: tuple[SourceEvidence, ...],
) -> list[tuple[str, SourceSpan]]:
    candidates: list[tuple[str, SourceSpan]] = []
    if "seed" in evidence_refs:
        candidates.extend(("seed", span) for span in seed_spans)
    cited = set(evidence_refs)
    candidates.extend(
        (item.id, item.source_span) for item in source_evidence if item.id in cited and item.source_span is not None
    )
    return candidates


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

    def __post_init__(self) -> None:
        """Reject navigation state and delivered exchanges of the wrong type."""
        if not isinstance(self.navigation_available, bool):
            raise ValueError("evidence prompt navigation state must be boolean")
        if not isinstance(self.delivered, tuple) or not all(isinstance(item, str) for item in self.delivered):
            raise ValueError("evidence prompt delivered exchanges must be strings")

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
