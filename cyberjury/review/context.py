"""Shared context envelope used by Diff Review and Repository Review."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from cyberjury.numbering import numbered_source
from cyberjury.review.definitions import DefinitionDependency, DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.facts import FactLimitation, render_fact_limitations
from cyberjury.review.failures import BackendUnavailable

if TYPE_CHECKING:
    from cyberjury.review.navigation import SourceNavigator


@dataclass(frozen=True, kw_only=True)
class GroundingCoverage:
    """Evidence obligations and the subset available to one judgment."""

    required: tuple[str, ...] = ()
    included: tuple[str, ...] = ()
    omitted: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def missing(self) -> tuple[str, ...]:
        """Return every required evidence identity absent from the prompt."""
        absent = set(self.required).difference(self.included)
        return tuple(dict.fromkeys((*self.omitted, *sorted(absent))))

    @property
    def complete(self) -> bool:
        """Require every known obligation to be resolved and included."""
        return self.reviewable and not self.limitations

    @property
    def reviewable(self) -> bool:
        """Allow judgment when limitations are visible but required evidence is present."""
        return not self.missing and not self.unresolved

    @property
    def failure_reason(self) -> str:
        """Explain why this grounding cannot support a complete judgment."""
        reasons: list[str] = []
        if self.missing:
            reasons.append(f"omitted required evidence: {', '.join(self.missing)}")
        if self.unresolved:
            reasons.append(f"unresolved required evidence: {', '.join(self.unresolved)}")
        if self.limitations:
            reasons.append(f"structured facts unavailable: {', '.join(self.limitations)}")
        return f"grounding incomplete, {'; '.join(reasons)}" if reasons else ""


@dataclass(frozen=True, kw_only=True)
class EvidenceItem:
    """One exact source fragment available through a bounded evidence request."""

    id: str
    identity: str
    label: str
    text: str
    preview: str = ""

    @classmethod
    def create(
        cls,
        *,
        identity: str,
        label: str,
        text: str,
        preview: str = "",
    ) -> EvidenceItem:
        """Build a stable opaque id from the exact source identity."""
        digest = hashlib.sha256(identity.encode()).hexdigest()[:12]
        return cls(id=f"ev-{digest}", identity=identity, label=label, text=text, preview=preview)


@dataclass(frozen=True, kw_only=True)
class EvidenceSelection:
    """Validated evidence returned for one model request."""

    text: str
    coverage: GroundingCoverage


class EvidenceRequestError(RuntimeError):
    """A model requested evidence outside the published catalog or budget."""


@dataclass(frozen=True)
class RelationshipEvidence:
    """One resolved definition edge that must remain visible and receipted."""

    identity: str
    summary: str


def definition_relationships(plan: DefinitionUnitPlan) -> tuple[RelationshipEvidence, ...]:
    """Preserve exact dependency semantics beside the selected source fragments."""
    relationships = []
    for edge in plan.dependencies:
        source = edge.source.identity if edge.source is not None else edge.source_file
        relationships.append(
            RelationshipEvidence(
                identity=edge.identity,
                summary=(
                    f"{source} --{edge.kind} {edge.reference or edge.target.name} "
                    f"[{edge.resolution}]--> {edge.target.identity}"
                ),
            )
        )
    return tuple(relationships)


def render_relationships(relationships: tuple[RelationshipEvidence, ...]) -> str:
    """Render the graph semantics that make co-located definitions meaningful."""
    if not relationships:
        return ""
    return "Resolved definition relationships:\n" + "\n".join(
        f"- {relationship.summary}" for relationship in relationships
    )


def definition_evidence(
    root: str | Path,
    plan: DefinitionUnitPlan,
    *,
    include_seeds: bool = False,
) -> tuple[EvidenceItem, ...]:
    """Materialize dependency targets omitted from the initial source window."""
    base = Path(root).resolve()
    included = set(plan.fragments)
    if include_seeds:
        included.difference_update(plan.seeds)
    edges_by_target: dict[DefinitionFragment, list[DefinitionDependency]] = {}
    for edge in plan.dependencies:
        if edge.target not in included:
            edges_by_target.setdefault(edge.target, []).append(edge)
    if include_seeds:
        for seed in plan.seeds:
            edges_by_target.setdefault(seed, [])
    sources: dict[str, str] = {}
    items: list[EvidenceItem] = []
    for target, edges in edges_by_target.items():
        path = (base / target.file).resolve()
        try:
            path.relative_to(base)
            source = sources.setdefault(target.file, path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise BackendUnavailable(f"could not materialize dependency evidence {target.identity}: {exc}") from exc
        if target.end > len(source):
            raise BackendUnavailable(f"dependency evidence range exceeds source {target.identity}")
        first_line = source[: target.start].count("\n") + 1
        relationships = (
            ", ".join(
                dict.fromkeys(
                    f"{edge.kind} {edge.reference or target.name} from "
                    f"{edge.source.name if edge.source is not None else edge.source_file} [{edge.resolution}]"
                    for edge in edges
                )
            )
            if edges
            else "complete changed definition"
        )
        items.append(
            EvidenceItem.create(
                identity=target.identity,
                label=f"{target.file}:{target.name}, {relationships}",
                text=numbered_source(target.file, source[target.start : target.end], first_line),
                preview=_definition_preview(source[target.start : target.end]),
            )
        )
    return tuple(items)


def _definition_preview(source: str, max_chars: int = 240) -> str:
    """Render a compact exact declaration without exposing an implementation body."""
    parts: list[str] = []
    for raw in source.splitlines():
        line = raw.strip()
        if not line:
            continue
        if "{" in line:
            line = line.partition("{")[0].rstrip() + " {"
        parts.append(line)
        preview = " ".join(parts)
        if len(preview) >= max_chars or line.endswith(":") or "{" in line or line.endswith(";"):
            break
        if len(parts) == 3:
            break
    return " ".join(parts)[:max_chars]


def evidence_index(items: tuple[EvidenceItem, ...]) -> str:
    """Render the exact evidence ids a reviewer may request."""
    if not items:
        return ""
    lines = [
        "Additional repository evidence available by id:",
        "Request an id only when its source is needed to establish a controlling fact.",
    ]
    lines.extend(
        f"- `{item.id}` [{len(item.text)} chars] {item.label}"
        + (f" | declaration: `{item.preview}`" if item.preview else "")
        for item in items
    )
    return "\n".join(lines)


def select_evidence(
    items: tuple[EvidenceItem, ...],
    requested: object,
    *,
    target_chars: int,
) -> EvidenceSelection:
    """Resolve only published ids and fail rather than return partial evidence."""
    if not isinstance(requested, list) or not all(isinstance(item, str) for item in requested):
        raise EvidenceRequestError("evidence_requests must be a list of evidence ids")
    ids = tuple(dict.fromkeys(item.strip() for item in requested if item.strip()))
    catalog = {item.id: item for item in items}
    unknown = tuple(item for item in ids if item not in catalog)
    if unknown:
        raise EvidenceRequestError(f"evidence request contains unknown ids: {', '.join(unknown)}")
    selected = tuple(catalog[item] for item in ids)
    if len(selected) > 1 and sum(len(item.text) for item in selected) > target_chars:
        raise EvidenceRequestError(f"evidence request exceeds the {target_chars} character target")
    return EvidenceSelection(
        text="\n\n".join(item.text for item in selected),
        coverage=GroundingCoverage(
            required=tuple(item.identity for item in selected),
            included=tuple(item.identity for item in selected),
        ),
    )


def merge_grounding_coverage(values: tuple[GroundingCoverage, ...]) -> GroundingCoverage:
    """Merge coverage receipts without losing any incomplete obligation."""

    def unique(items: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(items))

    return GroundingCoverage(
        required=unique(tuple(item for value in values for item in value.required)),
        included=unique(tuple(item for value in values for item in value.included)),
        omitted=unique(tuple(item for value in values for item in value.omitted)),
        unresolved=unique(tuple(item for value in values for item in value.unresolved)),
        limitations=unique(tuple(item for value in values for item in value.limitations)),
        references=unique(tuple(item for value in values for item in value.references)),
    )


def definition_plan_source_files(plan: DefinitionUnitPlan | None) -> tuple[str, ...]:
    """Return every source published by one definition plan."""
    if plan is None:
        return ()
    return tuple(
        dict.fromkeys(
            (
                *(seed.file for seed in plan.seeds),
                *plan.seed_files,
                *(
                    file
                    for dependency in plan.dependencies
                    for file in (
                        dependency.source.file if dependency.source is not None else dependency.source_file,
                        dependency.target.file,
                    )
                ),
                *(fragment.file for fragment in plan.evidence),
            )
        )
    )


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
    files: tuple[str, ...] = ()
    source: Literal["diff", "repository"] = "repository"
    coverage: GroundingCoverage = field(default_factory=GroundingCoverage)
    evidence: tuple[EvidenceItem, ...] = ()
    navigator: SourceNavigator | None = None
    controls: str = ""

    @property
    def selection_text(self) -> str:
        """Expose all exact unit evidence to the profile knowledge selector."""
        return "\n\n".join(block for block in (self.text, *(item.text for item in self.evidence)) if block)

    @property
    def prompt_text(self) -> str:
        """Combine initial source with the bounded evidence catalog."""
        prompt = self.prompt
        return "\n\n".join(block for block in (prompt.source, prompt.controls) if block)

    @property
    def prompt(self) -> EvidencePromptContext:
        """Separate repository source from engine owned review controls."""
        if self.controls:
            return EvidencePromptContext(source=self.text, controls=self.controls)
        controls = [evidence_reference_instructions(), evidence_index(self.evidence)]
        if self.navigator is not None:
            from cyberjury.review.navigation import navigation_instructions

            controls.append(navigation_instructions())
        return EvidencePromptContext(
            source=self.text,
            controls="\n\n".join(block for block in controls if block),
        )


@dataclass(frozen=True, kw_only=True)
class EvidencePromptContext:
    """Repository source and trusted orchestration controls for one model call."""

    source: str
    controls: str = ""


def evidence_reference_instructions() -> str:
    """Describe the evidence references accepted on model findings."""
    return (
        "Every finding must include a nonempty `evidence_refs` list. Use `seed` for the code under "
        "review, an `ev-*` id for published repository evidence, and a `src-*` id returned by source "
        "search. Citing published but unread evidence asks the engine to deliver its source. The finding "
        "remains provisional and must be returned again after delivery. Search results alone are not "
        "finding evidence."
    )
