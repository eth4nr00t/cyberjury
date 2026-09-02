"""Shared context envelope used by Diff Review and Repository Review."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal

from cyberjury.numbering import numbered_source
from cyberjury.review.definitions import DefinitionDependency, DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.facts import FactLimitation, render_fact_limitations
from cyberjury.review.failures import BackendUnavailable

if TYPE_CHECKING:
    from cyberjury.review.navigation import SourceNavigator
    from cyberjury.sources.snapshot import SourceSnapshot


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _source_path(path: str) -> str:
    if not isinstance(path, str):
        raise ValueError("grounding source path must be a normalized repository path")
    normalized = PurePosixPath(path)
    if (
        not path
        or path == "."
        or path.startswith("/")
        or "\\" in path
        or normalized.as_posix() != path
        or ".." in normalized.parts
    ):
        raise ValueError("grounding source path must be a normalized repository path")
    return path


def _unique_strings(values: tuple[str, ...], label: str) -> None:
    if not isinstance(values, tuple) or not all(isinstance(value, str) and value for value in values):
        raise ValueError(f"grounding {label} must be a tuple of nonempty strings")
    if len(values) != len(set(values)):
        raise ValueError(f"grounding {label} must not contain duplicates")


@dataclass(frozen=True, kw_only=True)
class EvidenceRevision:
    """Content identity for one complete model judgment input."""

    source_snapshot_key: str
    seed_sha256: str
    evidence: tuple[tuple[str, str], ...]
    source_evidence: tuple[tuple[str, str], ...]
    controls_sha256: str

    def __post_init__(self) -> None:
        """Reject an incomplete or malformed evidence identity."""
        if not isinstance(self.source_snapshot_key, str) or not isinstance(self.seed_sha256, str):
            raise ValueError("evidence revision source identity is invalid")
        for value in (self.seed_sha256, self.controls_sha256):
            if not _SHA256.fullmatch(value):
                raise ValueError("evidence revision content hash is invalid")
        for label, values in (("evidence", self.evidence), ("source evidence", self.source_evidence)):
            identities = []
            for identity, content_hash in values:
                if not identity or not _SHA256.fullmatch(content_hash):
                    raise ValueError(f"evidence revision {label} is invalid")
                identities.append(identity)
            if len(identities) != len(set(identities)):
                raise ValueError(f"evidence revision {label} identities must be unique")

    @property
    def id(self) -> str:
        """Return one stable digest for comparison, trace, and persistence."""
        digest = hashlib.sha256()
        digest.update(b"evidence-revision-v1\x00")
        for value in (self.source_snapshot_key, self.seed_sha256, self.controls_sha256):
            digest.update(value.encode("utf-8"))
            digest.update(b"\x00")
        for identity, content_hash in (*self.evidence, *self.source_evidence):
            digest.update(identity.encode("utf-8"))
            digest.update(b"\x00")
            digest.update(content_hash.encode("ascii"))
            digest.update(b"\x00")
        return f"revision-{digest.hexdigest()[:24]}"


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

    @classmethod
    def from_dict(cls, value: object) -> GroundingCoverage:
        """Load one exact coverage record."""
        fields = {"required", "included", "omitted", "unresolved", "limitations", "references"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("grounding coverage has an unsupported shape")
        if any(not isinstance(value[field], list) for field in fields):
            raise ValueError("grounding coverage fields must be lists")
        return cls(**{field: tuple(value[field]) for field in fields})

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
class SourceSpan:
    """Record the source lines covered by one delivered fragment."""

    file: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        """Reject unsafe paths and invalid line ranges."""
        _source_path(self.file)
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

    @classmethod
    def from_dict(cls, value: object) -> SourceSpan:
        """Load one exact source line range."""
        if not isinstance(value, dict) or set(value) != {"file", "range"}:
            raise ValueError("grounding source span has an unsupported shape")
        line_range = value["range"]
        if not isinstance(line_range, list) or len(line_range) != 2:
            raise ValueError("grounding source span range must contain start and end")
        return cls(file=value["file"], start_line=line_range[0], end_line=line_range[1])


@dataclass(frozen=True, kw_only=True)
class EvidenceItem:
    """One exact source fragment available through a bounded evidence request."""

    id: str
    identity: str
    label: str
    text: str
    preview: str = ""
    source_span: SourceSpan | None = None

    def __post_init__(self) -> None:
        """Require one content bound catalog entry."""
        if not all(isinstance(value, str) and value for value in (self.identity, self.label, self.text)):
            raise ValueError("evidence item identity, label, and text must be nonempty strings")
        content_hash = _text_sha256(self.text)
        expected_id = f"ev-{hashlib.sha256(f'{self.identity}\0{content_hash}'.encode()).hexdigest()[:12]}"
        if self.id != expected_id:
            raise ValueError("evidence item id does not match its identity and content")
        if not isinstance(self.preview, str):
            raise ValueError("evidence item preview must be a string")
        if self.source_span is not None and not isinstance(self.source_span, SourceSpan):
            raise ValueError("evidence item source span is invalid")

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
        """Build a stable opaque id from the exact source identity."""
        content_hash = _text_sha256(text)
        digest = hashlib.sha256(f"{identity}\0{content_hash}".encode()).hexdigest()[:12]
        return cls(
            id=f"ev-{digest}",
            identity=identity,
            label=label,
            text=text,
            preview=preview,
            source_span=source_span,
        )


@dataclass(frozen=True, kw_only=True)
class SourceEvidence:
    """One exact source range read through repository navigation."""

    id: str
    identity: str
    text: str
    source_span: SourceSpan | None = None

    def __post_init__(self) -> None:
        """Require one exact delivered source receipt."""
        if not isinstance(self.id, str) or not self.id.startswith(("ev-", "src-")):
            raise ValueError("source evidence id must use the ev- or src- namespace")
        if not isinstance(self.identity, str) or not self.identity or not isinstance(self.text, str) or not self.text:
            raise ValueError("source evidence identity and text must be nonempty strings")
        if self.source_span is not None and not isinstance(self.source_span, SourceSpan):
            raise ValueError("source evidence source span is invalid")


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


def render_unresolved_relationships(identities: tuple[str, ...]) -> str:
    """Render unresolved relationship identities as clues, never proven edges."""
    if not identities:
        return ""
    return "Unresolved definition relationship clues. These are not established bindings:\n" + "\n".join(
        f"- {identity}" for identity in identities
    )


def definition_evidence(
    root: str | Path,
    plan: DefinitionUnitPlan,
    *,
    include_seeds: bool = False,
) -> tuple[EvidenceItem, ...]:
    """Materialize dependency targets omitted from the initial source window."""
    base = Path(root).resolve()
    included = {fragment for fragment in plan.fragments if fragment.name != "<file>"}
    if include_seeds:
        included.difference_update(plan.seeds)
    edges_by_target: dict[DefinitionFragment, list[DefinitionDependency]] = {}
    for edge in plan.dependencies:
        if edge.target not in included:
            edges_by_target.setdefault(edge.target, []).append(edge)
    if include_seeds:
        for seed in plan.seeds:
            if seed.name != "<file>":
                edges_by_target.setdefault(seed, [])
    sources: dict[str, str] = {}
    items: list[EvidenceItem] = []
    for target, edges in edges_by_target.items():
        path = (base / target.file).resolve()
        try:
            path.relative_to(base)
            if target.file not in sources:
                sources[target.file] = path.read_text(encoding="utf-8")
            source = sources[target.file]
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise BackendUnavailable(f"could not materialize dependency evidence {target.identity}: {exc}") from exc
        if target.end > len(source):
            raise BackendUnavailable(f"dependency evidence range exceeds source {target.identity}")
        selected = source[target.start : target.end]
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
                text=numbered_source(target.file, selected, first_line),
                preview=_definition_preview(selected),
                source_span=SourceSpan(
                    file=target.file,
                    start_line=first_line,
                    end_line=first_line + max(1, len(selected.splitlines())) - 1,
                ),
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
    ids = evidence_request_ids(requested)
    if len({item.id for item in items}) != len(items) or len({item.identity for item in items}) != len(items):
        raise EvidenceRequestError("evidence catalog contains duplicate ids or identities")
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


def evidence_request_ids(requested: object) -> tuple[str, ...]:
    """Validate one exact request batch without repairing malformed model output."""
    if not isinstance(requested, list) or not all(isinstance(item, str) for item in requested):
        raise EvidenceRequestError("evidence_requests must be a list of evidence ids")
    if any(not item or item != item.strip() for item in requested):
        raise EvidenceRequestError("evidence_requests must contain nonempty exact evidence ids")
    if len(requested) != len(set(requested)):
        raise EvidenceRequestError("evidence_requests must not repeat evidence ids")
    return tuple(requested)


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
    facts: str = ""
    files: tuple[str, ...] = ()
    source: Literal["diff", "repository"] = "repository"
    coverage: GroundingCoverage = field(default_factory=GroundingCoverage)
    evidence: tuple[EvidenceItem, ...] = ()
    source_spans: tuple[SourceSpan, ...] = ()
    source_evidence: tuple[SourceEvidence, ...] = ()
    navigator: SourceNavigator | None = None
    controls: str = ""
    source_snapshot: SourceSnapshot | None = None
    snapshot_files: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject malformed or ambiguous initial evidence."""
        if not isinstance(self.text, str) or not isinstance(self.facts, str) or not isinstance(self.controls, str):
            raise ValueError("grounding context text fields must be strings")
        if self.source not in {"diff", "repository"}:
            raise ValueError("grounding context source is invalid")
        if not isinstance(self.coverage, GroundingCoverage):
            raise ValueError("grounding context coverage is invalid")
        for label, paths in (("files", self.files), ("snapshot files", self.snapshot_files)):
            _unique_strings(paths, label)
            for path in paths:
                _source_path(path)
        if not isinstance(self.source_spans, tuple) or not all(
            isinstance(span, SourceSpan) for span in self.source_spans
        ):
            raise ValueError("grounding context source spans are invalid")
        for label, items, expected in (
            ("evidence catalog", self.evidence, EvidenceItem),
            ("source evidence", self.source_evidence, SourceEvidence),
        ):
            if not isinstance(items, tuple) or not all(isinstance(item, expected) for item in items):
                raise ValueError(f"grounding context {label} is invalid")
            if len({item.id for item in items}) != len(items):
                raise ValueError(f"grounding context {label} ids must be unique")
            if len({item.identity for item in items}) != len(items):
                raise ValueError(f"grounding context {label} identities must be unique")
        catalog = {item.id: item for item in self.evidence}
        for delivered in self.source_evidence:
            published = catalog.get(delivered.id)
            if published is not None and (delivered.identity != published.identity or delivered.text != published.text):
                raise ValueError("grounding context delivered evidence differs from its catalog entry")

    @property
    def revision(self) -> EvidenceRevision:
        """Bind every judgment input to one source and evidence identity."""
        seed = "\x00".join((self.source, *self.files, *self.snapshot_files, self.text, self.facts))
        return EvidenceRevision(
            source_snapshot_key=self.source_snapshot.snapshot_id if self.source_snapshot is not None else "",
            seed_sha256=hashlib.sha256(seed.encode("utf-8")).hexdigest(),
            evidence=tuple(
                sorted(
                    (
                        f"{item.id}\x00{item.identity}",
                        hashlib.sha256(item.text.encode("utf-8")).hexdigest(),
                    )
                    for item in self.evidence
                )
            ),
            source_evidence=tuple(
                sorted(
                    (
                        f"{item.id}\x00{item.identity}",
                        hashlib.sha256(item.text.encode("utf-8")).hexdigest(),
                    )
                    for item in self.source_evidence
                )
            ),
            controls_sha256=hashlib.sha256(self.prompt.controls.encode("utf-8")).hexdigest(),
        )

    def validate_snapshot(self) -> None:
        """Fail when source referenced by this evidence envelope changes."""
        if self.source_snapshot is not None and not self.source_snapshot.matches_files(
            self.snapshot_files or self.source_snapshot.files
        ):
            raise BackendUnavailable("repository source changed during review")

    @property
    def selection_text(self) -> str:
        """Expose all exact unit evidence to the profile knowledge selector."""
        return "\n\n".join(
            block
            for block in (
                self.text,
                *(item.text for item in self.evidence),
                *(item.text for item in self.source_evidence),
            )
            if block
        )

    @property
    def prompt_text(self) -> str:
        """Combine initial source with the bounded evidence catalog."""
        prompt = self.prompt
        return "\n\n".join(block for block in (prompt.source, prompt.controls) if block)

    @property
    def prompt(self) -> EvidencePromptContext:
        """Separate repository source from engine owned review controls."""
        source = "\n\n".join(
            block
            for block in (
                self.text,
                *(f"Navigated exact repository source `{item.id}`:\n{item.text}" for item in self.source_evidence),
            )
            if block
        )
        if self.controls:
            return EvidencePromptContext(source=source, controls=self.controls)
        controls = [evidence_reference_instructions(), evidence_index(self.evidence)]
        if self.navigator is not None:
            from cyberjury.review.navigation import navigation_instructions

            controls.append(navigation_instructions())
        return EvidencePromptContext(
            source=source,
            controls="\n\n".join(block for block in controls if block),
        )


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
    delivered = GroundingCoverage(
        required=tuple(item.identity for item in delivered_items),
        included=tuple(item.identity for item in delivered_items),
        references=tuple(item.id for item in delivered_items),
    )
    return replace(
        context,
        source_evidence=tuple(by_id.values()),
        coverage=merge_grounding_coverage((context.coverage, delivered)),
    )


def source_location_is_grounded(
    *,
    file: str,
    line: int,
    evidence_refs: tuple[str, ...],
    seed_spans: tuple[SourceSpan, ...] = (),
    source_evidence: tuple[SourceEvidence, ...] = (),
) -> bool:
    """Check that a cited evidence receipt covers one exact source location."""
    spans: list[SourceSpan] = []
    if "seed" in evidence_refs:
        spans.extend(seed_spans)
    cited = set(evidence_refs)
    spans.extend(item.source_span for item in source_evidence if item.id in cited and item.source_span is not None)
    normalized = file.replace("\\", "/").removeprefix("./")
    return any(
        span.file.replace("\\", "/").removeprefix("./") == normalized and span.start_line <= line <= span.end_line
        for span in spans
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
        "search. Request either exact id through `evidence_requests`. Citing registered but unread evidence "
        "asks the engine to deliver its source. The finding remains provisional and must be returned again "
        "after delivery. Search results alone are not finding evidence."
    )
