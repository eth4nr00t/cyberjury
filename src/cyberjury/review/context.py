"""Shared context envelope used by Diff Review and Repository Review."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal

from cyberjury.canonical import normalized_repository_path, text_sha256
from cyberjury.numbering import numbered_source
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.facts import FactLimitation, render_fact_limitations
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.prompts import inline_source, one_line_source
from cyberjury.review.relationships import DefinitionEvidence, RelationshipEvidenceBundle

if TYPE_CHECKING:
    from cyberjury.review.navigation import SourceNavigator
    from cyberjury.sources.snapshot import SourceSnapshot


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_EVIDENCE_REQUESTS_PER_BATCH = 64
_MAX_EVIDENCE_ID_CHARS = 128


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
        content_hash = text_sha256(self.text)
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
        content_hash = text_sha256(text)
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
    """One exact source range read through a verified source provider."""

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


class EvidenceBudgetError(EvidenceRequestError):
    """One evidence exchange exceeds its published character target."""


class UnknownEvidenceRequest(EvidenceRequestError):
    """A model requested evidence identifiers absent from the current catalog."""

    def __init__(self, ids: tuple[str, ...]) -> None:
        """Retain unknown ids for one bounded response correction."""
        self.ids = ids
        super().__init__(f"evidence request contains unknown ids: {', '.join(ids)}")


@dataclass(frozen=True, kw_only=True)
class CandidateCallContext:
    """Unverified call candidates and exact candidate source receipts."""

    text: str = ""
    source_evidence: tuple[SourceEvidence, ...] = ()


def candidate_call_context(
    root: str | Path,
    plan: DefinitionUnitPlan | None,
    relationships: RelationshipEvidenceBundle,
    *,
    max_chars: int,
    callsite_ids: frozenset[str] | None = None,
) -> CandidateCallContext:
    """Expose bounded call candidates from unit seeds without promoting bindings."""
    if plan is None or not plan.seeds:
        return CandidateCallContext()
    seeds = {(seed.file, seed.name, seed.start, seed.end) for seed in plan.seeds if seed.name != "<file>"}
    definitions = {definition.id: definition for definition in relationships.definitions}
    seed_definition_ids = {
        definition.id
        for definition in relationships.definitions
        if (
            definition.source.path,
            definition.name,
            definition.source.start,
            definition.source.end,
        )
        in seeds
    }
    targets_by_callsite = {
        relationship.callsite_id: relationship
        for relationship in relationships.call_relationships
        if relationship.target_status == "candidate" and relationship.candidate_callee_definition_ids
    }
    calls_by_definition: dict[str, list[str]] = {}
    for callsite in relationships.callsites:
        spelling = callsite.callee_spelling
        receiver = callsite.receiver_expression
        if receiver and not spelling.startswith(f"{receiver}."):
            spelling = f"{receiver}.{spelling}"
        calls_by_definition.setdefault(callsite.caller_definition_id, []).append(spelling)
    candidates = []
    candidate_sources: dict[str, tuple[int, DefinitionEvidence]] = {}
    for callsite in relationships.callsites:
        relationship = targets_by_callsite.get(callsite.id)
        if (
            callsite.caller_definition_id not in seed_definition_ids
            or relationship is None
            or (callsite_ids is not None and callsite.id not in callsite_ids)
        ):
            continue
        caller = definitions[callsite.caller_definition_id]
        callees = tuple(definitions[item] for item in relationship.candidate_callee_definition_ids)
        if callsite.receiver_expression or len(callees) != 1:
            continue
        candidate_text = f"`{callees[0].id}` {callees[0].source.path}:{callees[0].name}"
        callee_calls = tuple(dict.fromkeys(calls_by_definition.get(callees[0].id, ())))[:12]
        if callee_calls:
            candidate_text += f"; candidate callee calls: {', '.join(callee_calls)}"
        expression = " ".join(callsite.expression.split())
        expression = expression if len(expression) <= 120 else expression[:117] + "..."
        same_file = caller.source.path == callees[0].source.path
        same_extension = PurePosixPath(caller.source.path).suffix == PurePosixPath(callees[0].source.path).suffix
        priority = 0 if same_file else 1 if same_extension else 2
        if callees[0].id not in seed_definition_ids:
            candidate_sources.setdefault(callees[0].id, (priority, callees[0]))
        candidates.append(
            (
                priority,
                callsite.source.path,
                callsite.source.start,
                callsite.id,
                callees[0].id,
                caller,
                f"  - relationship `{relationship.id}` callsite `{callsite.id}` `{expression}` at "
                f"{callsite.source.path}:{callsite.source.start}-{callsite.source.end}; candidates: {candidate_text}",
            )
        )
    if not candidates:
        return CandidateCallContext()
    header = (
        "Unverified direct call candidates from this unit. Each callee source is delivered below, listed in the "
        "evidence catalog, or reachable through source navigation:"
    )
    if len(header) > max_chars:
        return CandidateCallContext()
    lines = [header]
    omitted = 0
    included_candidate_ids = set()
    active_caller = ""
    for *_identity, candidate_id, caller, line in sorted(candidates):
        caller_line = f"- caller `{caller.id}` {caller.source.path}:{caller.signature or caller.name}"
        additions = (caller_line, line) if caller.id != active_caller else (line,)
        if len("\n".join((*lines, *additions))) > max_chars:
            omitted += 1
            continue
        lines.extend(additions)
        included_candidate_ids.add(candidate_id)
        active_caller = caller.id
    source_omitted = 0
    source_evidence = []
    source_chars = 0
    base = Path(root).resolve()
    for _priority, candidate in sorted(candidate_sources.values(), key=lambda item: (item[0], item[1].id)):
        if candidate.id not in included_candidate_ids:
            continue
        candidate_identity = f"{candidate.source.path}:{candidate.name}:{candidate.source.start}:{candidate.source.end}"
        path = (base / candidate.source.path).resolve()
        try:
            path.relative_to(base)
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise BackendUnavailable(f"could not materialize candidate call source {candidate.id}: {exc}") from exc
        if candidate.source.end > len(source):
            raise BackendUnavailable(f"candidate call source range exceeds {candidate.id}")
        selected = source[candidate.source.start : candidate.source.end]
        if text_sha256(selected) != candidate.source.content_sha256:
            raise BackendUnavailable(f"candidate call source content changed for {candidate.id}")
        first_line = source.count("\n", 0, candidate.source.start) + 1
        evidence = SourceEvidence(
            id=f"src-{hashlib.sha256(candidate_identity.encode()).hexdigest()[:12]}",
            identity=candidate_identity,
            text=numbered_source(candidate.source.path, selected, first_line),
            source_span=SourceSpan(
                file=candidate.source.path,
                start_line=first_line,
                end_line=first_line + max(1, len(selected.splitlines())) - 1,
            ),
        )
        if len("\n".join(lines)) + source_chars + len(evidence.text) > max_chars:
            source_omitted += 1
            continue
        source_evidence.append(evidence)
        source_chars += len(evidence.text)
    if omitted:
        omission = f"- {omitted} additional call candidates omitted by the relationship character limit"
        if len("\n".join((*lines, omission))) <= max_chars:
            lines.append(omission)
    if source_omitted:
        omission = f"- {source_omitted} candidate callee source blocks omitted by the relationship character limit"
        if len("\n".join((*lines, omission))) <= max_chars:
            lines.append(omission)
    return CandidateCallContext(text="\n".join(lines), source_evidence=tuple(source_evidence))


def publish_candidate_evidence(
    existing: tuple[EvidenceItem, ...],
    source: tuple[SourceEvidence, ...],
) -> tuple[EvidenceItem, ...]:
    """Publish candidate callee source for retrieval without claiming it was delivered."""
    candidates = tuple(
        EvidenceItem.create(
            identity=item.identity,
            label=f"candidate callee {item.identity}",
            text=item.text,
            preview=" ".join(item.text.split())[:240],
            source_span=item.source_span,
        )
        for item in source
    )
    by_id = {item.id: item for item in existing}
    for item in candidates:
        prior = by_id.get(item.id)
        if prior is not None and (prior.identity != item.identity or prior.text != item.text):
            raise ValueError(f"candidate evidence id {item.id} changed identity or content")
        by_id.setdefault(item.id, item)
    return tuple(by_id.values())


def definition_evidence(root: str | Path, plan: DefinitionUnitPlan) -> tuple[EvidenceItem, ...]:
    """Publish each complete seed definition as exact retrievable evidence."""
    base = Path(root).resolve()
    sources: dict[str, str] = {}
    items: list[EvidenceItem] = []
    for seed in dict.fromkeys(seed for seed in plan.seeds if seed.name != "<file>"):
        path = (base / seed.file).resolve()
        try:
            path.relative_to(base)
            if seed.file not in sources:
                sources[seed.file] = path.read_text(encoding="utf-8")
            source = sources[seed.file]
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise BackendUnavailable(f"could not materialize definition evidence {seed.identity}: {exc}") from exc
        if seed.end > len(source):
            raise BackendUnavailable(f"definition evidence range exceeds source {seed.identity}")
        selected = source[seed.start : seed.end]
        first_line = source[: seed.start].count("\n") + 1
        items.append(
            EvidenceItem.create(
                identity=seed.identity,
                label=f"{seed.file}:{seed.name}, complete changed definition",
                text=numbered_source(seed.file, selected, first_line),
                preview=_definition_preview(selected),
                source_span=SourceSpan(
                    file=seed.file,
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
    lines = ["Evidence catalog, source not delivered yet:"]
    lines.extend(
        f"- `{item.id}` [{len(item.text)} chars] {one_line_source(item.label)}"
        + (f" | declaration: {inline_source(item.preview)}" if item.preview else "")
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
        raise UnknownEvidenceRequest(unknown)
    selected = tuple(catalog[item] for item in ids)
    if len(selected) > 1 and sum(len(item.text) for item in selected) > target_chars:
        raise EvidenceBudgetError(f"evidence request exceeds the {target_chars} character target")
    return EvidenceSelection(
        text="\n\n".join(item.text for item in selected),
        coverage=GroundingCoverage(
            required=tuple(item.identity for item in selected),
            included=tuple(item.identity for item in selected),
        ),
    )


def evidence_request_ids(requested: object) -> tuple[str, ...]:
    """Validate one exact request batch and collapse semantically identical ids."""
    if not isinstance(requested, list) or not all(isinstance(item, str) for item in requested):
        raise EvidenceRequestError("evidence_requests must be a list of evidence ids")
    if len(requested) > _MAX_EVIDENCE_REQUESTS_PER_BATCH:
        raise EvidenceRequestError("evidence_requests cannot contain more than 64 ids")
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
    return tuple(
        dict.fromkeys(
            (
                *(seed.file for seed in plan.seeds),
                *plan.seed_files,
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
    source_snapshot: SourceSnapshot | None = None
    snapshot_files: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject malformed or ambiguous initial evidence."""
        if not isinstance(self.text, str) or not isinstance(self.facts, str):
            raise ValueError("grounding context text fields must be strings")
        if self.source not in {"diff", "repository"}:
            raise ValueError("grounding context source is invalid")
        if not isinstance(self.coverage, GroundingCoverage):
            raise ValueError("grounding context coverage is invalid")
        for label, paths in (("files", self.files), ("snapshot files", self.snapshot_files)):
            _unique_strings(paths, label)
            for path in paths:
                normalized_repository_path(path, "grounding source path")
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
        if self.source_snapshot is not None and not self.source_snapshot.matches_scope_and_files(
            self.snapshot_files or self.source_snapshot.files
        ):
            raise BackendUnavailable("repository source changed during review")

    @property
    def prompt(self) -> EvidencePromptContext:
        """Separate stable unit evidence from engine owned controls."""
        source = "\n\n".join(
            block for block in (self.text, *(delivered_source_block(item) for item in self.source_evidence)) if block
        )
        return EvidencePromptContext(
            source=source,
            catalog=evidence_index(self.evidence),
            navigation_available=self.navigator is not None,
        )


def delivered_source_block(item: SourceEvidence) -> str:
    """Label source the review agent delivered before the model requested anything."""
    return f"Initial source `{item.id}`, delivered by the review agent:\n{item.text}"


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

    def normalized(path: str) -> str:
        return path.strip().replace("\\", "/").removeprefix("./")

    requested = normalized(file)
    candidates: list[tuple[str, SourceSpan]] = []
    if "seed" in evidence_refs:
        candidates.extend(("seed", span) for span in seed_spans)
    cited = set(evidence_refs)
    candidates.extend(
        (item.id, item.source_span) for item in source_evidence if item.id in cited and item.source_span is not None
    )
    for evidence_ref, span in candidates:
        canonical = normalized(span.file)
        if canonical == requested and span.start_line <= line <= span.end_line:
            return SourceLocationReceipt(file=canonical, line=line, evidence_ref=evidence_ref)
    return None


@dataclass(frozen=True, kw_only=True)
class EvidencePromptContext:
    """Stable unit evidence followed by the engine controls of one model call."""

    source: str
    catalog: str = ""
    delivered: tuple[str, ...] = ()
    correction: str = ""
    provisional: str = ""
    budget: str = ""
    revision: int = 0
    navigation_available: bool = False

    def __post_init__(self) -> None:
        """Reject a revision that cannot represent ordered evidence calls."""
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or self.revision < 0:
            raise ValueError("evidence prompt revision must be a nonnegative integer")
        if not isinstance(self.navigation_available, bool):
            raise ValueError("evidence prompt navigation state must be boolean")
        if not isinstance(self.delivered, tuple) or not all(isinstance(item, str) for item in self.delivered):
            raise ValueError("evidence prompt delivered exchanges must be strings")

    @property
    def followup(self) -> str:
        """Render delivered exchanges, then the one current correction, provisional findings, and budget."""
        parts = (*self.delivered, self.correction, self.provisional, self.budget)
        return "\n\n".join(part for part in parts if part)

    @property
    def controls(self) -> str:
        """Render everything after the unit source, in prompt order."""
        return "\n\n".join(part for part in (self.catalog, self.followup) if part)
