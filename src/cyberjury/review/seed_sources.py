"""Source evidence derived from unit seeds: complete seed definitions and their candidate callees."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from cyberjury.numbering import split_lines
from cyberjury.review.context import (
    EvidenceItem,
    SourceEvidence,
    delivered_source_block,
    numbered_source_range,
    source_id,
)
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.prompts import inline_source, one_line_source
from cyberjury.review.relationships import (
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
)


@dataclass(frozen=True, kw_only=True)
class CandidateCallContext:
    """Unverified call candidates with the exact receipt of each candidate callee source."""

    text: str = ""
    delivered: tuple[SourceEvidence, ...] = ()
    published: tuple[EvidenceItem, ...] = ()

    @property
    def source_files(self) -> tuple[str, ...]:
        """Return every file whose candidate callee source is delivered or published."""
        spans = (*(item.source_span for item in self.delivered), *(item.source_span for item in self.published))
        return tuple(dict.fromkeys(span.file for span in spans if span is not None))


_CALL_CANDIDATE_HEADER = (
    "Unverified direct call candidates from this unit. Each candidate callee is a syntax match, and "
    "each line states where its source is available:"
)
_RECEIPT_PLACEHOLDER = f"source `src-{'0' * 12}` in the evidence catalog"


def _delivered_receipt(item_id: str) -> str:
    return f"source `{item_id}` delivered below"


def _catalog_receipt(item_id: str) -> str:
    return f"source `{item_id}` in the evidence catalog"


type _Call = tuple[CallsiteEvidence, DefinitionEvidence, DefinitionEvidence]


class _CandidateSources:
    def __init__(self, root: str | Path) -> None:
        self._base = Path(root).resolve()
        self._texts: dict[str, str] = {}

    def text(self, path: str, subject: str) -> str:
        if path not in self._texts:
            try:
                self._texts[path] = (self._base / path).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise BackendUnavailable(f"could not materialize candidate call source {subject}: {exc}") from exc
        return self._texts[path]

    def lines(self, reference: SourceReference, subject: str) -> tuple[int, int]:
        text = self.text(reference.path, subject)
        first = text.count("\n", 0, reference.start) + 1
        return first, text.count("\n", 0, max(reference.start, reference.end - 1)) + 1


@dataclass(frozen=True)
class _CallListing:
    sources: _CandidateSources
    calls_by_definition: Mapping[str, list[str]]

    def caller_line(self, caller: DefinitionEvidence) -> str:
        return f"- caller {one_line_source(caller.source.path)}: {_inline_code(caller.signature or caller.name)}"

    def call_line(self, callsite: CallsiteEvidence, callee: DefinitionEvidence, receipt: str) -> str:
        line, _ = self.sources.lines(callsite.source, callsite.id)
        callee_start, callee_end = self.sources.lines(callee.source, callee.id)
        expression = " ".join(callsite.expression.split())
        expression = expression if len(expression) <= 120 else expression[:117] + "..."
        text = (
            f"  - {inline_source(expression)} at {one_line_source(callsite.source.path)}:{line}, candidate callee "
            f"{one_line_source(callee.source.path)}:{one_line_source(callee.name)} lines "
            f"{callee_start}-{callee_end}, {receipt}"
        )
        callee_calls = tuple(dict.fromkeys(self.calls_by_definition.get(callee.id, ())))[:12]
        if callee_calls:
            text += f", candidate callee calls: {', '.join(_inline_code(call) for call in callee_calls)}"
        return text

    def render(self, calls: Iterable[_Call], receipt: Callable[[DefinitionEvidence], str]) -> list[str]:
        lines = [_CALL_CANDIDATE_HEADER]
        active_caller = ""
        for callsite, caller, callee in calls:
            if caller.id != active_caller:
                lines.append(self.caller_line(caller))
                active_caller = caller.id
            lines.append(self.call_line(callsite, callee, receipt(callee)))
        return lines


def _calls_by_definition(relationships: RelationshipEvidenceBundle) -> dict[str, list[str]]:
    calls: dict[str, list[str]] = {}
    for callsite in relationships.callsites:
        spelling = callsite.callee_spelling
        receiver = callsite.receiver_expression
        if receiver and not spelling.startswith(f"{receiver}."):
            spelling = f"{receiver}.{spelling}"
        calls.setdefault(callsite.caller_definition_id, []).append(spelling)
    return calls


def _single_candidate_calls(
    relationships: RelationshipEvidenceBundle,
    seed_ids: set[str],
    callsite_ids: frozenset[str] | None,
) -> list[_Call]:
    definitions = {definition.id: definition for definition in relationships.definitions}
    targets = {
        relationship.callsite_id: relationship
        for relationship in relationships.call_relationships
        if relationship.target_status == "candidate" and relationship.candidate_callee_definition_ids
    }
    calls: list[_Call] = []
    for callsite in sorted(relationships.callsites, key=lambda item: (item.source.path, item.source.start, item.id)):
        relationship = targets.get(callsite.id)
        if (
            callsite.caller_definition_id not in seed_ids
            or relationship is None
            or (callsite_ids is not None and callsite.id not in callsite_ids)
            or callsite.receiver_expression
            or len(relationship.candidate_callee_definition_ids) != 1
        ):
            continue
        callee = definitions[relationship.candidate_callee_definition_ids[0]]
        calls.append((callsite, definitions[callsite.caller_definition_id], callee))
    return calls


def _budgeted_calls(listing: _CallListing, calls: list[_Call], max_chars: int) -> tuple[list[_Call], int]:
    lines = [_CALL_CANDIDATE_HEADER]
    included: list[_Call] = []
    omitted = 0
    active_caller = ""
    for callsite, caller, callee in calls:
        call = listing.call_line(callsite, callee, _RECEIPT_PLACEHOLDER)
        additions = (listing.caller_line(caller), call) if caller.id != active_caller else (call,)
        if len("\n".join((*lines, *additions))) > max_chars:
            omitted += 1
            continue
        lines.extend(additions)
        included.append((callsite, caller, callee))
        active_caller = caller.id
    return included, omitted


def _callee_sources(
    sources: _CandidateSources,
    included: list[_Call],
    seed_ids: set[str],
    budget: int,
) -> tuple[list[tuple[DefinitionEvidence, SourceEvidence, str]], int]:
    selected_sources: list[tuple[DefinitionEvidence, SourceEvidence, str]] = []
    used = 0
    omitted = 0
    for callee in dict.fromkeys(callee for _callsite, _caller, callee in included):
        if callee.id in seed_ids:
            continue
        source = sources.text(callee.source.path, callee.id)
        selected = source[callee.source.start : callee.source.end]
        text, span = numbered_source_range(callee.source.path, source, callee.source.start, callee.source.end)
        evidence = SourceEvidence(id=source_id(callee.identity), identity=callee.identity, text=text, source_span=span)
        if used + len(evidence.text) > budget:
            omitted += 1
            continue
        selected_sources.append((callee, evidence, _definition_preview(selected)))
        used += len(evidence.text)
    return selected_sources, omitted


def _deliver_or_publish(
    callee_sources: list[tuple[DefinitionEvidence, SourceEvidence, str]],
    catalog: tuple[EvidenceItem, ...],
    deliver_budget: int,
) -> tuple[list[SourceEvidence], list[EvidenceItem], dict[str, str]]:
    delivered: list[SourceEvidence] = []
    published: list[EvidenceItem] = []
    receipts = {item.identity: _catalog_receipt(item.id) for item in catalog}
    for callee, evidence, preview in callee_sources:
        cost = len(delivered_source_block(evidence)) + 2
        if cost <= deliver_budget:
            delivered.append(evidence)
            deliver_budget -= cost
            receipts[evidence.identity] = _delivered_receipt(evidence.id)
            continue
        span = evidence.source_span
        item = EvidenceItem.create(
            identity=evidence.identity,
            label=f"candidate callee {span.file}:{callee.name} lines {span.start_line}-{span.end_line}",
            text=evidence.text,
            preview=preview,
            source_span=span,
        )
        published.append(item)
        receipts[evidence.identity] = _catalog_receipt(item.id)
    return delivered, published, receipts


def candidate_call_context(
    root: str | Path,
    plan: DefinitionUnitPlan | None,
    relationships: RelationshipEvidenceBundle,
    *,
    max_chars: int,
    callsite_ids: frozenset[str] | None = None,
    catalog: tuple[EvidenceItem, ...] = (),
    deliver_chars: int,
) -> CandidateCallContext:
    """Expose bounded call candidates from unit seeds, in source order, without promoting bindings."""
    if plan is None or not plan.seeds:
        return CandidateCallContext()
    seed_ids = {seed.id for seed in plan.seeds if seed.kind != "file"}
    calls = _single_candidate_calls(relationships, seed_ids, callsite_ids)
    if not calls:
        return CandidateCallContext()
    listing = _CallListing(_CandidateSources(root), _calls_by_definition(relationships))
    included, omitted = _budgeted_calls(listing, calls, max_chars)
    listed_chars = len("\n".join(listing.render(included, lambda _callee: _RECEIPT_PLACEHOLDER)))
    callee_sources, source_omitted = _callee_sources(listing.sources, included, seed_ids, max_chars - listed_chars)
    delivered, published, receipts = _deliver_or_publish(
        callee_sources, catalog, min(deliver_chars, max(0, max_chars - listed_chars))
    )

    def receipt(callee: DefinitionEvidence) -> str:
        if callee.identity in receipts:
            return receipts[callee.identity]
        if callee.id in seed_ids:
            return "source in the code under review"
        return "source reachable through source navigation"

    rendered = listing.render(included, receipt)
    for count, noun in ((omitted, "call candidates"), (source_omitted, "candidate callee source blocks")):
        omission = f"- {count} additional {noun} omitted by the relationship character limit"
        if count and len("\n".join((*rendered, omission))) <= max_chars:
            rendered.append(omission)
    return CandidateCallContext(text="\n".join(rendered), delivered=tuple(delivered), published=tuple(published))


def _inline_code(source: str) -> str:
    return inline_source(" ".join(source.split()))


def definition_evidence(root: str | Path, plan: DefinitionUnitPlan) -> tuple[EvidenceItem, ...]:
    """Publish each complete seed definition as exact retrievable evidence."""
    base = Path(root).resolve()
    sources: dict[str, str] = {}
    items: list[EvidenceItem] = []
    for seed in plan.seeds:
        if seed.kind == "file":
            continue
        file, start, end = seed.source.path, seed.source.start, seed.source.end
        try:
            if file not in sources:
                sources[file] = (base / file).read_text(encoding="utf-8")
            source = sources[file]
        except (OSError, UnicodeDecodeError) as exc:
            raise BackendUnavailable(f"could not materialize definition evidence {seed.identity}: {exc}") from exc
        text, span = numbered_source_range(file, source, start, end)
        items.append(
            EvidenceItem.create(
                identity=seed.identity,
                label=f"{file}:{seed.name}, complete changed definition",
                text=text,
                preview=_definition_preview(source[start:end]),
                source_span=span,
            )
        )
    return tuple(items)


def _definition_preview(source: str) -> str:
    parts: list[str] = []
    for raw in split_lines(source):
        line = raw.strip()
        if not line:
            continue
        if "{" in line:
            line = line.partition("{")[0].rstrip() + " {"
        parts.append(line)
        preview = " ".join(parts)
        if len(preview) >= 240 or line.endswith(":") or "{" in line or line.endswith(";"):
            break
        if len(parts) == 3:
            break
    return " ".join(parts)[:240]
