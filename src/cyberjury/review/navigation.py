"""Bounded source navigation over verified repository facts."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol

from cyberjury.canonical import text_sha256
from cyberjury.numbering import split_lines
from cyberjury.review.context import (
    EvidenceBudgetError,
    GroundingCoverage,
    SourceEvidence,
    SourceSpan,
    merge_grounding_coverage,
    numbered_source_range,
    source_id,
)
from cyberjury.review.definitions import definitions_by_name
from cyberjury.review.paths import contained_repository_path, normalized_location_path, safe_repository_path
from cyberjury.review.prompts import fenced_source, inline_source, one_line_source
from cyberjury.review.relationships import (
    AnalysisObservation,
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
    StructuralRelationshipEvidence,
)

_MAX_RESULTS_PER_PAGE = 20
_MAX_SEARCHABLE_FILE_BYTES = 2_000_000
_SOURCE_LABELS = {"production": "source", "documentation": "documentation", "dependency": "third-party source"}
MAX_QUERIES_PER_BATCH = 8
MAX_UNIQUE_QUERIES_PER_SESSION = 64
_MAX_SOURCE_TARGET_CHARS = 24_000


class SourceNavigationError(RuntimeError):
    """A source query is malformed, unsafe, or exceeds its budget."""


class SourceBudgetError(SourceNavigationError, EvidenceBudgetError):
    """Source query results or reads exceed the exchange character target."""


class SourceQueryLimitError(SourceNavigationError):
    """A model returned more source queries than one batch permits."""

    def __init__(self, count: int, limit: int) -> None:
        """Retain the observed count and published limit for correction."""
        self.count = count
        self.limit = limit
        self.response_findings: tuple[object, ...] = ()
        super().__init__(f"source_queries cannot contain more than {limit} queries")


class RepeatedSourceQueryError(SourceNavigationError):
    """A model repeated an exact query in one navigation session."""

    def __init__(self, query: dict[str, object]) -> None:
        """Retain the repeated query for a bounded model correction."""
        self.query = query
        super().__init__("source query repeats an earlier query in this session")


class UnknownDefinitionQueryError(SourceNavigationError):
    """A model requested relationship candidates for an unpublished definition id."""

    def __init__(self, definition_id: str) -> None:
        """Retain the unknown definition id for one bounded correction."""
        self.definition_id = definition_id
        super().__init__(f"relationship candidate query references undiscovered definition {definition_id!r}")


@dataclass(frozen=True, kw_only=True)
class SourceTarget:
    """One real normalized character range returned by a navigation search."""

    id: str
    identity: str
    file: str
    name: str
    start: int
    end: int
    preview: str
    definition_id: str = ""
    source_kind: Literal["production", "documentation", "dependency"] = "production"

    @classmethod
    def create(
        cls,
        *,
        file: str,
        name: str,
        start: int,
        end: int,
        preview: str,
        definition_id: str = "",
        source_kind: Literal["production", "documentation", "dependency"] = "production",
    ) -> SourceTarget:
        """Build an opaque id from one exact repository source range."""
        identity = f"{file}:{name}:{start}:{end}"
        return cls(
            id=source_id(identity),
            identity=identity,
            file=file,
            name=name,
            start=start,
            end=end,
            preview=preview,
            definition_id=definition_id,
            source_kind=source_kind,
        )


@dataclass(frozen=True, kw_only=True)
class SourceNavigationResult:
    """Prompt text and evidence receipt from one query batch."""

    text: str
    coverage: GroundingCoverage = field(default_factory=GroundingCoverage)
    source_evidence: tuple[SourceEvidence, ...] = ()


@dataclass(frozen=True, kw_only=True)
class SourceNavigator:
    """Search verified source identities without inferring language bindings."""

    root: Path
    definitions: tuple[DefinitionEvidence, ...]
    files: tuple[str, ...]
    relationship_evidence: RelationshipEvidenceBundle = field(default_factory=RelationshipEvidenceBundle)
    documentation_files: frozenset[str] = frozenset()
    dependency_files: frozenset[str] = frozenset()

    @classmethod
    def from_facts(
        cls,
        root: str | Path,
        *,
        source_files: Iterable[str] = (),
        import_files: Iterable[str] = (),
        relationship_evidence: RelationshipEvidenceBundle | None = None,
        documentation_files: Iterable[str] = (),
        dependency_files: Iterable[str] = (),
    ) -> SourceNavigator | None:
        """Build navigation from shared facts without adding resolver semantics."""
        base = Path(root).resolve()
        relationships = relationship_evidence or RelationshipEvidenceBundle()
        all_definitions = definitions_by_name(relationships.definitions)
        relationship_files = (
            *(definition.source.path for definition in relationships.definitions),
            *(callsite.source.path for callsite in relationships.callsites),
            *(source.path for source in relationships.sources),
        )
        files = _navigation_files(
            base,
            (
                *(definition.source.path for definition in all_definitions),
                *source_files,
                *relationship_files,
                *import_files,
            ),
        )
        included = set(files)
        definitions = tuple(definition for definition in all_definitions if definition.source.path in included)
        if not definitions and not files and not relationships.definitions:
            return None
        return cls(
            root=base,
            definitions=definitions,
            files=files,
            relationship_evidence=relationships,
            documentation_files=frozenset(documentation_files).intersection(included),
            dependency_files=frozenset(dependency_files).intersection(included),
        )

    def session(self) -> SourceNavigationSession:
        """Create an isolated target catalog for one model judgment."""
        return SourceNavigationSession(self)


class SourceNavigationSession:
    """Execute model queries while retaining only targets this judgment discovered."""

    def __init__(self, navigator: SourceNavigator) -> None:
        """Bind one immutable navigator to an isolated discovered target set."""
        self._navigator = navigator
        self._targets: dict[str, SourceTarget] = {}
        self._targets_by_identity: dict[str, SourceTarget] = {}
        self._source_bytes: dict[str, bytes] = {}
        self._sources: dict[str, str] = {}
        self._relationship_definitions = {
            definition.id: definition for definition in navigator.relationship_evidence.definitions
        }
        self._callsites = {callsite.id: callsite for callsite in navigator.relationship_evidence.callsites}
        self._call_relationships = {
            relationship.callsite_id: relationship
            for relationship in navigator.relationship_evidence.call_relationships
        }
        self._structural_relationships = navigator.relationship_evidence.structural_relationships
        self._observations_by_callsite = self._group_callsite_observations(navigator.relationship_evidence.observations)
        self._discovered_definition_ids: set[str] = set()
        self._executed_query_keys: set[str] = set()
        self._delivered: dict[str, tuple[str, int, int] | None] = {}

    def record_delivered(self, evidence: Iterable[SourceEvidence], *, seed_spans: Iterable[SourceSpan] = ()) -> None:
        """Remember source this judgment already holds, so navigation never delivers it again."""
        for span in seed_spans:
            self._delivered.setdefault(f"seed:{len(self._delivered)}", _span_key(span))
        for item in evidence:
            self._delivered.setdefault(item.id, _span_key(item.source_span) if item.source_span is not None else None)

    def _delivered_as(self, target: SourceTarget) -> str | None:
        if target.id in self._delivered:
            return target.id
        source = self._source(target.file)
        first = source.count("\n", 0, target.start) + 1
        last = source.count("\n", 0, max(target.start, target.end - 1)) + 1
        file = normalized_location_path(target.file)
        for item_id, span in self._delivered.items():
            if span is not None and span[0] == file and span[1] <= first and last <= span[2]:
                return "seed" if item_id.startswith("seed:") else item_id
        return None

    def source_operation_id(self, file: str, line: int | None) -> str:
        """Map one source line to one unambiguous outer callsite identity."""
        if line is None or isinstance(line, bool) or not isinstance(line, int) or line < 1:
            return ""
        normalized = normalized_location_path(file)
        callsites = tuple(callsite for callsite in self._callsites.values() if callsite.source.path == normalized)
        if not callsites:
            return ""
        source = self._source(normalized)
        line_range = _line_character_range(source, line)
        if line_range is None:
            return ""
        line_start, line_end = line_range
        containing = tuple(
            callsite for callsite in callsites if callsite.source.start < line_end and line_start < callsite.source.end
        )
        if not containing:
            return ""
        outer = tuple(
            callsite
            for callsite in containing
            if not any(
                other.source.start <= callsite.source.start
                and callsite.source.end <= other.source.end
                and (other.source.start, other.source.end) != (callsite.source.start, callsite.source.end)
                for other in containing
            )
        )
        coordinates = {(callsite.source.start, callsite.source.end) for callsite in outer}
        if len(coordinates) != 1:
            return ""
        return min(callsite.id for callsite in outer)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Roll back discovered targets and query receipts when one exchange fails."""
        state = (
            dict(self._targets),
            dict(self._targets_by_identity),
            dict(self._source_bytes),
            dict(self._sources),
            set(self._discovered_definition_ids),
            set(self._executed_query_keys),
            dict(self._delivered),
        )
        try:
            yield
        except BaseException:
            (
                self._targets,
                self._targets_by_identity,
                self._source_bytes,
                self._sources,
                self._discovered_definition_ids,
                self._executed_query_keys,
                self._delivered,
            ) = state
            raise

    def execute(self, requested: object, *, target_chars: int) -> SourceNavigationResult:
        """Execute a strict batch and fail rather than reinterpret malformed queries."""
        queries = parse_source_queries(requested)
        query_keys = tuple(_query_key(query) for query in queries)
        if len(query_keys) != len(set(query_keys)):
            repeated = next(query for query, key in zip(queries, query_keys, strict=True) if query_keys.count(key) > 1)
            raise RepeatedSourceQueryError(repeated)
        already_executed = next(
            (query for query, key in zip(queries, query_keys, strict=True) if key in self._executed_query_keys),
            None,
        )
        if already_executed is not None:
            raise RepeatedSourceQueryError(already_executed)
        if len(self._executed_query_keys) + len(query_keys) > MAX_UNIQUE_QUERIES_PER_SESSION:
            raise SourceNavigationError(
                f"source navigation exceeds {MAX_UNIQUE_QUERIES_PER_SESSION} unique queries per session"
            )
        blocks: list[str] = []
        coverage = GroundingCoverage()
        source_evidence: list[SourceEvidence] = []
        held_receipts: list[SourceEvidence] = []
        for index, (query, query_key) in enumerate(zip(queries, query_keys, strict=True), start=1):
            self._executed_query_keys.add(query_key)
            kind = query["kind"]
            if kind in {"search_symbols", "search_text"}:
                if kind == "search_symbols":
                    targets, page, more, exact_match = self._search_symbols(query["query"], query["page"])
                    label = "Unique exact symbol match"
                else:
                    targets, page, more = self._search_text(query["query"], query["page"])
                    exact_match, label = True, "Unique exact text match"
                blocks.append(
                    _render_search(
                        index,
                        kind,
                        query["query"],
                        targets,
                        page,
                        more,
                        self._held_targets(targets, held_receipts),
                        exact_match=exact_match,
                    )
                )
                if kind == "search_symbols" and not exact_match and page == 0:
                    bindings = self._import_bindings(query["query"].split(".")[0])
                    if bindings:
                        blocks[-1] += "\n" + bindings
                exact = (
                    self._unique_exact_read(
                        targets, page=page, more=more, blocks=blocks, target_chars=target_chars, label=label
                    )
                    if exact_match
                    else None
                )
                if exact is not None:
                    blocks.append(f"{label}:\n{exact.text}")
                    coverage = merge_grounding_coverage((coverage, exact.coverage))
                    source_evidence.extend(exact.source_evidence)
            elif kind == "search_call_candidates":
                text = self._search_call_candidates(
                    query["definition_id"],
                    query["direction"],
                    query["page"],
                )
                blocks.append(f"Source query {index} {text}")
            elif kind == "search_structural_candidates":
                text = self._search_structural_candidates(
                    query["definition_id"],
                    query["direction"],
                    query["page"],
                )
                blocks.append(f"Source query {index} {text}")
            else:
                raise SourceNavigationError(f"source query {index} has unknown kind {kind!r}")
            if len("\n\n".join(blocks)) > target_chars:
                raise SourceBudgetError(f"source query results exceed the {target_chars} character target")
        source_evidence.extend(held_receipts)
        identities = tuple(dict.fromkeys(item.identity for item in held_receipts))
        coverage = merge_grounding_coverage(
            (
                coverage,
                GroundingCoverage(
                    required=identities,
                    included=identities,
                    references=tuple(dict.fromkeys(item.id for item in held_receipts)),
                ),
            )
        )
        return SourceNavigationResult(
            text="\n\n".join(blocks),
            coverage=coverage,
            source_evidence=tuple(source_evidence),
        )

    def _held_targets(self, targets: tuple[SourceTarget, ...], receipts: list[SourceEvidence]) -> dict[str, str]:
        held = {}
        for target in targets:
            delivered_as = self._delivered_as(target)
            if delivered_as is None:
                continue
            held[target.id] = delivered_as
            if delivered_as != target.id:
                receipt = self._receipt(target)
                receipts.append(receipt)
                self._delivered[target.id] = _span_key(receipt.source_span)
        return held

    def _receipt(self, target: SourceTarget) -> SourceEvidence:
        source = self._source(target.file)
        if target.end > len(source):
            raise SourceNavigationError(f"source target {target.id} exceeds {target.file}")
        text, span = numbered_source_range(target.file, source, target.start, target.end)
        return SourceEvidence(id=target.id, identity=target.identity, text=text, source_span=span)

    def read(self, requested: Iterable[str], *, target_chars: int) -> SourceNavigationResult:
        """Read exact targets, validated by `evidence_request_ids`, that this session already discovered."""
        targets = tuple(dict.fromkeys(requested))
        blocks: list[str] = []
        source_evidence: list[SourceEvidence] = []
        coverage = GroundingCoverage()
        read_chars = 0
        for index, target_id in enumerate(targets, start=1):
            target = self._targets.get(target_id)
            if target is None:
                raise SourceNavigationError(
                    f"evidence request {index} references unknown target {target_id!r}. "
                    "Read only target ids returned by an earlier search."
                )
            delivered_as = self._delivered_as(target)
            receipt = self._receipt(target)
            label = _SOURCE_LABELS[target.source_kind]
            heading = f"{label} `{target.id}` {one_line_source(target.file)}:{one_line_source(target.name)}"
            if delivered_as is None:
                read_chars += len(receipt.text)
                if read_chars > target_chars:
                    raise SourceBudgetError(f"evidence requests exceed the {target_chars} character target")
                blocks.append(f"Read {heading}:\n{fenced_source(receipt.text)}")
            else:
                blocks.append(_already_delivered(heading, receipt.source_span, target.id, delivered_as))
            self._delivered[target.id] = _span_key(receipt.source_span)
            source_evidence.append(receipt)
            coverage = GroundingCoverage(
                required=(*coverage.required, target.identity),
                included=(*coverage.included, target.identity),
                references=(*coverage.references, target.id),
            )
        return SourceNavigationResult(
            text="\n\n".join(blocks),
            coverage=coverage,
            source_evidence=tuple(source_evidence),
        )

    def _unique_exact_read(
        self,
        targets: tuple[SourceTarget, ...],
        *,
        page: int,
        more: bool,
        blocks: list[str],
        target_chars: int,
        label: str,
    ) -> SourceNavigationResult | None:
        if page != 0 or len(targets) != 1 or more or self._delivered_as(targets[0]) is not None:
            return None
        exact = self.read(
            [targets[0].id],
            target_chars=max(target_chars, _MAX_SOURCE_TARGET_CHARS * 2),
        )
        candidate = "\n\n".join((*blocks, f"{label}:\n{exact.text}"))
        if len(candidate) > target_chars:
            self._delivered.pop(targets[0].id, None)
            return None
        return exact

    def can_read(self, target: str) -> bool:
        """Report whether this session returned an exact target in an earlier search."""
        return target in self._targets

    @property
    def readable_ids(self) -> tuple[str, ...]:
        """Return exact source ids published by this session."""
        return tuple(sorted(self._targets))

    def query_was_executed(self, query: dict[str, object]) -> bool:
        """Check whether one normalized query has already run in this session."""
        return _query_key(query) in self._executed_query_keys

    def _search_symbols(
        self,
        query: str,
        page: int,
    ) -> tuple[tuple[SourceTarget, ...], int, bool, bool]:
        *qualifier, symbol = query.split(".")
        named = [definition for definition in self._navigator.definitions if definition.name == symbol]
        matches = [definition for definition in self._navigator.definitions if definition.name == query]
        if qualifier:
            matches.extend(definition for definition in named if self._owned_by(definition, tuple(qualifier)))
        exact = bool(matches)
        targets = tuple(target for definition in (matches or named) for target in self._definition_targets(definition))
        selected, selected_page, more = _page(targets, page)
        published = tuple(self._register_target(target) for target in selected)
        self._discovered_definition_ids.update(target.definition_id for target in published if target.definition_id)
        return published, selected_page, more, exact

    def _import_bindings(self, name: str) -> str:
        if not name or any(definition.name == name for definition in self._navigator.definitions):
            return ""
        identifier = re.compile(rf"(?<![\w$]){re.escape(name)}(?![\w$])")
        statements: list[tuple[bool, str, int, str]] = []
        for relationship in self._structural_relationships:
            if relationship.kind not in {"import", "namespace"}:
                continue
            reference = relationship.source
            source = self._source(reference.path)
            selected = source[reference.start : reference.end]
            text = " ".join(selected.split())
            if text_sha256(selected) != reference.content_sha256 or not identifier.search(text):
                continue
            module = PurePosixPath(relationship.reference.strip("\"'")).name.split(".")[0]
            binds = name in {relationship.reference, module} or relationship.reference.startswith(f"{name} from ")
            statements.append((not binds, reference.path, source.count("\n", 0, reference.start) + 1, text[:240]))
        if not statements:
            return ""
        statements = sorted(set(statements))
        lines = [
            f"No definition named {inline_source(name)} was found in the reviewed source. "
            f"Import statements that name {inline_source(name)}:"
        ]
        lines.extend(
            f"- {one_line_source(path)}:{line} | {inline_source(text)}"
            for _, path, line, text in statements[:_MAX_RESULTS_PER_PAGE]
        )
        if len(statements) > _MAX_RESULTS_PER_PAGE:
            lines.append(f"- {len(statements) - _MAX_RESULTS_PER_PAGE} more import statements are not listed")
        return "\n".join(lines)

    def _owned_by(self, definition: DefinitionEvidence, qualifier: tuple[str, ...]) -> bool:
        owners: list[str] = []
        owner_id = definition.owner_id
        while owner_id and len(owners) < len(qualifier):
            owner = self._relationship_definitions.get(owner_id)
            if owner is None:
                break
            owners.insert(0, owner.name)
            owner_id = owner.owner_id
        return tuple(owners) == qualifier

    def _search_text(
        self,
        query: str,
        page: int,
    ) -> tuple[tuple[SourceTarget, ...], int, bool]:
        targets: list[SourceTarget] = []
        for file in self._navigator.files:
            source = self._source(file)
            for line_no, line in enumerate(split_lines(source, keepends=True), start=1):
                if query in line:
                    match = _line_offset(source, line_no) + line.index(query)
                    start = max(_line_offset(source, max(1, line_no - 3)), match - _MAX_SOURCE_TARGET_CHARS // 2)
                    end = min(_line_offset(source, line_no + 4), start + _MAX_SOURCE_TARGET_CHARS)
                    target = SourceTarget.create(
                        file=file,
                        name=f"text line {line_no}",
                        start=start,
                        end=end,
                        preview=line.strip()[:240],
                        source_kind=self._source_kind(file),
                    )
                    targets.append(target)
        selected, selected_page, more = _page(tuple(targets), page)
        return tuple(self._register_target(target) for target in selected), selected_page, more

    def _search_call_candidates(self, definition_id: str, direction: str, page: int) -> str:
        if definition_id not in self._discovered_definition_ids:
            raise UnknownDefinitionQueryError(definition_id)
        selected = self._relationship_definitions.get(definition_id)
        if selected is None:
            raise SourceNavigationError(f"call candidate query references unknown definition {definition_id!r}")
        calls = []
        for callsite in self._callsites.values():
            candidate_ids = self._callsite_candidate_ids(callsite)
            if direction in {"callees", "both"} and callsite.caller_definition_id == definition_id:
                calls.append((callsite, candidate_ids))
                continue
            if direction in {"callers", "both"} and definition_id in candidate_ids:
                calls.append((callsite, candidate_ids))
        calls = sorted(calls, key=lambda item: (item[0].source.path, item[0].source.start, item[0].id))
        selected_calls, selected_page, more = _page(tuple(calls), page)
        lines = [
            f"`search_call_candidates` for `{definition_id}` direction `{direction}`, page {selected_page}.",
        ]
        for callsite, candidate_ids in selected_calls:
            lines.extend(self._render_call_candidate(callsite, candidate_ids))
        if not selected_calls:
            lines.append("- no matches")
        if more:
            lines.append(f"- more results are available on page {selected_page + 1}")
        return "\n".join(lines)

    def _callsite_candidate_ids(self, callsite: CallsiteEvidence) -> tuple[str, ...]:
        relationship = self._call_relationships.get(callsite.id)
        if relationship is None:
            raise SourceNavigationError(f"callsite {callsite.id} has no relationship target state")
        return relationship.candidate_callee_definition_ids

    def _search_structural_candidates(self, definition_id: str, direction: str, page: int) -> str:
        if definition_id not in self._discovered_definition_ids:
            raise UnknownDefinitionQueryError(definition_id)
        selected = self._relationship_definitions.get(definition_id)
        if selected is None:
            raise SourceNavigationError(f"structural candidate query references unknown definition {definition_id!r}")
        relationships: list[StructuralRelationshipEvidence] = []
        for relationship in self._structural_relationships:
            outgoing = relationship.source_definition_id == definition_id
            incoming = definition_id in relationship.candidate_target_definition_ids
            if (direction in {"outgoing", "both"} and outgoing) or (direction in {"incoming", "both"} and incoming):
                relationships.append(relationship)
        relationships = sorted(
            relationships,
            key=lambda item: (item.source.path, item.source.start, item.kind, item.id),
        )
        expanded = tuple(
            (relationship, candidate_id)
            for relationship in relationships
            for candidate_id in relationship.candidate_target_definition_ids or ("",)
        )
        selected_relationships, selected_page, more = _page(expanded, page)
        lines = [
            f"`search_structural_candidates` for `{definition_id}` direction `{direction}`, page {selected_page}.",
        ]
        for relationship, candidate_id in selected_relationships:
            lines.extend(self._render_structural_candidate(relationship, candidate_id))
        if not selected_relationships:
            lines.append("- no matches")
        if more:
            lines.append(f"- more results are available on page {selected_page + 1}")
        return "\n".join(lines)

    def _render_structural_candidate(
        self,
        relationship: StructuralRelationshipEvidence,
        candidate_id: str,
    ) -> list[str]:
        relation_target = self._source_reference_target(
            relationship.source,
            name=f"{relationship.kind} {relationship.reference}",
        )
        lines = [
            f"- relationship `{relationship.id}` kind `{relationship.kind}` reference "
            f"{inline_source(relationship.reference)}",
            f"  syntax source `{relation_target.id}` {one_line_source(relationship.source.path)}",
        ]
        if relationship.source_definition_id:
            owner = self._relationship_definitions[relationship.source_definition_id]
            owner_target = self._relationship_target(owner)
            lines.append(
                f"  owner `{owner.id}` source `{owner_target.id}` "
                f"{one_line_source(owner.source.path)}:{one_line_source(owner.name)}"
            )
        if not candidate_id:
            lines.append("  candidates: no repository definition candidate")
            return lines
        candidate = self._relationship_definitions[candidate_id]
        candidate_target = self._relationship_target(candidate)
        lines.append(f"  candidate `{candidate.id}` source `{candidate_target.id}` {_definition_label(candidate)}")
        return lines

    def _render_call_candidate(self, callsite: CallsiteEvidence, candidate_ids: tuple[str, ...]) -> list[str]:
        caller = self._relationship_definitions[callsite.caller_definition_id]
        caller_target = self._relationship_target(caller)
        call_target = self._source_reference_target(
            callsite.source,
            name=f"call {callsite.callee_spelling}",
        )
        self._discovered_definition_ids.add(caller.id)
        lines = [
            f"- callsite `{callsite.id}` {inline_source(' '.join(callsite.expression.split()))}",
            f"  caller `{caller.id}` source `{caller_target.id}` "
            f"{one_line_source(caller.source.path)}:{one_line_source(caller.name)}",
            f"  call source `{call_target.id}` receiver {inline_source(callsite.receiver_expression)}",
        ]
        observations = self._observations_by_callsite.get(callsite.id, ())
        for observation in observations:
            label = f" {inline_source(observation.label)}" if observation.label else ""
            lines.append(f"  observation `{observation.id}` {observation.producer}:{observation.kind}{label}")
        if not candidate_ids:
            lines.append("  candidates: no repository definition candidate")
            return lines
        for candidate_id in candidate_ids:
            candidate = self._relationship_definitions[candidate_id]
            candidate_target = self._relationship_target(candidate)
            self._discovered_definition_ids.add(candidate.id)
            lines.append(f"  candidate `{candidate.id}` source `{candidate_target.id}` {_definition_label(candidate)}")
        return lines

    def _definition_targets(self, definition: DefinitionEvidence) -> tuple[SourceTarget, ...]:
        file, start, end = definition.source.path, definition.source.start, definition.source.end
        source = self._source(file)
        if end > len(source):
            raise SourceNavigationError(f"definition range exceeds source {definition.identity}")
        preview = next(
            (line.strip() for line in split_lines(source[start:end]) if line.strip()),
            "",
        )
        ranges = tuple(
            (page_start, min(page_start + _MAX_SOURCE_TARGET_CHARS, end))
            for page_start in range(start, end, _MAX_SOURCE_TARGET_CHARS)
        )
        total = len(ranges)
        return tuple(
            SourceTarget.create(
                file=file,
                name=(definition.name if total == 1 else f"{definition.name} page {index}/{total}"),
                start=page_start,
                end=page_end,
                preview=preview[:240],
                definition_id=definition.id,
                source_kind=self._source_kind(file),
            )
            for index, (page_start, page_end) in enumerate(ranges, start=1)
        )

    def _relationship_target(self, definition: DefinitionEvidence) -> SourceTarget:
        target = self._source_reference_target(definition.source, name=definition.name, definition_id=definition.id)
        self._discovered_definition_ids.add(definition.id)
        return target

    def _source_reference_target(
        self,
        reference: SourceReference,
        *,
        name: str,
        definition_id: str = "",
    ) -> SourceTarget:
        source = self._source(reference.path)
        if reference.end > len(source):
            raise SourceNavigationError(f"relationship source exceeds {reference.path}")
        selected = source[reference.start : reference.end]
        if text_sha256(selected) != reference.content_sha256:
            raise SourceNavigationError(f"relationship source changed at {reference.path}:{reference.start}")
        preview = next((line.strip() for line in split_lines(selected) if line.strip()), "")
        return self._register_target(
            SourceTarget.create(
                file=reference.path,
                name=name,
                start=reference.start,
                end=reference.end,
                preview=preview[:240],
                definition_id=definition_id,
                source_kind=self._source_kind(reference.path),
            )
        )

    @staticmethod
    def _group_callsite_observations(
        observations: tuple[AnalysisObservation, ...],
    ) -> dict[str, tuple[AnalysisObservation, ...]]:
        grouped: dict[str, list[AnalysisObservation]] = {}
        for observation in observations:
            for subject in observation.subject_ids:
                if subject.startswith("call-"):
                    grouped.setdefault(subject, []).append(observation)
        return {key: tuple(values) for key, values in grouped.items()}

    def _register_target(self, target: SourceTarget) -> SourceTarget:
        existing = self._targets_by_identity.get(target.identity)
        if existing is not None:
            return existing
        collision = self._targets.get(target.id)
        if collision is not None and collision.identity != target.identity:
            raise SourceNavigationError(f"source target id collision for {target.identity}")
        registered = target
        self._targets[registered.id] = registered
        self._targets_by_identity[registered.identity] = registered
        return registered

    def _source_kind(self, file: str) -> Literal["production", "documentation", "dependency"]:
        if file in self._navigator.documentation_files:
            return "documentation"
        if file in self._navigator.dependency_files:
            return "dependency"
        return "production"

    def _source(self, file: str) -> str:
        source = self._sources.get(file)
        if source is not None:
            return source
        raw = self._source_bytes_for(file)
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SourceNavigationError(f"cannot decode navigation source {file!r}: {exc}") from exc
        source = source.replace("\r\n", "\n").replace("\r", "\n")
        self._sources[file] = source
        return source

    def _source_bytes_for(self, file: str) -> bytes:
        source = self._source_bytes.get(file)
        if source is not None:
            return source
        try:
            path = contained_repository_path(self._navigator.root, file)
            if not path.is_file():
                raise OSError("not a regular file")
            if path.stat().st_size > _MAX_SEARCHABLE_FILE_BYTES:
                raise OSError(f"file exceeds {_MAX_SEARCHABLE_FILE_BYTES} bytes")
            source = path.read_bytes()
        except (OSError, ValueError) as exc:
            raise SourceNavigationError(f"cannot read navigation source {file!r}: {exc}") from exc
        self._source_bytes[file] = source
        return source


class _OperationBindable(Protocol):
    file: str
    line: int | None
    source_operation_id: str


def bind_source_operation[T: _OperationBindable](
    finding: T,
    navigator: SourceNavigationSession | None,
) -> T:
    """Bind one report line to an unambiguous shared callsite identity."""
    if navigator is None or finding.source_operation_id:
        return finding
    operation_id = navigator.source_operation_id(finding.file, finding.line)
    return replace(finding, source_operation_id=operation_id) if operation_id else finding


def navigation_instructions() -> str:
    """Render the shared source query contract."""
    return (
        "# Source Navigation\n\n"
        "`source_queries` searches the repository. Leading and trailing whitespace of `query` is ignored. Each "
        f"query returns at most {_MAX_RESULTS_PER_PAGE} results per page. `page` starts at 0, and a result list "
        "states when a next page exists.\n"
        "- `search_symbols` returns definitions whose name equals `query` exactly. A dotted `query` also matches a "
        "definition named by its last segment whose enclosing definitions are named by the preceding segments, in "
        "order. When nothing matches exactly, definitions named by the last segment are listed as candidates.\n"
        "- `search_text` returns lines that contain `query` as a literal, case-sensitive substring of one line, "
        "each with up to three surrounding lines on each side. Regular expressions, wildcards, and multi-line text "
        "are not supported.\n"
        "- Results list `src-*` ids and, for definitions, `def-*` ids. When page 0 holds exactly one exact match, "
        "its source is also delivered if it fits the exchange budget.\n"
        "- `search_call_candidates` lists call candidates for a `def-*` id returned by an earlier search: "
        "`callees` are calls inside that definition, `callers` are calls whose candidate callee is that "
        "definition, and `both` lists both.\n"
        "- `search_structural_candidates` lists inheritance, imports, and other non-call syntax for a `def-*` id "
        "returned by an earlier search: `outgoing` is syntax inside that definition, `incoming` is syntax that "
        "names it as a candidate target, and `both` lists both.\n"
        "- Search results and candidates are unverified syntax matches. Read the source before relying on a "
        "relationship.\n"
        "- Searches cover only the reviewed repository snapshot. Code from installed packages, git submodules, or "
        "other locations outside it cannot be searched, and no evidence id delivers it. A symbol search that finds "
        "no definition also lists any import statements that name it. When needed code is outside the snapshot, "
        "judge with the delivered evidence and treat that code's behavior as an assumption.\n"
        "- Batch every independent search and evidence request into one response and never repeat a query. "
        f"Send at most {MAX_QUERIES_PER_BATCH} `source_queries` in one response and "
        f"{MAX_UNIQUE_QUERIES_PER_SESSION} unique queries across this unit."
    )


def parse_source_queries(value: object) -> list[dict[str, object]]:
    """Validate model-facing source searches without accepting exact reads."""
    if not isinstance(value, list):
        raise SourceNavigationError("source_queries must be a list")
    if len(value) > MAX_QUERIES_PER_BATCH:
        raise SourceQueryLimitError(len(value), MAX_QUERIES_PER_BATCH)
    queries: list[dict[str, object]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise SourceNavigationError(f"source query {index + 1} must be an object")
        kind = raw.get("kind")
        if kind not in {
            "search_symbols",
            "search_text",
            "search_call_candidates",
            "search_structural_candidates",
        }:
            raise SourceNavigationError(f"source query {index + 1} has unknown kind {kind!r}")
        allowed = (
            {"kind", "definition_id", "direction", "page"}
            if kind in {"search_call_candidates", "search_structural_candidates"}
            else {"kind", "query", "page"}
        )
        extra = set(raw).difference(allowed)
        if extra:
            raise SourceNavigationError(
                f"source query {index + 1} has unknown fields: {', '.join(sorted(str(item) for item in extra))}"
            )
        if kind in {"search_call_candidates", "search_structural_candidates"}:
            definition_id = raw.get("definition_id")
            direction = raw.get("direction")
            page = raw.get("page")
            if not isinstance(definition_id, str) or not definition_id.startswith("def-"):
                raise SourceNavigationError(f"source query {index + 1} definition_id must be a def-* id")
            allowed_directions = (
                {"callers", "callees", "both"} if kind == "search_call_candidates" else {"incoming", "outgoing", "both"}
            )
            if direction not in allowed_directions:
                choices = ", ".join(sorted(allowed_directions))
                raise SourceNavigationError(f"source query {index + 1} direction must be one of: {choices}")
            if not isinstance(page, int) or isinstance(page, bool) or page < 0:
                raise SourceNavigationError(f"source query {index + 1} page must be a nonnegative integer")
            queries.append(
                {
                    "kind": kind,
                    "definition_id": definition_id,
                    "direction": direction,
                    "page": page,
                }
            )
            continue
        query = raw.get("query")
        if "page" not in raw:
            raise SourceNavigationError(f"source query {index + 1} must include page")
        page = raw["page"]
        if not isinstance(query, str) or not query.strip():
            raise SourceNavigationError(f"source query {index + 1} query must be a nonempty string")
        if not isinstance(page, int) or isinstance(page, bool) or page < 0:
            raise SourceNavigationError(f"source query {index + 1} page must be a nonnegative integer")
        queries.append({"kind": kind, "query": query.strip(), "page": page})
    return queries


def _definition_label(definition: DefinitionEvidence) -> str:
    label = f"{one_line_source(definition.source.path)}:{one_line_source(definition.name)}"
    signature = " ".join(definition.signature.split())
    return f"{label} | {inline_source(signature)}" if signature else label


def _page[T](targets: tuple[T, ...], page: int) -> tuple[tuple[T, ...], int, bool]:
    start = page * _MAX_RESULTS_PER_PAGE
    selected = targets[start : start + _MAX_RESULTS_PER_PAGE]
    return selected, page, start + len(selected) < len(targets)


def _query_key(query: Mapping[str, object]) -> str:
    return json.dumps(query, sort_keys=True, separators=(",", ":"))


def _render_search(
    index: int,
    kind: str,
    query: str,
    targets: tuple[SourceTarget, ...],
    page: int,
    more: bool,
    held: Mapping[str, str],
    *,
    exact_match: bool = True,
) -> str:
    lines = [
        f"Source query {index} `{kind}` for {inline_source(query)}, page {page}.",
    ]
    if not exact_match and targets:
        lines.append(
            "No definition matches the qualified name exactly. These definitions only share its last segment "
            "and are unverified candidates."
        )
    lines.extend(
        f"- `{target.id}`"
        + (f" definition `{target.definition_id}`" if target.definition_id else "")
        + f" [{target.source_kind}] {one_line_source(target.file)}:{one_line_source(target.name)} | "
        + inline_source(target.preview)
        + _held_note(target.id, held.get(target.id))
        for target in targets
    )
    if not targets:
        lines.append("- no matches")
    if more:
        lines.append(f"- more results are available on page {page + 1}")
    return "\n".join(lines)


def _held_note(target_id: str, delivered_as: str | None) -> str:
    if delivered_as is None:
        return ""
    if delivered_as == target_id:
        return " | already delivered"
    return f" | already delivered in `{delivered_as}`"


def _already_delivered(heading: str, span: SourceSpan, target_id: str, delivered_as: str) -> str:
    where = "" if delivered_as == target_id else f" in `{delivered_as}`"
    return (
        f"Requested {heading} lines {span.start_line}-{span.end_line} is already delivered{where}. "
        "It is not repeated. Cite it directly."
    )


def _span_key(span: SourceSpan) -> tuple[str, int, int]:
    return (normalized_location_path(span.file), span.start_line, span.end_line)


def _navigation_files(root: Path, candidates: Iterable[str]) -> tuple[str, ...]:
    files = []
    for file in dict.fromkeys(candidates):
        path = safe_repository_path(root, file)
        if path is not None and path.is_file():
            files.append(file)
    return tuple(files)


def _line_offset(source: str, line: int) -> int:
    if line <= 1:
        return 0
    offset = 0
    for _ in range(line - 1):
        next_line = source.find("\n", offset)
        if next_line < 0:
            return len(source)
        offset = next_line + 1
    return offset


def _line_character_range(source: str, line: int) -> tuple[int, int] | None:
    start = _line_offset(source, line)
    if start >= len(source):
        return None
    end = _line_offset(source, line + 1)
    return (start, end if end > start else len(source))
