"""Bounded source navigation over verified repository facts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from cyberjury.numbering import numbered_source
from cyberjury.review.context import GroundingCoverage, SourceEvidence, SourceSpan, merge_grounding_coverage
from cyberjury.review.definitions import (
    DefinitionFragment,
    FactsGraph,
    definition_fragments,
)
from cyberjury.review.relationships import (
    AnalysisObservation,
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
)

type SourceQueryKind = Literal["search_symbols", "search_text", "search_call_candidates"]

_MAX_RESULTS_PER_PAGE = 20
_MAX_SEARCHABLE_FILE_BYTES = 2_000_000
_MAX_QUERIES_PER_BATCH = 8
_MAX_UNIQUE_QUERIES_PER_SESSION = 64
_MAX_SOURCE_TARGET_CHARS = 24_000


class SourceNavigationError(RuntimeError):
    """A source query is malformed, unsafe, or exceeds its budget."""


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
    source_kind: Literal["production", "test"] = "production"

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
        source_kind: Literal["production", "test"] = "production",
    ) -> SourceTarget:
        """Build an opaque id from one exact repository source range."""
        identity = f"{file}:{name}:{start}:{end}"
        digest = hashlib.sha256(identity.encode()).hexdigest()[:12]
        return cls(
            id=f"src-{digest}",
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
    definitions: tuple[DefinitionFragment, ...]
    files: tuple[str, ...]
    relationship_evidence: RelationshipEvidenceBundle = field(default_factory=RelationshipEvidenceBundle)
    source_hashes: tuple[tuple[str, str], ...] = ()
    test_files: frozenset[str] = frozenset()

    @classmethod
    def from_graph(
        cls,
        root: str | Path,
        graph: FactsGraph,
        *,
        source_files: Iterable[str] = (),
        relationship_evidence: RelationshipEvidenceBundle | None = None,
        test_files: Iterable[str] = (),
    ) -> SourceNavigator | None:
        """Build navigation from shared facts without adding resolver semantics."""
        base = Path(root).resolve()
        fragments = definition_fragments(graph)
        all_definitions = tuple(fragment for values in fragments.values() for fragment in values)
        relationships = relationship_evidence or RelationshipEvidenceBundle()
        relationship_files = (
            *(definition.source.path for definition in relationships.definitions),
            *(callsite.source.path for callsite in relationships.callsites),
            *(source.path for source in relationships.sources),
        )
        files = _graph_source_files(
            base,
            graph,
            all_definitions,
            (*source_files, *relationship_files),
        )
        included = set(files)
        definitions = tuple(fragment for fragment in all_definitions if fragment.file in included)
        if not definitions and relationships.definitions:
            definitions = tuple(
                DefinitionFragment(
                    definition.source.path,
                    definition.name,
                    definition.source.start,
                    definition.source.end,
                )
                for definition in relationships.definitions
                if definition.kind != "file" and definition.source.path in included
            )
        if not definitions and not files and not relationships.definitions:
            return None
        return cls(
            root=base,
            definitions=definitions,
            files=files,
            relationship_evidence=relationships,
            source_hashes=tuple((file, _source_hash(base, file)) for file in files),
            test_files=frozenset(test_files),
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
        self._relationship_definitions_by_identity = {
            self._definition_identity(definition): definition
            for definition in navigator.relationship_evidence.definitions
        }
        self._callsites = {callsite.id: callsite for callsite in navigator.relationship_evidence.callsites}
        self._observations_by_callsite = self._group_callsite_observations(navigator.relationship_evidence.observations)
        self._discovered_definition_ids: set[str] = set()
        self._source_hashes = dict(navigator.source_hashes)
        self._search_results: dict[str, tuple[tuple[SourceTarget, ...], int, bool]] = {}
        self._call_results: dict[str, str] = {}
        self._auto_read_ids: set[str] = set()

    def execute(self, requested: object, *, target_chars: int) -> SourceNavigationResult:
        """Execute a strict batch and fail rather than reinterpret malformed queries."""
        queries = _queries(requested)
        blocks: list[str] = []
        coverage = GroundingCoverage()
        source_evidence: list[SourceEvidence] = []
        for index, query in enumerate(queries, start=1):
            query_key = json.dumps(query, sort_keys=True, separators=(",", ":"))
            cached_queries = len(self._search_results) + len(self._call_results)
            if (
                query_key not in self._search_results
                and query_key not in self._call_results
                and cached_queries >= _MAX_UNIQUE_QUERIES_PER_SESSION
            ):
                raise SourceNavigationError(
                    f"source navigation exceeds {_MAX_UNIQUE_QUERIES_PER_SESSION} unique queries per session"
                )
            kind = query["kind"]
            if kind == "search_symbols":
                cached = self._search_results.get(query_key)
                if cached is None:
                    cached = self._search_symbols(query["query"], query["page"])
                    self._search_results[query_key] = cached
                targets, page, more = cached
                blocks.append(_render_search(index, kind, query["query"], targets, page, more))
                if page == 0 and len(targets) == 1 and not more and targets[0].id not in self._auto_read_ids:
                    exact = self.read(
                        [targets[0].id],
                        target_chars=max(target_chars, _MAX_SOURCE_TARGET_CHARS * 2),
                    )
                    candidate = "\n\n".join((*blocks, "Unique exact symbol match:\n" + exact.text))
                    if len(candidate) <= target_chars:
                        blocks.append("Unique exact symbol match:\n" + exact.text)
                        coverage = merge_grounding_coverage((coverage, exact.coverage))
                        source_evidence.extend(exact.source_evidence)
                        self._auto_read_ids.add(targets[0].id)
            elif kind == "search_text":
                cached = self._search_results.get(query_key)
                if cached is None:
                    cached = self._search_text(query["query"], query["page"])
                    self._search_results[query_key] = cached
                targets, page, more = cached
                blocks.append(_render_search(index, kind, query["query"], targets, page, more))
            elif kind == "search_call_candidates":
                cached = self._call_results.get(query_key)
                if cached is None:
                    cached = self._search_call_candidates(
                        query["definition_id"],
                        query["direction"],
                        query["page"],
                    )
                    self._call_results[query_key] = cached
                text = cached
                blocks.append(f"Source query {index} {text}")
            else:
                raise SourceNavigationError(f"source query {index} has unknown kind {kind!r}")
            if len("\n\n".join(blocks)) > target_chars:
                raise SourceNavigationError(f"source query results exceed the {target_chars} character target")
        return SourceNavigationResult(
            text="\n\n".join(blocks),
            coverage=coverage,
            source_evidence=tuple(source_evidence),
        )

    def read(self, requested: object, *, target_chars: int) -> SourceNavigationResult:
        """Read exact targets already discovered by this session."""
        if not isinstance(requested, list) or not all(isinstance(item, str) for item in requested):
            raise SourceNavigationError("evidence_requests must contain source target ids")
        targets = tuple(dict.fromkeys(item.strip() for item in requested if item.strip()))
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
            source = self._source(target.file)
            if target.end > len(source):
                raise SourceNavigationError(f"source target {target.id} exceeds {target.file}")
            selected = source[target.start : target.end]
            text = numbered_source(
                target.file,
                selected,
                source[: target.start].count("\n") + 1,
            )
            read_chars += len(text)
            if read_chars > target_chars:
                raise SourceNavigationError(f"evidence requests exceed the {target_chars} character target")
            blocks.append(f"Read source `{target.id}` {target.file}:{target.name}:\n{text}")
            source_evidence.append(
                SourceEvidence(
                    id=target.id,
                    identity=target.identity,
                    text=text,
                    source_span=self._source_span(target, source),
                )
            )
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

    def can_read(self, target: str) -> bool:
        """Report whether this session returned an exact target in an earlier search."""
        return target in self._targets

    def _search_symbols(
        self,
        query: str,
        page: int,
    ) -> tuple[tuple[SourceTarget, ...], int, bool]:
        symbol = query.rsplit(".", 1)[-1]
        matches = [fragment for fragment in self._navigator.definitions if fragment.name == query]
        if not matches and symbol != query:
            matches = [fragment for fragment in self._navigator.definitions if fragment.name == symbol]
        targets = tuple(target for fragment in matches for target in self._definition_targets(fragment))
        self._discovered_definition_ids.update(target.definition_id for target in targets if target.definition_id)
        return _page(targets, page)

    def _search_text(
        self,
        query: str,
        page: int,
    ) -> tuple[tuple[SourceTarget, ...], int, bool]:
        targets: list[SourceTarget] = []
        for file in self._navigator.files:
            source = self._source(file)
            for line_no, line in enumerate(source.splitlines(keepends=True), start=1):
                if query in line:
                    start = _line_offset(source, max(1, line_no - 3))
                    end = _line_offset(source, line_no + 4)
                    target = SourceTarget.create(
                        file=file,
                        name=f"text line {line_no}",
                        start=start,
                        end=end,
                        preview=line.strip()[:240],
                        source_kind=self._source_kind(file),
                    )
                    targets.append(self._register_target(target))
        return _page(tuple(targets), page)

    def _search_call_candidates(self, definition_id: str, direction: str, page: int) -> str:
        if definition_id not in self._discovered_definition_ids:
            raise SourceNavigationError(f"call candidate query references undiscovered definition {definition_id!r}")
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
            "These are syntax and analyzer candidates, not established call relationships or security conclusions.",
        ]
        for callsite, candidate_ids in selected_calls:
            lines.extend(self._render_call_candidate(callsite, candidate_ids))
        if not selected_calls:
            lines.append("- no matches")
        if more:
            lines.append(f"- more results are available on page {selected_page + 1}")
        return "\n".join(lines)

    def _callsite_candidate_ids(self, callsite: CallsiteEvidence) -> tuple[str, ...]:
        observed = {
            target
            for observation in self._observations_by_callsite.get(callsite.id, ())
            for target in observation.candidate_target_ids
        }
        spelling = _relationship_name(callsite.callee_spelling)
        exact = {
            definition.id
            for definition in self._relationship_definitions.values()
            if definition.kind != "file" and _relationship_name(definition.name) == spelling
        }
        return tuple(sorted(observed | exact))

    def _render_call_candidate(self, callsite: CallsiteEvidence, candidate_ids: tuple[str, ...]) -> list[str]:
        caller = self._relationship_definitions[callsite.caller_definition_id]
        caller_target = self._relationship_target(caller)
        call_target = self._source_reference_target(
            callsite.source,
            name=f"call {callsite.callee_spelling}",
        )
        self._discovered_definition_ids.add(caller.id)
        lines = [
            f"- callsite `{callsite.id}` `{callsite.expression}`",
            f"  caller `{caller.id}` source `{caller_target.id}` {caller.source.path}:{caller.name}",
            f"  call source `{call_target.id}` receiver `{callsite.receiver_expression}`",
        ]
        observations = self._observations_by_callsite.get(callsite.id, ())
        for observation in observations:
            label = f" `{observation.label}`" if observation.label else ""
            lines.append(f"  clue `{observation.id}` {observation.producer}:{observation.kind}{label}")
        if not candidate_ids:
            lines.append("  candidates: no repository definition candidate")
            return lines
        for candidate_id in candidate_ids:
            candidate = self._relationship_definitions[candidate_id]
            candidate_target = self._relationship_target(candidate)
            self._discovered_definition_ids.add(candidate.id)
            lines.append(
                f"  candidate `{candidate.id}` source `{candidate_target.id}` "
                f"{candidate.source.path}:{candidate.signature or candidate.name}"
            )
        return lines

    def _source_span(self, target: SourceTarget, source: str) -> SourceSpan:
        selected = source[target.start : target.end]
        start_line = source[: target.start].count("\n") + 1
        return SourceSpan(
            file=target.file,
            start_line=start_line,
            end_line=start_line + max(1, len(selected.splitlines())) - 1,
        )

    def _definition_target(self, fragment: DefinitionFragment) -> SourceTarget:
        return self._definition_targets(fragment)[0]

    def _definition_targets(self, fragment: DefinitionFragment) -> tuple[SourceTarget, ...]:
        source = self._source(fragment.file)
        if fragment.end > len(source):
            raise SourceNavigationError(f"definition range exceeds source {fragment.identity}")
        selected = source[fragment.start : fragment.end]
        preview = next(
            (line.strip() for line in selected.splitlines() if line.strip()),
            "",
        )
        relationship = self._relationship_definitions_by_identity.get(fragment.identity)
        ranges = tuple(
            (start, min(start + _MAX_SOURCE_TARGET_CHARS, fragment.end))
            for start in range(fragment.start, fragment.end, _MAX_SOURCE_TARGET_CHARS)
        )
        total = len(ranges)
        return tuple(
            self._register_target(
                SourceTarget.create(
                    file=fragment.file,
                    name=(fragment.name if total == 1 else f"{fragment.name} page {index}/{total}"),
                    start=start,
                    end=end,
                    preview=preview[:240],
                    definition_id=relationship.id if relationship is not None else "",
                    source_kind=self._source_kind(fragment.file),
                )
            )
            for index, (start, end) in enumerate(ranges, start=1)
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
        if hashlib.sha256(selected.encode()).hexdigest() != reference.content_sha256:
            raise SourceNavigationError(f"relationship source changed at {reference.path}:{reference.start}")
        preview = next((line.strip() for line in selected.splitlines() if line.strip()), "")
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
    def _definition_identity(definition: DefinitionEvidence) -> str:
        source = definition.source
        return f"{source.path}:{definition.name}:{source.start}:{source.end}"

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

    def _source_kind(self, file: str) -> Literal["production", "test"]:
        return "test" if file in self._navigator.test_files else "production"

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
        path = (self._navigator.root / file).resolve()
        try:
            path.relative_to(self._navigator.root)
            if not path.is_file():
                raise OSError("not a regular file")
            if path.stat().st_size > _MAX_SEARCHABLE_FILE_BYTES:
                raise OSError(f"file exceeds {_MAX_SEARCHABLE_FILE_BYTES} bytes")
            source = path.read_bytes()
        except (OSError, ValueError) as exc:
            raise SourceNavigationError(f"cannot read navigation source {file!r}: {exc}") from exc
        expected_hash = self._source_hashes.get(file)
        current_hash = hashlib.sha256(source).hexdigest()
        if expected_hash is not None and current_hash != expected_hash:
            raise SourceNavigationError(f"navigation source changed after snapshot: {file}")
        self._source_bytes[file] = source
        return source


def navigation_instructions() -> str:
    """Render the shared model query contract."""
    return (
        "Repository source navigation is available. Syntax relationships are clues, not proven bindings. "
        "Use `search_symbols` or `search_text` to discover real source targets. Symbol results also publish a "
        "stable `def-*` definition id when relationship evidence exists. Search objects "
        "have exactly the keys `kind`, `query`, and `page`. Never add `path`, `file`, `symbol`, `target`, or "
        "explanation keys to a search object. The only valid search shapes are "
        '`{"kind":"search_symbols","query":"Handler","page":0}` and '
        '`{"kind":"search_text","query":"permission check","page":0}`. '
        "Use `search_call_candidates` only with a `def-*` id returned by a prior query. It returns syntax and "
        "analyzer candidates in either direction without claiming a binding. Its exact shape is "
        '`{"kind":"search_call_candidates","definition_id":"def-id","direction":"callers|callees|both",'
        '"page":0}`. Search results publish '
        "`src-*` ids. A unique complete `search_symbols` match may include its exact source and evidence "
        "receipt in the same exchange. Do not request that id again. Other search results do not expose "
        "source. Request every unread `ev-*` or `src-*` id through `evidence_requests` before relying on it "
        "in a finding. The engine dispatches registered ids and never chooses one candidate for you. "
        "Do not claim external calls or relationships that exact source does not establish. An unrelated call "
        "needs no claim. Batch every independent search that can be named from "
        "the current evidence into one response. Do not use `source_queries` to read a path or target. "
        "Return an empty list when no search is needed."
    )


def parse_source_queries(value: object) -> list[dict[str, object]]:
    """Validate model-facing source searches without accepting exact reads."""
    return _queries(value)


def _queries(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise SourceNavigationError("source_queries must be a list")
    if len(value) > _MAX_QUERIES_PER_BATCH:
        raise SourceNavigationError(f"source_queries cannot contain more than {_MAX_QUERIES_PER_BATCH} queries")
    queries: list[dict[str, object]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise SourceNavigationError(f"source query {index + 1} must be an object")
        kind = raw.get("kind")
        if kind not in {"search_symbols", "search_text", "search_call_candidates"}:
            raise SourceNavigationError(f"source query {index + 1} has unknown kind {kind!r}")
        allowed = (
            {"kind", "definition_id", "direction", "page"}
            if kind == "search_call_candidates"
            else {"kind", "query", "page"}
        )
        extra = set(raw).difference(allowed)
        if extra:
            raise SourceNavigationError(
                f"source query {index + 1} has unknown fields: {', '.join(sorted(str(item) for item in extra))}"
            )
        if kind == "search_call_candidates":
            definition_id = raw.get("definition_id")
            direction = raw.get("direction")
            page = raw.get("page")
            if not isinstance(definition_id, str) or not definition_id.startswith("def-"):
                raise SourceNavigationError(f"source query {index + 1} definition_id must be a def-* id")
            if direction not in {"callers", "callees", "both"}:
                raise SourceNavigationError(f"source query {index + 1} direction must be callers, callees, or both")
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


def _page[T](targets: tuple[T, ...], page: int) -> tuple[tuple[T, ...], int, bool]:
    start = page * _MAX_RESULTS_PER_PAGE
    selected = targets[start : start + _MAX_RESULTS_PER_PAGE]
    return selected, page, start + len(selected) < len(targets)


def _render_search(
    index: int,
    kind: str,
    query: str,
    targets: tuple[SourceTarget, ...],
    page: int,
    more: bool,
) -> str:
    lines = [
        f"Source query {index} `{kind}` for `{query}`, page {page}.",
        "These are search clues, not resolved bindings or finding evidence.",
    ]
    lines.extend(
        f"- `{target.id}`"
        + (f" definition `{target.definition_id}`" if target.definition_id else "")
        + f" [{target.source_kind}] {target.file}:{target.name} | `{target.preview}`"
        for target in targets
    )
    if not targets:
        lines.append("- no matches")
    if more:
        lines.append(f"- more results are available on page {page + 1}")
    return "\n".join(lines)


def _graph_source_files(
    root: Path,
    graph: FactsGraph,
    definitions: tuple[DefinitionFragment, ...],
    source_files: Iterable[str],
) -> tuple[str, ...]:
    candidates = [*(fragment.file for fragment in definitions), *source_files]
    for key in ("syntax_imports", "imports", "references", "import_targets"):
        values = graph.get(key)
        if not isinstance(values, dict):
            continue
        candidates.extend(str(file) for file in values if isinstance(file, str))
        if key == "import_targets":
            candidates.extend(
                target
                for targets in values.values()
                if isinstance(targets, list)
                for target in targets
                if isinstance(target, str)
            )
    files = []
    for file in dict.fromkeys(candidates):
        path = (root / file).resolve()
        try:
            path.relative_to(root)
        except (OSError, ValueError):
            continue
        if path.is_file():
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


def _source_hash(root: Path, file: str) -> str:
    path = (root / file).resolve()
    try:
        path.relative_to(root)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, ValueError) as exc:
        raise SourceNavigationError(f"cannot snapshot navigation source {file!r}: {exc}") from exc


def _relationship_name(value: str) -> str:
    """Normalize one qualified syntax spelling for candidate search."""
    return value.rsplit(".", 1)[-1]
