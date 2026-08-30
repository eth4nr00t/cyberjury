"""Bounded source navigation over verified repository facts."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from cyberjury.numbering import numbered_source
from cyberjury.review.context import GroundingCoverage, SourceEvidence, SourceSpan
from cyberjury.review.definitions import (
    DefinitionDependency,
    DefinitionFragment,
    FactsGraph,
    definition_dependencies,
    definition_fragments,
)

type SourceQueryKind = Literal["search_symbols", "search_text", "related_sources"]

_MAX_RESULTS_PER_PAGE = 20
_MAX_SEARCHABLE_FILE_BYTES = 2_000_000


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

    @classmethod
    def create(
        cls,
        *,
        file: str,
        name: str,
        start: int,
        end: int,
        preview: str,
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
    dependencies: tuple[DefinitionDependency, ...]
    files: tuple[str, ...]

    @classmethod
    def from_graph(
        cls,
        root: str | Path,
        graph: FactsGraph,
        *,
        source_files: Iterable[str] = (),
    ) -> SourceNavigator | None:
        """Build navigation from shared facts without adding resolver semantics."""
        base = Path(root).resolve()
        fragments = definition_fragments(graph)
        all_definitions = tuple(fragment for values in fragments.values() for fragment in values)
        files = _graph_source_files(base, graph, all_definitions, source_files)
        included = set(files)
        definitions = tuple(fragment for fragment in all_definitions if fragment.file in included)
        if not definitions and not files:
            return None
        graph_dependencies = definition_dependencies(graph) if "dependencies" in graph else ()
        dependencies = tuple(
            dependency
            for dependency in graph_dependencies
            if dependency.resolution == "supported"
            and dependency.kind == "call"
            and dependency.target.file in included
            and (dependency.source is None or dependency.source.file in included)
        )
        return cls(root=base, definitions=definitions, dependencies=dependencies, files=files)

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

    def execute(self, requested: object, *, target_chars: int) -> SourceNavigationResult:
        """Execute a strict batch and fail rather than reinterpret malformed queries."""
        queries = _queries(requested)
        blocks: list[str] = []
        for index, query in enumerate(queries, start=1):
            kind = query["kind"]
            if kind == "search_symbols":
                targets, page, more = self._search_symbols(query["query"], query["page"])
                blocks.append(_render_search(index, kind, query["query"], targets, page, more))
                continue
            if kind == "search_text":
                targets, page, more = self._search_text(query["query"], query["page"])
                blocks.append(_render_search(index, kind, query["query"], targets, page, more))
                continue
            if kind == "related_sources":
                targets, page, more = self._related_sources(
                    query["target"],
                    query["direction"],
                    query["page"],
                )
                blocks.append(_render_related(index, query["target"], query["direction"], targets, page, more))
                continue
            raise SourceNavigationError(f"source query {index} has unknown kind {kind!r}")
        return SourceNavigationResult(text="\n\n".join(blocks))

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
        targets = tuple(self._definition_target(fragment) for fragment in matches)
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
                    )
                    targets.append(self._register_target(target))
        return _page(tuple(targets), page)

    def _related_sources(
        self,
        target_id: str,
        direction: str,
        page: int,
    ) -> tuple[tuple[SourceTarget, ...], int, bool]:
        target = self._targets.get(target_id)
        if target is None:
            raise SourceNavigationError(
                f"related source query requests unknown target {target_id!r}. "
                "Use only a definition target returned by an earlier search."
            )
        fragments = {fragment.identity: fragment for fragment in self._navigator.definitions}
        selected = fragments.get(target.identity)
        if selected is None:
            raise SourceNavigationError(f"source target {target_id!r} is not a definition")
        related: list[DefinitionFragment] = []
        for dependency in self._navigator.dependencies:
            if direction in {"callees", "both"} and dependency.source == selected:
                related.append(dependency.target)
            if direction in {"callers", "both"} and dependency.target == selected and dependency.source is not None:
                related.append(dependency.source)
        targets = tuple(self._definition_target(fragment) for fragment in dict.fromkeys(related))
        return _page(targets, page)

    def _source_span(self, target: SourceTarget, source: str) -> SourceSpan:
        selected = source[target.start : target.end]
        start_line = source[: target.start].count("\n") + 1
        return SourceSpan(
            file=target.file,
            start_line=start_line,
            end_line=start_line + max(1, len(selected.splitlines())) - 1,
        )

    def _definition_target(self, fragment: DefinitionFragment) -> SourceTarget:
        source = self._source(fragment.file)
        if fragment.end > len(source):
            raise SourceNavigationError(f"definition range exceeds source {fragment.identity}")
        selected = source[fragment.start : fragment.end]
        preview = next(
            (line.strip() for line in selected.splitlines() if line.strip()),
            "",
        )
        target = SourceTarget.create(
            file=fragment.file,
            name=fragment.name,
            start=fragment.start,
            end=fragment.end,
            preview=preview[:240],
        )
        return self._register_target(target)

    def _register_target(self, target: SourceTarget) -> SourceTarget:
        existing = self._targets_by_identity.get(target.identity)
        if existing is not None:
            return existing
        registered = SourceTarget(
            id=f"src-{len(self._targets_by_identity) + 1}",
            identity=target.identity,
            file=target.file,
            name=target.name,
            start=target.start,
            end=target.end,
            preview=target.preview,
        )
        self._targets[registered.id] = registered
        self._targets_by_identity[registered.identity] = registered
        return registered

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
        self._source_bytes[file] = source
        return source


def navigation_instructions() -> str:
    """Render the shared model query contract."""
    return (
        "Repository source navigation is available. Syntax relationships are clues, not proven bindings. "
        "Use `search_symbols` or `search_text` to discover real source targets. Use `related_sources` only on "
        "a definition target returned by a search to inspect exact callers, callees, or both. Search objects "
        "have exactly the keys `kind`, `query`, and `page`. Never add `path`, `file`, `symbol`, `target`, or "
        "explanation keys to a search object. The only valid search shapes are "
        '`{"kind":"search_symbols","query":"Handler","page":0}` and '
        '`{"kind":"search_text","query":"permission check","page":0}`. A relationship object has exactly '
        "the keys `kind`, `target`, `direction`, and `page`. Its shape is "
        '`{"kind":"related_sources","target":"src-1","direction":"callees","page":0}`. Search results publish '
        "`src-*` ids but do not expose their source. Request every exact `ev-*` or `src-*` id through "
        "`evidence_requests` before relying on it in a finding. The engine dispatches registered ids and "
        "never chooses one search result for you. Batch every independent search that can be named from "
        "the current evidence into one response. Do not use `source_queries` to read a path or target. "
        "Return an empty list when no search is needed."
    )


def parse_source_queries(value: object) -> list[dict[str, object]]:
    """Validate model-facing source searches without accepting exact reads."""
    return _queries(value)


def _queries(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise SourceNavigationError("source_queries must be a list")
    queries: list[dict[str, object]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise SourceNavigationError(f"source query {index + 1} must be an object")
        kind = raw.get("kind")
        if kind not in {"search_symbols", "search_text", "related_sources"}:
            raise SourceNavigationError(f"source query {index + 1} has unknown kind {kind!r}")
        allowed = {"kind", "target", "direction", "page"} if kind == "related_sources" else {"kind", "query", "page"}
        extra = set(raw).difference(allowed)
        if extra:
            raise SourceNavigationError(
                f"source query {index + 1} has unknown fields: {', '.join(sorted(str(item) for item in extra))}"
            )
        if kind == "related_sources":
            target = raw.get("target")
            direction = raw.get("direction")
            page = raw.get("page")
            if not isinstance(target, str) or not target.strip():
                raise SourceNavigationError(f"source query {index + 1} target must be a nonempty string")
            if direction not in {"callers", "callees", "both"}:
                raise SourceNavigationError(f"source query {index + 1} direction must be callers, callees, or both")
            if not isinstance(page, int) or isinstance(page, bool) or page < 0:
                raise SourceNavigationError(f"source query {index + 1} page must be a nonnegative integer")
            queries.append({"kind": kind, "target": target.strip(), "direction": direction, "page": page})
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


def _page(targets: tuple[SourceTarget, ...], page: int) -> tuple[tuple[SourceTarget, ...], int, bool]:
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
    lines.extend(f"- `{target.id}` {target.file}:{target.name} | `{target.preview}`" for target in targets)
    if not targets:
        lines.append("- no matches")
    if more:
        lines.append(f"- more results are available on page {page + 1}")
    return "\n".join(lines)


def _render_related(
    index: int,
    target: str,
    direction: str,
    targets: tuple[SourceTarget, ...],
    page: int,
    more: bool,
) -> str:
    lines = [
        f"Source query {index} `related_sources` for `{target}` direction `{direction}`, page {page}.",
        "These are exact repository relationships, not security conclusions or finding evidence.",
    ]
    lines.extend(f"- `{item.id}` {item.file}:{item.name} | `{item.preview}`" for item in targets)
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
