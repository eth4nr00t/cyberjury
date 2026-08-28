"""Bounded source navigation over verified repository facts."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from cyberjury.numbering import numbered_source
from cyberjury.review.context import GroundingCoverage, SourceEvidence
from cyberjury.review.definitions import DefinitionFragment, FactsGraph, definition_fragments

type SourceQueryKind = Literal["search_symbols", "search_text", "read_source"]

_MAX_RESULTS_PER_PAGE = 20
_MAX_SEARCHABLE_FILE_BYTES = 2_000_000


class SourceNavigationError(RuntimeError):
    """A source query is malformed, unsafe, or exceeds its budget."""


@dataclass(frozen=True, kw_only=True)
class SourceTarget:
    """One real UTF-8 byte range returned by a navigation search."""

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
        return cls(root=base, definitions=definitions, files=files)

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
        source_evidence: list[SourceEvidence] = []
        coverage = GroundingCoverage()
        read_chars = 0
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
            target = self._targets.get(query["target"])
            if target is None:
                raise SourceNavigationError(
                    f"source query {index} requests unknown target {query['target']!r}. "
                    "Read only target ids returned by an earlier search."
                )
            source = self._source_bytes_for(target.file)
            if target.end > len(source):
                raise SourceNavigationError(f"source target {target.id} exceeds {target.file}")
            try:
                selected = source[target.start : target.end].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SourceNavigationError(f"source target {target.id} splits a UTF-8 character") from exc
            text = numbered_source(
                target.file,
                selected,
                source[: target.start].count(b"\n") + 1,
            )
            read_chars += len(text)
            if read_chars > target_chars:
                raise SourceNavigationError(f"source queries exceed the {target_chars} character target")
            blocks.append(f"Read source `{target.id}` {target.file}:{target.name}:\n{text}")
            source_evidence.append(SourceEvidence(id=target.id, identity=target.identity, text=text))
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

    def read(self, requested: object, *, target_chars: int) -> SourceNavigationResult:
        """Read exact targets already discovered by this session."""
        if not isinstance(requested, list) or not all(isinstance(item, str) for item in requested):
            raise SourceNavigationError("evidence_requests must contain source target ids")
        targets = tuple(dict.fromkeys(item.strip() for item in requested if item.strip()))
        return self.execute(
            [{"kind": "read_source", "target": target} for target in targets],
            target_chars=target_chars,
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
                    source_bytes = self._source_bytes_for(file)
                    start = _line_byte_offset(source_bytes, max(1, line_no - 3))
                    end = _line_byte_offset(source_bytes, line_no + 4)
                    target = SourceTarget.create(
                        file=file,
                        name=f"text line {line_no}",
                        start=start,
                        end=end,
                        preview=line.strip()[:240],
                    )
                    targets.append(self._register_target(target))
        return _page(tuple(targets), page)

    def _definition_target(self, fragment: DefinitionFragment) -> SourceTarget:
        source = self._source_bytes_for(fragment.file)
        if fragment.end > len(source):
            raise SourceNavigationError(f"definition range exceeds source {fragment.identity}")
        try:
            selected = source[fragment.start : fragment.end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SourceNavigationError(f"definition range splits a UTF-8 character {fragment.identity}") from exc
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
        "Use `search_symbols` or `search_text` to discover real source targets. Each search object has exactly "
        "the keys `kind`, `query`, and `page`. Never add `path`, `file`, `symbol`, `target`, or explanation keys. "
        "The only valid search shapes are "
        '`{"kind":"search_symbols","query":"Handler","page":0}` and '
        '`{"kind":"search_text","query":"permission check","page":0}`. Search results publish '
        "`src-*` ids but do not expose their source. Request every exact `ev-*` or `src-*` id through "
        "`evidence_requests` before relying on it in a finding. The engine dispatches registered ids and "
        "never chooses one search result for you. Batch every independent search that can be named from "
        "the current evidence into one response. Do not use `source_queries` to read a path or target. "
        "Return an empty list when no search is needed."
    )


def partition_source_queries(value: object) -> tuple[list[dict[str, object]], list[str]]:
    """Separate searches from exact reads using the strict source query grammar."""
    searches: list[dict[str, object]] = []
    reads: list[str] = []
    for query in _queries(value):
        if query["kind"] == "read_source":
            reads.append(str(query["target"]))
        else:
            searches.append(query)
    return searches, reads


def _queries(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise SourceNavigationError("source_queries must be a list")
    queries: list[dict[str, object]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise SourceNavigationError(f"source query {index + 1} must be an object")
        kind = raw.get("kind")
        if kind not in {"search_symbols", "search_text", "read_source"}:
            raise SourceNavigationError(f"source query {index + 1} has unknown kind {kind!r}")
        allowed = {"kind", "query", "page"} if kind != "read_source" else {"kind", "target"}
        extra = set(raw).difference(allowed)
        if extra:
            raise SourceNavigationError(
                f"source query {index + 1} has unknown fields: {', '.join(sorted(str(item) for item in extra))}"
            )
        if kind == "read_source":
            target = raw.get("target")
            if not isinstance(target, str) or not target.strip():
                raise SourceNavigationError(f"source query {index + 1} target must be a nonempty string")
            queries.append({"kind": kind, "target": target.strip()})
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


def _line_byte_offset(source: bytes, line: int) -> int:
    if line <= 1:
        return 0
    offset = 0
    for _ in range(line - 1):
        next_line = source.find(b"\n", offset)
        if next_line < 0:
            return len(source)
        offset = next_line + 1
    return offset
