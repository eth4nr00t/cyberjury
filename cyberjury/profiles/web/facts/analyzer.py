"""Parse one source file into language-neutral graph inputs."""

from __future__ import annotations

import importlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import yaml

if TYPE_CHECKING:
    from tree_sitter import Language, Node

if sys.version_info >= (3, 13):
    from types import CapsuleType
else:
    CapsuleType = object

_QUERIES_FILE = Path(__file__).resolve().parent / "queries.yaml"
MAX_SOURCE_BYTES = 400_000


class SourceParseError(RuntimeError):
    """A reviewable source file cannot produce complete syntax facts."""

    def __init__(self, reason: str, *, line: int | None = None, column: int | None = None) -> None:
        """Preserve a stable reason and optional source location."""
        super().__init__(reason)
        self.reason = reason
        self.line = line
        self.column = column


class AnalyzerConfigurationError(RuntimeError):
    """The configured grammar queries cannot produce a valid analysis."""


class SourceReadError(RuntimeError):
    """Source bytes required for analysis are unavailable."""


@dataclass(frozen=True)
class AnalyzedDefinition:
    """One syntax definition and its unresolved call names."""

    name: str
    file: str
    start: int
    end: int
    unqualified_scope: str
    unqualified_target: bool
    is_type: bool
    calls: tuple[str, ...] = ()
    direct_calls: tuple[str, ...] = ()
    local_calls: tuple[str, ...] = ()
    owner: AnalyzedOwner | None = None
    type_owner: AnalyzedOwner | None = None
    local_receiver_is_type_bound: bool = False


@dataclass(frozen=True)
class AnalyzedOwner:
    """Identify the nearest lexical definition that owns another definition."""

    name: str
    start: int
    end: int


@dataclass(frozen=True, kw_only=True)
class AnalyzedLimitation:
    """One source that remains reviewable without complete syntax facts."""

    source: str
    analyzer: str
    reason: str
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True)
class LangSpec:
    """Define one language grammar and its graph queries."""

    name: str
    extensions: tuple[str, ...]
    resolution_languages: tuple[str, ...]
    module: str
    accessor: str
    definitions: str
    type_definitions: str
    calls: str
    imports: tuple[ImportQuery, ...]
    unqualified_call_scope: Literal["file", "package"]
    package_name_query: str = ""
    module_entries: tuple[str, ...] = ()
    local_receivers: tuple[str, ...] = ()
    local_receiver_roots: str = ""
    local_receiver_barriers: str = ""
    namespace_imports: tuple[str, ...] = ()
    qualified_uses: str = ""
    default_exports: str = ""
    namespace_resolves_directory: bool = False
    namespace_binds: str = "last-segment"


@dataclass(frozen=True)
class ImportQuery:
    """Define one declarative import query and its optional remote literal."""

    query: str
    imported: str = ""


@dataclass(frozen=True)
class AnalyzedImport:
    """Preserve one remote symbol, local binding, and module specifier."""

    imported: str
    local: str
    module: str


@dataclass(frozen=True, kw_only=True)
class AnalyzedFile:
    """Syntax facts extracted from one complete source file."""

    definitions: tuple[AnalyzedDefinition, ...]
    imports: tuple[AnalyzedImport, ...]
    namespaces: tuple[tuple[str, str], ...]
    qualified_uses: tuple[tuple[str, str], ...]
    default_exports: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class AnalyzedRepository:
    """Syntax analysis and explicit source limitations before resolution."""

    definitions: tuple[AnalyzedDefinition, ...]
    imports: dict[str, list[AnalyzedImport]]
    namespaces: dict[str, dict[str, str]]
    qualified_uses: dict[str, list[tuple[str, str]]]
    default_exports: dict[str, list[str]]
    limitations: tuple[AnalyzedLimitation, ...] = ()


type AnalyzableSource = tuple[Path, str, LangSpec]


def load_specs(path: Path | None = None) -> dict[str, LangSpec]:
    """Load declarative language grammar and query contracts."""
    raw = yaml.safe_load((path or _QUERIES_FILE).read_text(encoding="utf-8")) or {}
    specs: dict[str, LangSpec] = {}
    for name, config in raw.items():
        module, accessor = config["grammar"]
        specs[name] = LangSpec(
            name=name,
            extensions=tuple(config["extensions"]),
            resolution_languages=_resolution_languages(name, config.get("resolution_languages")),
            module=module,
            accessor=accessor,
            definitions=_definition_query(name, config.get("definitions")),
            type_definitions=(config.get("type_definitions") or "").strip(),
            calls=config["calls"].strip(),
            imports=_import_queries(name, config.get("imports", ())),
            unqualified_call_scope=_unqualified_call_scope(name, config),
            package_name_query=(config.get("package_name_query") or "").strip(),
            module_entries=tuple(str(value) for value in config.get("module_entries", ())),
            local_receivers=tuple(str(value) for value in config.get("local_receivers", ())),
            local_receiver_roots=(config.get("local_receiver_roots") or "").strip(),
            local_receiver_barriers=(config.get("local_receiver_barriers") or "").strip(),
            namespace_imports=tuple(query.strip() for query in config.get("namespace_imports", ())),
            qualified_uses=(config.get("qualified_uses") or "").strip(),
            default_exports=(config.get("default_exports") or "").strip(),
            namespace_resolves_directory=_boolean_setting(name, config, "namespace_resolves_directory"),
            namespace_binds=_namespace_binding(name, config),
        )
    for name, spec in specs.items():
        missing = set(spec.resolution_languages) - specs.keys()
        if missing:
            names = ", ".join(sorted(missing))
            raise ValueError(f"{name} resolution_languages names unknown languages: {names}")
    return specs


def _unqualified_call_scope(language: str, config: dict[str, object]) -> Literal["file", "package"]:
    value = config.get("unqualified_call_scope")
    if value not in ("file", "package"):
        raise ValueError(f"{language} unqualified_call_scope must be file or package")
    package_query = config.get("package_name_query")
    if value == "package" and (not isinstance(package_query, str) or not package_query.strip()):
        raise ValueError(f"{language} package_name_query must contain a query")
    return value


def _definition_query(language: str, raw: object) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{language} definitions must contain query text")
    missing = [capture for capture in ("@def", "@name", "@target") if capture not in raw]
    if missing:
        names = ", ".join(missing)
        raise ValueError(f"{language} definitions must declare captures: {names}")
    return raw.strip()


def _import_queries(language: str, raw: object) -> tuple[ImportQuery, ...]:
    if not isinstance(raw, list | tuple):
        raise ValueError(f"{language} imports must be a list")
    queries: list[ImportQuery] = []
    for position, value in enumerate(raw):
        if isinstance(value, str):
            query = value
            imported = ""
        elif isinstance(value, dict):
            query = value.get("query")
            imported = value.get("imported", "")
        else:
            raise ValueError(f"{language} import query {position} must be text or a mapping")
        if not isinstance(query, str) or not query.strip():
            raise ValueError(f"{language} import query {position} must contain query text")
        if not isinstance(imported, str):
            raise ValueError(f"{language} import query {position} imported must be text")
        queries.append(ImportQuery(query.strip(), imported))
    return tuple(queries)


def _namespace_binding(language: str, config: dict[str, object]) -> str:
    value = str(config.get("namespace_binds") or "last-segment").strip()
    if value not in ("whole", "last-segment"):
        raise ValueError(f"{language} declares an unknown namespace_binds {value!r}")
    return value


def _boolean_setting(language: str, config: dict[str, object], key: str) -> bool:
    value = config.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{language} {key} must be a boolean")
    return value


def _resolution_languages(language: str, raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list | tuple) or not raw:
        raise ValueError(f"{language} resolution_languages must be a nonempty list")
    values = tuple(raw)
    if not all(isinstance(value, str) and value for value in values):
        raise ValueError(f"{language} resolution_languages must contain nonempty names")
    if language not in values:
        raise ValueError(f"{language} resolution_languages must include itself")
    if len(values) != len(set(values)):
        raise ValueError(f"{language} resolution_languages must be unique")
    return values


def spec_for(specs: dict[str, LangSpec], rel: str) -> LangSpec | None:
    """Select the language contract for one repository path."""
    suffix = Path(rel).suffix
    return next((spec for spec in specs.values() if suffix in spec.extensions), None)


def grammar_for(spec: LangSpec) -> CapsuleType | None:
    """Return the installed grammar object for one language specification."""
    try:
        module = importlib.import_module(spec.module)
    except ImportError:
        return None
    accessor = getattr(module, spec.accessor, None)
    return accessor() if callable(accessor) else None


def available(specs: dict[str, LangSpec]) -> bool:
    """Require the Tree-sitter query API and one configured grammar."""
    try:
        module = importlib.import_module("tree_sitter")
    except ImportError:
        return False
    if not all(hasattr(module, name) for name in ("Language", "Parser", "Query", "QueryCursor")):
        return False
    return any(grammar_for(spec) is not None for spec in specs.values())


def character_offsets(source: bytes) -> dict[int, int] | None:
    """Map Tree-sitter byte offsets to decoded text offsets when they differ."""
    if source.isascii() and b"\r" not in source:
        return None
    text = source.decode("utf-8", "replace")
    offsets: dict[int, int] = {}
    byte = index = position = 0
    while position < len(text):
        offsets[byte] = index
        character = text[position]
        if character == "\r" and text[position + 1 : position + 2] == "\n":
            byte += 2
            position += 2
        else:
            byte += len(character.encode("utf-8"))
            position += 1
        index += 1
    offsets[byte] = index
    return offsets


def _text(source: bytes, node: Node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _is_direct_self_call(definition_name: str, callee_name: str, callee: Node) -> bool:
    if callee_name != definition_name:
        return False
    parent = callee.parent
    return parent is not None and parent.type in ("call", "call_expression")


def _node_range(node: Node, offsets: dict[int, int] | None) -> tuple[int, int]:
    start, end = node.start_byte, node.end_byte
    if offsets is not None:
        start, end = offsets.get(start, start), offsets.get(end, end)
    return start, end


def _nearest_definition(node: Node, definitions: tuple[tuple[Node, Node], ...]) -> tuple[Node, Node] | None:
    candidates = [
        definition
        for definition in definitions
        if definition[0].start_byte <= node.start_byte
        and node.end_byte <= definition[0].end_byte
        and (definition[0].start_byte, definition[0].end_byte) != (node.start_byte, node.end_byte)
    ]
    return min(candidates, key=lambda definition: definition[0].end_byte - definition[0].start_byte, default=None)


def _belongs_to_definition(node: Node, definition: Node, definitions: tuple[tuple[Node, Node], ...]) -> bool:
    owner = _nearest_definition(node, definitions)
    return owner is not None and owner[0] == definition


def _definition_calls(
    source: bytes,
    node: Node,
    name: str,
    definitions: tuple[tuple[Node, Node], ...],
    call_query: object,
    spec: LangSpec,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    from tree_sitter import QueryCursor

    calls: dict[str, None] = {}
    direct_calls: dict[str, None] = {}
    local_calls: dict[str, None] = {}
    for _, captures in QueryCursor(call_query).matches(node):
        for callee in captures.get("callee") or ():
            if not _belongs_to_definition(callee, node, definitions):
                continue
            called = _text(source, callee)
            if not _is_direct_self_call(name, called, callee):
                calls.setdefault(called, None)
                direct_calls.setdefault(called, None)
        members = captures.get("member") or ()
        receivers = captures.get("receiver") or ()
        for member in members:
            if not _belongs_to_definition(member, node, definitions):
                continue
            called = _text(source, member)
            calls.setdefault(called, None)
            if receivers and _text(source, receivers[0]) in spec.local_receivers:
                local_calls.setdefault(called, None)
    return tuple(calls), tuple(direct_calls), tuple(local_calls)


def _lexical_owner(
    source: bytes,
    node: Node,
    containers: tuple[tuple[Node, Node], ...],
    offsets: dict[int, int] | None,
) -> AnalyzedOwner | None:
    owner_match = _nearest_definition(node, containers)
    if owner_match is None:
        return None
    owner_node, owner_name = owner_match
    owner_start, owner_end = _node_range(owner_node, offsets)
    return AnalyzedOwner(_text(source, owner_name), owner_start, owner_end)


def _query_nodes(root: Node, language: Language, query_text: str, capture: str) -> tuple[Node, ...]:
    from tree_sitter import Query, QueryCursor

    if not query_text:
        return ()
    return tuple(
        node
        for _, captures in QueryCursor(Query(language, query_text)).matches(root)
        for node in captures.get(capture) or ()
    )


def _nearest_enclosing(node: Node, candidates: tuple[Node, ...]) -> Node | None:
    enclosing = [
        candidate
        for candidate in candidates
        if candidate.start_byte <= node.start_byte and node.end_byte <= candidate.end_byte
    ]
    return min(enclosing, key=lambda candidate: candidate.end_byte - candidate.start_byte, default=None)


def _local_receiver_is_type_bound(
    node: Node,
    type_owner: AnalyzedOwner | None,
    roots: tuple[Node, ...],
    barriers: tuple[Node, ...],
) -> bool:
    if type_owner is None:
        return False
    if not roots and not barriers:
        return True
    root = _nearest_enclosing(node, roots)
    if root is None:
        return False
    barrier = _nearest_enclosing(node, barriers)
    if barrier is None:
        return True
    root_size = root.end_byte - root.start_byte
    barrier_size = barrier.end_byte - barrier.start_byte
    return root_size <= barrier_size


def _definitions(
    source: bytes,
    root: Node,
    language: Language,
    spec: LangSpec,
    unqualified_scope: str,
) -> tuple[AnalyzedDefinition, ...]:
    from tree_sitter import Query, QueryCursor

    call_query = Query(language, spec.calls)
    offsets = character_offsets(source)
    matches: list[tuple[Node, Node, bool]] = []
    for _, captures in QueryCursor(Query(language, spec.definitions)).matches(root):
        node = (captures.get("def") or [None])[0]
        identifier = (captures.get("name") or [None])[0]
        if node is not None and identifier is not None:
            targets = captures.get("target") or ()
            is_target = any(
                target.start_byte == node.start_byte and target.end_byte == node.end_byte for target in targets
            )
            matches.append((node, identifier, is_target))
    definition_nodes = tuple((node, identifier) for node, identifier, _ in matches)
    type_nodes: tuple[tuple[Node, Node], ...] = ()
    if spec.type_definitions:
        type_nodes = tuple(
            (node, identifier)
            for _, captures in QueryCursor(Query(language, spec.type_definitions)).matches(root)
            if (node := (captures.get("type") or [None])[0]) is not None
            and (identifier := (captures.get("name") or [None])[0]) is not None
        )
    receiver_roots = _query_nodes(root, language, spec.local_receiver_roots, "root")
    receiver_barriers = _query_nodes(root, language, spec.local_receiver_barriers, "barrier")
    definitions: list[AnalyzedDefinition] = []
    type_ranges = {(node.start_byte, node.end_byte) for node, _ in type_nodes}
    for node, identifier, unqualified_target in matches:
        name = _text(source, identifier)
        calls, direct_calls, local_calls = _definition_calls(
            source,
            node,
            name,
            definition_nodes,
            call_query,
            spec,
        )
        start, end = _node_range(node, offsets)
        type_owner = _lexical_owner(source, node, type_nodes, offsets)
        definitions.append(
            AnalyzedDefinition(
                name=name,
                file="",
                start=start,
                end=end,
                calls=calls,
                direct_calls=direct_calls,
                local_calls=local_calls,
                unqualified_scope=unqualified_scope,
                unqualified_target=unqualified_target,
                is_type=(node.start_byte, node.end_byte) in type_ranges,
                owner=_lexical_owner(source, node, definition_nodes, offsets),
                type_owner=type_owner,
                local_receiver_is_type_bound=_local_receiver_is_type_bound(
                    node,
                    type_owner,
                    receiver_roots,
                    receiver_barriers,
                ),
            )
        )
    return tuple(definitions)


def _unqualified_scope(source: bytes, root: Node, language: Language, spec: LangSpec, rel: str) -> str:
    if spec.unqualified_call_scope == "file":
        return f"file:{rel}"
    names = tuple(
        dict.fromkeys(_text(source, node) for node in _query_nodes(root, language, spec.package_name_query, "name"))
    )
    if len(names) != 1:
        raise SourceParseError("package scope must resolve one package name")
    parent = Path(rel).parent.as_posix()
    return f"package:{parent}:{names[0]}"


def _imports(source: bytes, root: Node, language: Language, spec: LangSpec) -> tuple[AnalyzedImport, ...]:
    from tree_sitter import Query, QueryCursor

    imports: list[AnalyzedImport] = []
    for import_query in spec.imports:
        for _, captures in QueryCursor(Query(language, import_query.query)).matches(root):
            modules = captures.get("module") or ()
            imported_nodes = captures.get("imported") or ()
            aliases = captures.get("alias") or ()
            imported_names = tuple(_text(source, node) for node in imported_nodes)
            if import_query.imported:
                imported_names = (import_query.imported,)
            if not modules or not imported_names:
                continue
            module = _text(source, modules[0])
            for position, imported in enumerate(imported_names):
                local = _text(source, aliases[position]) if position < len(aliases) else imported
                imports.append(AnalyzedImport(imported=imported, local=local, module=module))
    return tuple(imports)


def _namespaces(source: bytes, root: Node, language: Language, spec: LangSpec) -> tuple[tuple[str, str], ...]:
    from tree_sitter import Query, QueryCursor

    namespaces: list[tuple[str, str]] = []
    for query_text in spec.namespace_imports:
        for _, captures in QueryCursor(Query(language, query_text)).matches(root):
            modules = captures.get("module") or ()
            if not modules:
                continue
            specifier = _text(source, modules[0]).strip("\"'")
            aliases = captures.get("alias") or ()
            if aliases:
                local = _text(source, aliases[0])
            elif spec.namespace_binds == "whole":
                local = specifier
            else:
                local = specifier.replace("/", ".").split(".")[-1]
            namespaces.append((local, specifier))
    return tuple(namespaces)


def _qualified_uses(
    source: bytes,
    root: Node,
    language: Language,
    spec: LangSpec,
) -> tuple[tuple[str, str], ...]:
    from tree_sitter import Query, QueryCursor

    if not spec.qualified_uses:
        return ()
    uses: list[tuple[str, str]] = []
    for _, captures in QueryCursor(Query(language, spec.qualified_uses)).matches(root):
        qualifiers = captures.get("qualifier") or ()
        names = captures.get("name") or ()
        if qualifiers and names:
            uses.append((_text(source, qualifiers[0]), _text(source, names[0])))
    return tuple(uses)


def _default_exports(source: bytes, root: Node, language: Language, spec: LangSpec) -> tuple[str, ...]:
    from tree_sitter import Query, QueryCursor

    if not spec.default_exports:
        return ()
    names = [
        _text(source, name)
        for _, captures in QueryCursor(Query(language, spec.default_exports)).matches(root)
        for name in captures.get("name") or ()
    ]
    return tuple(dict.fromkeys(names))


def _first_parse_problem(root: Node) -> tuple[int, int]:
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == "ERROR" or node.is_missing:
            return node.start_point.row + 1, node.start_point.column + 1
        pending.extend(reversed(node.children))
    return root.start_point.row + 1, root.start_point.column + 1


def parse_file(path: Path, rel: str, spec: LangSpec) -> AnalyzedFile:
    """Parse every configured query family for one reviewable file."""
    from tree_sitter import Language, Parser

    grammar = grammar_for(spec)
    if grammar is None:
        raise AnalyzerConfigurationError(f"missing grammar for {spec.name}")
    try:
        source = path.read_bytes()
    except OSError as exc:
        raise SourceReadError(f"cannot read source {rel}") from exc
    if len(source) > MAX_SOURCE_BYTES:
        raise SourceParseError("over the parse cap")
    language = Language(grammar)
    try:
        tree = Parser(language).parse(source)
    except (ValueError, RuntimeError) as exc:
        raise SourceParseError("unparsable") from exc
    if tree.root_node.has_error:
        line, column = _first_parse_problem(tree.root_node)
        raise SourceParseError("unparsable", line=line, column=column)
    try:
        unqualified_scope = _unqualified_scope(source, tree.root_node, language, spec, rel)
        definitions = tuple(
            AnalyzedDefinition(
                name=definition.name,
                file=rel,
                start=definition.start,
                end=definition.end,
                calls=definition.calls,
                direct_calls=definition.direct_calls,
                local_calls=definition.local_calls,
                unqualified_scope=definition.unqualified_scope,
                unqualified_target=definition.unqualified_target,
                is_type=definition.is_type,
                owner=definition.owner,
                type_owner=definition.type_owner,
                local_receiver_is_type_bound=definition.local_receiver_is_type_bound,
            )
            for definition in _definitions(source, tree.root_node, language, spec, unqualified_scope)
        )
        return AnalyzedFile(
            definitions=definitions,
            imports=_imports(source, tree.root_node, language, spec),
            namespaces=_namespaces(source, tree.root_node, language, spec),
            qualified_uses=_qualified_uses(source, tree.root_node, language, spec),
            default_exports=_default_exports(source, tree.root_node, language, spec),
        )
    except (ValueError, RuntimeError) as exc:
        raise AnalyzerConfigurationError(f"invalid query for {spec.name}") from exc


def analyze_repository(sources: list[AnalyzableSource]) -> AnalyzedRepository:
    """Analyze every reviewable source and retain file level limitations."""
    definitions: list[AnalyzedDefinition] = []
    imports: dict[str, list[AnalyzedImport]] = {}
    namespaces: dict[str, dict[str, str]] = {}
    qualified_uses: dict[str, list[tuple[str, str]]] = {}
    default_exports: dict[str, list[str]] = {}
    limitations: list[AnalyzedLimitation] = []
    for path, rel, spec in sources:
        try:
            analyzed = parse_file(path, rel, spec)
        except SourceParseError as exc:
            limitations.append(
                AnalyzedLimitation(
                    source=rel,
                    analyzer=spec.name,
                    reason=exc.reason,
                    line=exc.line,
                    column=exc.column,
                )
            )
            continue
        definitions.extend(analyzed.definitions)
        imports.setdefault(rel, []).extend(analyzed.imports)
        namespaces.setdefault(rel, {}).update(analyzed.namespaces)
        qualified_uses.setdefault(rel, []).extend(analyzed.qualified_uses)
        default_exports.setdefault(rel, []).extend(analyzed.default_exports)
    return AnalyzedRepository(
        definitions=tuple(definitions),
        imports=imports,
        namespaces=namespaces,
        qualified_uses=qualified_uses,
        default_exports=default_exports,
        limitations=tuple(limitations),
    )
