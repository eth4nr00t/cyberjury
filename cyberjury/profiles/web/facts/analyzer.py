"""Parse one source file into language-neutral graph inputs."""

from __future__ import annotations

import importlib
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING

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
    is_type: bool
    calls: tuple[str, ...] = ()
    owner: AnalyzedOwner | None = None
    type_owner: AnalyzedOwner | None = None
    is_file_scope: bool = False
    callsites: tuple[AnalyzedCallsite, ...] = ()
    signature: str = ""
    parameters: tuple[AnalyzedParameter, ...] = ()
    receiver: AnalyzedReceiver | None = None


@dataclass(frozen=True, order=True, kw_only=True)
class AnalyzedParameter:
    """Preserve one declared parameter and its exact syntax range."""

    position: int
    name: str
    declaration: str
    start: int
    end: int
    type_name: str = ""


@dataclass(frozen=True, order=True, kw_only=True)
class AnalyzedReceiver:
    """Preserve one receiver declaration outside a formal parameter list."""

    name: str
    declaration: str
    start: int
    end: int
    type_name: str = ""


@dataclass(frozen=True, order=True, kw_only=True)
class AnalyzedArgument:
    """Preserve one exact syntax argument without inferring value flow."""

    position: int
    expression: str
    start: int
    end: int
    name: str = ""


@dataclass(frozen=True, order=True, kw_only=True)
class AnalyzedCallsite:
    """Preserve one concrete syntax call occurrence inside its caller."""

    start: int
    end: int
    expression: str
    callee: str
    receiver: str = ""
    arguments: tuple[AnalyzedArgument, ...] = ()


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
    module: str
    accessor: str
    definitions: str
    type_definitions: str
    calls: str
    imports: tuple[ImportQuery, ...]
    receivers: str = ""
    namespace_imports: tuple[str, ...] = ()
    qualified_uses: str = ""


@dataclass(frozen=True)
class ImportQuery:
    """Define one declarative import query and its optional remote literal."""

    query: str
    imported: str = ""


@dataclass(frozen=True)
class AnalyzedImport:
    """Preserve one import binding with its lexical owner."""

    imported: str
    local: str
    module: str
    owner: AnalyzedOwner | None = None
    start: int = 0
    end: int = 0


@dataclass(frozen=True, order=True, kw_only=True)
class AnalyzedNamespace:
    """Preserve one namespace binding and its exact import statement."""

    local: str
    specifier: str
    start: int
    end: int
    owner: AnalyzedOwner | None = None


@dataclass(frozen=True, order=True, kw_only=True)
class AnalyzedQualifiedUse:
    """Preserve one qualified name use and its exact syntax range."""

    qualifier: str
    name: str
    start: int
    end: int
    owner: AnalyzedOwner | None = None


@dataclass(frozen=True, kw_only=True)
class AnalyzedFile:
    """Syntax facts extracted from one complete source file."""

    definitions: tuple[AnalyzedDefinition, ...]
    imports: tuple[AnalyzedImport, ...]
    namespaces: tuple[AnalyzedNamespace, ...]
    qualified_uses: tuple[AnalyzedQualifiedUse, ...]
    source: str


@dataclass(frozen=True, kw_only=True)
class AnalyzedRepository:
    """Syntax analysis and explicit source limitations before resolution."""

    definitions: tuple[AnalyzedDefinition, ...]
    imports: dict[str, list[AnalyzedImport]]
    namespaces: dict[str, list[AnalyzedNamespace]]
    qualified_uses: dict[str, list[AnalyzedQualifiedUse]]
    sources: dict[str, str]
    limitations: tuple[AnalyzedLimitation, ...] = ()
    producer_version: str = "unknown"


type AnalyzableSource = tuple[Path, str, LangSpec]


def load_specs(path: Path | None = None) -> dict[str, LangSpec]:
    """Load declarative language grammar and query contracts."""
    raw = yaml.safe_load((path or _QUERIES_FILE).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, Mapping) or not raw:
        raise ValueError("analyzer queries must contain a nonempty language mapping")
    specs: dict[str, LangSpec] = {}
    for name, config in raw.items():
        if not isinstance(name, str) or not name or not isinstance(config, Mapping):
            raise ValueError("analyzer language entries must map nonempty names to configuration mappings")
        allowed = {
            "extensions",
            "grammar",
            "definitions",
            "type_definitions",
            "calls",
            "imports",
            "receivers",
            "namespace_imports",
            "qualified_uses",
        }
        unknown = sorted(set(config) - allowed)
        if unknown:
            raise ValueError(f"{name} contains unknown analyzer query fields: {', '.join(unknown)}")
        grammar = config.get("grammar")
        if (
            not isinstance(grammar, Sequence)
            or isinstance(grammar, str)
            or len(grammar) != 2
            or not all(isinstance(item, str) and item for item in grammar)
        ):
            raise ValueError(f"{name} grammar must contain a module and accessor")
        module, accessor = grammar
        raw_extensions = config.get("extensions")
        if not isinstance(raw_extensions, Sequence) or isinstance(raw_extensions, str):
            raise ValueError(f"{name} extensions must be a list")
        extensions = tuple(value.lower() for value in raw_extensions if isinstance(value, str))
        if len(extensions) != len(raw_extensions):
            raise ValueError(f"{name} extensions must contain strings")
        if not extensions or any(not value.startswith(".") or value == "." for value in extensions):
            raise ValueError(f"{name} extensions must contain file extensions beginning with a dot")
        if len(extensions) != len(set(extensions)):
            raise ValueError(f"{name} extensions must be unique")
        specs[name] = LangSpec(
            name=name,
            extensions=extensions,
            module=module,
            accessor=accessor,
            definitions=_definition_query(name, config.get("definitions")),
            type_definitions=_captured_optional_query(
                name,
                config.get("type_definitions"),
                "type_definitions",
                ("type", "name"),
            ),
            calls=_calls_query(name, config.get("calls")),
            imports=_import_queries(name, config.get("imports", ())),
            receivers=_receiver_query(name, config.get("receivers")),
            namespace_imports=_namespace_queries(name, config.get("namespace_imports", ())),
            qualified_uses=_captured_optional_query(
                name,
                config.get("qualified_uses"),
                "qualified_uses",
                ("qualifier", "name"),
            ),
        )
    owners: dict[str, str] = {}
    for name, spec in specs.items():
        for extension in spec.extensions:
            owner = owners.setdefault(extension, name)
            if owner != name:
                raise ValueError(f"{extension} is owned by both {owner} and {name}")
    return specs


def _optional_query(language: str, raw: object, field: str) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{language} {field} must contain query text")
    return raw.strip()


def _captured_optional_query(
    language: str,
    raw: object,
    field: str,
    required_captures: tuple[str, ...],
) -> str:
    query = _optional_query(language, raw, field)
    if not query:
        return ""
    captures = set(re.findall(r"@([A-Za-z_][A-Za-z0-9_]*)", query))
    missing = [f"@{capture}" for capture in required_captures if capture not in captures]
    if missing:
        raise ValueError(f"{language} {field} must declare captures: {', '.join(missing)}")
    return query


def _definition_query(language: str, raw: object) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{language} definitions must contain query text")
    captures = set(re.findall(r"@([A-Za-z_][A-Za-z0-9_]*)", raw))
    missing = [f"@{capture}" for capture in ("def", "name") if capture not in captures]
    if missing:
        names = ", ".join(missing)
        raise ValueError(f"{language} definitions must declare captures: {names}")
    return raw.strip()


def _calls_query(language: str, raw: object) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{language} calls must contain query text")
    captures = set(re.findall(r"@([A-Za-z_][A-Za-z0-9_]*)", raw))
    if captures.isdisjoint({"callee", "member"}):
        raise ValueError(f"{language} calls must declare a callee or member capture")
    missing = ["@call"] if "call" not in captures else []
    if missing:
        raise ValueError(f"{language} calls must declare captures: {', '.join(missing)}")
    return raw.strip()


def _receiver_query(language: str, raw: object) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{language} receivers must contain query text")
    captures = set(re.findall(r"@([A-Za-z_][A-Za-z0-9_]*)", raw))
    missing = [f"@{capture}" for capture in ("def", "receiver") if capture not in captures]
    if missing:
        raise ValueError(f"{language} receivers must declare captures: {', '.join(missing)}")
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
        captures = set(re.findall(r"@([A-Za-z_][A-Za-z0-9_]*)", query))
        missing = [f"@{capture}" for capture in ("module", "statement") if capture not in captures]
        if missing:
            raise ValueError(f"{language} import query {position} must declare captures: {', '.join(missing)}")
        if not isinstance(imported, str):
            raise ValueError(f"{language} import query {position} imported must be text")
        queries.append(ImportQuery(query.strip(), imported))
    return tuple(queries)


def _namespace_queries(language: str, raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list | tuple):
        raise ValueError(f"{language} namespace_imports must be a list")
    queries: list[str] = []
    for position, value in enumerate(raw):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{language} namespace query {position} must contain query text")
        captures = set(re.findall(r"@([A-Za-z_][A-Za-z0-9_]*)", value))
        missing = [f"@{capture}" for capture in ("module", "statement") if capture not in captures]
        if missing:
            raise ValueError(f"{language} namespace query {position} must declare captures: {', '.join(missing)}")
        queries.append(value.strip())
    return tuple(queries)


def spec_for(specs: dict[str, LangSpec], rel: str) -> LangSpec | None:
    """Select the language contract for one repository path."""
    suffix = Path(rel).suffix.lower()
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


def validate_specs(specs: dict[str, LangSpec]) -> None:
    """Compile every configured query against each available native grammar."""
    from tree_sitter import Language, Query

    for spec in specs.values():
        grammar = grammar_for(spec)
        if grammar is None:
            continue
        language = Language(grammar)
        queries = [spec.definitions, spec.calls]
        queries.extend(query.query for query in spec.imports)
        queries.extend(spec.namespace_imports)
        queries.extend(query for query in (spec.type_definitions, spec.receivers, spec.qualified_uses) if query)
        try:
            for query in queries:
                Query(language, query)
        except (ValueError, RuntimeError) as exc:
            raise AnalyzerConfigurationError(f"invalid query for {spec.name}: {exc}") from exc


def character_offsets(source: bytes) -> dict[int, int] | None:
    """Map Tree-sitter byte offsets to decoded text offsets when they differ."""
    if source.isascii() and b"\r" not in source:
        return None
    text = source.decode("utf-8")
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
    return source[node.start_byte : node.end_byte].decode("utf-8")


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


def _definition_nodes(root: Node, language: Language, spec: LangSpec) -> tuple[tuple[Node, Node], ...]:
    """Prefer the widest syntax wrapper for each exact declared name."""
    from tree_sitter import Query, QueryCursor

    by_name_range: dict[tuple[int, int], tuple[Node, Node]] = {}
    for _, captures in QueryCursor(Query(language, spec.definitions)).matches(root):
        node = (captures.get("def") or [None])[0]
        identifier = (captures.get("name") or [None])[0]
        if node is None or identifier is None:
            continue
        key = (identifier.start_byte, identifier.end_byte)
        existing = by_name_range.get(key)
        if existing is None or node.end_byte - node.start_byte > existing[0].end_byte - existing[0].start_byte:
            by_name_range[key] = (node, identifier)
    return tuple(sorted(by_name_range.values(), key=lambda item: (item[0].start_byte, item[0].end_byte)))


def _definition_calls(
    source: bytes,
    node: Node,
    definitions: tuple[tuple[Node, Node], ...],
    call_query: object,
    *,
    file_scope: bool = False,
) -> tuple[tuple[str, ...], tuple[AnalyzedCallsite, ...]]:
    from tree_sitter import QueryCursor

    callsites: dict[tuple[int, int], AnalyzedCallsite] = {}
    offsets = character_offsets(source)
    for _, captures in QueryCursor(call_query).matches(node):
        call = (captures.get("call") or [None])[0]
        arguments = (captures.get("arguments") or [None])[0]
        owner = _nearest_definition(call, definitions) if call is not None else None
        belongs = owner is None if file_scope else owner is not None and owner[0] == node
        if call is None or not belongs:
            continue
        callee = (captures.get("callee") or [None])[0]
        if callee is not None:
            called = _text(source, callee)
            callsite = _analyzed_callsite(source, call, arguments, called, offsets=offsets)
            callsites.setdefault((callsite.start, callsite.end), callsite)
            continue
        member = (captures.get("member") or [None])[0]
        if member is not None:
            called = _text(source, member)
            receiver = (captures.get("receiver") or [None])[0]
            receiver_text = _text(source, receiver) if receiver is not None else ""
            callsite = _analyzed_callsite(
                source,
                call,
                arguments,
                called,
                receiver=receiver_text,
                offsets=offsets,
            )
            callsites.setdefault((callsite.start, callsite.end), callsite)
    ordered = tuple(
        sorted(
            callsites.values(),
            key=lambda item: (item.start, item.end, item.callee, item.receiver, item.expression),
        )
    )
    return tuple(dict.fromkeys(item.callee for item in ordered)), ordered


def _analyzed_callsite(
    source: bytes,
    call: Node,
    arguments: Node | None,
    spelling: str,
    *,
    receiver: str = "",
    offsets: dict[int, int] | None,
) -> AnalyzedCallsite:
    analyzed_arguments: list[AnalyzedArgument] = []
    for position, argument in enumerate(arguments.named_children if arguments is not None else ()):
        argument_start, argument_end = _node_range(argument, offsets)
        name_node = argument.child_by_field_name("name")
        analyzed_arguments.append(
            AnalyzedArgument(
                position=position,
                expression=_text(source, argument),
                start=argument_start,
                end=argument_end,
                name=_text(source, name_node) if name_node is not None else "",
            )
        )
    start, end = _node_range(call, offsets)
    return AnalyzedCallsite(
        start=start,
        end=end,
        expression=_text(source, call),
        callee=spelling,
        receiver=receiver,
        arguments=tuple(analyzed_arguments),
    )


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


def _definitions(
    source: bytes,
    root: Node,
    language: Language,
    spec: LangSpec,
) -> tuple[AnalyzedDefinition, ...]:
    from tree_sitter import Query, QueryCursor

    call_query = Query(language, spec.calls)
    offsets = character_offsets(source)
    definition_nodes = _definition_nodes(root, language, spec)
    type_nodes: tuple[tuple[Node, Node], ...] = ()
    if spec.type_definitions:
        type_nodes = tuple(
            (node, identifier)
            for _, captures in QueryCursor(Query(language, spec.type_definitions)).matches(root)
            if (node := (captures.get("type") or [None])[0]) is not None
            and (identifier := (captures.get("name") or [None])[0]) is not None
        )
    receiver_nodes: dict[tuple[int, int], Node] = {}
    if spec.receivers:
        receiver_nodes = {
            (definition.start_byte, definition.end_byte): receiver
            for _, captures in QueryCursor(Query(language, spec.receivers)).matches(root)
            if (definition := (captures.get("def") or [None])[0]) is not None
            and (receiver := (captures.get("receiver") or [None])[0]) is not None
        }
    definitions: list[AnalyzedDefinition] = []
    type_ranges = {(node.start_byte, node.end_byte) for node, _ in type_nodes}
    for node, identifier in definition_nodes:
        name = _text(source, identifier)
        is_type = (node.start_byte, node.end_byte) in type_ranges
        calls, callsites = _definition_calls(
            source,
            node,
            definition_nodes,
            call_query,
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
                is_type=is_type,
                owner=_lexical_owner(source, node, definition_nodes, offsets),
                type_owner=type_owner,
                callsites=callsites,
                signature=_definition_signature(source, node, identifier),
                parameters=() if is_type else _definition_parameters(source, node, offsets),
                receiver=(
                    None
                    if is_type
                    else _definition_receiver(
                        source,
                        receiver_nodes.get((node.start_byte, node.end_byte)),
                        offsets,
                    )
                ),
            )
        )
    file_calls, file_callsites = _definition_calls(
        source,
        root,
        definition_nodes,
        call_query,
        file_scope=True,
    )
    if file_callsites:
        start, end = _node_range(root, offsets)
        definitions.append(
            AnalyzedDefinition(
                name="<file>",
                file="",
                start=start,
                end=end,
                is_type=False,
                is_file_scope=True,
                calls=file_calls,
                callsites=file_callsites,
            )
        )
    return tuple(definitions)


def _definition_signature(source: bytes, node: Node, identifier: Node) -> str:
    """Render one compact syntax signature without language binding claims."""
    parameters = _parameters_node(node)
    if parameters is None:
        return _text(source, identifier)
    return f"{_text(source, identifier)}{_text(source, parameters)}"


def _definition_parameters(
    source: bytes,
    node: Node,
    offsets: dict[int, int] | None,
) -> tuple[AnalyzedParameter, ...]:
    """Read declared parameter syntax without inferring call argument binding."""
    output: list[AnalyzedParameter] = []
    parameters = _parameters_node(node)
    if parameters is None:
        return tuple(output)
    for parameter in parameters.named_children:
        type_node = parameter.child_by_field_name("type")
        name_nodes = tuple(parameter.children_by_field_name("name"))
        pattern = parameter.child_by_field_name("pattern")
        if not name_nodes and pattern is not None:
            name_nodes = (pattern,)
        if not name_nodes and type_node is None:
            fallback = _parameter_name_node(parameter)
            name_nodes = (fallback,) if fallback is not None else ()
        declared_names: tuple[Node | None, ...] = name_nodes or (None,)
        start, end = _node_range(parameter, offsets)
        for name_node in declared_names:
            output.append(
                AnalyzedParameter(
                    position=len(output),
                    name=_text(source, name_node) if name_node is not None else "",
                    declaration=_text(source, parameter),
                    start=start,
                    end=end,
                    type_name=_text(source, type_node) if type_node is not None else "",
                )
            )
    return tuple(output)


def _definition_receiver(
    source: bytes,
    receiver: Node | None,
    offsets: dict[int, int] | None,
) -> AnalyzedReceiver | None:
    if receiver is None:
        return None
    name_node = receiver.child_by_field_name("name")
    type_node = receiver.child_by_field_name("type")
    start, end = _node_range(receiver, offsets)
    return AnalyzedReceiver(
        name=_text(source, name_node or type_node or receiver),
        declaration=_text(source, receiver),
        start=start,
        end=end,
        type_name=_text(source, type_node) if type_node is not None else _text(source, receiver),
    )


def _parameters_node(node: Node) -> Node | None:
    parameters = node.child_by_field_name("parameters")
    if parameters is not None:
        return parameters
    body = node.child_by_field_name("body")
    for child in node.named_children:
        if body is not None and child == body:
            continue
        parameters = _parameters_node(child)
        if parameters is not None:
            return parameters
    return None


def _parameter_name_node(node: Node) -> Node | None:
    named = node.child_by_field_name("name")
    if named is not None:
        return named
    if not node.named_children:
        return node
    for child in node.named_children:
        candidate = _parameter_name_node(child)
        if candidate is not None:
            return candidate
    return None


def _imports(source: bytes, root: Node, language: Language, spec: LangSpec) -> tuple[AnalyzedImport, ...]:
    from tree_sitter import Query, QueryCursor

    imports: list[AnalyzedImport] = []
    definition_nodes = _definition_nodes(root, language, spec)
    offsets = character_offsets(source)
    for import_query in spec.imports:
        for _, captures in QueryCursor(Query(language, import_query.query)).matches(root):
            modules = captures.get("module") or ()
            statements = captures.get("statement") or ()
            imported_nodes = captures.get("imported") or ()
            aliases = captures.get("alias") or ()
            imported_names = tuple(_text(source, node) for node in imported_nodes)
            if import_query.imported:
                imported_names = (import_query.imported,)
            if not modules or not statements or not imported_names:
                continue
            module = _text(source, modules[0])
            owner = _lexical_owner(source, modules[0], definition_nodes, offsets)
            statement = statements[0]
            start, end = _node_range(statement, offsets)
            for position, imported in enumerate(imported_names):
                local = _text(source, aliases[position]) if position < len(aliases) else imported
                imports.append(
                    AnalyzedImport(
                        imported=imported,
                        local=local,
                        module=module,
                        owner=owner,
                        start=start,
                        end=end,
                    )
                )
    return tuple(
        sorted(
            dict.fromkeys(imports),
            key=lambda item: (
                item.start,
                item.end,
                item.module,
                item.imported,
                item.local,
                _owner_sort_key(item.owner),
            ),
        )
    )


def _namespaces(source: bytes, root: Node, language: Language, spec: LangSpec) -> tuple[AnalyzedNamespace, ...]:
    from tree_sitter import Query, QueryCursor

    namespaces: list[AnalyzedNamespace] = []
    offsets = character_offsets(source)
    definitions = _definition_nodes(root, language, spec)
    for query_text in spec.namespace_imports:
        for _, captures in QueryCursor(Query(language, query_text)).matches(root):
            modules = captures.get("module") or ()
            statements = captures.get("statement") or ()
            if not modules or not statements:
                continue
            specifier = _text(source, modules[0]).strip("\"'")
            aliases = captures.get("alias") or ()
            local = _text(source, aliases[0]) if aliases else ""
            statement = statements[0]
            start, end = _node_range(statement, offsets)
            namespaces.append(
                AnalyzedNamespace(
                    local=local,
                    specifier=specifier,
                    start=start,
                    end=end,
                    owner=_lexical_owner(source, statement, definitions, offsets),
                )
            )
    return tuple(
        sorted(
            dict.fromkeys(namespaces),
            key=lambda item: (item.start, item.end, item.specifier, item.local, _owner_sort_key(item.owner)),
        )
    )


def _qualified_uses(
    source: bytes,
    root: Node,
    language: Language,
    spec: LangSpec,
) -> tuple[AnalyzedQualifiedUse, ...]:
    from tree_sitter import Query, QueryCursor

    if not spec.qualified_uses:
        return ()
    definitions = tuple(
        (node, identifier)
        for _, captures in QueryCursor(Query(language, spec.definitions)).matches(root)
        if (node := (captures.get("def") or [None])[0]) is not None
        and (identifier := (captures.get("name") or [None])[0]) is not None
    )
    offsets = character_offsets(source)
    uses: list[AnalyzedQualifiedUse] = []
    for _, captures in QueryCursor(Query(language, spec.qualified_uses)).matches(root):
        qualifiers = captures.get("qualifier") or ()
        names = captures.get("name") or ()
        if qualifiers and names:
            expression = names[0].parent if names[0].parent is not None else names[0]
            start, end = _node_range(expression, offsets)
            uses.append(
                AnalyzedQualifiedUse(
                    qualifier=_text(source, qualifiers[0]),
                    name=_text(source, names[0]),
                    start=start,
                    end=end,
                    owner=_lexical_owner(source, expression, definitions, offsets),
                )
            )
    return tuple(
        sorted(
            dict.fromkeys(uses),
            key=lambda item: (item.start, item.end, item.qualifier, item.name, _owner_sort_key(item.owner)),
        )
    )


def _owner_sort_key(owner: AnalyzedOwner | None) -> tuple[int, int, str]:
    return (owner.start, owner.end, owner.name) if owner is not None else (-1, -1, "")


def _first_parse_problem(source: bytes, root: Node) -> tuple[int, int]:
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == "ERROR" or node.is_missing:
            return _source_position(source, node.start_byte)
        pending.extend(reversed(node.children))
    return _source_position(source, root.start_byte)


def _source_position(source: bytes, byte_offset: int) -> tuple[int, int]:
    prefix = source[:byte_offset].decode("utf-8")
    normalized = prefix.replace("\r\n", "\n").replace("\r", "\n")
    line_prefix = normalized.rsplit("\n", 1)[-1]
    return normalized.count("\n") + 1, len(line_prefix) + 1


def parse_file(path: Path, rel: str, spec: LangSpec) -> AnalyzedFile:
    """Parse every configured query family for one reviewable file."""
    from tree_sitter import Language, Parser

    grammar = grammar_for(spec)
    if grammar is None:
        raise AnalyzerConfigurationError(f"missing grammar for {spec.name}")
    try:
        with path.open("rb") as stream:
            source = stream.read(MAX_SOURCE_BYTES + 1)
    except OSError as exc:
        raise SourceReadError(f"cannot read source {rel}") from exc
    try:
        source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceReadError(f"source {rel} is not valid UTF-8") from exc
    if len(source) > MAX_SOURCE_BYTES:
        raise SourceParseError("over the parse cap")
    language = Language(grammar)
    try:
        tree = Parser(language).parse(source)
    except (ValueError, RuntimeError) as exc:
        raise SourceParseError("unparsable") from exc
    if tree.root_node.has_error:
        line, column = _first_parse_problem(source, tree.root_node)
        raise SourceParseError("unparsable", line=line, column=column)
    try:
        definitions = tuple(
            AnalyzedDefinition(
                name=definition.name,
                file=rel,
                start=definition.start,
                end=definition.end,
                calls=definition.calls,
                is_type=definition.is_type,
                owner=definition.owner,
                type_owner=definition.type_owner,
                is_file_scope=definition.is_file_scope,
                callsites=definition.callsites,
                signature=definition.signature,
                parameters=definition.parameters,
                receiver=definition.receiver,
            )
            for definition in _definitions(source, tree.root_node, language, spec)
        )
        return AnalyzedFile(
            definitions=definitions,
            imports=_imports(source, tree.root_node, language, spec),
            namespaces=_namespaces(source, tree.root_node, language, spec),
            qualified_uses=_qualified_uses(source, tree.root_node, language, spec),
            source=source.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n"),
        )
    except (ValueError, RuntimeError) as exc:
        raise AnalyzerConfigurationError(f"invalid query for {spec.name}") from exc


def analyze_repository(sources: list[AnalyzableSource]) -> AnalyzedRepository:
    """Analyze every reviewable source and retain file level limitations."""
    definitions: list[AnalyzedDefinition] = []
    imports: dict[str, list[AnalyzedImport]] = {}
    namespaces: dict[str, list[AnalyzedNamespace]] = {}
    qualified_uses: dict[str, list[AnalyzedQualifiedUse]] = {}
    normalized_sources: dict[str, str] = {}
    limitations: list[AnalyzedLimitation] = []
    ordered_sources = sorted(sources, key=lambda item: item[1])
    names = [rel for _path, rel, _spec in ordered_sources]
    if len(names) != len(set(names)):
        raise AnalyzerConfigurationError("analyzer source paths must be unique")
    for path, rel, spec in ordered_sources:
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
        namespaces.setdefault(rel, []).extend(analyzed.namespaces)
        qualified_uses.setdefault(rel, []).extend(analyzed.qualified_uses)
        normalized_sources[rel] = analyzed.source
    return AnalyzedRepository(
        definitions=tuple(definitions),
        imports=imports,
        namespaces=namespaces,
        qualified_uses=qualified_uses,
        sources=normalized_sources,
        limitations=tuple(limitations),
        producer_version=_tree_sitter_version(),
    )


def _tree_sitter_version() -> str:
    try:
        return version("tree-sitter")
    except PackageNotFoundError:
        return "unknown"
