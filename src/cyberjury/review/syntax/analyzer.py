"""Load each language's grammar queries and parse every reviewable source into language-neutral graph inputs."""

from __future__ import annotations

import ctypes
import importlib
import sys
from dataclasses import dataclass
from functools import cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury.review.detection import MAX_SOURCE_BYTES
from cyberjury.review.facts import FactLimitation
from cyberjury.review.languages import load_languages
from cyberjury.review.relationships import StructuralRelationKind

if TYPE_CHECKING:
    from collections.abc import Iterator

    from tree_sitter import Language, Node, Query

if sys.version_info >= (3, 13):
    from types import CapsuleType
else:
    CapsuleType = object


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
    has_receiver: bool = False


@dataclass(frozen=True, order=True, kw_only=True)
class AnalyzedCallsite:
    """Preserve one concrete syntax call occurrence inside its caller."""

    start: int
    end: int
    expression: str
    callee: str
    receiver: str = ""


@dataclass(frozen=True)
class AnalyzedOwner:
    """Identify the nearest lexical definition that owns another definition."""

    name: str
    start: int
    end: int


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
    structural_relationships: tuple[StructuralQuery, ...] = ()


@dataclass(frozen=True)
class ImportQuery:
    """Define one declarative import query and its optional remote literal."""

    query: str
    imported: str = ""


@dataclass(frozen=True)
class StructuralQuery:
    """Define one declarative non-call relationship query."""

    kind: StructuralRelationKind
    query: str


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


@dataclass(frozen=True, order=True, kw_only=True)
class AnalyzedStructuralRelationship:
    """Preserve one exact structural relationship spelling."""

    kind: StructuralRelationKind
    reference: str
    target_name: str
    start: int
    end: int
    owner: AnalyzedOwner


@dataclass(frozen=True, kw_only=True)
class AnalyzedFile:
    """Syntax facts extracted from one source file, and the first syntax error when the tree is partial."""

    definitions: tuple[AnalyzedDefinition, ...]
    imports: tuple[AnalyzedImport, ...]
    namespaces: tuple[AnalyzedNamespace, ...]
    qualified_uses: tuple[AnalyzedQualifiedUse, ...]
    structural_relationships: tuple[AnalyzedStructuralRelationship, ...]
    source: str
    syntax_error: tuple[int, int] | None = None


@dataclass(frozen=True, kw_only=True)
class AnalyzedRepository:
    """Repository syntax evidence, its exact source text, and explicit source limitations."""

    definitions: tuple[AnalyzedDefinition, ...]
    imports: dict[str, list[AnalyzedImport]]
    namespaces: dict[str, list[AnalyzedNamespace]]
    qualified_uses: dict[str, list[AnalyzedQualifiedUse]]
    structural_relationships: dict[str, list[AnalyzedStructuralRelationship]]
    sources: dict[str, str]
    limitations: tuple[FactLimitation, ...] = ()
    producer_version: str = "unknown"


type AnalyzableSource = tuple[Path, str, LangSpec]


_SYNTAX_FIELDS = frozenset(
    {
        "definitions",
        "type_definitions",
        "calls",
        "imports",
        "receivers",
        "namespace_imports",
        "qualified_uses",
        "structural_relationships",
    }
)


def load_specs() -> dict[str, LangSpec]:
    """Load the grammar and syntax queries of every language that declares a grammar."""
    specs: dict[str, LangSpec] = {}
    for name, language in load_languages().items():
        if language.grammar is None:
            continue
        config = language.syntax
        unknown = sorted(set(config) - _SYNTAX_FIELDS)
        if unknown:
            raise ValueError(f"{name} contains unknown analyzer query fields: {', '.join(unknown)}")
        module, accessor = language.grammar
        specs[name] = LangSpec(
            name=name,
            extensions=language.extensions,
            module=module,
            accessor=accessor,
            definitions=config["definitions"].strip(),
            type_definitions=config.get("type_definitions", "").strip(),
            calls=config["calls"].strip(),
            imports=tuple(
                ImportQuery(item.strip())
                if isinstance(item, str)
                else ImportQuery(item["query"].strip(), item.get("imported", ""))
                for item in config.get("imports", ())
            ),
            receivers=config.get("receivers", "").strip(),
            namespace_imports=tuple(item.strip() for item in config.get("namespace_imports", ())),
            qualified_uses=config.get("qualified_uses", "").strip(),
            structural_relationships=tuple(
                StructuralQuery(kind=item["kind"], query=item["query"].strip())
                for item in config.get("structural_relationships", ())
            ),
        )
    return specs


def spec_for(specs: dict[str, LangSpec], rel: str) -> LangSpec | None:
    """Select the language contract for one repository path."""
    suffix = Path(rel).suffix.lower()
    return next((spec for spec in specs.values() if suffix in spec.extensions), None)


def grammar_for(spec: LangSpec) -> CapsuleType:
    """Return the installed grammar of one language specification as the capsule tree-sitter loads."""
    grammar = getattr(importlib.import_module(spec.module), spec.accessor)()
    return _language_capsule(grammar) if isinstance(grammar, int) else grammar


def _language_capsule(address: int) -> CapsuleType:
    new_capsule = ctypes.pythonapi.PyCapsule_New
    new_capsule.restype = ctypes.py_object
    new_capsule.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p)
    return new_capsule(address, b"tree_sitter.Language", None)


@cache
def _language(spec: LangSpec) -> Language:
    from tree_sitter import Language

    return Language(grammar_for(spec))


@cache
def _compiled(spec: LangSpec, text: str) -> Query:
    from tree_sitter import Query

    return Query(_language(spec), text)


_STRUCTURAL_CAPTURES = frozenset({"owner", "owner_name", "reference", "target_name"})


def _check_queries(spec: LangSpec) -> None:
    texts = (
        spec.definitions,
        spec.type_definitions,
        spec.calls,
        spec.receivers,
        spec.qualified_uses,
        *spec.namespace_imports,
        *(item.query for item in spec.imports),
        *(item.query for item in spec.structural_relationships),
    )
    try:
        for text in texts:
            if text:
                _compiled(spec, text)
    except (ValueError, RuntimeError) as exc:
        raise AnalyzerConfigurationError(f"invalid query for {spec.name}") from exc
    for item in spec.structural_relationships:
        query = _compiled(spec, item.query)
        names = {query.capture_name(index) for index in range(query.capture_count)}
        if not names >= _STRUCTURAL_CAPTURES:
            raise AnalyzerConfigurationError(f"{spec.name} structural relationship query lacks required captures")


def _matches(query: Query, node: Node) -> Iterator[tuple[int, dict[str, list[Node]]]]:
    from tree_sitter import QueryCursor

    for pattern, captures in QueryCursor(query).matches(node):
        present = {
            name: kept
            for name, nodes in captures.items()
            if (kept := [item for item in nodes if item.start_byte < item.end_byte])
        }
        yield pattern, present


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


type _DefinitionIndex = dict[tuple[int, int], tuple[Node, Node]]


def _definition_index(definitions: tuple[tuple[Node, Node], ...]) -> _DefinitionIndex:
    index: _DefinitionIndex = {}
    for definition in definitions:
        index.setdefault((definition[0].start_byte, definition[0].end_byte), definition)
    return index


def _nearest_definition(node: Node, index: _DefinitionIndex) -> tuple[Node, Node] | None:
    own = (node.start_byte, node.end_byte)
    ancestor = node.parent
    while ancestor is not None:
        span = (ancestor.start_byte, ancestor.end_byte)
        if span != own and span in index:
            return index[span]
        ancestor = ancestor.parent
    return None


def _definition_nodes(root: Node, spec: LangSpec) -> tuple[tuple[Node, Node], ...]:
    by_name_range: dict[tuple[int, int], tuple[Node, Node]] = {}
    for _, captures in _matches(_compiled(spec, spec.definitions), root):
        node = (captures.get("def") or [None])[0]
        identifier = (captures.get("name") or [None])[0]
        if node is None or identifier is None:
            continue
        key = (identifier.start_byte, identifier.end_byte)
        existing = by_name_range.get(key)
        if existing is None or node.end_byte - node.start_byte > existing[0].end_byte - existing[0].start_byte:
            by_name_range[key] = (node, identifier)
    return tuple(sorted(by_name_range.values(), key=lambda item: (item[0].start_byte, item[0].end_byte)))


@dataclass(frozen=True, kw_only=True)
class _ParsedTree:
    source: bytes
    root: Node
    spec: LangSpec
    offsets: dict[int, int] | None
    definitions: tuple[tuple[Node, Node], ...]
    definition_index: _DefinitionIndex


def _definition_calls(
    source: bytes,
    node: Node,
    definition_index: _DefinitionIndex,
    call_query: Query,
    offsets: dict[int, int] | None,
    *,
    file_scope: bool = False,
) -> tuple[tuple[str, ...], tuple[AnalyzedCallsite, ...]]:
    callsites: dict[tuple[int, int], AnalyzedCallsite] = {}
    for _, captures in _matches(call_query, node):
        call = (captures.get("call") or [None])[0]
        owner = _nearest_definition(call, definition_index) if call is not None else None
        belongs = owner is None if file_scope else owner is not None and owner[0] == node
        if call is None or not belongs:
            continue
        callee = (captures.get("callee") or [None])[0]
        if callee is not None:
            called = _text(source, callee)
            callsite = _analyzed_callsite(source, call, called, offsets=offsets)
            callsites.setdefault((callsite.start, callsite.end), callsite)
            continue
        member = (captures.get("member") or [None])[0]
        if member is not None:
            called = _text(source, member)
            receiver = (captures.get("receiver") or [None])[0]
            receiver_text = _text(source, receiver) if receiver is not None else ""
            callsite = _analyzed_callsite(source, call, called, receiver=receiver_text, offsets=offsets)
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
    spelling: str,
    *,
    receiver: str = "",
    offsets: dict[int, int] | None,
) -> AnalyzedCallsite:
    start, end = _node_range(call, offsets)
    return AnalyzedCallsite(
        start=start,
        end=end,
        expression=_text(source, call),
        callee=spelling,
        receiver=receiver,
    )


def _lexical_owner(
    source: bytes,
    node: Node,
    containers: _DefinitionIndex,
    offsets: dict[int, int] | None,
) -> AnalyzedOwner | None:
    owner_match = _nearest_definition(node, containers)
    if owner_match is None:
        return None
    owner_node, owner_name = owner_match
    owner_start, owner_end = _node_range(owner_node, offsets)
    return AnalyzedOwner(_text(source, owner_name), owner_start, owner_end)


def _definitions(tree: _ParsedTree, file: str) -> tuple[AnalyzedDefinition, ...]:
    source, root, spec, offsets = tree.source, tree.root, tree.spec, tree.offsets
    definition_nodes = tree.definitions
    definition_index = tree.definition_index
    call_query = _compiled(spec, spec.calls)
    type_nodes: tuple[tuple[Node, Node], ...] = ()
    if spec.type_definitions:
        type_nodes = tuple(
            (node, identifier)
            for _, captures in _matches(_compiled(spec, spec.type_definitions), root)
            if (node := (captures.get("type") or [None])[0]) is not None
            and (identifier := (captures.get("name") or [None])[0]) is not None
        )
    receiver_ranges: set[tuple[int, int]] = set()
    if spec.receivers:
        receiver_ranges = {
            (definition.start_byte, definition.end_byte)
            for _, captures in _matches(_compiled(spec, spec.receivers), root)
            if (definition := (captures.get("def") or [None])[0]) is not None
            and (captures.get("receiver") or [None])[0] is not None
        }
    definitions: list[AnalyzedDefinition] = []
    type_index = _definition_index(type_nodes)
    type_ranges = {(node.start_byte, node.end_byte) for node, _ in type_nodes}
    for node, identifier in definition_nodes:
        name = _text(source, identifier)
        is_type = (node.start_byte, node.end_byte) in type_ranges
        calls, callsites = _definition_calls(source, node, definition_index, call_query, offsets)
        start, end = _node_range(node, offsets)
        type_owner = _lexical_owner(source, node, type_index, offsets)
        definitions.append(
            AnalyzedDefinition(
                name=name,
                file=file,
                start=start,
                end=end,
                calls=calls,
                is_type=is_type,
                owner=_lexical_owner(source, node, definition_index, offsets),
                type_owner=type_owner,
                callsites=callsites,
                signature=_definition_signature(source, node, identifier),
                has_receiver=not is_type and (node.start_byte, node.end_byte) in receiver_ranges,
            )
        )
    file_calls, file_callsites = _definition_calls(source, root, definition_index, call_query, offsets, file_scope=True)
    if file_callsites:
        start, end = _node_range(root, offsets)
        definitions.append(
            AnalyzedDefinition(
                name="<file>",
                file=file,
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
    parameters = _parameters_node(node)
    if parameters is None:
        return _text(source, identifier)
    return f"{_text(source, identifier)}{_text(source, parameters)}"


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


def _imports(tree: _ParsedTree) -> tuple[AnalyzedImport, ...]:
    source, root, spec, offsets = tree.source, tree.root, tree.spec, tree.offsets
    definition_index = tree.definition_index
    imports: list[AnalyzedImport] = []
    for import_query in spec.imports:
        for _, captures in _matches(_compiled(spec, import_query.query), root):
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
            owner = _lexical_owner(source, modules[0], definition_index, offsets)
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


def _namespaces(tree: _ParsedTree) -> tuple[AnalyzedNamespace, ...]:
    source, root, spec, offsets = tree.source, tree.root, tree.spec, tree.offsets
    definition_index = tree.definition_index
    namespaces: list[AnalyzedNamespace] = []
    for query_text in spec.namespace_imports:
        for _, captures in _matches(_compiled(spec, query_text), root):
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
                    owner=_lexical_owner(source, statement, definition_index, offsets),
                )
            )
    return tuple(
        sorted(
            dict.fromkeys(namespaces),
            key=lambda item: (item.start, item.end, item.specifier, item.local, _owner_sort_key(item.owner)),
        )
    )


def _qualified_uses(tree: _ParsedTree) -> tuple[AnalyzedQualifiedUse, ...]:
    source, root, spec, offsets = tree.source, tree.root, tree.spec, tree.offsets
    if not spec.qualified_uses:
        return ()
    definition_index = tree.definition_index
    uses: list[AnalyzedQualifiedUse] = []
    for _, captures in _matches(_compiled(spec, spec.qualified_uses), root):
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
                    owner=_lexical_owner(source, expression, definition_index, offsets),
                )
            )
    return tuple(
        sorted(
            dict.fromkeys(uses),
            key=lambda item: (item.start, item.end, item.qualifier, item.name, _owner_sort_key(item.owner)),
        )
    )


def _structural_relationships(tree: _ParsedTree) -> tuple[AnalyzedStructuralRelationship, ...]:
    source, root, spec, offsets = tree.source, tree.root, tree.spec, tree.offsets
    by_identifier = {(identifier.start_byte, identifier.end_byte): node for node, identifier in tree.definitions}
    relationships: list[AnalyzedStructuralRelationship] = []
    for configured in spec.structural_relationships:
        for _, captures in _matches(_compiled(spec, configured.query), root):
            owners = captures.get("owner") or ()
            owner_names = captures.get("owner_name") or ()
            references = captures.get("reference") or ()
            target_names = captures.get("target_name") or ()
            if len(owners) != 1 or len(owner_names) != 1 or not references or len(references) != len(target_names):
                raise SourceParseError("structural relationship captures are incomplete")
            captured_owner = owners[0]
            owner_name = owner_names[0]
            owner_node = by_identifier.get((owner_name.start_byte, owner_name.end_byte))
            if (
                owner_node is None
                or owner_node.start_byte > captured_owner.start_byte
                or captured_owner.end_byte > owner_node.end_byte
            ):
                raise SourceParseError("structural relationship has no unique definition owner")
            owner_start, owner_end = _node_range(owner_node, offsets)
            owner = AnalyzedOwner(_text(source, owner_name), owner_start, owner_end)
            for reference, target_name in zip(references, target_names, strict=True):
                start, end = _node_range(reference, offsets)
                if start < owner_start or end > owner_end:
                    raise SourceParseError("structural relationship source is outside its owner")
                relationships.append(
                    AnalyzedStructuralRelationship(
                        kind=configured.kind,
                        reference=_text(source, reference),
                        target_name=_text(source, target_name),
                        start=start,
                        end=end,
                        owner=owner,
                    )
                )
    return tuple(
        sorted(
            dict.fromkeys(relationships),
            key=lambda item: (
                item.start,
                item.end,
                item.kind,
                item.reference,
                item.target_name,
                _owner_sort_key(item.owner),
            ),
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
    from tree_sitter import Parser

    try:
        with path.open("rb") as stream:
            source = stream.read(MAX_SOURCE_BYTES + 1)
    except OSError as exc:
        raise SourceReadError(f"cannot read source {rel}") from exc
    if len(source) > MAX_SOURCE_BYTES:
        raise SourceParseError("over the parse cap")
    try:
        source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceParseError("not valid UTF-8") from exc
    try:
        tree = Parser(_language(spec)).parse(source)
    except (ValueError, RuntimeError) as exc:
        raise SourceParseError("unparsable") from exc
    syntax_error = _first_parse_problem(source, tree.root_node) if tree.root_node.has_error else None
    definitions = _definition_nodes(tree.root_node, spec)
    parsed = _ParsedTree(
        source=source,
        root=tree.root_node,
        spec=spec,
        offsets=character_offsets(source),
        definitions=definitions,
        definition_index=_definition_index(definitions),
    )
    try:
        structural_relationships = _structural_relationships(parsed)
    except SourceParseError as exc:
        if syntax_error is None:
            raise
        raise SourceParseError(
            "analysis failed after a syntax error", line=syntax_error[0], column=syntax_error[1]
        ) from exc
    return AnalyzedFile(
        definitions=_definitions(parsed, rel),
        imports=_imports(parsed),
        namespaces=_namespaces(parsed),
        qualified_uses=_qualified_uses(parsed),
        structural_relationships=structural_relationships,
        source=source.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n"),
        syntax_error=syntax_error,
    )


def analyze_repository(sources: list[AnalyzableSource]) -> AnalyzedRepository:
    """Analyze every reviewable source and retain file level limitations."""
    definitions: list[AnalyzedDefinition] = []
    imports: dict[str, list[AnalyzedImport]] = {}
    namespaces: dict[str, list[AnalyzedNamespace]] = {}
    qualified_uses: dict[str, list[AnalyzedQualifiedUse]] = {}
    structural_relationships: dict[str, list[AnalyzedStructuralRelationship]] = {}
    normalized_sources: dict[str, str] = {}
    limitations: list[FactLimitation] = []
    ordered_sources = sorted(sources, key=lambda item: item[1])
    names = [rel for _path, rel, _spec in ordered_sources]
    if len(names) != len(set(names)):
        raise AnalyzerConfigurationError("analyzer source paths must be unique")
    for spec in {spec.name: spec for _path, _rel, spec in ordered_sources}.values():
        _check_queries(spec)
    for path, rel, spec in ordered_sources:
        try:
            analyzed = parse_file(path, rel, spec)
        except SourceParseError as exc:
            limitations.append(
                FactLimitation(
                    source=rel,
                    analyzer=spec.name,
                    reason=exc.reason,
                    line=exc.line,
                    column=exc.column,
                )
            )
        except SourceReadError:
            raise
        except Exception as exc:
            limitations.append(
                FactLimitation(source=rel, analyzer=spec.name, reason=f"analysis failed ({type(exc).__name__})")
            )
        else:
            if analyzed.syntax_error is not None:
                line, column = analyzed.syntax_error
                limitations.append(
                    FactLimitation(source=rel, analyzer=spec.name, reason="partially parsed", line=line, column=column)
                )
            definitions.extend(analyzed.definitions)
            imports.setdefault(rel, []).extend(analyzed.imports)
            namespaces.setdefault(rel, []).extend(analyzed.namespaces)
            qualified_uses.setdefault(rel, []).extend(analyzed.qualified_uses)
            structural_relationships.setdefault(rel, []).extend(analyzed.structural_relationships)
            normalized_sources[rel] = analyzed.source
    return AnalyzedRepository(
        definitions=tuple(definitions),
        imports=imports,
        namespaces=namespaces,
        qualified_uses=qualified_uses,
        structural_relationships=structural_relationships,
        sources=normalized_sources,
        limitations=tuple(limitations),
        producer_version=_tree_sitter_version(),
    )


def _tree_sitter_version() -> str:
    try:
        return version("tree-sitter")
    except PackageNotFoundError:
        return "unknown"
