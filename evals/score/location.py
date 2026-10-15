"""Locate report evidence within benchmark source files."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from functools import cache, lru_cache
from pathlib import Path
from typing import Any


class SymbolLocationError(RuntimeError):
    """Signal that a configured source parser could not locate symbols reliably."""


@dataclass(frozen=True)
class LanguageSpec:
    """Define one evaluator owned Tree-sitter symbol location contract."""

    name: str
    extensions: tuple[str, ...]
    module: str
    accessor: str
    definitions: str


_PYTHON_DEFINITIONS = """
[(function_definition name: (identifier) @name)
 (class_definition name: (identifier) @name)
 (assignment left: (identifier) @name)] @def
"""

_JAVASCRIPT_DEFINITIONS = """
[(function_declaration name: (identifier) @name)
 (class_declaration name: (identifier) @name)
 (method_definition name: (property_identifier) @name)
 (variable_declarator name: (identifier) @name)
 (assignment_expression
   left: (member_expression property: (property_identifier) @name))] @def
"""

_TYPESCRIPT_DEFINITIONS = """
[(function_declaration name: (identifier) @name)
 (class_declaration name: (type_identifier) @name)
 (method_definition name: (property_identifier) @name)
 (variable_declarator name: (identifier) @name)
 (assignment_expression
   left: (member_expression property: (property_identifier) @name))] @def
"""

_GO_DEFINITIONS = """
[(function_declaration name: (identifier) @name)
 (method_declaration name: (field_identifier) @name)
 (type_declaration (type_spec name: (type_identifier) @name))
 (const_spec name: (identifier) @name)
 (var_spec name: (identifier) @name)] @def
"""

_LANGUAGE_SPECS = (
    LanguageSpec("python", (".py",), "tree_sitter_python", "language", _PYTHON_DEFINITIONS),
    LanguageSpec(
        "javascript",
        (".js", ".jsx", ".mjs", ".cjs"),
        "tree_sitter_javascript",
        "language",
        _JAVASCRIPT_DEFINITIONS,
    ),
    LanguageSpec(
        "typescript",
        (".ts", ".mts", ".cts"),
        "tree_sitter_typescript",
        "language_typescript",
        _TYPESCRIPT_DEFINITIONS,
    ),
    LanguageSpec(
        "tsx",
        (".tsx",),
        "tree_sitter_typescript",
        "language_tsx",
        _TYPESCRIPT_DEFINITIONS,
    ),
    LanguageSpec("go", (".go",), "tree_sitter_go", "language", _GO_DEFINITIONS),
)


def _spec_for(path: Path) -> LanguageSpec | None:
    suffix = path.suffix.lower()
    return next((spec for spec in _LANGUAGE_SPECS if suffix in spec.extensions), None)


@cache
def _tree_sitter_runtime(spec: LanguageSpec):
    try:
        grammar_module = importlib.import_module(spec.module)
        from tree_sitter import Language, Query

        accessor = getattr(grammar_module, spec.accessor)
        grammar = accessor()
        if grammar is None:
            raise ValueError("grammar accessor returned no grammar")
        language = Language(grammar)
        query = Query(language, spec.definitions)
    except (AttributeError, ImportError, RuntimeError, TypeError, ValueError) as exc:
        raise SymbolLocationError(f"cannot initialize {spec.name} symbol parser: {exc}") from exc
    return language, query


def _tree_sitter_symbol_line_spans(path: Path, source: bytes, symbol: str, spec: LanguageSpec):
    language, query = _tree_sitter_runtime(spec)
    symbol_parts = tuple(part for part in symbol.casefold().split(".") if part)
    local_symbol = symbol_parts[-1]
    try:
        from tree_sitter import Parser, QueryCursor

        tree = Parser(language).parse(source)
        matches = QueryCursor(query).matches(tree.root_node)
    except (ImportError, RuntimeError, TypeError, ValueError) as exc:
        raise SymbolLocationError(f"cannot parse {path} with the {spec.name} symbol parser: {exc}") from exc

    spans: set[tuple[int, int]] = set()
    for _, captures in matches:
        nodes = captures.get("def") or []
        names = captures.get("name") or []
        if not nodes or not names:
            raise SymbolLocationError(f"{spec.name} symbol query returned incomplete captures for {path}")
        name = source[names[0].start_byte : names[0].end_byte].decode("utf-8")
        if name.casefold() == local_symbol and _definition_qualifier(source, nodes[0], symbol_parts):
            node = nodes[0]
            start_line = source.count(b"\n", 0, node.start_byte) + 1
            end_line = source.count(b"\n", 0, node.end_byte) + 1
            spans.add((start_line, end_line))
    return tuple(sorted(spans))


def _definition_qualifier(source: bytes, node: Any, symbol_parts: tuple[str, ...]) -> bool:
    """Match a qualified class member without conflating sibling definitions."""
    if len(symbol_parts) == 1:
        return True
    owners: list[str] = []
    parent = node.parent
    while parent is not None:
        if parent.type in {"class_definition", "class_declaration"}:
            name = parent.child_by_field_name("name")
            if name is not None:
                owners.append(source[name.start_byte : name.end_byte].decode("utf-8").casefold())
        parent = parent.parent
    qualified = (*reversed(owners), symbol_parts[-1])
    return len(qualified) >= len(symbol_parts) and qualified[-len(symbol_parts) :] == symbol_parts


@lru_cache(maxsize=512)
def symbol_line_spans(source_root: str, rel_file: str, symbol: str) -> tuple[tuple[int, int], ...]:
    """Return every inclusive source line span for matching symbol definitions."""
    path = Path(source_root) / rel_file
    if not path.is_file():
        return ()
    spec = _spec_for(path)
    if spec is not None:
        source = path.read_bytes()
        return _tree_sitter_symbol_line_spans(path, source, symbol, spec)
    return ()
