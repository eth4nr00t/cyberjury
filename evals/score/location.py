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
        if name.casefold() == symbol.casefold():
            node = nodes[0]
            start_line = source.count(b"\n", 0, node.start_byte) + 1
            end_line = source.count(b"\n", 0, node.end_byte) + 1
            spans.add((start_line, end_line))
    return tuple(sorted(spans))


@cache
def _slither_runtime(source_root: str) -> Any:
    try:
        from slither import Slither

        return Slither(source_root)
    except Exception as exc:
        raise SymbolLocationError(f"cannot initialize Solidity symbol parser for {source_root}: {exc}") from exc


def _solidity_declarations(analysis: Any):
    for contract in analysis.contracts:
        yield contract
        for attribute in (
            "functions_declared",
            "modifiers_declared",
            "state_variables_declared",
            "structures_declared",
            "enums_declared",
        ):
            yield from getattr(contract, attribute)
    for compilation_unit in analysis.compilation_units:
        for attribute in (
            "functions_top_level",
            "variables_top_level",
            "structures_top_level",
            "enums_top_level",
        ):
            yield from getattr(compilation_unit, attribute)


def _mapping_targets_file(mapping: Any, path: Path, source_root: Path) -> bool:
    filename = mapping.filename
    absolute = str(getattr(filename, "absolute", ""))
    if absolute and Path(absolute).resolve() == path.resolve():
        return True
    relative = str(getattr(filename, "relative", ""))
    return bool(relative and (source_root / relative).resolve() == path.resolve())


def _slither_symbol_line_spans(
    source_root: str,
    path: Path,
    symbol: str,
) -> tuple[tuple[int, int], ...]:
    analysis = _slither_runtime(source_root)
    spans: set[tuple[int, int]] = set()
    for declaration in _solidity_declarations(analysis):
        if str(declaration.name).casefold() != symbol.casefold():
            continue
        mapping = declaration.source_mapping
        if not _mapping_targets_file(mapping, path, Path(source_root)):
            continue
        lines = tuple(int(line) for line in mapping.lines)
        if not lines or min(lines) < 1:
            raise SymbolLocationError(f"Solidity parser returned no safe source span for {symbol} in {path}")
        spans.add((min(lines), max(lines)))
    return tuple(sorted(spans))


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
    if path.suffix.lower() == ".sol":
        return _slither_symbol_line_spans(source_root, path, symbol)
    return ()
