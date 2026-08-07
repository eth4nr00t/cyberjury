"""A function-level call graph and import graph for the web domain.

extracted with tree-sitter. Without a graph the engine packs a unit's context by
guessing which files look like a business layer from their path, and a path name says
nothing about what an entry file actually reaches, so a definition one hop below it is
never shown to the model. Two kinds of edge, because one alone misses the case: - a
**call** edge, function to function, for a handler that invokes a sink - an **import**
edge, file to definition, from three forms: a name imported directly, a name re-exported
by an entry facade, and a name used through an imported namespace. The facade case is
why this exists, `web.py` never calls `_set_status`, it re-exports `StreamResponse`. The
namespace case is the only source Go has, since a Go import names a directory rather
than a symbol. A namespace binds nothing unless its specifier resolves inside the tree.
Syntax only, no type resolution. A callee is matched by name across the tree, so
`service.readOne` resolves to every `readOne`. That over-matches, which is the recall-
safe direction, invariant 2: an extra definition costs a slice of prompt, a missing one
costs the finding.
"""

from __future__ import annotations

import collections
import importlib
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

import yaml

from cyberjury.domains.base import BackendUnavailable, Facts, FactsBackend

if TYPE_CHECKING:
    from tree_sitter import Node

_QUERIES_FILE = Path(__file__).resolve().parent / "queries.yaml"

_MAX_PARSE_BYTES = 400_000


@dataclass(frozen=True)
class LangSpec:
    """One language's grammar plus the queries the graphs need."""

    name: str
    extensions: tuple[str, ...]
    module: str
    accessor: str
    definitions: str
    calls: str
    imports: tuple[str, ...]
    namespace_imports: tuple[str, ...] = ()
    qualified_calls: str = ""
    namespace_binds: str = "last-segment"


@dataclass
class Definition:
    """One function or class definition, the names it calls, and its char range in its file."""

    name: str
    file: str
    start: int
    end: int
    calls: tuple[str, ...] = ()


@dataclass
class Graph:
    """Every definition in the tree, a name index so a callee resolves without types.

    and the import edges from a file to the definitions it brings in.
    """

    defs: list[Definition] = field(default_factory=list)
    by_name: dict[str, list[int]] = field(default_factory=dict)
    imports: dict[str, list[str]] = field(default_factory=dict)

    def add(self, d: Definition) -> None:
        """Index a definition before appending it so the stored offset stays stable."""
        self.by_name.setdefault(d.name, []).append(len(self.defs))
        self.defs.append(d)

    def resolve(self, name: str) -> list[Definition]:
        """Resolve the result."""
        return [self.defs[i] for i in self.by_name.get(name, ())]

    def module_level_names_in_file(self, source_file: str) -> tuple[str, ...]:
        """Expose export star targets without treating class methods as module bindings."""
        defs = [d for d in self.defs if d.file == source_file]
        return tuple(
            dict.fromkeys(
                d.name
                for d in defs
                if not any(
                    other is not d
                    and (other.start, other.end) != (d.start, d.end)
                    and other.start <= d.start
                    and d.end <= other.end
                    for other in defs
                )
            )
        )

    def to_data(self) -> dict:
        """The payload the engine indexes, a list per name because a name repeats inside one file."""
        out: dict[str, dict[str, list[dict]]] = {}
        for d in self.defs:
            entry = {"range": [d.start, d.end], "calls": list(d.calls)}
            out.setdefault(d.file, {}).setdefault(d.name, []).append(entry)
        return out


def load_specs(path: Path | None = None) -> dict[str, LangSpec]:
    """The language specs from `queries.yaml`. Adding a language is a row there, not code here."""
    raw = yaml.safe_load((path or _QUERIES_FILE).read_text(encoding="utf-8")) or {}
    specs: dict[str, LangSpec] = {}
    for name, cfg in raw.items():
        module, accessor = cfg["grammar"]
        specs[name] = LangSpec(
            name=name,
            extensions=tuple(cfg["extensions"]),
            module=module,
            accessor=accessor,
            definitions=cfg["definitions"].strip(),
            calls=cfg["calls"].strip(),
            imports=tuple(q.strip() for q in cfg.get("imports", ())),
            namespace_imports=tuple(q.strip() for q in cfg.get("namespace_imports", ())),
            qualified_calls=(cfg.get("qualified_calls") or "").strip(),
            namespace_binds=_namespace_binds(name, cfg),
        )
    return specs


def _namespace_binds(language: str, cfg: dict) -> str:
    """Which part of a namespace specifier binds the local name.

    refusing a value it cannot honor. A typo here would silently halve one language's
    namespace edges, and a query table that reads as valid while binding nothing is the
    shape invariant 4 forbids.
    """
    value = (cfg.get("namespace_binds") or "last-segment").strip()
    if value not in ("whole", "last-segment"):
        raise ValueError(f"{language} declares an unknown namespace_binds {value!r}")
    return value


def char_offsets(src: bytes) -> dict[int, int] | None:
    r"""A byte offset to character offset map for one file, or None when the two already agree.

    tree-sitter reports byte offsets, and a `Definition` range is read back against
    `Path.read_text`, so the map has to land in that text and not merely in a decode of
    these bytes. Two things shift the two apart: a multi-byte character, and a line ending,
    since text mode folds `\r\n` and a lone `\r` to one `\n`. Either one earlier in the file
    offsets every later range, and the unit then carries the wrong source and cites the
    wrong line. Returns None for a plain ASCII LF file, so the common path pays two cheap
    scans and builds nothing.
    """
    if src.isascii() and b"\r" not in src:
        return None
    text = src.decode("utf-8", "replace")
    out: dict[int, int] = {}
    byte = index = position = 0
    while position < len(text):
        out[byte] = index
        char = text[position]
        if char == "\r" and text[position + 1 : position + 2] == "\n":
            byte += 2
            position += 2
        else:
            byte += len(char.encode("utf-8"))
            position += 1
        index += 1
    out[byte] = index
    return out


def _ancestors(rel: str) -> list[str]:
    """Every directory prefix of a path, so a namespace naming a directory can be matched."""
    parts = rel.split("/")[:-1]
    return ["/".join(parts[: i + 1]) for i in range(len(parts))]


def namespace_in_tree(
    src: str,
    spec: str,
    known: set[str],
    dirs: set[str],
    extensions: tuple[str, ...],
    scope_prefixes: tuple[str, ...] = (),
) -> bool:
    """Whether a namespace specifier names something inside the tree.

    so a name qualified by it is a first-party edge and not `os.path.join` or `fmt.Println`.
    A namespace may name a directory rather than a file, which is how a Go import and a
    Python package import work, so a directory counts. An absolute specifier carries a
    prefix the tree does not have, `example.com/app/store` for the `store` directory, so
    leading segments are dropped one at a time until a directory matches. That needs no
    manifest to read, and the engine still locates the definition by name, so a wrong guess
    costs a slice of prompt rather than a missed finding.
    """
    if resolve_specifier(src, spec, known, extensions, scope_prefixes) is not None:
        return True
    cleaned = spec.strip().strip("\"'").lstrip(".")
    if not cleaned:
        return False
    parts = cleaned.replace(".", "/").split("/")
    return any("/".join(parts[start:]) in dirs for start in range(len(parts)))


def _spec_for(specs: dict[str, LangSpec], rel: str) -> LangSpec | None:
    suffix = Path(rel).suffix
    for spec in specs.values():
        if suffix in spec.extensions:
            return spec
    return None


def _scope_prefixes(base: Path) -> tuple[str, ...]:
    """The directory names a package-absolute specifier repeats because the review root sits.

    inside the package, longest first, bounded by the repository so the containing
    filesystem contributes none of its own.
    """
    parts: list[str] = []
    for d in (base, *base.parents):
        if (d / ".git").exists():
            break
        if d.parent == d:
            return ()
        parts.append(d.name)
    return tuple("/".join(reversed(parts[:i])) for i in range(len(parts), 0, -1))


def resolve_specifier(
    src: str, spec: str, known: set[str], extensions: tuple[str, ...], scope_prefixes: tuple[str, ...] = ()
) -> str | None:
    """The file an import specifier names, or None when it names none in the tree.

    `extensions` comes from the language specs rather than a list written here, so a
    language added to queries.yaml resolves without a second edit, invariant 1. A specifier
    may name a sibling by its compiled extension, `./x.js` for `x.ts`, so any declared
    extension is stripped before the declared set is tried. Normalizes `..` rather than
    joining it literally, since a parent-directory specifier is how a file reaches a sibling
    package and a literal `a/b/../c` matches no key. A bare specifier is tried as a tree
    path too, so a package-absolute Python import such as `app.services.billing` resolves,
    and a third-party name simply misses every candidate and is dropped. A package-absolute
    specifier spells its path from the package root while every key here is relative to the
    review root, so one of `scope_prefixes` coming off the front is what makes
    `apps.webui.internal.db` reach `internal/db.py` when the review root is the package
    itself.
    """
    parent = str(PurePosixPath(src).parent)
    spec = spec.strip().strip("\"'")
    if not spec:
        return None
    if spec.startswith("."):
        if "/" in spec or spec.startswith("./") or spec.startswith("../"):
            base = os.path.join(parent, spec)
        else:
            up = len(spec) - len(spec.lstrip("."))
            tail = spec.lstrip(".").replace(".", "/")
            base = os.path.join(parent, *[".."] * (up - 1), tail)
    else:
        base = spec.replace(".", "/") if "/" not in spec else spec
    base = os.path.normpath(base).removeprefix("./")
    stem = base
    for ext in extensions:
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    for cand in (base, *(f"{stem}{ext}" for ext in extensions)):
        if cand in known:
            return cand
    for prefix in scope_prefixes:
        if base == prefix or base.startswith(f"{prefix}/"):
            inner = base[len(prefix) :].lstrip("/")
            if inner:
                hit = resolve_specifier(src, inner, known, extensions)
                if hit is not None:
                    return hit
    for index in ("__init__.py", *(f"index{ext}" for ext in extensions)):
        cand = str(PurePosixPath(base) / index)
        if cand in known:
            return cand
    return None


def _is_direct_self_call(definition_name: str, callee_name: str, callee: Node) -> bool:
    if callee_name != definition_name:
        return False
    parent = callee.parent
    return parent is not None and parent.type in ("call", "call_expression")


class TreeSitterCallGraph(FactsBackend):
    """Extract a definition-level call and import graph from a source tree."""

    def __init__(self, specs: dict[str, LangSpec] | None = None) -> None:
        """Load language specs and derive the install hint from their grammars."""
        self._specs = specs if specs is not None else load_specs()
        packages = sorted({"tree-sitter"} | {s.module.replace("_", "-") for s in self._specs.values()})
        self.install_hint = f"install {', '.join(packages)} to enable it"

    def available(self) -> bool:
        """Whether tree-sitter carries the query API this uses and at least one grammar imports.

        Checks the symbol and not just the package, since an older tree-sitter imports fine and
        then raises inside extraction, which reads as a failed pass rather than an absent
        toolchain. A missing grammar for one language is not unavailable, the pass still graphs
        the languages whose grammar is present.
        """
        try:
            module = importlib.import_module("tree_sitter")
        except ImportError:
            return False
        if not all(hasattr(module, name) for name in ("Language", "Parser", "Query", "QueryCursor")):
            return False
        return any(self._grammar(spec) is not None for spec in self._specs.values())

    def _grammar(self, spec: LangSpec):
        try:
            module = importlib.import_module(spec.module)
        except ImportError:
            return None
        accessor = getattr(module, spec.accessor, None)
        return accessor() if callable(accessor) else None

    def extract(self, root: str | Path) -> Facts:
        """Extract deterministic facts from the source tree."""
        if not self.available():
            raise BackendUnavailable(self.install_hint)
        from cyberjury.detection import load_detection

        base = Path(root).resolve()
        det = load_detection()
        graphable: list[tuple[Path, str, LangSpec]] = []
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(base).as_posix()
            if det.is_skipped_dir(Path(rel).parts[:-1]) or det.is_test_path(rel):
                continue
            spec = _spec_for(self._specs, rel)
            if spec is not None:
                graphable.append((path, rel, spec))
        known = {rel for _p, rel, _s in graphable}
        dirs = {d for rel in known for d in _ancestors(rel)}
        extensions = tuple(sorted({e for s in self._specs.values() for e in s.extensions}))
        scope_prefixes = _scope_prefixes(base)
        graph = Graph()
        raw_imports: dict[str, list[tuple[str, str]]] = {}
        namespaces: dict[str, dict[str, str]] = {}
        qualified: dict[str, list[tuple[str, str]]] = {}
        skipped: collections.Counter[str] = collections.Counter()
        for path, rel, spec in graphable:
            reason = self._parse_into(graph, raw_imports, namespaces, qualified, path, rel, spec)
            if reason:
                skipped[reason] += 1
        for rel, pairs in raw_imports.items():
            for name, specifier in pairs:
                target = resolve_specifier(rel, specifier, known, extensions, scope_prefixes)
                if target is None:
                    continue
                if name == "*":
                    graph.imports.setdefault(rel, []).extend(graph.module_level_names_in_file(target))
                else:
                    graph.imports.setdefault(rel, []).append(name)
        for rel, uses in qualified.items():
            bound = namespaces.get(rel) or {}
            first_party = {
                local
                for local, spec_text in bound.items()
                if namespace_in_tree(rel, spec_text, known, dirs, extensions, scope_prefixes)
            }
            for qualifier, name in uses:
                if qualifier in first_party:
                    graph.imports.setdefault(rel, []).append(name)
        if not graph.defs:
            if skipped:
                raise BackendUnavailable(f"no file could be graphed, {_render_skips(skipped)}")
            return Facts()
        data = {
            "graph": {
                "callgraph": graph.to_data(),
                "imports": {f: list(dict.fromkeys(n)) for f, n in graph.imports.items()},
            },
            "by_file": render_by_file(graph),
        }
        return Facts(summary=render_summary(graph, skipped), data=data)

    def _parse_into(
        self,
        graph: Graph,
        raw_imports: dict[str, list[tuple[str, str]]],
        namespaces: dict[str, dict[str, str]],
        qualified: dict[str, list[tuple[str, str]]],
        path: Path,
        rel: str,
        spec: LangSpec,
    ) -> str:
        """Fill the graph, the raw import pairs.

        the namespace bindings and the qualified uses for one file, and name why it was skipped.
        A skip returns its reason rather than raising: one unparsable file in a large tree is
        not an unusable toolchain. The reasons are counted by the caller, so a tree the backend
        could not read is never reported as a tree with no code in it, invariant 4.
        """
        from tree_sitter import Language, Parser, Query, QueryCursor

        grammar = self._grammar(spec)
        if grammar is None:
            return "no grammar installed"
        try:
            src = path.read_bytes()
        except OSError:
            return "unreadable"
        if len(src) > _MAX_PARSE_BYTES:
            return "over the parse cap"
        language = Language(grammar)
        parser = Parser(language)
        try:
            tree = parser.parse(src)
        except (ValueError, RuntimeError):
            return "unparsable"

        def text(node: Node) -> str:
            return src[node.start_byte : node.end_byte].decode("utf-8", "replace")

        call_query = Query(language, spec.calls)
        to_char = char_offsets(src)
        for _, caps in QueryCursor(Query(language, spec.definitions)).matches(tree.root_node):
            node = (caps.get("def") or [None])[0]
            ident = (caps.get("name") or [None])[0]
            if node is None or ident is None:
                continue
            name = text(ident)
            calls: dict[str, None] = {}
            for _, ccaps in QueryCursor(call_query).matches(node):
                for callee in ccaps.get("callee") or ():
                    called = text(callee)
                    if not _is_direct_self_call(name, called, callee):
                        calls.setdefault(called, None)
            start, end = node.start_byte, node.end_byte
            if to_char is not None:
                start, end = to_char.get(start, start), to_char.get(end, end)
            graph.add(Definition(name=name, file=rel, start=start, end=end, calls=tuple(calls)))
        for query_text in spec.imports:
            for _, caps in QueryCursor(Query(language, query_text)).matches(tree.root_node):
                modules = caps.get("module") or ()
                names = caps.get("imported") or ()
                if not modules:
                    continue
                specifier = text(modules[0])
                for ident in names:
                    name = text(ident)
                    raw_imports.setdefault(rel, []).append((name, specifier))
        for query_text in spec.namespace_imports:
            for _, caps in QueryCursor(Query(language, query_text)).matches(tree.root_node):
                modules = caps.get("module") or ()
                if not modules:
                    continue
                specifier = text(modules[0]).strip("\"'")
                aliases = caps.get("alias") or ()
                if aliases:
                    local = text(aliases[0])
                elif spec.namespace_binds == "whole":
                    local = specifier
                else:
                    local = specifier.replace("/", ".").split(".")[-1]
                namespaces.setdefault(rel, {})[local] = specifier
        if spec.qualified_calls:
            for _, caps in QueryCursor(Query(language, spec.qualified_calls)).matches(tree.root_node):
                quals, names = caps.get("qualifier") or (), caps.get("name") or ()
                if quals and names:
                    qualified.setdefault(rel, []).append((text(quals[0]), text(names[0])))
        return ""


def render_by_file(graph: Graph) -> dict[str, str]:
    """A prompt-ready graph block per file.

    the `by_file` convention the engine indexes by a unit's files so a split file still
    carries its whole graph.
    """
    out: dict[str, list[str]] = {}
    for d in graph.defs:
        line = f"  {d.name}()"
        if d.calls:
            line += "  calls " + ", ".join(d.calls)
        out.setdefault(d.file, []).append(line)
    for file, names in graph.imports.items():
        out.setdefault(file, []).insert(0, "  imports " + ", ".join(dict.fromkeys(names)))
    return {file: f"{file}\n" + "\n".join(lines) for file, lines in out.items()}


def _render_skips(skipped: collections.Counter) -> str:
    """The skip tally as one clause, so a caller can put it in a sentence."""
    return ", ".join(f"{count} {reason}" for reason, count in sorted(skipped.items()))


def render_summary(graph: Graph, skipped: collections.Counter | None = None) -> str:
    """Prompt-ready text for the shared context.

    naming the scale rather than dumping the graph. Names the files the pass could not
    graph, so a reader is told the graph is partial instead of reading a smaller graph as
    the whole tree. The per-file blocks carry the detail, so a global dump would repeat it
    truncated.
    """
    if not graph.defs:
        return ""
    files = len({d.file for d in graph.defs})
    edges = sum(len(d.calls) for d in graph.defs)
    partial = f" {sum((skipped or {}).values())} files were skipped, {_render_skips(skipped)}." if skipped else ""
    return (
        f"Call graph: {len(graph.defs)} definitions across {files} files, {edges} call edges, "
        "extracted from syntax. A callee is matched by name, so a name shared by several "
        f"definitions resolves to all of them.{partial}"
    )
