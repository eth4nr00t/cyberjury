"""A function-level call graph and import graph for the web domain, extracted with tree-sitter.

Without a graph the engine packs a unit's context by guessing which files look like a business layer
from their path. Measured on 28 real benchmark targets, that guess captures 0% of the downstream a
real graph reaches on 24 of them and at most 30% on the rest, so a definition one hop below an entry
file is never shown to the model. On aiohttp the planted CVE sits in `web_response.py`, the entry
file `web.py` imports from it, and an ungrounded review scores 0/1.

Two kinds of edge, because one alone misses the case:

- a **call** edge, function to function, for a handler that invokes a sink
- an **import** edge, file to definition, for an entry facade that re-exports the class whose
  method carries the bug. `web.py` never calls `_set_status`, it re-exports `StreamResponse`.

Syntax only, no type resolution. A callee is matched by name across the tree, so `service.readOne`
resolves to every `readOne`. That over-matches, which is the recall-safe direction, invariant 2: an
extra definition costs a slice of prompt, a missing one costs the finding.
"""

from __future__ import annotations

import collections
import importlib
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from cyberjury.domains.base import BackendUnavailable, Facts, FactsBackend

_QUERIES_FILE = Path(__file__).resolve().parent / "queries.yaml"

# a file this large is skipped rather than parsed, so one vendored bundle cannot dominate the pass
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
    """Every definition in the tree, a name index so a callee resolves without types, and the
    import edges from a file to the definitions it brings in."""

    defs: list[Definition] = field(default_factory=list)
    by_name: dict[str, list[int]] = field(default_factory=dict)
    imports: dict[str, list[str]] = field(default_factory=dict)

    def add(self, d: Definition) -> None:
        self.by_name.setdefault(d.name, []).append(len(self.defs))
        self.defs.append(d)

    def resolve(self, name: str) -> list[Definition]:
        return [self.defs[i] for i in self.by_name.get(name, ())]

    def to_data(self) -> dict:
        """The payload the engine indexes, a list per name because a name repeats inside one file.

        Keying a single entry per name silently dropped 13 of this repository's own 475 definitions,
        every `__init__` past the first in a file with two classes among them, and a definition the
        payload never carries is a definition no unit can pack, invariant 2."""
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
        )
    return specs


def char_offsets(src: bytes) -> dict[int, int] | None:
    """A byte offset to character offset map for one file, or None when the two already agree.

    tree-sitter reports byte offsets, and a `Definition` range is read back against
    `Path.read_text`, so the map has to land in that text and not merely in a decode of these
    bytes. Two things shift the two apart: a multi-byte character, and a line ending, since text
    mode folds `\\r\\n` and a lone `\\r` to one `\\n`. Either one earlier in the file offsets every
    later range, and the unit then carries the wrong source and cites the wrong line. Returns None
    for a plain ASCII LF file, so the common path pays two cheap scans and builds nothing."""
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


def _spec_for(specs: dict[str, LangSpec], rel: str) -> LangSpec | None:
    suffix = Path(rel).suffix
    for spec in specs.values():
        if suffix in spec.extensions:
            return spec
    return None


def resolve_specifier(src: str, spec: str, known: set[str], extensions: tuple[str, ...]) -> str | None:
    """The file an import specifier names, or None when it names none in the tree.

    `extensions` comes from the language specs rather than a list written here, so a language added
    to queries.yaml resolves without a second edit, invariant 1. A specifier may name a sibling by
    its compiled extension, `./x.js` for `x.ts`, so any declared extension is stripped before the
    declared set is tried.

    Normalizes `..` rather than joining it literally, since a parent-directory specifier is how a
    file reaches a sibling package and a literal `a/b/../c` matches no key. A bare specifier is
    tried as a tree path too, so a package-absolute Python import such as `app.services.billing`
    resolves, and a third-party name simply misses every candidate and is dropped."""
    parent = str(PurePosixPath(src).parent)
    spec = spec.strip().strip("\"'")
    if not spec:
        return None
    if spec.startswith("."):
        if "/" in spec or spec.startswith("./") or spec.startswith("../"):
            base = os.path.join(parent, spec)
        else:
            # a dotted python specifier: each leading dot past the first climbs one package
            up = len(spec) - len(spec.lstrip("."))
            tail = spec.lstrip(".").replace(".", "/")
            base = os.path.join(parent, *[".."] * (up - 1), tail)
    else:
        base = spec.replace(".", "/") if "/" not in spec else spec
    # normpath keeps a climb past the tree root as a leading `..`, and every key in `known` is a
    # path relative to that root, so such a specifier matches nothing and binds no edge
    base = os.path.normpath(base).removeprefix("./")
    stem = base
    for ext in extensions:
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    for cand in (base, *(f"{stem}{ext}" for ext in extensions)):
        if cand in known:
            return cand
    # a specifier may name a package directory, resolved through the entry file its language uses
    for index in ("__init__.py", *(f"index{ext}" for ext in extensions)):
        cand = str(PurePosixPath(base) / index)
        if cand in known:
            return cand
    return None


class TreeSitterCallGraph(FactsBackend):
    """Extract a definition-level call and import graph from a source tree."""

    def __init__(self, specs: dict[str, LangSpec] | None = None) -> None:
        self._specs = specs if specs is not None else load_specs()
        # from the specs, so a language added to queries.yaml cannot leave this naming the
        # wrong packages
        packages = sorted({"tree-sitter"} | {s.module.replace("_", "-") for s in self._specs.values()})
        self.install_hint = f"install {', '.join(packages)} to enable it"

    def available(self) -> bool:
        """Whether tree-sitter carries the query API this uses and at least one grammar imports.

        Checks the symbol and not just the package, since an older tree-sitter imports fine and
        then raises inside extraction, which reads as a failed pass rather than an absent
        toolchain. A missing grammar for one language is not unavailable, the pass still graphs
        the languages whose grammar is present."""
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
        extensions = tuple(sorted({e for s in self._specs.values() for e in s.extensions}))
        graph = Graph()
        raw_imports: dict[str, list[tuple[str, str]]] = {}
        skipped: collections.Counter[str] = collections.Counter()
        for path, rel, spec in graphable:
            reason = self._parse_into(graph, raw_imports, path, rel, spec)
            if reason:
                skipped[reason] += 1
        # resolve after the parse loop, since raw_imports is only complete once every file ran
        for rel, pairs in raw_imports.items():
            for name, specifier in pairs:
                if resolve_specifier(rel, specifier, known, extensions) is not None:
                    graph.imports.setdefault(rel, []).append(name)
        if not graph.defs:
            if skipped:
                # every graphable file failed, which is a backend that could not run on this tree,
                # not a tree with no code in it. The caller turns this into a loud degrade note
                raise BackendUnavailable(f"no file could be graphed, {_render_skips(skipped)}")
            # a payload of empty maps would have the caller persist an empty _facts.md, which a
            # later stage reads as grounding that succeeded
            return Facts()
        # no "units" key, unlike the evm backend: this one runs before candidate selection, and
        # anchoring on every imported definition instead emits 160 units for aiohttp's 48 file
        # tree, the whole library rather than an entrypoint's reachable set
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
        path: Path,
        rel: str,
        spec: LangSpec,
    ) -> str:
        """Add one file's definitions and raw import pairs to the graph, and name why it was skipped.

        A skip returns its reason rather than raising: one unparsable file in a large tree is not an
        unusable toolchain. The reasons are counted by the caller, so a tree the backend could not
        read is never reported as a tree with no code in it, invariant 4."""
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
        call_query = Query(language, spec.calls)
        to_char = char_offsets(src)
        for _, caps in QueryCursor(Query(language, spec.definitions)).matches(tree.root_node):
            node = (caps.get("def") or [None])[0]
            ident = (caps.get("name") or [None])[0]
            if node is None or ident is None:
                continue
            name = src[ident.start_byte : ident.end_byte].decode("utf-8", "replace")
            # match inside the node already parsed, never re-parse its source standalone: a method
            # body read on its own loses the class context, so `async post(){}` parses `async` as a
            # call and the graph gains a callee the file never had
            calls: dict[str, None] = {}
            for _, ccaps in QueryCursor(call_query).matches(node):
                for callee in ccaps.get("callee") or ():
                    called = src[callee.start_byte : callee.end_byte].decode("utf-8", "replace")
                    if called != name:
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
                specifier = src[modules[0].start_byte : modules[0].end_byte].decode("utf-8", "replace")
                for ident in names:
                    name = src[ident.start_byte : ident.end_byte].decode("utf-8", "replace")
                    raw_imports.setdefault(rel, []).append((name, specifier))
        return ""


def render_by_file(graph: Graph) -> dict[str, str]:
    """A prompt-ready graph block per file, the `by_file` convention the engine indexes by a unit's
    files so a split file still carries its whole graph."""
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
    """Prompt-ready text for the shared context, naming the scale rather than dumping the graph.

    Names the files the pass could not graph, so a reader is told the graph is partial instead of
    reading a smaller graph as the whole tree.

    The per-file blocks carry the detail, so a global dump would repeat it truncated."""
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
