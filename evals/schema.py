"""The shared eval schema: a normalized report from any path, an answer key entry, and the
answer key itself.

These shapes are the public internal API every runner and scorer agrees on. The diff path
and the repository path differ only in how they produce reports, see runners/, then everything
downstream speaks Report and AnswerKey. The answer key never reaches the review under test,
so a high score cannot come from the review reading the key.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from evals.scorers.match import category_of, normalize_endpoint


@dataclass(frozen=True, kw_only=True)
class Report:
    """One reported issue, however a path produced it. Endpoint is stored normalized, text
    is the lowercased finding body a symbol-anchored key entry searches for its framing.
    `lines` are the source lines the report pins in its cited files, so a symbol anchor can
    credit a report that located the bug by line inside the symbol's body without typing the
    symbol's name."""

    name: str
    endpoint: str = ""
    category: str = ""
    files: tuple[str, ...] = ()
    text: str = ""
    lines: tuple[int, ...] = ()

    @classmethod
    def make(cls, name: str, endpoint: str, category: str, files, text: str = "", lines=()) -> Report:
        return cls(
            name=name,
            endpoint=normalize_endpoint(endpoint),
            category=category_of(category),
            files=tuple(files),
            text=text.lower(),
            lines=tuple(sorted({int(n) for n in lines})),
        )


def knowledge_refs(block) -> tuple[str, ...]:
    """Flatten a knowledge block, {vulnerabilities: [...], guides: [...]}, into the single
    namespaced form the coverage matrix indexes on, vuln:<id> and guide:<path>. Both an
    answer key entry and a benchmark manifest carry this block, so they attribute alike."""
    block = block or {}
    refs = [f"vuln:{v}" for v in block.get("vulnerabilities") or []]
    refs += [f"guide:{g}" for g in block.get("guides") or []]
    return tuple(refs)


@dataclass(frozen=True, kw_only=True)
class KeyEntry:
    """A planted issue or a safe lookalike from the answer key. `files` are the acceptable
    file anchors, since a vuln may be correctly reported at its sink or at a call site that
    feeds it, so a report matching any one counts. `symbols` narrows an entry from a
    whole file to its real framing, the function names on the true bug's path, so a report of
    the same class on a sibling function in the file no longer credits it. Several are
    accepted, a report naming any one of the path's functions counts. `knowledge` names the
    vulnerability classes and guides the entry exercises, so the coverage matrix can
    attribute it, empty for a legacy key authored before the rename."""

    id: str
    entry: str = ""
    files: tuple[str, ...] = ()
    category: str = ""
    severity: str = ""
    note: str = ""
    knowledge: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class AnswerKey:
    target: str
    planted: tuple[KeyEntry, ...]
    safe: tuple[KeyEntry, ...]


def _entry_files(row: dict) -> tuple[str, ...]:
    """The file anchors a key entry accepts. `files` lists several when a vuln may be
    reported at its sink or at a call site, the singular `file` is the single anchor form a
    legacy key uses, so both load alike."""
    raw = row.get("files")
    if raw is None:
        single = row.get("file")
        raw = [single] if single else []
    return tuple(str(f) for f in raw)


def _entry_symbols(row: dict) -> tuple[str, ...]:
    """The framing anchors a key entry accepts, lowercased to match a report's lowercased
    body. `symbols` lists several functions on the bug's path, the singular `symbol` is the
    single form, so both load alike."""
    raw = row.get("symbols")
    if raw is None:
        single = row.get("symbol")
        raw = [single] if single else []
    return tuple(str(s).strip().lower() for s in raw if str(s).strip())


def _key_entries(rows, *, require_category: bool, where: str) -> tuple[KeyEntry, ...]:
    out: list[KeyEntry] = []
    for i, r in enumerate(rows or []):
        if not isinstance(r, dict):
            raise ValueError(f"{where}[{i}] is not a mapping")
        files = _entry_files(r)
        if "entry" not in r and not files:
            # invariant: no location means a report can never be matched to it, so a key
            # entry with neither an endpoint nor a file is unscoreable and is rejected loud
            raise ValueError(f"{where}[{i}] has neither entry nor file, it cannot be matched")
        if require_category and not r.get("category"):
            raise ValueError(f"{where}[{i}] has no category")
        out.append(
            KeyEntry(
                id=str(r.get("id") or f"{where}-{i}"),
                entry=str(r.get("entry", "")),
                files=files,
                category=category_of(str(r.get("category", ""))),
                severity=str(r.get("severity", "")),
                note=str(r.get("note", "")),
                knowledge=knowledge_refs(r.get("knowledge")),
                symbols=_entry_symbols(r),
            )
        )
    return tuple(out)


def load_answer_key(path: str | Path) -> AnswerKey:
    """Load and validate an answer key, failing loud on a malformed one rather than
    scoring against a silently empty key. Accepts `planted:` and the legacy `issues:` as
    aliases, so a key authored before the rename loads unchanged."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"answer key {path} is not a mapping")
    planted_rows = data.get("planted", data.get("issues"))
    if planted_rows is None:
        raise ValueError(f"answer key {path} has no planted (or legacy issues) list")
    return AnswerKey(
        target=str(data.get("target", Path(path).stem)),
        planted=_key_entries(planted_rows, require_category=True, where="planted"),
        safe=_key_entries(data.get("safe"), require_category=False, where="safe"),
    )
