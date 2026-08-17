"""The shared eval schema.

a normalized report from any path, an answer key entry, and the answer key itself. These
shapes are the public internal API every runner and scorer agrees on. The diff path and
the repository path differ only in how they produce reports, see runners/, then
everything downstream speaks Report and AnswerKey. The answer key never reaches the
review under test, so a high score cannot come from the review reading the key.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from evals.scorers.match import category_of, normalize_endpoint

SCHEMA_VERSION = 1


@dataclass(frozen=True, kw_only=True)
class Report:
    """One reported issue, however a path produced it.

    Endpoint is stored normalized, text is the lowercased finding body a symbol-anchored key
    entry searches for its framing. `lines` are the source lines the report pins in its
    cited files, so a symbol anchor can credit a report that located the bug by line inside
    the symbol's body without typing the symbol's name.
    """

    name: str
    endpoint: str = ""
    category: str = ""
    files: tuple[str, ...] = ()
    text: str = ""
    lines: tuple[int, ...] = ()

    @classmethod
    def make(cls, name: str, endpoint: str, category: str, files, text: str = "", lines=()) -> Report:
        """Build the result."""
        return cls(
            name=name,
            endpoint=normalize_endpoint(endpoint),
            category=category_of(category),
            files=tuple(files),
            text=text.lower(),
            lines=tuple(sorted({int(n) for n in lines})),
        )


def knowledge_refs(block) -> tuple[str, ...]:
    """Flatten a knowledge block, {vulnerabilities.

    [...], guides: [...]}, into the single namespaced form the coverage matrix indexes on,
    vuln:<id> and guide:<path>. Both an answer key entry and a benchmark manifest carry this
    block, so they attribute alike.
    """
    block = block or {}
    refs = [f"vuln:{v}" for v in block.get("vulnerabilities") or []]
    refs += [f"guide:{g}" for g in block.get("guides") or []]
    return tuple(refs)


def require_schema_version(data: dict, path: str | Path, kind: str) -> None:
    """Require an explicit schema version so benchmark data can evolve without guessing."""
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"{kind} {path} has schema_version {data.get('schema_version')!r}, expected {SCHEMA_VERSION}")


@dataclass(frozen=True, kw_only=True)
class KeyEntry:
    """A planted issue or a safe lookalike from the answer key.

    `files` are the acceptable file anchors, since a vuln may be correctly reported at its
    sink or at a call site that feeds it, so a report matching any one counts. `symbols`
    narrows an entry from a file to its real framing, the function names on the true
    bug's path, so a report of the same class on a sibling function in the file no longer
    credits it. Several are accepted, a report naming any one of the path's functions
    counts. `knowledge` names the vulnerability classes and guides the entry exercises, so
    the coverage matrix can attribute it.
    """

    id: str
    entry: str = ""
    files: tuple[str, ...] = ()
    category: str = ""
    severity: str = ""
    note: str = ""
    knowledge: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    applies_to: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class AnswerKey:
    """Expected findings and safe anchors for one benchmark."""

    target: str
    planted: tuple[KeyEntry, ...]
    safe: tuple[KeyEntry, ...]


def _list_field(row: dict, key: str, where: str) -> tuple[str, ...]:
    raw = row.get(key)
    if raw is None:
        return ()
    if isinstance(raw, str) or not isinstance(raw, list):
        raise ValueError(f"{where}.{key} is not a list")
    return tuple(str(v) for v in raw)


def _entry_files(row: dict, where: str) -> tuple[str, ...]:
    """The file anchors a key entry accepts.

    `files` lists several when a vuln may be reported at its sink or at a call site.
    """
    return _list_field(row, "files", where)


def _entry_symbols(row: dict, where: str) -> tuple[str, ...]:
    """The framing anchors a key entry accepts, lowercased to match a report's lowercased body.

    `symbols` lists several functions on the bug's path.
    """
    return tuple(s.strip().lower() for s in _list_field(row, "symbols", where) if s.strip())


def _key_entries(rows, *, require_category: bool, where: str) -> tuple[KeyEntry, ...]:
    out: list[KeyEntry] = []
    for i, r in enumerate(rows or []):
        if not isinstance(r, dict):
            raise ValueError(f"{where}[{i}] is not a mapping")
        entry_where = f"{where}[{i}]"
        if "file" in r:
            raise ValueError(f"{entry_where} uses file, expected files")
        if "symbol" in r:
            raise ValueError(f"{entry_where} uses symbol, expected symbols")
        files = _entry_files(r, entry_where)
        if "entry" not in r and not files:
            raise ValueError(f"{where}[{i}] has neither entry nor files, it cannot be matched")
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
                symbols=_entry_symbols(r, entry_where),
                applies_to=_list_field(r, "applies_to", entry_where),
            )
        )
    return tuple(out)


def load_answer_key(path: str | Path, *, task_id: str | None = None) -> AnswerKey:
    """Load and validate an answer key, failing loud on a malformed one rather than scoring.

    against a silently empty key.
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"answer key {path} is not a mapping")
    require_schema_version(data, path, "answer key")
    if "issues" in data:
        raise ValueError(f"answer key {path} uses issues, expected planted")
    planted_rows = data.get("planted")
    if planted_rows is None:
        raise ValueError(f"answer key {path} has no planted list")
    key = AnswerKey(
        target=str(data.get("target", Path(path).stem)),
        planted=_key_entries(planted_rows, require_category=True, where="planted"),
        safe=_key_entries(data.get("safe"), require_category=False, where="safe"),
    )
    _validate_disjoint_entry_scopes(key.planted, "planted")
    _validate_disjoint_entry_scopes(key.safe, "safe")
    _validate_disjoint_entry_sections(key.planted, key.safe)
    if task_id is None:
        return key
    return filter_answer_key(key, task_id)


def filter_answer_key(key: AnswerKey, task_id: str) -> AnswerKey:
    """Keep entries that apply to one task, with empty applies_to applying to every task."""

    def keep(entry: KeyEntry) -> bool:
        return not entry.applies_to or task_id in entry.applies_to

    filtered = AnswerKey(
        target=key.target,
        planted=tuple(entry for entry in key.planted if keep(entry)),
        safe=tuple(entry for entry in key.safe if keep(entry)),
    )
    _validate_unique_entry_ids(filtered.planted, "planted", task_id)
    _validate_unique_entry_ids(filtered.safe, "safe", task_id)
    return filtered


def _validate_disjoint_entry_scopes(entries: tuple[KeyEntry, ...], section: str) -> None:
    """Allow a finding id to move only when its task scopes cannot overlap."""
    by_id: dict[str, list[KeyEntry]] = {}
    for entry in entries:
        for prior in by_id.setdefault(entry.id, []):
            if _entry_scopes_overlap(prior, entry):
                raise ValueError(f"duplicate {section} id {entry.id!r} has overlapping applies_to scopes")
        by_id[entry.id].append(entry)


def _entry_scopes_overlap(left: KeyEntry, right: KeyEntry) -> bool:
    if not left.applies_to or not right.applies_to:
        return True
    return bool(set(left.applies_to).intersection(right.applies_to))


def _validate_disjoint_entry_sections(planted: tuple[KeyEntry, ...], safe: tuple[KeyEntry, ...]) -> None:
    """Prevent one task from expecting the same finding id as both planted and safe."""
    safe_by_id: dict[str, list[KeyEntry]] = {}
    for entry in safe:
        safe_by_id.setdefault(entry.id, []).append(entry)
    for entry in planted:
        if any(_entry_scopes_overlap(entry, other) for other in safe_by_id.get(entry.id, [])):
            raise ValueError(f"finding id {entry.id!r} has overlapping planted and safe applies_to scopes")


def _validate_unique_entry_ids(entries: tuple[KeyEntry, ...], section: str, task_id: str) -> None:
    seen: set[str] = set()
    for entry in entries:
        if entry.id in seen:
            raise ValueError(f"duplicate {section} id {entry.id!r} applies to task {task_id!r}")
        seen.add(entry.id)
