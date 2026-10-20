"""Load the per-language contract: extensions, grammar, file conventions, and syntax queries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cache

import yaml

from cyberjury.review.contract import LANGUAGE_FILES

_FIELDS = frozenset({"extensions", "grammar", "inherits", "files", "syntax"})
FILE_CONVENTIONS = frozenset({"ignored_dirs", "dependency_dirs", "test_dirs", "test_name_patterns", "lockfiles"})


@dataclass(frozen=True, kw_only=True)
class Language:
    """One language's file conventions and, when it has a grammar, its syntax queries."""

    name: str
    extensions: tuple[str, ...]
    grammar: tuple[str, str] | None = None
    files: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    syntax: Mapping[str, object] = field(default_factory=dict)


@cache
def load_languages() -> dict[str, Language]:
    """Load every language file, resolving each `inherits` chain of syntax queries."""
    raw = {path.stem: yaml.safe_load(path.read_text(encoding="utf-8")) for path in LANGUAGE_FILES}
    for name, config in raw.items():
        unknown = sorted(set(config) - _FIELDS) or sorted(set(config.get("files", {})) - FILE_CONVENTIONS)
        if unknown:
            raise ValueError(f"language {name} contains unknown fields: {', '.join(unknown)}")
        parent = config.get("inherits")
        if parent is not None and parent not in raw:
            raise ValueError(f"language {name} inherits unknown language {parent}")

    def syntax(name: str, seen: tuple[str, ...] = ()) -> dict[str, object]:
        if name in seen:
            raise ValueError(f"language {name} has an inheritance cycle")
        config = raw[name]
        parent = config.get("inherits")
        inherited = syntax(parent, (*seen, name)) if parent else {}
        return {**inherited, **(config.get("syntax") or {})}

    return {
        name: Language(
            name=name,
            extensions=tuple(value.lower() for value in config["extensions"]),
            grammar=tuple(config["grammar"]) if config.get("grammar") else None,
            files={key: tuple(values) for key, values in (config.get("files") or {}).items()},
            syntax=syntax(name),
        )
        for name, config in sorted(raw.items())
    }
