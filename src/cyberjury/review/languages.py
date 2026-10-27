"""Load the per-language contract: extensions, grammar, file conventions, and syntax queries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cache

import yaml

from cyberjury.review.contract import LANGUAGE_FILES

_FIELDS = frozenset({"extensions", "grammar", "inherits", "files", "syntax"})
_FILE_CONVENTIONS = frozenset({"ignored_dirs", "dependency_dirs", "test_dirs", "test_name_patterns", "lockfiles"})


@dataclass(frozen=True, kw_only=True)
class Language:
    """One language's file conventions, grammar, and syntax queries."""

    name: str
    extensions: tuple[str, ...]
    grammar: tuple[str, str]
    files: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    syntax: Mapping[str, object] = field(default_factory=dict)


@cache
def load_languages() -> dict[str, Language]:
    """Load every language file, resolving each `inherits` chain of syntax queries."""
    raw = {path.stem: yaml.safe_load(path.read_text(encoding="utf-8")) for path in LANGUAGE_FILES}
    for name, config in raw.items():
        unknown = sorted(set(config) - _FIELDS) or sorted(set(config.get("files", {})) - _FILE_CONVENTIONS)
        if unknown:
            raise ValueError(f"language {name} contains unknown fields: {', '.join(unknown)}")

    def syntax(name: str) -> dict[str, object]:
        parent = raw[name].get("inherits")
        return {**(syntax(parent) if parent else {}), **(raw[name].get("syntax") or {})}

    return {
        name: Language(
            name=name,
            extensions=tuple(value.lower() for value in config["extensions"]),
            grammar=tuple(config["grammar"]),
            files={key: tuple(values) for key, values in (config.get("files") or {}).items()},
            syntax=syntax(name),
        )
        for name, config in sorted(raw.items())
    }
