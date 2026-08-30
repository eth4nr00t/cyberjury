"""Profile source and patch classification config loaded from `detection.yaml`.

What the engine treats as a source file, a dependency manifest, a noise directory, or
test code, across ecosystems. Kept in data so the implementation enumerates no language
itself: adding a language is a data edit, not a code change. This is distinct from a
guide's stack detection in `guides.py`, which decides which language, framework, or
protocol applies.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

from cyberjury.resources import DETECTION_FILE

_REQUIRED_KEYS = frozenset(
    {
        "skip_dirs",
        "source_extensions",
        "config_extensions",
        "manifests",
        "test_dirs",
        "test_name_patterns",
        "doc_extensions",
        "lockfiles",
    }
)
_OPTIONAL_KEYS = frozenset(
    {
        "skip_root_dirs",
        "compile_roots",
        "auto_select_extensions",
        "fact_focus_flags",
        "target_fact_unit_source_chars",
        "patch_definition_patterns",
        "patch_call_patterns",
        "patch_callable_assignment_patterns",
    }
)
_ALLOWED_KEYS = _REQUIRED_KEYS | _OPTIONAL_KEYS


@dataclass(frozen=True)
class PatchSyntax:
    """Profile-owned lexical hints used only for patch-local grounding."""

    definition_patterns: tuple[str, ...] = ()
    call_patterns: tuple[str, ...] = ()
    callable_assignment_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class Detection:
    """File classification rules loaded from one profile detection config."""

    skip_dirs: frozenset[str]
    source_extensions: frozenset[str]
    config_extensions: frozenset[str]
    manifests: tuple[str, ...]
    test_dirs: frozenset[str]
    test_name_patterns: tuple[str, ...]
    doc_extensions: frozenset[str]
    lockfiles: frozenset[str]
    skip_root_dirs: frozenset[str] = frozenset()
    compile_roots: tuple[str, ...] = ()
    auto_select_extensions: frozenset[str] = frozenset()

    @property
    def detection_extensions(self) -> frozenset[str]:
        """Source plus config, the files sampled when detecting the stack."""
        return self.source_extensions | self.config_extensions

    def is_skipped_dir(self, dir_parts: Sequence[str]) -> bool:
        """True when a path's directory segments fall under a skipped directory.

        A name in skip_dirs matches at any depth. A name in skip_root_dirs matches only as the
        top segment, so a dependency dir such as Foundry's root lib/ is pruned without
        suppressing a real source dir named lib deeper in the tree, invariant 2.
        """
        if any(p in self.skip_dirs for p in dir_parts):
            return True
        return bool(dir_parts) and dir_parts[0] in self.skip_root_dirs

    def is_test_path(self, path: str) -> bool:
        """Return whether a path matches a test directory or file naming convention."""
        parts = path.replace("\\", "/").split("/")
        if any(p in self.test_dirs for p in parts[:-1]):
            return True
        name = parts[-1].lower()
        return any(fnmatch.fnmatch(name, pat) for pat in self.test_name_patterns)

    def is_noise_path(self, path: str) -> bool:
        """Return whether a path should be excluded from security review.

        Excluded paths cover noise or vendored directories, test code, documentation, and generated
        dependency lockfile. This is a denylist of files known to carry no logic, not the
        inverse of source_extensions, so a security-relevant non-source file such as a `.sql`
        migration, a shell script, or a Dockerfile is kept, invariant 2.
        """
        parts = path.replace("\\", "/").split("/")
        if self.is_skipped_dir(parts[:-1]):
            return True
        if self.is_test_path(path):
            return True
        name = parts[-1]
        if name in self.lockfiles:
            return True
        return Path(name).suffix.lower() in self.doc_extensions


@cache
def load_detection_mapping(detection_file: Path = DETECTION_FILE) -> Mapping:
    """Load and validate one profile detection mapping."""
    data = yaml.safe_load(Path(detection_file).read_text(encoding="utf-8")) or {}
    if not isinstance(data, Mapping):
        raise ValueError(f"{detection_file} must contain a mapping")
    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        raise ValueError(f"{detection_file} contains unknown detection keys: {', '.join(unknown)}")
    missing = sorted(_REQUIRED_KEYS - set(data))
    if missing:
        raise ValueError(f"{detection_file} is missing required detection keys: {', '.join(missing)}")
    return data


@cache
def load_detection(detection_file: Path = DETECTION_FILE) -> Detection:
    """Load file and patch classification for one profile.

    Results are cached per file so each profile's `detection.yaml` is independent.
    Defaults to the web profile.
    """
    data = load_detection_mapping(detection_file)

    def list_field(key: str) -> tuple[str, ...]:
        value = data.get(key, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"{detection_file} field {key} must be a list of strings")
        return tuple(value)

    def extension_field(key: str) -> frozenset[str]:
        values = list_field(key)
        normalized = tuple(value.lower() for value in values)
        invalid = [value for value in normalized if not value.startswith(".") or value == "."]
        if invalid:
            raise ValueError(f"{detection_file} field {key} must contain file extensions beginning with a dot")
        if len(normalized) != len(set(normalized)):
            raise ValueError(f"{detection_file} field {key} contains duplicate extensions")
        return frozenset(normalized)

    return Detection(
        skip_dirs=frozenset(list_field("skip_dirs")),
        source_extensions=extension_field("source_extensions"),
        config_extensions=extension_field("config_extensions"),
        manifests=list_field("manifests"),
        test_dirs=frozenset(list_field("test_dirs")),
        test_name_patterns=list_field("test_name_patterns"),
        doc_extensions=extension_field("doc_extensions"),
        lockfiles=frozenset(list_field("lockfiles")),
        skip_root_dirs=frozenset(list_field("skip_root_dirs")),
        compile_roots=list_field("compile_roots"),
        auto_select_extensions=extension_field("auto_select_extensions"),
    )


@cache
def load_patch_syntax(detection_file: Path = DETECTION_FILE) -> PatchSyntax:
    """Load profile-owned lexical hints for patch-local grounding."""
    data = load_detection_mapping(detection_file)
    return PatchSyntax(
        definition_patterns=_regex_field(data, detection_file, "patch_definition_patterns"),
        call_patterns=_regex_field(data, detection_file, "patch_call_patterns"),
        callable_assignment_patterns=_regex_field(data, detection_file, "patch_callable_assignment_patterns"),
    )


def _regex_field(data: Mapping, path: Path, key: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{path} field {key} must be a list of nonempty regex strings")
    try:
        for pattern in value:
            re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"{path} field {key} contains an invalid regex: {exc}") from exc
    return tuple(value)
