"""Classify noise and known parser inputs without limiting review to known languages."""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import yaml

_REQUIRED_KEYS = frozenset(
    {
        "skip_dirs",
        "source_extensions",
        "test_dirs",
        "test_name_patterns",
        "doc_extensions",
        "lockfiles",
    }
)
_OPTIONAL_KEYS = frozenset({"asset_extensions"})
_ALLOWED_KEYS = _REQUIRED_KEYS | _OPTIONAL_KEYS


@dataclass(frozen=True)
class Detection:
    """File classification rules loaded from one profile detection config."""

    skip_dirs: frozenset[str]
    source_extensions: frozenset[str]
    test_dirs: frozenset[str]
    test_name_patterns: tuple[str, ...]
    doc_extensions: frozenset[str]
    lockfiles: frozenset[str]
    asset_extensions: frozenset[str] = frozenset()

    def is_skipped_dir(self, dir_parts: Sequence[str]) -> bool:
        """True when any of a path's directory segments names a skipped directory."""
        return any(p in self.skip_dirs for p in dir_parts)

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
        migration, a shell script, or a Dockerfile is kept.
        """
        parts = path.replace("\\", "/").split("/")
        if self.is_skipped_dir(parts[:-1]):
            return True
        if self.is_test_path(path):
            return True
        name = parts[-1]
        if name in self.lockfiles:
            return True
        return Path(name).suffix.lower() in self.doc_extensions | self.asset_extensions


def load_detection_mapping(detection_file: Path) -> Mapping[str, tuple[str, ...]]:
    """Load one profile detection mapping and fail loud on unknown, missing, or non-list fields."""
    data = yaml.safe_load(Path(detection_file).read_text(encoding="utf-8")) or {}
    if not isinstance(data, Mapping):
        raise ValueError(f"{detection_file} must contain a mapping")
    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        raise ValueError(f"{detection_file} contains unknown detection keys: {', '.join(unknown)}")
    missing = sorted(_REQUIRED_KEYS - set(data))
    if missing:
        raise ValueError(f"{detection_file} is missing required detection keys: {', '.join(missing)}")
    for key, value in data.items():
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise ValueError(f"{detection_file} field {key} must be a list of nonempty strings")
    return MappingProxyType({key: tuple(value) for key, value in data.items()})


def load_detection(detection_file: Path) -> Detection:
    """Load file and patch classification for one profile."""
    data = load_detection_mapping(detection_file)

    def extension_field(key: str) -> frozenset[str]:
        normalized = tuple(value.lower() for value in data.get(key, ()))
        if any(not value.startswith(".") or value == "." or "/" in value or "\\" in value for value in normalized):
            raise ValueError(f"{detection_file} field {key} must contain file extensions beginning with a dot")
        return frozenset(normalized)

    return Detection(
        skip_dirs=frozenset(data["skip_dirs"]),
        source_extensions=extension_field("source_extensions"),
        test_dirs=frozenset(data["test_dirs"]),
        test_name_patterns=data["test_name_patterns"],
        doc_extensions=extension_field("doc_extensions"),
        lockfiles=frozenset(data["lockfiles"]),
        asset_extensions=extension_field("asset_extensions"),
    )
