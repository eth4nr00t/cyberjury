"""Classify noise files without limiting review to known languages."""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

from cyberjury.review.contract import DETECTION_FILE


@dataclass(frozen=True)
class Detection:
    """File classification rules loaded from the review contract."""

    skip_dirs: frozenset[str]
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
        dependency lockfile. This is a denylist of files known to carry no logic, not an
        allowlist of parsed languages, so a security-relevant non-source file such as a `.sql`
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


@cache
def load_detection() -> Detection:
    """Load file classification once."""
    data = yaml.safe_load(DETECTION_FILE.read_text(encoding="utf-8"))
    return Detection(
        skip_dirs=frozenset(data["skip_dirs"]),
        test_dirs=frozenset(data["test_dirs"]),
        test_name_patterns=tuple(data["test_name_patterns"]),
        doc_extensions=frozenset(data["doc_extensions"]),
        lockfiles=frozenset(data["lockfiles"]),
        asset_extensions=frozenset(data["asset_extensions"]),
    )
