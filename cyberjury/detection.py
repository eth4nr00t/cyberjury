"""File and path classification config, loaded from `detection.yaml`.

What the engine treats as a source file, a dependency manifest, a noise directory, or
test code, across ecosystems. Kept in data so the implementation enumerates no language
itself: adding a language is a data edit, not a code change. This is distinct from a
guide's stack detection in `guides.py`, which decides which language, framework, or
protocol applies.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

from cyberjury.resources import DETECTION_FILE


@dataclass(frozen=True)
class Detection:
    """File classification rules loaded from one domain detection config."""

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
        """True when a path is test code, by a test directory segment or a test-file naming.

        convention. Conservative, so a production file is not suppressed.
        """
        parts = path.replace("\\", "/").split("/")
        if any(p in self.test_dirs for p in parts[:-1]):
            return True
        name = parts[-1].lower()
        return any(fnmatch.fnmatch(name, pat) for pat in self.test_name_patterns)

    def is_noise_path(self, path: str) -> bool:
        """True when a path cannot hold an exploitable code change and should not be sent to a.

        reviewer: a noise or vendored directory, test code, a documentation file, or a generated
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
def load_detection(detection_file: Path = DETECTION_FILE) -> Detection:
    """Load the file classification config.

    cached per file so each domain's `detection.yaml` is read and cached independently.
    Defaults to the web domain.
    """
    data = yaml.safe_load(Path(detection_file).read_text(encoding="utf-8")) or {}
    return Detection(
        skip_dirs=frozenset(data.get("skip_dirs", [])),
        source_extensions=frozenset(data.get("source_extensions", [])),
        config_extensions=frozenset(data.get("config_extensions", [])),
        manifests=tuple(data.get("manifests", [])),
        test_dirs=frozenset(data.get("test_dirs", [])),
        test_name_patterns=tuple(data.get("test_name_patterns", [])),
        doc_extensions=frozenset(data.get("doc_extensions", [])),
        lockfiles=frozenset(data.get("lockfiles", [])),
        skip_root_dirs=frozenset(data.get("skip_root_dirs", [])),
        compile_roots=tuple(data.get("compile_roots", [])),
    )
