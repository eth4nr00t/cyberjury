"""Classify noise files without limiting review to known languages."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from functools import cache
from pathlib import Path, PurePosixPath

import yaml

from cyberjury.review.contract import DETECTION_FILE
from cyberjury.review.languages import load_languages

MAX_SOURCE_BYTES = 400_000
_ATTRIBUTES = ("linguist-vendored", "linguist-documentation")


@dataclass(frozen=True)
class Detection:
    """File classification rules loaded from the review contract.

    A source tree's `.gitattributes` declarations of linguist-vendored and linguist-documentation
    override the contract defaults for the paths they match.
    """

    ignored_dirs: frozenset[str]
    dependency_dirs: frozenset[str]
    test_dirs: frozenset[str]
    test_name_patterns: tuple[str, ...]
    doc_extensions: frozenset[str]
    asset_extensions: frozenset[str]
    lockfiles: frozenset[str]
    attribute_rules: tuple[tuple[re.Pattern[str], str, bool], ...] = ()
    oversized_files: frozenset[str] = frozenset()

    def is_ignored(self, path: str) -> bool:
        """Return whether a path lies in a directory that holds no project source."""
        return any(part in self.ignored_dirs for part in PurePosixPath(path).parts[:-1])

    def is_dependency(self, path: str) -> bool:
        """Return whether a path is third-party code, declared linguist-vendored or under a dependency directory."""
        declared = self._declared(path, "linguist-vendored")
        if declared is not None:
            return declared
        return any(part in self.dependency_dirs for part in PurePosixPath(path).parts[:-1])

    def is_documentation(self, path: str) -> bool:
        """Return whether a path is documentation, declared linguist-documentation or by its extension."""
        declared = self._declared(path, "linguist-documentation")
        if declared is not None:
            return declared
        return PurePosixPath(path).suffix.lower() in self.doc_extensions

    def is_test_path(self, path: str) -> bool:
        """Return whether a path matches a test directory or file naming convention."""
        parts = path.replace("\\", "/").split("/")
        if any(p in self.test_dirs for p in parts[:-1]):
            return True
        name = parts[-1].lower()
        return any(fnmatch.fnmatch(name, pat) for pat in self.test_name_patterns)

    def is_noise_path(self, path: str) -> bool:
        """Return whether a path is excluded from security review.

        Excluded paths cover ignored directories, third-party code, test code, documentation,
        assets, and dependency lockfiles. This is a denylist of files known to carry no project
        logic, not an allowlist of parsed languages, so a security-relevant non-source file such as
        a `.sql` migration, a shell script, or a Dockerfile is kept.
        """
        path = path.replace("\\", "/")
        name = PurePosixPath(path).name
        return (
            self.is_ignored(path)
            or self.is_dependency(path)
            or self.is_test_path(path)
            or self.is_documentation(path)
            or name in self.lockfiles
            or PurePosixPath(name).suffix.lower() in self.asset_extensions
        )

    def _declared(self, path: str, attribute: str) -> bool | None:
        declared = None
        for pattern, name, value in self.attribute_rules:
            if name == attribute and pattern.fullmatch(path):
                declared = value
        return declared


@cache
def load_detection() -> Detection:
    """Load the language-neutral classification rules joined with every language's file conventions."""
    data = yaml.safe_load(DETECTION_FILE.read_text(encoding="utf-8"))
    languages = load_languages().values()

    def joined(key: str) -> tuple[str, ...]:
        values = [*data.get(key, ()), *(value for language in languages for value in language.files.get(key, ()))]
        return tuple(sorted(set(values)))

    return Detection(
        ignored_dirs=frozenset(joined("ignored_dirs")),
        dependency_dirs=frozenset(joined("dependency_dirs")),
        test_dirs=frozenset(joined("test_dirs")),
        test_name_patterns=joined("test_name_patterns"),
        doc_extensions=frozenset(data["doc_extensions"]),
        asset_extensions=frozenset(data["asset_extensions"]),
        lockfiles=frozenset(joined("lockfiles")),
    )


def detection_for(root: str | Path, files: Sequence[str]) -> Detection:
    """Load file classification for one source tree.

    The tree adds the linguist-vendored and linguist-documentation rules of its `.gitattributes`
    files and the files larger than the review file size limit.
    """
    detection = load_detection()
    oversized = frozenset(file for file in files if (Path(root) / file).stat().st_size > MAX_SOURCE_BYTES)
    rules: list[tuple[re.Pattern[str], str, bool]] = []
    attribute_files = [file for file in files if PurePosixPath(file).name == ".gitattributes"]
    for file in sorted(attribute_files, key=lambda item: (len(PurePosixPath(item).parts), item)):
        directory = PurePosixPath(file).parent.as_posix()
        prefix = "" if directory == "." else re.escape(directory + "/")
        text = (Path(root) / file).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            fields = line.split()
            if not fields or fields[0].startswith(("#", "!", '"')) or fields[0].endswith("/"):
                continue
            pattern = fields[0]
            anchor = "" if "/" in pattern.lstrip("/") else "(?:.*/)?"
            compiled = re.compile(prefix + anchor + _glob_regex(pattern.lstrip("/")))
            for attribute in _ATTRIBUTES:
                value = _attribute_value(fields[1:], attribute)
                if value is not None:
                    rules.append((compiled, attribute, value))
    return replace(detection, attribute_rules=tuple(rules), oversized_files=oversized)


def _attribute_value(attributes: Sequence[str], name: str) -> bool | None:
    value = None
    for attribute in attributes:
        if attribute in (name, f"{name}=true"):
            value = True
        elif attribute.lstrip("-!").split("=", 1)[0] == name:
            value = False
    return value


def _glob_regex(pattern: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        at_segment = i == 0 or pattern[i - 1] == "/"
        if at_segment and pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif at_segment and pattern.startswith("**", i) and i + 2 == len(pattern):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        elif pattern[i] == "[" and (end := pattern.find("]", i + 2)) != -1:
            body = pattern[i + 1 : end]
            body = "^" + body[1:] if body.startswith("!") else body
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = end + 1
        elif pattern[i] == "\\" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)
