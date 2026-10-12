"""Acquire exact npm package members selected by a project lock."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

from cyberjury.review.dependencies import DependencySource, DependencySourceError


def _json_object(raw: bytes) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise DependencySourceError(f"dependency selection repeats JSON key {key!r}")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DependencySourceError("dependency selection is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise DependencySourceError("dependency selection must be a JSON object")
    return parsed


def npm_members(archive: Path) -> tuple[str, str, tuple[str, ...]]:
    """Index one package without extracting it into the reviewed tree."""
    try:
        with tarfile.open(archive, "r:*") as opened:
            info = opened.getmember("package/package.json")
            if not info.isfile() or info.size > 100_000:
                raise DependencySourceError("JavaScript archive metadata must be a bounded regular file")
            stream = opened.extractfile(info)
            if stream is None:
                raise DependencySourceError("JavaScript package archive has no readable metadata")
            with stream:
                package = _json_object(stream.read(100_001))
            names = tuple(item.name for item in opened.getmembers() if item.isfile())
    except (OSError, KeyError, tarfile.TarError) as exc:
        raise DependencySourceError(f"JavaScript package archive is unreadable: {exc}") from exc
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise DependencySourceError("JavaScript package metadata has no identity")
    return name, version, names


def npm_selection(source: DependencySource, selection: bytes, archive: bytes) -> None:
    """Require the exact package and strong artifact integrity in package-lock.json."""
    parsed = _json_object(selection)
    packages = parsed.get("packages")
    entry = packages.get(f"node_modules/{source.package}") if isinstance(packages, dict) else None
    if not isinstance(entry, dict) or entry.get("version") != source.version:
        raise DependencySourceError("JavaScript package has no unique selected lock entry")
    integrity = entry.get("integrity")
    if not isinstance(integrity, str):
        raise DependencySourceError("JavaScript package lock has no artifact integrity")
    digests = {
        f"{algorithm}-{base64.b64encode(hashlib.new(algorithm, archive).digest()).decode('ascii')}"
        for algorithm in ("sha256", "sha384", "sha512")
    }
    if not digests.intersection(integrity.split()):
        raise DependencySourceError("JavaScript archive does not match the selected lock entry")
    if not source.archive.name.endswith((".tgz", ".tar.gz")):
        raise DependencySourceError("JavaScript dependency must be a locked package archive")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as opened:
        info = opened.getmember("package/package.json")
        if not info.isfile() or info.size > 100_000:
            raise DependencySourceError("JavaScript archive metadata must be a bounded regular file")
        stream = opened.extractfile(info)
        if stream is None:
            raise DependencySourceError("JavaScript archive has no package metadata")
        with stream:
            package = _json_object(stream.read(100_001))
    if package.get("name") != source.package or package.get("version") != source.version:
        raise DependencySourceError("JavaScript archive metadata does not match the selected package")
