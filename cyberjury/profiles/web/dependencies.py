"""Validate package archive selection against the reviewed Web project."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import subprocess
import tomllib
import zipfile
from pathlib import Path

from cyberjury.review.dependencies import DependencyCatalog, DependencySource, DependencySourceError
from cyberjury.sources.npm import npm_members, npm_selection
from cyberjury.sources.packages import build_package_catalog

_MAX_PACKAGE_METADATA_BYTES = 100_000


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


def _pipfile_selection(source: DependencySource, selection: bytes, archive: bytes) -> None:
    parsed = _json_object(selection)
    packages = []
    for section in ("default", "develop"):
        entries = parsed.get(section)
        if not isinstance(entries, dict):
            continue
        packages.extend(value for key, value in entries.items() if key.casefold() == source.package.casefold())
    distinct = {json.dumps(entry, sort_keys=True, separators=(",", ":")) for entry in packages}
    if len(distinct) != 1:
        raise DependencySourceError("Python dependency has no unique lock entry")
    entry = packages[0]
    digest = hashlib.sha256(archive).hexdigest()
    hashes = entry.get("hashes") if isinstance(entry, dict) else None
    if (
        not isinstance(entry, dict)
        or entry.get("version") != f"=={source.version}"
        or not isinstance(hashes, list)
        or f"sha256:{digest}" not in hashes
    ):
        raise DependencySourceError("Python archive does not match the selected lock entry")
    _python_wheel_metadata(source, archive)


def _wheel_identity(opened: zipfile.ZipFile) -> tuple[str, str]:
    """Read one bounded distribution identity from a wheel."""
    entries = [
        info
        for info in opened.infolist()
        if info.filename.endswith(".dist-info/METADATA")
        and "/" not in info.filename.removesuffix(".dist-info/METADATA")
    ]
    if len(entries) != 1 or entries[0].is_dir() or entries[0].file_size > _MAX_PACKAGE_METADATA_BYTES:
        raise DependencySourceError("Python wheel has no unique bounded distribution metadata")
    try:
        with opened.open(entries[0]) as stream:
            raw = stream.read(_MAX_PACKAGE_METADATA_BYTES + 1)
        metadata = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError, RuntimeError) as exc:
        raise DependencySourceError(f"Python wheel metadata is unreadable: {exc}") from exc
    if len(raw) > _MAX_PACKAGE_METADATA_BYTES:
        raise DependencySourceError("Python wheel distribution metadata exceeds the size limit")
    attributes = dict(
        line.split(": ", 1)
        for line in metadata.splitlines()
        if line.startswith(("Name: ", "Version: ")) and ": " in line
    )
    return attributes.get("Name", ""), attributes.get("Version", "")


def _python_wheel_metadata(source: DependencySource, archive: bytes) -> None:
    """Require the selected artifact to identify the claimed distribution."""
    if not source.archive.name.endswith(".whl"):
        raise DependencySourceError("Python dependency must be an exact wheel archive")
    normalized = re.sub(r"[-_.]+", "-", source.package).casefold()
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        name, version = _wheel_identity(opened)
    if re.sub(r"[-_.]+", "-", name).casefold() != normalized or version != source.version:
        raise DependencySourceError("Python wheel metadata does not match the selected package")


def _uv_selection(source: DependencySource, selection: bytes, archive: bytes) -> None:
    """Accept only the exact wheel listed for one unambiguous locked version."""
    try:
        parsed = tomllib.loads(selection.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise DependencySourceError("Python dependency lock is not valid TOML") from exc
    packages = parsed.get("package")
    if not isinstance(packages, list):
        raise DependencySourceError("Python dependency lock has no package list")
    canonical = re.sub(r"[-_.]+", "-", source.package).casefold()
    matches = [
        item
        for item in packages
        if isinstance(item, dict) and re.sub(r"[-_.]+", "-", str(item.get("name", ""))).casefold() == canonical
    ]
    if len(matches) != 1 or matches[0].get("version") != source.version:
        raise DependencySourceError("Python dependency has no unique selected lock version")
    wheels = matches[0].get("wheels")
    if not isinstance(wheels, list) or not any(
        isinstance(item, dict) and item.get("hash") == f"sha256:{hashlib.sha256(archive).hexdigest()}"
        for item in wheels
    ):
        raise DependencySourceError("Python wheel does not match the selected lock entry")
    _python_wheel_metadata(source, archive)


def _go_module_selected(source: DependencySource, repository: Path) -> None:
    workspace = (repository / source.selection_file).parent
    if os.environ.get("GOWORK") not in {None, "", "off"}:
        raise DependencySourceError("Go workspace override prevents verified standalone module selection")
    for parent in (workspace, *workspace.parents):
        if not parent.is_relative_to(repository):
            break
        if (parent / "go.work").is_file():
            raise DependencySourceError("Go workspaces need their own verified source selection")
    environment = {
        **os.environ,
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOTOOLCHAIN": "local",
        "GOFLAGS": "-mod=readonly",
        "GOWORK": "off",
    }
    try:
        result = subprocess.run(
            ["go", "list", "-m", "-json", "all"],
            cwd=workspace,
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DependencySourceError(f"Go module selection could not be checked: {exc}") from exc
    if result.returncode:
        raise DependencySourceError("Go module selection could not be established offline")
    decoder = json.JSONDecoder()
    remaining = result.stdout.lstrip()
    found = []
    while remaining:
        try:
            module, offset = decoder.raw_decode(remaining)
        except json.JSONDecodeError as exc:
            raise DependencySourceError("Go module selection output is invalid") from exc
        if isinstance(module, dict) and module.get("Path") == source.package:
            found.append(module)
        remaining = remaining[offset:].lstrip()
    if len(found) != 1 or found[0].get("Version") != source.version or found[0].get("Replace") is not None:
        raise DependencySourceError("Go module archive is not the selected module version")


def _go_archive_hash(archive: bytes) -> str:
    digest = hashlib.sha256()
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as opened:
            names = opened.namelist()
            if len(names) != len(set(names)) or len(names) > 200_000:
                raise DependencySourceError("Go module archive has duplicate or excessive entries")
            total = 0
            for name in sorted(names):
                if "\n" in name:
                    raise DependencySourceError("Go module archive has an invalid filename")
                info = opened.getinfo(name)
                if info.is_dir():
                    continue
                total += info.file_size
                if total > 100_000_000:
                    raise DependencySourceError("Go module archive exceeds the content limit")
                content = opened.read(info)
                digest.update(f"{hashlib.sha256(content).hexdigest()}  {name}\n".encode())
    except (OSError, zipfile.BadZipFile, ValueError) as exc:
        raise DependencySourceError(f"Go module archive is unreadable: {exc}") from exc
    return "h1:" + base64.b64encode(digest.digest()).decode("ascii")


def _go_selection(source: DependencySource, selection: bytes, archive: bytes) -> None:
    try:
        lines = selection.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise DependencySourceError("Go module checksums are not UTF-8") from exc
    expected = (source.package, source.version, _go_archive_hash(archive))
    if not any(tuple(line.split()) == expected for line in lines):
        raise DependencySourceError("Go module archive does not match the selected checksum")


def read_locked_source(source: DependencySource, repository: str | Path) -> str:
    """Use ecosystem selection rules without putting them in the shared engine."""
    if source.ecosystem == "python" and Path(source.selection_file).name == "Pipfile.lock":

        def check(selection: bytes, archive: bytes) -> None:
            _pipfile_selection(source, selection, archive)

    elif source.ecosystem == "python" and Path(source.selection_file).name == "uv.lock":

        def check(selection: bytes, archive: bytes) -> None:
            _uv_selection(source, selection, archive)

    elif source.ecosystem in {"javascript", "typescript"} and Path(source.selection_file).name == "package-lock.json":

        def check(selection: bytes, archive: bytes) -> None:
            npm_selection(source, selection, archive)

    elif source.ecosystem == "go" and Path(source.selection_file).name == "go.sum":
        _go_module_selected(source, Path(repository).resolve())

        def check(selection: bytes, archive: bytes) -> None:
            _go_selection(source, selection, archive)

    else:
        raise DependencySourceError("dependency selection format is not supported by this profile")
    return source.read(repository, check_selection=check)


def _archive_members(archive: Path) -> tuple[str, str, str, tuple[str, ...]]:
    """Name only source members from a supported package archive."""
    if archive.suffix == ".whl":
        with zipfile.ZipFile(archive) as opened:
            names = opened.namelist()
            package, version = _wheel_identity(opened)
        ecosystem = "python"
        members = tuple(name for name in names if name.endswith((".py", ".pyi")))
    elif archive.name.endswith((".tgz", ".tar.gz")):
        package, version, names = npm_members(archive)
        ecosystem = "javascript"
        members = tuple(name for name in names if name.endswith((".js", ".jsx", ".ts", ".tsx")))
    elif archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as opened:
            names = opened.namelist()
        roots = set()
        for name in names:
            if "@" not in name:
                raise DependencySourceError("Go module archive has no versioned source root")
            prefix, suffix = name.rsplit("@", 1)
            version_root = suffix.split("/", 1)[0]
            roots.add(f"{prefix}@{version_root}")
        if len(roots) != 1:
            raise DependencySourceError("Go module archive has no unique module root")
        package, version = next(iter(roots)).rsplit("@", 1)
        ecosystem = "go"
        members = tuple(name for name in names if name.endswith(".go"))
    else:
        raise DependencySourceError("dependency archive format is unsupported")
    if not isinstance(package, str) or not package or not isinstance(version, str) or not version:
        raise DependencySourceError("dependency archive has incomplete package identity")
    if len(members) > 4_000:
        raise DependencySourceError("dependency archive has too many source members")
    return ecosystem, package, version, members


def catalog_from_archives(repository: str | Path, directory: str | Path) -> DependencyCatalog | None:
    """Index local locked archives without importing or executing dependencies."""
    from cyberjury.detection import load_detection
    from cyberjury.profiles.base import content_paths

    def selection_names(ecosystem: str) -> frozenset[str]:
        return {
            "python": frozenset({"Pipfile.lock", "uv.lock"}),
            "javascript": frozenset({"package-lock.json"}),
            "go": frozenset({"go.sum"}),
        }[ecosystem]

    return build_package_catalog(
        repository,
        directory,
        detection=load_detection(content_paths(Path(__file__).parent).detection_file),
        lock_names=frozenset({"Pipfile.lock", "uv.lock", "package-lock.json", "go.sum"}),
        suffixes=(".whl", ".tgz", ".tar.gz", ".zip"),
        archive_members=_archive_members,
        selection_names=selection_names,
        read_source=read_locked_source,
    )
