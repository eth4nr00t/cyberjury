"""Resolve syntax relationships to repository paths and definition endpoints."""

from __future__ import annotations

import configparser
import json
import posixpath
import re
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Protocol

from json_repair import loads as repair_json

from cyberjury.profiles.base import content_paths
from cyberjury.profiles.web.facts.analyzer import (
    AnalyzableSource,
    AnalyzedDefinition,
    AnalyzedOwner,
    AnalyzedRepository,
    LangSpec,
    spec_for,
)
from cyberjury.review.definitions import CallCandidate, DefinitionFragment, StructuralCandidate, StructuralGap
from cyberjury.review.facts import FactLimitation

if TYPE_CHECKING:
    from cyberjury.detection import Detection

_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file
_JAVASCRIPT_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

type DefinitionKey = tuple[str, int, int]


class _ScopedDeclaration(Protocol):
    @property
    def scope(self) -> str: ...


@dataclass(frozen=True, kw_only=True)
class ModuleResolution:
    """Classify one specifier against the repository module boundary."""

    targets: tuple[str, ...] = ()
    in_scope: bool = False


@dataclass(frozen=True, kw_only=True)
class ModuleAlias:
    """Map one declared JavaScript module pattern into a repository path."""

    pattern: str
    targets: tuple[str, ...]
    base: str = ""
    scope: str = ""


@dataclass(frozen=True, kw_only=True)
class WorkspacePackage:
    """Map one declared JavaScript package name to its source directory."""

    name: str
    root: str
    entries: tuple[str, ...] = ()
    scope: str = ""


@dataclass(frozen=True, kw_only=True)
class GoModule:
    """Map one declared Go module prefix to a repository directory."""

    name: str
    root: str
    scope: str = ""


@dataclass(frozen=True, kw_only=True)
class PythonModule:
    """Map one Python module name within its owning project scope."""

    name: str
    file: str
    scope: str = ""


@dataclass(frozen=True, kw_only=True)
class RepositoryModuleIndex:
    """Index repository modules through language declarations rather than basenames."""

    python: tuple[PythonModule, ...]
    javascript_packages: tuple[WorkspacePackage, ...] = ()
    javascript_aliases: tuple[ModuleAlias, ...] = ()
    go_modules: tuple[GoModule, ...] = ()
    limitations: tuple[FactLimitation, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ResolvedRepository:
    """Repository relationships resolved from syntax analyzer output."""

    imports: dict[str, list[str]]
    references: dict[str, list[str]]
    import_targets: dict[str, list[str]]
    call_candidates: tuple[CallCandidate, ...]
    structural_candidates: tuple[StructuralCandidate, ...]
    structural_gaps: tuple[StructuralGap, ...]
    limitations: tuple[FactLimitation, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ResolvedImport:
    """Bind one local name to a remote name in exact repository files."""

    imported: str
    local: str
    targets: tuple[str, ...]
    reexport: bool = False
    owner: AnalyzedOwner | None = None
    start: int = 0


@dataclass(frozen=True, kw_only=True)
class ResolvedReference:
    """Bind one qualified source name to exact repository files."""

    source_file: str
    reference: str
    target_name: str
    targets: tuple[str, ...]


def load_profile_detection() -> Detection:
    """Load the Web profile rules used while resolving review scope."""
    from cyberjury.detection import load_detection

    return load_detection(_DETECTION_FILE)


def reviewable_sources(
    base: Path,
    detection: Detection,
    specs: dict[str, LangSpec],
) -> list[AnalyzableSource]:
    """Resolve repository files that belong to the analyzer input."""
    sources: list[AnalyzableSource] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        try:
            if not path.resolve().is_relative_to(base):
                continue
        except OSError:
            continue
        rel = path.relative_to(base).as_posix()
        if detection.is_skipped_dir(Path(rel).parts[:-1]) or detection.is_test_path(rel):
            continue
        spec = spec_for(specs, rel)
        if spec is not None:
            sources.append((path, rel, spec))
    return sources


def build_module_index(
    base: Path,
    known: set[str],
    detection: Detection,
) -> RepositoryModuleIndex:
    """Build language module identities from repository structure and declarations."""
    python, python_limitations = _python_modules(base, known, detection)
    packages, package_limitations = _javascript_packages(base, known, detection)
    aliases, alias_limitations = _javascript_aliases(base, known, detection)
    go_modules, go_limitations = _go_modules(base, known, detection)
    return RepositoryModuleIndex(
        python=python,
        javascript_packages=packages,
        javascript_aliases=aliases,
        go_modules=go_modules,
        limitations=tuple(
            dict.fromkeys((*python_limitations, *package_limitations, *alias_limitations, *go_limitations))
        ),
    )


def _python_modules(
    base: Path,
    known: set[str],
    detection: Detection,
) -> tuple[tuple[PythonModule, ...], tuple[FactLimitation, ...]]:
    roots, limitations = _python_source_roots(base, known, detection)
    modules: list[PythonModule] = []
    for rel in sorted(path for path in known if path.endswith(".py")):
        identity = _python_module_name(rel)
        if identity:
            modules.append(PythonModule(name=identity, file=rel))
        for root, scope in roots:
            if root and _is_below(rel, root):
                identity = _python_module_name(str(PurePosixPath(rel).relative_to(root)))
                if identity:
                    modules.append(PythonModule(name=identity, file=rel, scope=scope))
    return tuple(dict.fromkeys(modules)), limitations


def _python_module_name(rel: str) -> str:
    path = PurePosixPath(rel)
    parts = list(path.parts)
    if not parts:
        return ""
    filename = parts.pop()
    stem = filename.removesuffix(".py")
    if stem != "__init__":
        parts.append(stem)
    return ".".join(parts)


def _python_source_roots(
    base: Path,
    known: set[str],
    detection: Detection,
) -> tuple[tuple[tuple[str, str], ...], tuple[FactLimitation, ...]]:
    roots: list[tuple[str, str]] = []
    limitations: list[FactLimitation] = []
    for config in _repository_files(base, "pyproject.toml", detection):
        try:
            data = tomllib.loads(config.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            if _has_sources(known, _relative_parent(base, config), (".py",)):
                limitations.append(_configuration_limitation(base, config, "could not read Python module declarations"))
            continue
        relative_parent = _relative_parent(base, config)
        tool = data.get("tool") if isinstance(data, dict) else None
        tool = tool if isinstance(tool, dict) else {}
        setuptools = tool.get("setuptools")
        setuptools = setuptools if isinstance(setuptools, dict) else {}
        package_dir = setuptools.get("package-dir")
        if isinstance(package_dir, dict):
            roots.append((_join_relative(relative_parent, package_dir.get("", "")), relative_parent))
        packages_find = setuptools.get("packages")
        packages_find = packages_find if isinstance(packages_find, dict) else {}
        find = packages_find.get("find")
        find = find if isinstance(find, dict) else {}
        where = find.get("where")
        if isinstance(where, list):
            roots.extend((_join_relative(relative_parent, value), relative_parent) for value in where)
        hatch = tool.get("hatch")
        hatch = hatch if isinstance(hatch, dict) else {}
        build = hatch.get("build")
        build = build if isinstance(build, dict) else {}
        targets = build.get("targets")
        targets = targets if isinstance(targets, dict) else {}
        wheel = targets.get("wheel")
        wheel = wheel if isinstance(wheel, dict) else {}
        packages = wheel.get("packages")
        if isinstance(packages, list):
            roots.extend((_package_parent(relative_parent, value), relative_parent) for value in packages)
        poetry = tool.get("poetry")
        poetry = poetry if isinstance(poetry, dict) else {}
        poetry_packages = poetry.get("packages")
        if isinstance(poetry_packages, list):
            roots.extend(
                (_join_relative(relative_parent, entry.get("from", "")), relative_parent)
                for entry in poetry_packages
                if isinstance(entry, dict)
            )
    for config in _repository_files(base, "setup.cfg", detection):
        parser = configparser.ConfigParser()
        try:
            parser.read(config, encoding="utf-8")
        except (OSError, UnicodeError, configparser.Error):
            if _has_sources(known, _relative_parent(base, config), (".py",)):
                limitations.append(_configuration_limitation(base, config, "could not read Python module declarations"))
            continue
        relative_parent = _relative_parent(base, config)
        if parser.has_option("options", "package_dir"):
            for line in parser.get("options", "package_dir").splitlines():
                _name, separator, value = line.partition("=")
                if separator and value.strip():
                    roots.append((_join_relative(relative_parent, value.strip()), relative_parent))
        if parser.has_option("options.packages.find", "where"):
            values = re.split(r"[\s,]+", parser.get("options.packages.find", "where"))
            roots.extend((_join_relative(relative_parent, value), relative_parent) for value in values if value)
    return (
        tuple(dict.fromkeys((root.strip("/"), scope) for root, scope in roots if root and root != ".")),
        tuple(limitations),
    )


def _javascript_packages(
    base: Path,
    known: set[str],
    detection: Detection,
) -> tuple[tuple[WorkspacePackage, ...], tuple[FactLimitation, ...]]:
    manifests: list[tuple[str, dict[str, object]]] = []
    limitations: list[FactLimitation] = []
    for manifest in _repository_files(base, "package.json", detection):
        data, limitation = _read_mapping_configuration(
            base,
            manifest,
            known,
            extensions=_JAVASCRIPT_EXTENSIONS,
            read_reason="could not read JavaScript package declarations",
            shape_reason="JavaScript package declarations are not an object",
        )
        if limitation is not None:
            limitations.append(limitation)
        if data is not None:
            manifests.append((_relative_parent(base, manifest), data))

    packages = list(_self_packages(manifests, known))
    packages.extend(_workspace_packages(manifests))
    return tuple(dict.fromkeys(packages)), tuple(limitations)


def _self_packages(
    manifests: list[tuple[str, dict[str, object]]],
    known: set[str],
) -> tuple[WorkspacePackage, ...]:
    packages: list[WorkspacePackage] = []
    for root, data in manifests:
        name = data.get("name")
        if not isinstance(name, str) or not name:
            continue
        if not any(_is_below(rel, root) for rel in known):
            continue
        packages.append(
            WorkspacePackage(
                name=name,
                root=root,
                entries=_javascript_entries(data),
                scope=root,
            )
        )
    return tuple(packages)


def _workspace_packages(manifests: list[tuple[str, dict[str, object]]]) -> tuple[WorkspacePackage, ...]:
    packages: list[WorkspacePackage] = []
    for workspace_root, workspace in manifests:
        patterns = _workspace_patterns(workspace)
        if not patterns:
            continue
        for package_root, package in manifests:
            if package_root == workspace_root or not _workspace_member(workspace_root, package_root, patterns):
                continue
            name = package.get("name")
            if not isinstance(name, str) or not name:
                continue
            packages.append(
                WorkspacePackage(
                    name=name,
                    root=package_root,
                    entries=_javascript_entries(package),
                    scope=workspace_root,
                )
            )
    return tuple(packages)


def _javascript_entries(data: dict[str, object]) -> tuple[str, ...]:
    return tuple(
        value
        for key in ("source", "module", "main", "types", "typings")
        if isinstance((value := data.get(key)), str) and value
    )


def _workspace_patterns(data: dict[str, object]) -> tuple[str, ...]:
    workspaces = data.get("workspaces")
    if isinstance(workspaces, dict):
        workspaces = workspaces.get("packages")
    if not isinstance(workspaces, list):
        return ()
    return tuple(pattern.rstrip("/") for pattern in workspaces if isinstance(pattern, str) and pattern)


def _workspace_member(root: str, package: str, patterns: tuple[str, ...]) -> bool:
    if root and not _is_below(package, root):
        return False
    relative = package[len(root) :].lstrip("/") if root else package
    return any(fnmatchcase(relative, pattern) for pattern in patterns)


def _javascript_aliases(
    base: Path,
    known: set[str],
    detection: Detection,
) -> tuple[tuple[ModuleAlias, ...], tuple[FactLimitation, ...]]:
    aliases: list[ModuleAlias] = []
    limitations: list[FactLimitation] = []
    for name in ("tsconfig.json", "jsconfig.json"):
        for config in _repository_files(base, name, detection):
            data, limitation = _read_mapping_configuration(
                base,
                config,
                known,
                extensions=_JAVASCRIPT_EXTENSIONS,
                read_reason="could not read JavaScript path declarations",
                shape_reason="JavaScript path declarations are not an object",
                repair=True,
            )
            if limitation is not None:
                limitations.append(limitation)
            if data is not None:
                aliases.extend(_aliases_from_configuration(base, config, data))
    return tuple(dict.fromkeys(aliases)), tuple(limitations)


def _aliases_from_configuration(base: Path, config: Path, data: dict[str, object]) -> tuple[ModuleAlias, ...]:
    compiler = data.get("compilerOptions")
    if not isinstance(compiler, dict):
        return ()
    parent = _relative_parent(base, config)
    raw_base = compiler.get("baseUrl", ".")
    alias_base = _join_relative(parent, raw_base) if isinstance(raw_base, str) else parent
    aliases: list[ModuleAlias] = []
    paths = compiler.get("paths")
    if isinstance(paths, dict):
        for pattern, raw_targets in paths.items():
            if not isinstance(pattern, str) or not isinstance(raw_targets, list):
                continue
            targets = tuple(value for value in raw_targets if isinstance(value, str) and value)
            if targets:
                aliases.append(ModuleAlias(pattern=pattern, targets=targets, base=alias_base, scope=parent))
    if "baseUrl" in compiler and isinstance(raw_base, str):
        aliases.append(ModuleAlias(pattern="*", targets=("*",), base=alias_base, scope=parent))
    return tuple(aliases)


def _go_modules(
    base: Path,
    known: set[str],
    detection: Detection,
) -> tuple[tuple[GoModule, ...], tuple[FactLimitation, ...]]:
    modules: list[GoModule] = []
    limitations: list[FactLimitation] = []
    for manifest in _repository_files(base, "go.mod", detection):
        try:
            text = manifest.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            if _has_sources(known, _relative_parent(base, manifest), (".go",)):
                limitations.append(_configuration_limitation(base, manifest, "could not read Go module declarations"))
            continue
        root = _relative_parent(base, manifest)
        name = next(
            (match.group(1) for line in text.splitlines() if (match := re.match(r"\s*module\s+(\S+)", line))),
            "",
        )
        if name:
            modules.append(GoModule(name=name, root=root, scope=root))
        elif _has_sources(known, root, (".go",)):
            limitations.append(_configuration_limitation(base, manifest, "Go module declaration is missing"))
        for line in text.splitlines():
            match = re.match(r"\s*replace\s+(\S+)(?:\s+\S+)?\s*=>\s*(\.\.?/\S+)", line)
            if match:
                modules.append(GoModule(name=match.group(1), root=_join_relative(root, match.group(2)), scope=root))
    return tuple(dict.fromkeys(modules)), tuple(limitations)


def _repository_files(base: Path, name: str, detection: Detection | None = None) -> tuple[Path, ...]:
    files = []
    for path in base.rglob(name):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        if detection is not None and (detection.is_skipped_dir(Path(rel).parts[:-1]) or detection.is_test_path(rel)):
            continue
        try:
            if not path.resolve().is_relative_to(base):
                continue
        except OSError:
            continue
        files.append(path)
    return tuple(sorted(files))


def _read_json(path: Path, *, repair: bool = False) -> object:
    text = path.read_text(encoding="utf-8")
    return repair_json(text) if repair else json.loads(text)


def _read_mapping_configuration(
    base: Path,
    path: Path,
    known: set[str],
    *,
    extensions: tuple[str, ...],
    read_reason: str,
    shape_reason: str,
    repair: bool = False,
) -> tuple[dict[str, object] | None, FactLimitation | None]:
    root = _relative_parent(base, path)
    try:
        data = _read_json(path, repair=repair)
    except (OSError, UnicodeError, ValueError):
        limitation = (
            _configuration_limitation(base, path, read_reason) if _has_sources(known, root, extensions) else None
        )
        return None, limitation
    if not isinstance(data, dict):
        limitation = (
            _configuration_limitation(base, path, shape_reason) if _has_sources(known, root, extensions) else None
        )
        return None, limitation
    return data, None


def _configuration_limitation(base: Path, path: Path, reason: str) -> FactLimitation:
    return FactLimitation(
        source=path.relative_to(base).as_posix(),
        analyzer="web-resolver",
        reason=reason,
    )


def _has_sources(known: set[str], root: str, extensions: tuple[str, ...]) -> bool:
    return any(_is_below(source, root) and source.endswith(extensions) for source in known)


def _relative_parent(base: Path, path: Path) -> str:
    parent = path.parent.relative_to(base).as_posix()
    return "" if parent == "." else parent


def _join_relative(parent: str, child: object) -> str:
    if not isinstance(child, str):
        return ""
    return posixpath.normpath(posixpath.join(parent, child)).removeprefix("./")


def _package_parent(parent: str, package: object) -> str:
    if not isinstance(package, str) or not package:
        return ""
    path = PurePosixPath(package)
    return _join_relative(parent, str(path.parent)) if len(path.parts) > 1 else parent


def _is_below(rel: str, root: str) -> bool:
    return not root or rel == root or rel.startswith(f"{root}/")


def scope_prefixes(base: Path) -> tuple[str, ...]:
    """Return package prefixes bounded by the repository root."""
    parts: list[str] = []
    for directory in (base, *base.parents):
        if (directory / ".git").exists():
            break
        if directory.parent == directory:
            return ()
        parts.append(directory.name)
    return tuple("/".join(reversed(parts[:index])) for index in range(len(parts), 0, -1))


def _resolve_exact(
    source: str,
    specifier: str,
    known: set[str],
    specs: tuple[LangSpec, ...],
    scope_names: tuple[str, ...] = (),
) -> str | None:
    base = _import_base(source, specifier)
    if base is None:
        return None
    for candidate_base in (base, *_alias_bases(base, scope_names)):
        for candidate in _source_candidates(candidate_base, specs):
            if candidate in known:
                return candidate
    return None


def _import_base(source: str, specifier: str) -> str | None:
    parent = str(PurePosixPath(source).parent)
    specifier = specifier.strip().strip("\"'")
    if not specifier:
        return None
    if specifier.startswith("."):
        if "/" in specifier or specifier.startswith("./") or specifier.startswith("../"):
            base = posixpath.join(parent, specifier)
        else:
            up = len(specifier) - len(specifier.lstrip("."))
            tail = specifier.lstrip(".").replace(".", "/")
            base = posixpath.join(parent, *[".."] * (up - 1), tail)
    else:
        base = specifier.replace(".", "/") if "/" not in specifier else specifier
    base = posixpath.normpath(base).removeprefix("./")
    return base


def _alias_bases(base: str, scope_names: tuple[str, ...]) -> tuple[str, ...]:
    aliases: list[str] = []
    for prefix in scope_names:
        if base == prefix or base.startswith(f"{prefix}/"):
            inner = base[len(prefix) :].lstrip("/")
            if inner:
                aliases.append(inner)
    return tuple(dict.fromkeys(aliases))


def _source_candidates(base: str, specs: tuple[LangSpec, ...]) -> tuple[str, ...]:
    extensions = _extensions(specs)
    stem = base
    for extension in extensions:
        if stem.endswith(extension):
            stem = stem[: -len(extension)]
            break
    return tuple(
        dict.fromkeys(
            (
                base,
                *(f"{stem}{extension}" for extension in extensions),
                *(str(PurePosixPath(stem) / entry) for entry in _module_entries(specs)),
            )
        )
    )


def resolve_specifiers(
    source: str,
    specifier: str,
    known: set[str],
    specs: tuple[LangSpec, ...],
    scope_names: tuple[str, ...] = (),
    modules: RepositoryModuleIndex | None = None,
) -> tuple[str, ...]:
    """Resolve repository files through declared language module identities."""
    return resolve_module(
        source,
        specifier,
        known,
        specs,
        scope_names,
        modules=modules,
    ).targets


def resolve_module(
    source: str,
    specifier: str,
    known: set[str],
    specs: tuple[LangSpec, ...],
    scope_names: tuple[str, ...] = (),
    *,
    modules: RepositoryModuleIndex | None = None,
) -> ModuleResolution:
    """Classify a module specifier without promoting basename guesses to facts."""
    compatible_specs = _compatible_specs(source, specs)
    cleaned = specifier.strip().strip("\"'")
    if not cleaned:
        return ModuleResolution()
    if cleaned.startswith("."):
        base = _import_base(source, cleaned)
        if base is None or base == ".." or base.startswith("../"):
            return ModuleResolution()
        exact = _resolve_exact(source, cleaned, known, compatible_specs)
        return ModuleResolution(targets=(exact,) if exact is not None else (), in_scope=True)
    source_spec = spec_for({spec.name: spec for spec in specs}, source)
    if source_spec is None:
        return ModuleResolution()
    index = modules or _path_module_index(known)
    if source_spec.name == "python":
        return _resolve_python_module(source, cleaned, known, compatible_specs, scope_names, index)
    if source_spec.name in {"javascript", "typescript", "tsx"}:
        return _resolve_javascript_module(source, cleaned, known, compatible_specs, index)
    if source_spec.name == "go":
        return _resolve_go_module(source, cleaned, known, index)
    exact = _resolve_exact(source, cleaned, known, compatible_specs, scope_names)
    return ModuleResolution(targets=(exact,) if exact is not None else (), in_scope=exact is not None)


def _path_module_index(known: set[str]) -> RepositoryModuleIndex:
    return RepositoryModuleIndex(
        python=tuple(
            PythonModule(name=_python_module_name(rel), file=rel)
            for rel in sorted(known)
            if rel.endswith(".py") and _python_module_name(rel)
        )
    )


def _resolve_python_module(
    source: str,
    specifier: str,
    known: set[str],
    specs: tuple[LangSpec, ...],
    scope_names: tuple[str, ...],
    modules: RepositoryModuleIndex,
) -> ModuleResolution:
    matching = _nearest_declarations(
        source,
        tuple(module for module in modules.python if module.name == specifier),
    )
    targets = tuple(dict.fromkeys(module.file for module in matching))
    if targets:
        return ModuleResolution(targets=targets, in_scope=True)
    for prefix in scope_names:
        dotted = prefix.replace("/", ".")
        if specifier == dotted or specifier.startswith(f"{dotted}."):
            inner = specifier[len(dotted) :].lstrip(".")
            exact = _resolve_exact("root.py", inner, known, specs)
            return ModuleResolution(targets=(exact,) if exact is not None else (), in_scope=True)
    prefix = specifier.split(".", 1)[0]
    applicable = _nearest_declarations(source, modules.python)
    return ModuleResolution(in_scope=any(module.name.split(".", 1)[0] == prefix for module in applicable))


def _resolve_javascript_module(
    source: str,
    specifier: str,
    known: set[str],
    specs: tuple[LangSpec, ...],
    modules: RepositoryModuleIndex,
) -> ModuleResolution:
    matching_aliases = tuple(
        alias for alias in modules.javascript_aliases if _alias_replacement(alias.pattern, specifier) is not None
    )
    scoped_aliases = _nearest_declarations(source, matching_aliases)
    if scoped_aliases:
        best_score = max(_alias_specificity(alias.pattern) for alias in scoped_aliases)
        selected_aliases = tuple(alias for alias in scoped_aliases if _alias_specificity(alias.pattern) == best_score)
        targets: list[str] = []
        for alias in selected_aliases:
            replacement = _alias_replacement(alias.pattern, specifier)
            if replacement is None:
                raise AssertionError("a selected alias must match the module specifier")
            targets.extend(
                candidate
                for raw in alias.targets
                for candidate in _source_candidates(
                    _join_relative(alias.base, raw.replace("*", replacement)),
                    specs,
                )
                if candidate in known
            )
        return ModuleResolution(targets=tuple(dict.fromkeys(targets)), in_scope=True)
    matching_packages = tuple(
        package
        for package in modules.javascript_packages
        if specifier == package.name or specifier.startswith(f"{package.name}/")
    )
    for package in sorted(
        _nearest_declarations(source, matching_packages),
        key=lambda item: len(item.name),
        reverse=True,
    ):
        subpath = specifier[len(package.name) :].lstrip("/")
        bases = (
            (_join_relative(package.root, subpath),)
            if subpath
            else (
                *(_join_relative(package.root, entry) for entry in package.entries),
                package.root,
            )
        )
        targets = tuple(
            dict.fromkeys(
                candidate for base in bases for candidate in _source_candidates(base, specs) if candidate in known
            )
        )
        return ModuleResolution(targets=targets, in_scope=True)
    return ModuleResolution()


def _alias_specificity(pattern: str) -> tuple[bool, int, int, int]:
    prefix, separator, suffix = pattern.partition("*")
    return (not separator, len(prefix) + len(suffix), len(prefix), len(suffix))


def _alias_replacement(pattern: str, specifier: str) -> str | None:
    if "*" not in pattern:
        return "" if pattern == specifier else None
    prefix, suffix = pattern.split("*", 1)
    if not specifier.startswith(prefix) or not specifier.endswith(suffix):
        return None
    end = len(specifier) - len(suffix) if suffix else len(specifier)
    return specifier[len(prefix) : end]


def _resolve_go_module(
    source: str,
    specifier: str,
    known: set[str],
    modules: RepositoryModuleIndex,
) -> ModuleResolution:
    matching = tuple(
        module for module in modules.go_modules if specifier == module.name or specifier.startswith(f"{module.name}/")
    )
    for module in sorted(
        _nearest_declarations(source, matching),
        key=lambda item: len(item.name),
        reverse=True,
    ):
        subpath = specifier[len(module.name) :].lstrip("/")
        directory = _join_relative(module.root, subpath).strip("/")
        targets = tuple(
            sorted(
                rel for rel in known if rel.endswith(".go") and str(PurePosixPath(rel).parent).strip(".") == directory
            )
        )
        return ModuleResolution(targets=targets, in_scope=True)
    return ModuleResolution()


def _nearest_declarations[T: _ScopedDeclaration](source: str, declarations: tuple[T, ...]) -> tuple[T, ...]:
    applicable = tuple(item for item in declarations if _is_below(source, item.scope))
    if not applicable:
        return ()
    depth = max(_scope_depth(item.scope) for item in applicable)
    return tuple(item for item in applicable if _scope_depth(item.scope) == depth)


def _scope_depth(scope: str) -> int:
    return len(PurePosixPath(scope).parts) if scope else 0


def _compatible_specs(source: str, specs: tuple[LangSpec, ...]) -> tuple[LangSpec, ...]:
    source_spec = spec_for({spec.name: spec for spec in specs}, source)
    if source_spec is None:
        return specs
    by_name = {spec.name: spec for spec in specs}
    try:
        return tuple(by_name[name] for name in source_spec.resolution_languages)
    except KeyError as exc:
        raise ValueError(f"{source_spec.name} resolves through an unavailable language {exc.args[0]}") from exc


def resolve_repository(
    analyzed: AnalyzedRepository,
    *,
    known: set[str],
    specs: tuple[LangSpec, ...],
    prefixes: tuple[str, ...],
    modules: RepositoryModuleIndex,
) -> ResolvedRepository:
    """Resolve imports, namespaces, and qualified uses against repository source."""
    imports: dict[str, list[str]] = {}
    references: dict[str, list[str]] = {}
    import_targets: dict[str, list[str]] = {}
    bindings: dict[str, list[ResolvedImport]] = {}
    unresolved: list[StructuralGap] = []
    for rel, analyzed_imports in analyzed.imports.items():
        for analyzed_import in analyzed_imports:
            resolution = resolve_module(
                rel,
                analyzed_import.module,
                known,
                specs,
                prefixes,
                modules=modules,
            )
            targets = resolution.targets
            binding = ResolvedImport(
                imported=analyzed_import.imported,
                local=analyzed_import.local,
                targets=targets,
                reexport=analyzed_import.reexport,
                owner=analyzed_import.owner,
                start=analyzed_import.start,
            )
            bindings.setdefault(rel, []).append(binding)
            if not targets:
                if resolution.in_scope:
                    unresolved.append(
                        StructuralGap(
                            source_file=rel,
                            reference=analyzed_import.module.strip("\"'"),
                            kind="import",
                        )
                    )
                continue
            import_targets.setdefault(rel, []).extend(targets)
            if analyzed_import.imported != "*":
                imports.setdefault(rel, []).append(analyzed_import.imported)
                continue
            for target in targets:
                imports.setdefault(rel, []).extend(_module_level_names(analyzed.definitions, target))
    qualified_references = _resolve_namespaces(
        analyzed,
        known=known,
        specs=specs,
        prefixes=prefixes,
        modules=modules,
        references=references,
        import_targets=import_targets,
        unresolved=unresolved,
    )
    call_candidates, structural_candidates, structural_gaps = resolve_relationship_clues(
        analyzed.definitions,
        bindings,
        qualified_references,
        analyzed.default_exports,
    )
    unresolved.extend(structural_gaps)
    return ResolvedRepository(
        imports=imports,
        references=references,
        import_targets=import_targets,
        call_candidates=call_candidates,
        structural_candidates=structural_candidates,
        structural_gaps=tuple(dict.fromkeys(unresolved)),
        limitations=modules.limitations,
    )


def resolve_relationship_clues(
    definitions: tuple[AnalyzedDefinition, ...],
    bindings: dict[str, list[ResolvedImport]],
    qualified_references: tuple[ResolvedReference, ...],
    default_exports: dict[str, list[str]],
) -> tuple[tuple[CallCandidate, ...], tuple[StructuralCandidate, ...], tuple[StructuralGap, ...]]:
    """Resolve calls and non-call syntax to candidate clues."""
    by_name: dict[str, list[AnalyzedDefinition]] = {}
    for definition in definitions:
        by_name.setdefault(definition.name, []).append(definition)
    definitions_by_key = {_definition_key(definition): definition for definition in definitions}
    call_candidates = _call_candidates(
        definitions,
        by_name,
        definitions_by_key,
        bindings,
        default_exports,
    )
    import_candidates = _import_candidates(definitions, by_name, bindings, default_exports)
    reference_candidates, unresolved_references = _reference_candidates(qualified_references, by_name)
    return (
        tuple(dict.fromkeys(call_candidates)),
        tuple(dict.fromkeys((*import_candidates, *reference_candidates))),
        tuple(dict.fromkeys(unresolved_references)),
    )


def _call_targets(
    definition: AnalyzedDefinition,
    name: str,
    *,
    local_receiver: bool,
    by_name: dict[str, list[AnalyzedDefinition]],
    definitions_by_key: dict[DefinitionKey, AnalyzedDefinition],
    bindings: dict[str, list[ResolvedImport]],
    default_exports: dict[str, list[str]],
) -> tuple[list[AnalyzedDefinition], tuple[tuple[str, str], ...]]:
    if local_receiver:
        if not definition.local_receiver_is_type_bound:
            return [], ()
        targets = [
            candidate
            for candidate in by_name.get(name, ())
            if candidate.file == definition.file and candidate.type_owner == definition.type_owner
        ]
        return targets, ()
    endpoints = symbol_endpoints_for(
        definition.file,
        name,
        bindings,
        default_exports,
        source_definition=definition,
    )
    active_bindings = tuple(
        binding
        for binding in bindings.get(definition.file, ())
        if binding.local in {name, "*"} and _binding_applies(definition, binding)
    )
    targets = [
        candidate
        for candidate in by_name.get(name, ())
        if _unqualified_target_is_visible(definition, candidate, definitions_by_key)
        and not any(_binding_shadows(binding, candidate) for binding in active_bindings)
    ]
    targets.extend(
        candidate
        for target_file, target_name in endpoints
        for candidate in by_name.get(target_name, ())
        if candidate.file == target_file
    )
    return list(dict.fromkeys(targets)), endpoints


def _definition_key(definition: AnalyzedDefinition) -> DefinitionKey:
    return definition.file, definition.start, definition.end


def _owner_key(file: str, owner: AnalyzedOwner) -> DefinitionKey:
    return file, owner.start, owner.end


def _unqualified_target_is_visible(
    source: AnalyzedDefinition,
    target: AnalyzedDefinition,
    definitions_by_key: dict[DefinitionKey, AnalyzedDefinition],
) -> bool:
    if not target.unqualified_target:
        return False
    if target.file != source.file:
        return target.unqualified_scope == source.unqualified_scope
    if target.owner is None:
        return True

    visible_scopes = {_definition_key(source)}
    owner = source.owner
    visited: set[DefinitionKey] = set()
    while owner is not None:
        key = _owner_key(source.file, owner)
        if key in visited:
            raise ValueError(f"cyclic lexical owner for {source.file}:{source.name}")
        visited.add(key)
        definition = definitions_by_key.get(key)
        if definition is None:
            raise ValueError(f"missing lexical owner for {source.file}:{source.name}")
        if not definition.is_type:
            visible_scopes.add(key)
        owner = definition.owner
    return _owner_key(target.file, target.owner) in visible_scopes


def _call_candidates(
    definitions: tuple[AnalyzedDefinition, ...],
    by_name: dict[str, list[AnalyzedDefinition]],
    definitions_by_key: dict[DefinitionKey, AnalyzedDefinition],
    bindings: dict[str, list[ResolvedImport]],
    default_exports: dict[str, list[str]],
) -> tuple[CallCandidate, ...]:
    candidates: list[CallCandidate] = []
    for definition in definitions:
        source = _definition_fragment(definition)
        scoped_calls = [(name, False) for name in definition.direct_calls]
        scoped_calls.extend((name, True) for name in definition.local_calls)
        for name, local_receiver in scoped_calls:
            targets, _endpoints = _call_targets(
                definition,
                name,
                local_receiver=local_receiver,
                by_name=by_name,
                definitions_by_key=definitions_by_key,
                bindings=bindings,
                default_exports=default_exports,
            )
            for target in targets:
                target_fragment = _definition_fragment(target)
                candidates.append(CallCandidate(source=source, target=target_fragment, reference=name))
    return tuple(candidates)


def _import_candidates(
    definitions: tuple[AnalyzedDefinition, ...],
    by_name: dict[str, list[AnalyzedDefinition]],
    bindings: dict[str, list[ResolvedImport]],
    default_exports: dict[str, list[str]],
) -> tuple[StructuralCandidate, ...]:
    candidates: list[StructuralCandidate] = []
    resolved_names = {
        source_file: _binding_names(source_bindings, definitions) for source_file, source_bindings in bindings.items()
    }
    for source_file, names in resolved_names.items():
        for name in names:
            targets = [
                candidate
                for target_file, target_name in symbol_endpoints_for(
                    source_file,
                    name,
                    bindings,
                    default_exports,
                )
                for candidate in by_name.get(target_name, ())
                if candidate.file == target_file and candidate.file != source_file
            ]
            targets = list(dict.fromkeys(targets))
            candidates.extend(
                StructuralCandidate(
                    source_file=source_file,
                    target=_definition_fragment(target),
                    kind="import",
                    reference=name,
                )
                for target in targets
            )
    return tuple(candidates)


def _reference_candidates(
    qualified_references: tuple[ResolvedReference, ...],
    by_name: dict[str, list[AnalyzedDefinition]],
) -> tuple[tuple[StructuralCandidate, ...], tuple[StructuralGap, ...]]:
    candidates: list[StructuralCandidate] = []
    unresolved: list[StructuralGap] = []
    for reference in qualified_references:
        targets = [
            candidate
            for candidate in by_name.get(reference.target_name, ())
            if candidate.file in reference.targets and candidate.file != reference.source_file
        ]
        targets = list(dict.fromkeys(targets))
        if not targets:
            unresolved.append(
                StructuralGap(
                    source_file=reference.source_file,
                    reference=reference.reference,
                    kind="reference",
                )
            )
            continue
        candidates.extend(
            StructuralCandidate(
                source_file=reference.source_file,
                target=_definition_fragment(target),
                kind="reference",
                reference=reference.reference,
            )
            for target in targets
        )
    return tuple(candidates), tuple(unresolved)


def _binding_names(
    bindings: list[ResolvedImport],
    definitions: tuple[AnalyzedDefinition, ...],
) -> tuple[str, ...]:
    names: list[str] = []
    for binding in bindings:
        if binding.local != "*":
            names.append(binding.local)
            continue
        for target in binding.targets:
            names.extend(_module_level_names(definitions, target))
    return tuple(dict.fromkeys(names))


def symbol_endpoints_for(
    source: str,
    name: str,
    bindings: dict[str, list[ResolvedImport]],
    default_exports: dict[str, list[str]] | None = None,
    *,
    source_definition: AnalyzedDefinition | None = None,
) -> tuple[tuple[str, str], ...]:
    """Follow local and remote names through every reachable import facade."""
    default_exports = default_exports or {}
    reached: set[tuple[str, str]] = set()
    frontier = {(source, name, True)}
    visited = set(frontier)
    while frontier:
        next_frontier: set[tuple[str, str, bool]] = set()
        for file, local, initial in frontier:
            if local == "default":
                reached.update((file, exported) for exported in default_exports.get(file, ()))
            for binding in bindings.get(file, ()):
                if initial and source_definition is not None and not _binding_applies(source_definition, binding):
                    continue
                if not initial and not binding.reexport:
                    continue
                if binding.local not in {local, "*"}:
                    continue
                if local == "default" and binding.imported == "*":
                    continue
                remote = local if binding.local == "*" else binding.imported
                next_frontier.update((target, remote, False) for target in binding.targets)
        next_frontier.difference_update(visited)
        reached.update((file, remote) for file, remote, _initial in next_frontier)
        visited.update(next_frontier)
        frontier = next_frontier
    return tuple(sorted(reached))


def _binding_applies(definition: AnalyzedDefinition, binding: ResolvedImport) -> bool:
    owner = binding.owner
    return owner is None or (owner.start <= definition.start and definition.end <= owner.end)


def _binding_shadows(binding: ResolvedImport, candidate: AnalyzedDefinition) -> bool:
    if binding.owner is None:
        return candidate.owner is None and binding.start > candidate.start
    if candidate.owner is None:
        return True
    if candidate.owner == binding.owner:
        return binding.start > candidate.start
    return False


def _definition_fragment(definition: AnalyzedDefinition) -> DefinitionFragment:
    return DefinitionFragment(definition.file, definition.name, definition.start, definition.end)


def _resolve_namespaces(
    analyzed: AnalyzedRepository,
    *,
    known: set[str],
    specs: tuple[LangSpec, ...],
    prefixes: tuple[str, ...],
    modules: RepositoryModuleIndex,
    references: dict[str, list[str]],
    import_targets: dict[str, list[str]],
    unresolved: list[StructuralGap],
) -> tuple[ResolvedReference, ...]:
    resolved: list[ResolvedReference] = []
    for rel, uses in analyzed.qualified_uses.items():
        namespaces = {item.local: item.specifier for item in analyzed.namespaces.get(rel, ())}
        for qualifier, name in uses:
            specifier = namespaces.get(qualifier)
            if specifier is None:
                continue
            resolution = resolve_module(rel, specifier, known, specs, prefixes, modules=modules)
            targets = resolution.targets
            if not targets:
                if resolution.in_scope:
                    unresolved.append(StructuralGap(source_file=rel, reference=specifier, kind="import"))
                continue
            references.setdefault(rel, []).append(name)
            import_targets.setdefault(rel, []).extend(targets)
            resolved.append(
                ResolvedReference(
                    source_file=rel,
                    reference=f"{qualifier}.{name}",
                    target_name=name,
                    targets=targets,
                )
            )
    return tuple(dict.fromkeys(resolved))


def _module_level_names(definitions: tuple[AnalyzedDefinition, ...], source_file: str) -> tuple[str, ...]:
    candidates = [definition for definition in definitions if definition.file == source_file]
    return tuple(
        dict.fromkeys(
            definition.name
            for definition in candidates
            if not any(
                other is not definition
                and (other.start, other.end) != (definition.start, definition.end)
                and other.start <= definition.start
                and definition.end <= other.end
                for other in candidates
            )
        )
    )


def _extensions(specs: tuple[LangSpec, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(extension for spec in specs for extension in spec.extensions))


def _module_entries(specs: tuple[LangSpec, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(entry for spec in specs for entry in spec.module_entries))
