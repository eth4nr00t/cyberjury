"""Resolve syntax relationships to repository paths and definition endpoints."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from cyberjury.profiles.base import content_paths
from cyberjury.profiles.web.facts.analyzer import (
    AnalyzableSource,
    AnalyzedDefinition,
    AnalyzedRepository,
    LangSpec,
    spec_for,
)
from cyberjury.review.definitions import DefinitionDependency, DefinitionFragment, UnresolvedDependency

if TYPE_CHECKING:
    from cyberjury.detection import Detection

_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file


@dataclass(frozen=True, kw_only=True)
class ResolvedRepository:
    """Repository relationships resolved from syntax analyzer output."""

    imports: dict[str, list[str]]
    references: dict[str, list[str]]
    import_targets: dict[str, list[str]]
    dependencies: tuple[DefinitionDependency, ...]
    unresolved: tuple[UnresolvedDependency, ...]


@dataclass(frozen=True, kw_only=True)
class ResolvedImport:
    """Bind one local name to a remote name in exact repository files."""

    imported: str
    local: str
    targets: tuple[str, ...]


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
        rel = path.relative_to(base).as_posix()
        if detection.is_skipped_dir(Path(rel).parts[:-1]) or detection.is_test_path(rel):
            continue
        spec = spec_for(specs, rel)
        if spec is not None:
            sources.append((path, rel, spec))
    return sources


def ancestor_directories(rel: str) -> list[str]:
    """Return every directory prefix used to match namespace imports."""
    parts = rel.split("/")[:-1]
    return ["/".join(parts[: index + 1]) for index in range(len(parts))]


def namespace_in_tree(
    source: str,
    specifier: str,
    known: set[str],
    directories: set[str],
    specs: tuple[LangSpec, ...],
    scope_prefixes: tuple[str, ...] = (),
) -> bool:
    """Return whether a namespace specifier identifies repository source."""
    if resolve_specifiers(source, specifier, known, specs, scope_prefixes):
        return True
    cleaned = specifier.strip().strip("\"'").lstrip(".")
    if not cleaned:
        return False
    parts = cleaned.replace(".", "/").split("/")
    return any("/".join(parts[start:]) in directories for start in range(len(parts)))


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
            base = os.path.join(parent, specifier)
        else:
            up = len(specifier) - len(specifier.lstrip("."))
            tail = specifier.lstrip(".").replace(".", "/")
            base = os.path.join(parent, *[".."] * (up - 1), tail)
    else:
        base = specifier.replace(".", "/") if "/" not in specifier else specifier
    base = os.path.normpath(base).removeprefix("./")
    return base


def _alias_bases(base: str, scope_names: tuple[str, ...]) -> tuple[str, ...]:
    aliases: list[str] = []
    first, separator, tail = base.partition("/")
    if separator and first in {"~", "@"}:
        aliases.append(tail)
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


def _bare_candidates(specifier: str, specs: tuple[LangSpec, ...]) -> tuple[str, ...]:
    cleaned = specifier.strip().strip("\"'")
    if not cleaned or cleaned.startswith("."):
        return ()
    base = cleaned.replace(".", "/") if "/" not in cleaned else cleaned
    return _source_candidates(base, specs)


def resolve_specifiers(
    source: str,
    specifier: str,
    known: set[str],
    specs: tuple[LangSpec, ...],
    scope_names: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Resolve every repository file that can satisfy one import specifier."""
    compatible_specs = _compatible_specs(source, specs)
    exact = _resolve_exact(source, specifier, known, compatible_specs, scope_names)
    if exact is not None:
        return (exact,)
    candidates = _bare_candidates(specifier, compatible_specs)
    matches = tuple(
        sorted(
            rel for rel in known if any(rel == candidate or rel.endswith(f"/{candidate}") for candidate in candidates)
        )
    )
    if matches:
        return matches
    if not any(spec.namespace_resolves_directory for spec in compatible_specs):
        return ()
    return _namespace_directory_targets(specifier, known)


def _namespace_directory_targets(specifier: str, known: set[str]) -> tuple[str, ...]:
    cleaned = specifier.strip().strip("\"'").strip("/")
    if not cleaned or cleaned.startswith("."):
        return ()
    parts = cleaned.replace(".", "/").split("/")
    directories = {"/".join(parts[start:]) for start in range(len(parts))}
    return tuple(
        sorted(
            rel
            for rel in known
            if any(
                str(PurePosixPath(rel).parent) == directory or str(PurePosixPath(rel).parent).endswith(f"/{directory}")
                for directory in directories
            )
        )
    )


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
    directories: set[str],
    specs: tuple[LangSpec, ...],
    prefixes: tuple[str, ...],
) -> ResolvedRepository:
    """Resolve imports, namespaces, and qualified uses against repository source."""
    imports: dict[str, list[str]] = {}
    references: dict[str, list[str]] = {}
    import_targets: dict[str, list[str]] = {}
    bindings: dict[str, list[ResolvedImport]] = {}
    unresolved: list[UnresolvedDependency] = []
    for rel, analyzed_imports in analyzed.imports.items():
        for analyzed_import in analyzed_imports:
            targets = resolve_specifiers(rel, analyzed_import.module, known, specs, prefixes)
            if not targets:
                if analyzed_import.module.strip().strip("\"'").startswith("."):
                    unresolved.append(UnresolvedDependency(rel, analyzed_import.module.strip("\"'")))
                continue
            import_targets.setdefault(rel, []).extend(targets)
            binding = ResolvedImport(
                imported=analyzed_import.imported,
                local=analyzed_import.local,
                targets=targets,
            )
            bindings.setdefault(rel, []).append(binding)
            if analyzed_import.imported != "*":
                imports.setdefault(rel, []).append(analyzed_import.imported)
                continue
            for target in targets:
                imports.setdefault(rel, []).extend(_module_level_names(analyzed.definitions, target))
    qualified_references = _resolve_namespaces(
        analyzed,
        known=known,
        directories=directories,
        specs=specs,
        prefixes=prefixes,
        references=references,
        import_targets=import_targets,
        unresolved=unresolved,
    )
    dependencies, dependency_gaps = resolve_dependencies(
        analyzed.definitions,
        bindings,
        qualified_references,
        analyzed.default_exports,
    )
    unresolved.extend(dependency_gaps)
    return ResolvedRepository(
        imports=imports,
        references=references,
        import_targets=import_targets,
        dependencies=dependencies,
        unresolved=tuple(dict.fromkeys(unresolved)),
    )


def resolve_dependencies(
    definitions: tuple[AnalyzedDefinition, ...],
    bindings: dict[str, list[ResolvedImport]],
    qualified_references: tuple[ResolvedReference, ...],
    default_exports: dict[str, list[str]],
) -> tuple[tuple[DefinitionDependency, ...], tuple[UnresolvedDependency, ...]]:
    """Resolve syntax names to scoped repository definition endpoints."""
    by_name: dict[str, list[AnalyzedDefinition]] = {}
    for definition in definitions:
        by_name.setdefault(definition.name, []).append(definition)
    call_dependencies, unresolved_calls = _call_dependencies(definitions, by_name, bindings, default_exports)
    import_dependencies = _import_dependencies(definitions, by_name, bindings, default_exports)
    reference_dependencies, unresolved_references = _reference_dependencies(qualified_references, by_name)
    return (
        tuple(dict.fromkeys((*call_dependencies, *import_dependencies, *reference_dependencies))),
        tuple(dict.fromkeys((*unresolved_calls, *unresolved_references))),
    )


def _call_targets(
    definition: AnalyzedDefinition,
    name: str,
    *,
    local_receiver: bool,
    by_name: dict[str, list[AnalyzedDefinition]],
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
    endpoints = symbol_endpoints_for(definition.file, name, bindings, default_exports)
    targets = [candidate for candidate in by_name.get(name, ()) if candidate.file == definition.file]
    targets.extend(
        candidate
        for target_file, target_name in endpoints
        for candidate in by_name.get(target_name, ())
        if candidate.file == target_file
    )
    return list(dict.fromkeys(targets)), endpoints


def _call_dependencies(
    definitions: tuple[AnalyzedDefinition, ...],
    by_name: dict[str, list[AnalyzedDefinition]],
    bindings: dict[str, list[ResolvedImport]],
    default_exports: dict[str, list[str]],
) -> tuple[tuple[DefinitionDependency, ...], tuple[UnresolvedDependency, ...]]:
    dependencies: list[DefinitionDependency] = []
    unresolved: list[UnresolvedDependency] = []
    for definition in definitions:
        source = _definition_fragment(definition)
        scoped_calls = [(name, False) for name in definition.direct_calls]
        scoped_calls.extend((name, True) for name in definition.local_calls)
        for name, local_receiver in scoped_calls:
            targets, endpoints = _call_targets(
                definition,
                name,
                local_receiver=local_receiver,
                by_name=by_name,
                bindings=bindings,
                default_exports=default_exports,
            )
            if not targets and endpoints:
                unresolved.append(UnresolvedDependency(definition.file, name, "call", source))
            resolution = "exact" if len(targets) == 1 else "ambiguous"
            for target in targets:
                target_fragment = _definition_fragment(target)
                if target_fragment != source:
                    dependencies.append(
                        DefinitionDependency(
                            definition.file,
                            target_fragment,
                            source,
                            "call",
                            resolution,
                            name,
                        )
                    )
    return tuple(dependencies), tuple(unresolved)


def _import_dependencies(
    definitions: tuple[AnalyzedDefinition, ...],
    by_name: dict[str, list[AnalyzedDefinition]],
    bindings: dict[str, list[ResolvedImport]],
    default_exports: dict[str, list[str]],
) -> tuple[DefinitionDependency, ...]:
    dependencies: list[DefinitionDependency] = []
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
            resolution = "exact" if len(targets) == 1 else "ambiguous"
            dependencies.extend(
                DefinitionDependency(
                    source_file,
                    _definition_fragment(target),
                    None,
                    "import",
                    resolution,
                    name,
                )
                for target in targets
            )
    return tuple(dependencies)


def _reference_dependencies(
    qualified_references: tuple[ResolvedReference, ...],
    by_name: dict[str, list[AnalyzedDefinition]],
) -> tuple[tuple[DefinitionDependency, ...], tuple[UnresolvedDependency, ...]]:
    dependencies: list[DefinitionDependency] = []
    unresolved: list[UnresolvedDependency] = []
    for reference in qualified_references:
        targets = [
            candidate
            for candidate in by_name.get(reference.target_name, ())
            if candidate.file in reference.targets and candidate.file != reference.source_file
        ]
        targets = list(dict.fromkeys(targets))
        if not targets:
            unresolved.append(UnresolvedDependency(reference.source_file, reference.reference, "reference"))
            continue
        resolution = "exact" if len(targets) == 1 else "ambiguous"
        dependencies.extend(
            DefinitionDependency(
                reference.source_file,
                _definition_fragment(target),
                None,
                "reference",
                resolution,
                reference.reference,
            )
            for target in targets
        )
    return tuple(dependencies), tuple(unresolved)


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
) -> tuple[tuple[str, str], ...]:
    """Follow local and remote names through every reachable import facade."""
    default_exports = default_exports or {}
    reached: set[tuple[str, str]] = set()
    frontier = {(source, name)}
    visited = set(frontier)
    while frontier:
        next_frontier: set[tuple[str, str]] = set()
        for file, local in frontier:
            if local == "default":
                reached.update((file, exported) for exported in default_exports.get(file, ()))
            for binding in bindings.get(file, ()):
                if binding.local not in {local, "*"}:
                    continue
                remote = local if binding.local == "*" else binding.imported
                next_frontier.update((target, remote) for target in binding.targets)
        next_frontier.difference_update(visited)
        reached.update(next_frontier)
        visited.update(next_frontier)
        frontier = next_frontier
    return tuple(sorted(reached))


def _definition_fragment(definition: AnalyzedDefinition) -> DefinitionFragment:
    return DefinitionFragment(definition.file, definition.name, definition.start, definition.end)


def _resolve_namespaces(
    analyzed: AnalyzedRepository,
    *,
    known: set[str],
    directories: set[str],
    specs: tuple[LangSpec, ...],
    prefixes: tuple[str, ...],
    references: dict[str, list[str]],
    import_targets: dict[str, list[str]],
    unresolved: list[UnresolvedDependency],
) -> tuple[ResolvedReference, ...]:
    resolved: list[ResolvedReference] = []
    for rel, uses in analyzed.qualified_uses.items():
        namespaces = analyzed.namespaces.get(rel, {})
        for qualifier, name in uses:
            specifier = namespaces.get(qualifier)
            if specifier is None:
                continue
            if not namespace_in_tree(rel, specifier, known, directories, specs, prefixes):
                if specifier.startswith("."):
                    unresolved.append(UnresolvedDependency(rel, specifier))
                continue
            targets = resolve_specifiers(rel, specifier, known, specs, prefixes)
            if not targets:
                unresolved.append(UnresolvedDependency(rel, specifier))
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
