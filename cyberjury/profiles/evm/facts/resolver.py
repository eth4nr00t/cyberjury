"""Resolve analyzed EVM identities into repository paths and call endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury.profiles.base import content_paths
from cyberjury.profiles.evm.facts.analyzer import (
    AnalyzedContract,
    AnalyzedFunction,
    AnalyzedProject,
    AnalyzedSource,
    AnalyzedStateVariable,
)
from cyberjury.review.definitions import DefinitionDependency, DefinitionFragment
from cyberjury.review.failures import BackendUnavailable

if TYPE_CHECKING:
    from cyberjury.detection import Detection

_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file


@dataclass(frozen=True, kw_only=True)
class ResolvedFunction:
    """One analyzed function resolved to stable repository facts."""

    name: str
    visibility: str
    modifiers: tuple[str, ...]
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    calls: tuple[str, ...]
    external_call: bool
    sends_eth: bool
    can_reenter: bool
    span: tuple[int, int] | None


@dataclass(frozen=True, kw_only=True)
class ResolvedContract:
    """One analyzed contract resolved to repository source."""

    identity: str
    name: str
    file: str
    state: tuple[AnalyzedStateVariable, ...]
    functions: tuple[ResolvedFunction, ...]


@dataclass(frozen=True, kw_only=True)
class ResolvedProject:
    """Repository identities and exact dependencies from one EVM analysis."""

    contracts: tuple[ResolvedContract, ...]
    dependencies: tuple[DefinitionDependency, ...]


def load_profile_detection() -> Detection:
    """Load the EVM profile rules used while resolving review scope."""
    from cyberjury.detection import load_detection

    return load_detection(_DETECTION_FILE)


def resolve_project(
    analyzed: AnalyzedProject,
    review_root: Path,
    detection: Detection,
) -> ResolvedProject:
    """Map analyzed EVM facts into repository coordinates and dependencies."""
    contracts: list[ResolvedContract] = []
    reviewed_functions: list[tuple[AnalyzedFunction, DefinitionFragment]] = []
    function_fragments: dict[int, DefinitionFragment] = {}
    source_bytes: dict[Path, bytes] = {}
    contract_identities: set[str] = set()
    for contract in analyzed.contracts:
        if contract.is_interface or not reviewable_contract(contract, review_root, detection):
            continue
        rel_file = relative_file(contract.source, review_root)
        identity = f"{rel_file}::{contract.name}" if rel_file else contract.identity
        if identity in contract_identities:
            raise BackendUnavailable(f"multiple Solidity contracts resolve to the same identity {identity}")
        contract_identities.add(identity)
        functions: list[ResolvedFunction] = []
        for function in contract.functions:
            span = function_range(function, source_bytes)
            functions.append(
                ResolvedFunction(
                    name=function.name,
                    visibility=function.visibility,
                    modifiers=function.modifiers,
                    reads=function.reads,
                    writes=function.writes,
                    calls=tuple(dict.fromkeys(call.target_name for call in function.calls)),
                    external_call=function.external_call,
                    sends_eth=function.sends_eth,
                    can_reenter=function.can_reenter,
                    span=span,
                )
            )
            if rel_file and span is not None:
                fragment = DefinitionFragment(rel_file, function.name, span[0], span[1])
                reviewed_functions.append((function, fragment))
                function_fragments[function.key] = fragment
        contracts.append(
            ResolvedContract(
                identity=identity,
                name=contract.name,
                file=rel_file,
                state=contract.state,
                functions=tuple(functions),
            )
        )
    return ResolvedProject(
        contracts=tuple(contracts),
        dependencies=resolve_dependencies(reviewed_functions, function_fragments),
    )


def resolve_compile_root(review_root: Path) -> Path:
    """Use the nearest repository bounded framework root for scoped analysis."""
    markers = load_profile_detection().compile_roots
    if not markers:
        return review_root
    ancestors = [review_root, *review_root.parents]
    repository = next((directory for directory in ancestors if (directory / ".git").exists()), None)
    if repository is None:
        return review_root
    for directory in ancestors:
        if any((directory / marker).is_file() for marker in markers):
            return directory
        if directory == repository:
            break
    return review_root


def analyzer_target(review_root: Path, compile_root: Path) -> Path:
    """Choose the narrowest input that retains the project compile context."""
    if compile_root != review_root or review_root.is_file() or _has_compile_config(review_root):
        return compile_root
    solidity_files = sorted(path for path in review_root.rglob("*.sol") if path.is_file())
    return solidity_files[0] if len(solidity_files) == 1 else compile_root


def source_path(source: AnalyzedSource) -> Path | None:
    """Resolve one normalized absolute source path when it is available."""
    return Path(source.absolute).resolve() if source.absolute else None


def in_scope(source: AnalyzedSource, review_root: Path) -> bool:
    """Keep pathless values because recall outranks path precision."""
    path = source_path(source)
    return path is None or path.is_relative_to(review_root)


def reviewable_contract(contract: AnalyzedContract, review_root: Path, detection: Detection) -> bool:
    """Apply review scope and profile noise rules before graph construction."""
    if not in_scope(contract.source, review_root):
        return False
    rel = relative_file(contract.source, review_root)
    return not rel or not detection.is_noise_path(rel)


def relative_file(source: AnalyzedSource, review_root: Path) -> str:
    """Map one analyzed source identity to a repository relative path."""
    absolute = source_path(source)
    if absolute is not None:
        try:
            rel = absolute.relative_to(review_root).as_posix()
        except ValueError:
            rel = ""
        return rel if rel and rel != "." else absolute.name
    return source.short or source.used


def function_range(function: AnalyzedFunction, source_bytes: dict[Path, bytes]) -> tuple[int, int] | None:
    """Translate analyzed byte offsets to normalized source character offsets."""
    start = function.source.start
    length = function.source.length
    if not isinstance(start, int) or not isinstance(length, int):
        return None
    if start < 0 or length <= 0:
        raise BackendUnavailable("Slither returned an invalid source range for a Solidity definition")
    path = source_path(function.source)
    if path is None:
        return None
    try:
        raw = source_bytes.get(path)
        if raw is None:
            raw = path.read_bytes()
            source_bytes[path] = raw
    except OSError as exc:
        raise BackendUnavailable(
            f"could not read Solidity source for Slither range conversion at {path}: {exc}"
        ) from exc
    end = start + length
    if end > len(raw):
        raise BackendUnavailable(f"Slither source range exceeds Solidity source at {path}:{start}:{end}")
    return (_character_offset(raw, start, path), _character_offset(raw, end, path))


def resolve_dependencies(
    reviewed_functions: list[tuple[AnalyzedFunction, DefinitionFragment]],
    function_fragments: dict[int, DefinitionFragment],
) -> tuple[DefinitionDependency, ...]:
    """Map analyzed call endpoint keys through the shared definition contract."""
    dependencies = [
        DefinitionDependency(source.file, target, source)
        for function, source in reviewed_functions
        for call in function.calls
        if (target := function_fragments.get(call.target_key)) is not None and target != source
    ]
    return tuple(dict.fromkeys(dependencies))


def _has_compile_config(root: Path) -> bool:
    return any((root / marker).is_file() for marker in load_profile_detection().compile_roots)


def _character_offset(raw: bytes, offset: int, path: Path) -> int:
    try:
        prefix = raw[:offset].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackendUnavailable(
            f"Slither source range is not on a UTF-8 character boundary at {path}:{offset}"
        ) from exc
    return len(prefix.replace("\r\n", "\n").replace("\r", "\n"))
