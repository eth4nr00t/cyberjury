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
from cyberjury.review.facts import FactLimitation
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
    span: tuple[int, int] | None = None


@dataclass(frozen=True, kw_only=True)
class ResolvedProject:
    """Repository identities and exact dependencies from one EVM analysis."""

    contracts: tuple[ResolvedContract, ...]
    dependencies: tuple[DefinitionDependency, ...]
    limitations: tuple[FactLimitation, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _ResolvedContractState:
    contract: ResolvedContract
    reviewed_functions: tuple[tuple[AnalyzedFunction, DefinitionFragment], ...]
    function_fragments: dict[int, DefinitionFragment]
    in_scope_functions: dict[int, str]
    reviewed_contract: tuple[AnalyzedContract, DefinitionFragment] | None
    contract_fragment: tuple[int, DefinitionFragment] | None
    in_scope_contract: tuple[int, str] | None
    limitations: tuple[FactLimitation, ...]


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
    in_scope_functions: dict[int, str] = {}
    reviewed_contracts: list[tuple[AnalyzedContract, DefinitionFragment]] = []
    contract_fragments: dict[int, DefinitionFragment] = {}
    in_scope_contracts: dict[int, str] = {}
    source_bytes: dict[Path, bytes] = {}
    contract_identities: set[str] = set()
    limitations: list[FactLimitation] = []
    for contract in analyzed.contracts:
        if contract.is_interface or not reviewable_contract(contract, review_root, detection):
            continue
        rel_file = relative_file(contract.source, review_root)
        identity = f"{rel_file}::{contract.name}" if rel_file else contract.identity
        if identity in contract_identities:
            raise BackendUnavailable(f"multiple Solidity contracts resolve to the same identity {identity}")
        contract_identities.add(identity)
        state = _resolve_contract(
            contract,
            identity=identity,
            relative_file=rel_file,
            review_root=review_root,
            source_bytes=source_bytes,
        )
        contracts.append(state.contract)
        reviewed_functions.extend(state.reviewed_functions)
        function_fragments.update(state.function_fragments)
        in_scope_functions.update(state.in_scope_functions)
        limitations.extend(state.limitations)
        if state.reviewed_contract is not None:
            reviewed_contracts.append(state.reviewed_contract)
        if state.contract_fragment is not None:
            contract_fragments.update((state.contract_fragment,))
        if state.in_scope_contract is not None:
            in_scope_contracts.update((state.in_scope_contract,))
    dependencies, dependency_limitations = resolve_dependencies(
        reviewed_functions,
        function_fragments,
        in_scope_functions,
    )
    contract_dependencies, contract_limitations = _resolve_contract_dependencies(
        reviewed_contracts,
        contract_fragments,
        in_scope_contracts,
    )
    return ResolvedProject(
        contracts=tuple(contracts),
        dependencies=tuple(dict.fromkeys((*dependencies, *contract_dependencies))),
        limitations=tuple(dict.fromkeys((*limitations, *dependency_limitations, *contract_limitations))),
    )


def _resolve_contract(
    contract: AnalyzedContract,
    *,
    identity: str,
    relative_file: str,
    review_root: Path,
    source_bytes: dict[Path, bytes],
) -> _ResolvedContractState:
    repository_file = _repository_relative_file(contract.source, review_root)
    contract_span = source_range(contract.source, source_bytes)
    limitations: list[FactLimitation] = []
    reviewed_contract = None
    contract_fragment = None
    in_scope_contract = None
    if not repository_file:
        limitations.append(
            FactLimitation(
                source=relative_file or contract.identity,
                analyzer="slither-resolver",
                reason=f"could not locate repository source for contract {contract.name}",
            )
        )
    else:
        in_scope_contract = (contract.key, contract.name)
        if contract_span is None:
            limitations.append(
                FactLimitation(
                    source=repository_file,
                    analyzer="slither-resolver",
                    reason=f"could not locate source range for contract {contract.name}",
                )
            )
        else:
            fragment = DefinitionFragment(repository_file, contract.name, *contract_span)
            reviewed_contract = (contract, fragment)
            contract_fragment = (contract.key, fragment)

    functions: list[ResolvedFunction] = []
    reviewed_functions: list[tuple[AnalyzedFunction, DefinitionFragment]] = []
    function_fragments: dict[int, DefinitionFragment] = {}
    in_scope_functions: dict[int, str] = {}
    for function in contract.functions:
        if repository_file:
            in_scope_functions[function.key] = function.name
        span = function_range(function, source_bytes)
        if repository_file and span is None:
            limitations.append(
                FactLimitation(
                    source=repository_file,
                    analyzer="slither-resolver",
                    reason=f"could not locate source range for function {function.name}",
                )
            )
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
        if repository_file and span is not None:
            fragment = DefinitionFragment(repository_file, function.name, *span)
            reviewed_functions.append((function, fragment))
            function_fragments[function.key] = fragment

    return _ResolvedContractState(
        contract=ResolvedContract(
            identity=identity,
            name=contract.name,
            file=relative_file,
            state=contract.state,
            functions=tuple(functions),
            span=contract_span,
        ),
        reviewed_functions=tuple(reviewed_functions),
        function_fragments=function_fragments,
        in_scope_functions=in_scope_functions,
        reviewed_contract=reviewed_contract,
        contract_fragment=contract_fragment,
        in_scope_contract=in_scope_contract,
        limitations=tuple(limitations),
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


def _repository_relative_file(source: AnalyzedSource, review_root: Path) -> str:
    absolute = source_path(source)
    if absolute is None:
        return ""
    if review_root.is_file():
        return absolute.name if absolute == review_root else ""
    try:
        relative = absolute.relative_to(review_root).as_posix()
    except ValueError:
        return ""
    return relative if relative != "." else ""


def function_range(function: AnalyzedFunction, source_bytes: dict[Path, bytes]) -> tuple[int, int] | None:
    """Translate analyzed byte offsets to normalized source character offsets."""
    return source_range(function.source, source_bytes)


def source_range(source: AnalyzedSource, source_bytes: dict[Path, bytes]) -> tuple[int, int] | None:
    """Translate one Slither source mapping to normalized character offsets."""
    start = source.start
    length = source.length
    if not isinstance(start, int) or not isinstance(length, int):
        return None
    if start < 0 or length <= 0:
        raise BackendUnavailable("Slither returned an invalid source range for a Solidity definition")
    path = source_path(source)
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
    in_scope_functions: dict[int, str],
) -> tuple[tuple[DefinitionDependency, ...], tuple[FactLimitation, ...]]:
    """Map analyzed call endpoint keys through the shared definition contract."""
    dependencies: list[DefinitionDependency] = []
    limitations: list[FactLimitation] = []
    for function, source in reviewed_functions:
        for call in function.calls:
            target = function_fragments.get(call.target_key)
            if target is not None:
                if target != source:
                    dependencies.append(DefinitionDependency(source.file, target, source))
                continue
            if call.target_key in in_scope_functions:
                limitations.append(
                    FactLimitation(
                        source=source.file,
                        analyzer="slither-resolver",
                        reason=f"could not locate in-scope call target {in_scope_functions[call.target_key]}",
                    )
                )
    return tuple(dict.fromkeys(dependencies)), tuple(dict.fromkeys(limitations))


def _resolve_contract_dependencies(
    reviewed_contracts: list[tuple[AnalyzedContract, DefinitionFragment]],
    contract_fragments: dict[int, DefinitionFragment],
    in_scope_contracts: dict[int, str],
) -> tuple[tuple[DefinitionDependency, ...], tuple[FactLimitation, ...]]:
    dependencies: list[DefinitionDependency] = []
    limitations: list[FactLimitation] = []
    for contract, source in reviewed_contracts:
        for base in contract.bases:
            target = contract_fragments.get(base.target_key)
            if target is not None:
                if target != source:
                    dependencies.append(
                        DefinitionDependency(source.file, target, source, "reference", "exact", base.target_name)
                    )
                continue
            if base.target_key in in_scope_contracts:
                limitations.append(
                    FactLimitation(
                        source=source.file,
                        analyzer="slither-resolver",
                        reason=f"could not locate in-scope base contract {in_scope_contracts[base.target_key]}",
                    )
                )
    return tuple(dict.fromkeys(dependencies)), tuple(dict.fromkeys(limitations))


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
