"""Resolve analyzed EVM identities into repository paths and call endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury.profiles.base import content_paths
from cyberjury.profiles.evm.facts.analyzer import (
    AnalyzedCallArgument,
    AnalyzedCallsite,
    AnalyzedContract,
    AnalyzedFunction,
    AnalyzedParameter,
    AnalyzedProject,
    AnalyzedSource,
    AnalyzedStateVariable,
)
from cyberjury.review.definitions import CallCandidate, DefinitionFragment, StructuralCandidate
from cyberjury.review.facts import FactLimitation
from cyberjury.review.failures import BackendUnavailable

if TYPE_CHECKING:
    from cyberjury.detection import Detection

_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file


@dataclass(frozen=True, order=True, kw_only=True)
class ResolvedCallArgument:
    """Preserve one SlithIR argument expression and optional type clue."""

    position: int
    expression: str
    type_name: str = ""
    name: str = ""
    file: str = ""
    span: tuple[int, int] | None = None


@dataclass(frozen=True, order=True, kw_only=True)
class ResolvedCallsite:
    """Resolve one SlithIR callsite to repository coordinates."""

    kind: str
    expression: str
    callee: str
    receiver: str
    arguments: tuple[ResolvedCallArgument, ...]
    file: str
    span: tuple[int, int] | None
    target_key: int | None = None
    target_name: str = ""


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
    key: int = 0
    callsites: tuple[ResolvedCallsite, ...] = ()
    kind: str = "function"
    parameters: tuple[ResolvedParameter, ...] = ()


@dataclass(frozen=True, order=True, kw_only=True)
class ResolvedParameter:
    """Map one Slither parameter declaration to repository coordinates."""

    position: int
    name: str
    declaration: str
    type_name: str
    file: str
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
    """Repository identities, call candidates, and structural dependencies."""

    contracts: tuple[ResolvedContract, ...]
    call_candidates: tuple[CallCandidate, ...] = ()
    structural_candidates: tuple[StructuralCandidate, ...] = ()
    limitations: tuple[FactLimitation, ...] = ()
    sources: dict[str, str] | None = None
    producer_version: str = "unknown"


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
    """Map analyzed EVM facts into repository coordinates and candidate clues."""
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
    call_candidates, candidate_limitations = resolve_call_candidates(
        reviewed_functions,
        function_fragments,
        in_scope_functions,
    )
    structural_candidates, contract_limitations = _resolve_contract_candidates(
        reviewed_contracts,
        contract_fragments,
        in_scope_contracts,
    )
    return ResolvedProject(
        contracts=tuple(contracts),
        call_candidates=call_candidates,
        structural_candidates=tuple(dict.fromkeys(structural_candidates)),
        limitations=tuple(dict.fromkeys((*limitations, *candidate_limitations, *contract_limitations))),
        sources=_resolved_sources(source_bytes, review_root),
        producer_version=analyzed.producer_version,
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
                key=function.key,
                name=function.name,
                visibility=function.visibility,
                modifiers=function.modifiers,
                reads=function.reads,
                writes=function.writes,
                calls=tuple(dict.fromkeys(call.target_name for call in function.calls)),
                callsites=tuple(
                    _resolve_callsite(callsite, source_bytes, review_root) for callsite in function.callsites
                ),
                external_call=function.external_call,
                sends_eth=function.sends_eth,
                can_reenter=function.can_reenter,
                span=span,
                kind=function.kind,
                parameters=tuple(
                    _resolve_parameter(parameter, source_bytes, review_root) for parameter in function.parameters
                ),
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


def _resolve_callsite(
    callsite: AnalyzedCallsite,
    source_bytes: dict[Path, bytes],
    review_root: Path,
) -> ResolvedCallsite:
    return ResolvedCallsite(
        kind=callsite.kind,
        expression=callsite.expression,
        callee=callsite.callee,
        receiver=callsite.receiver,
        arguments=tuple(_resolve_call_argument(argument, source_bytes, review_root) for argument in callsite.arguments),
        file=_repository_relative_file(callsite.source, review_root),
        span=source_range(callsite.source, source_bytes),
        target_key=callsite.target_key,
        target_name=callsite.target_name,
    )


def _resolve_call_argument(
    argument: AnalyzedCallArgument,
    source_bytes: dict[Path, bytes],
    review_root: Path,
) -> ResolvedCallArgument:
    return ResolvedCallArgument(
        position=argument.position,
        expression=argument.expression,
        type_name=argument.type_name,
        name=argument.name,
        file=_repository_relative_file(argument.source, review_root),
        span=source_range(argument.source, source_bytes),
    )


def _resolve_parameter(
    parameter: AnalyzedParameter,
    source_bytes: dict[Path, bytes],
    review_root: Path,
) -> ResolvedParameter:
    return ResolvedParameter(
        position=parameter.position,
        name=parameter.name,
        declaration=parameter.declaration,
        type_name=parameter.type_name,
        file=_repository_relative_file(parameter.source, review_root),
        span=source_range(parameter.source, source_bytes),
    )


def _resolved_sources(source_bytes: dict[Path, bytes], review_root: Path) -> dict[str, str]:
    sources: dict[str, str] = {}
    for path, raw in source_bytes.items():
        if not path.is_relative_to(review_root):
            continue
        rel = path.relative_to(review_root).as_posix()
        sources[rel] = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return sources


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


def resolve_call_candidates(
    reviewed_functions: list[tuple[AnalyzedFunction, DefinitionFragment]],
    function_fragments: dict[int, DefinitionFragment],
    in_scope_functions: dict[int, str],
) -> tuple[tuple[CallCandidate, ...], tuple[FactLimitation, ...]]:
    """Map analyzed static endpoints to repository candidate definitions."""
    candidates: list[CallCandidate] = []
    limitations: list[FactLimitation] = []
    for function, source in reviewed_functions:
        for call in function.calls:
            target = function_fragments.get(call.target_key)
            if target is not None:
                if target != source:
                    candidates.append(CallCandidate(source=source, target=target, reference=call.target_name))
                continue
            if call.target_key in in_scope_functions:
                limitations.append(
                    FactLimitation(
                        source=source.file,
                        analyzer="slither-resolver",
                        reason=f"could not locate in-scope call target {in_scope_functions[call.target_key]}",
                    )
                )
    return tuple(dict.fromkeys(candidates)), tuple(dict.fromkeys(limitations))


def _resolve_contract_candidates(
    reviewed_contracts: list[tuple[AnalyzedContract, DefinitionFragment]],
    contract_fragments: dict[int, DefinitionFragment],
    in_scope_contracts: dict[int, str],
) -> tuple[tuple[StructuralCandidate, ...], tuple[FactLimitation, ...]]:
    candidates: list[StructuralCandidate] = []
    limitations: list[FactLimitation] = []
    for contract, source in reviewed_contracts:
        for base in contract.bases:
            target = contract_fragments.get(base.target_key)
            if target is not None:
                if target != source:
                    candidates.append(
                        StructuralCandidate(
                            source_file=source.file,
                            source=source,
                            target=target,
                            kind="inheritance",
                            reference=base.target_name,
                        )
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
    return tuple(dict.fromkeys(candidates)), tuple(dict.fromkeys(limitations))


def _character_offset(raw: bytes, offset: int, path: Path) -> int:
    try:
        prefix = raw[:offset].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackendUnavailable(
            f"Slither source range is not on a UTF-8 character boundary at {path}:{offset}"
        ) from exc
    return len(prefix.replace("\r\n", "\n").replace("\r", "\n"))
