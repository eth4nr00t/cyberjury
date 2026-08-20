"""Normalize Slither output into typed EVM graph inputs."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path

from cyberjury.review.failures import BackendUnavailable

INSTALL_HINT = "install slither-analyzer and a Solidity compiler such as solc or Foundry to enable it"


@dataclass(frozen=True, kw_only=True)
class AnalyzedSource:
    """Normalized source identity and optional byte range from Slither."""

    absolute: str = ""
    short: str = ""
    used: str = ""
    start: int | None = None
    length: int | None = None


@dataclass(frozen=True, kw_only=True)
class AnalyzedCall:
    """One exact Slither call endpoint before repository resolution."""

    target_key: int
    target_name: str


@dataclass(frozen=True, kw_only=True)
class AnalyzedFunction:
    """One Solidity function normalized from Slither analysis."""

    key: int
    name: str
    visibility: str
    modifiers: tuple[str, ...]
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    calls: tuple[AnalyzedCall, ...]
    external_call: bool
    sends_eth: bool
    can_reenter: bool
    source: AnalyzedSource


@dataclass(frozen=True, kw_only=True)
class AnalyzedStateVariable:
    """One contract storage declaration normalized from Slither."""

    name: str
    type_name: str


@dataclass(frozen=True, kw_only=True)
class AnalyzedContract:
    """One Solidity contract normalized before repository scope resolution."""

    identity: str
    name: str
    is_interface: bool
    source: AnalyzedSource
    state: tuple[AnalyzedStateVariable, ...]
    functions: tuple[AnalyzedFunction, ...]


@dataclass(frozen=True, kw_only=True)
class AnalyzedProject:
    """Typed EVM facts extracted from one complete Slither analysis."""

    contracts: tuple[AnalyzedContract, ...]


def available() -> bool:
    """Report whether Slither can be imported."""
    return find_spec("slither") is not None


def analyze(compile_input: Path) -> AnalyzedProject:
    """Compile and normalize one Solidity project or fail loud."""
    from slither import Slither
    from slither.slithir.operations import InternalCall

    try:
        slither = Slither(str(compile_input))
    except Exception as exc:
        raise BackendUnavailable(
            f"the Solidity compile of {compile_input} failed, so check that a compiler matching the "
            f"pragma is selected and that the project's own dependencies are installed: {exc}"
        ) from exc
    return normalize_analysis(tuple(slither.contracts), InternalCall)


def normalize_analysis(contracts: tuple[object, ...], internal_call_type: type) -> AnalyzedProject:
    """Convert raw Slither contracts into the local typed analysis contract."""
    normalized = tuple(_normalize_contract(contract, internal_call_type) for contract in contracts)
    identities = [contract.identity for contract in normalized]
    if len(identities) != len(set(identities)):
        raise BackendUnavailable("Slither returned contracts without distinct source identities")
    return AnalyzedProject(contracts=normalized)


def _normalize_contract(contract: object, internal_call_type: type) -> AnalyzedContract:
    functions = tuple(
        _normalize_function(function, internal_call_type)
        for function in getattr(contract, "functions_declared", ())
        if not str(getattr(function, "name", "")).startswith("slitherConstructor")
    )
    state = tuple(
        AnalyzedStateVariable(name=str(variable.name), type_name=str(variable.type))
        for variable in getattr(contract, "state_variables", ())
    )
    name = str(contract.name)
    source = _source(contract)
    return AnalyzedContract(
        identity=_contract_identity(name, source),
        name=name,
        is_interface=bool(getattr(contract, "is_interface", False)),
        source=source,
        state=state,
        functions=functions,
    )


def _contract_identity(name: str, source: AnalyzedSource) -> str:
    location = (source.absolute or source.used or source.short).replace("\\", "/")
    return f"{location}::{name}" if location else name


def _normalize_function(function: object, internal_call_type: type) -> AnalyzedFunction:
    targets = _call_targets(function, internal_call_type)
    calls = tuple(
        sorted(
            (
                AnalyzedCall(target_key=id(target), target_name=str(target.full_name))
                for target in targets
                if getattr(target, "full_name", "")
            ),
            key=lambda call: (call.target_name, call.target_key),
        )
    )
    return AnalyzedFunction(
        key=id(function),
        name=str(function.full_name),
        visibility=str(function.visibility),
        modifiers=tuple(str(modifier.name) for modifier in function.modifiers),
        reads=tuple(sorted(str(variable.name) for variable in function.state_variables_read)),
        writes=tuple(sorted(str(variable.name) for variable in function.state_variables_written)),
        calls=calls,
        external_call=bool(function.high_level_calls or function.low_level_calls),
        sends_eth=bool(function.can_send_eth()),
        can_reenter=bool(function.can_reenter()),
        source=_source(function),
    )


def _source(value: object) -> AnalyzedSource:
    mapping = getattr(value, "source_mapping", None)
    filename = getattr(mapping, "filename", None)
    return AnalyzedSource(
        absolute=str(getattr(filename, "absolute", "") or ""),
        short=str(getattr(filename, "short", "") or ""),
        used=str(getattr(filename, "used", "") or ""),
        start=getattr(mapping, "start", None),
        length=getattr(mapping, "length", None),
    )


def _call_targets(function: object, internal_call_type: type) -> tuple[object, ...]:
    targets = [
        operation.function
        for operation in function.internal_calls
        if isinstance(operation, internal_call_type) and operation.function is not None
    ]
    targets.extend(
        call[1]
        for call in function.high_level_calls
        if isinstance(call, tuple) and len(call) == 2 and call[1] is not None
    )
    unique: dict[int, object] = {}
    for target in targets:
        unique.setdefault(id(target), target)
    return tuple(unique.values())
