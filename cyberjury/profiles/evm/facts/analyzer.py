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
class AnalyzedEndpoint:
    """One exact Slither relationship endpoint before repository resolution."""

    target_key: int
    target_name: str


@dataclass(frozen=True, kw_only=True)
class AnalyzedCall(AnalyzedEndpoint):
    """One exact function or modifier call endpoint."""


@dataclass(frozen=True, kw_only=True)
class AnalyzedBaseReference(AnalyzedEndpoint):
    """One exact base-contract endpoint."""


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
    key: int = 0
    bases: tuple[AnalyzedBaseReference, ...] = ()


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
    normalized = tuple(
        sorted(
            (_normalize_contract(contract, internal_call_type) for contract in contracts),
            key=lambda contract: contract.identity,
        )
    )
    identities = [contract.identity for contract in normalized]
    if len(identities) != len(set(identities)):
        raise BackendUnavailable("Slither returned contracts without distinct source identities")
    return AnalyzedProject(contracts=normalized)


def _normalize_contract(contract: object, internal_call_type: type) -> AnalyzedContract:
    raw_functions = tuple(
        {
            id(function): function
            for function in (
                *getattr(contract, "functions_declared", ()),
                *getattr(contract, "modifiers_declared", ()),
            )
        }.values()
    )
    functions = tuple(
        sorted(
            (
                _normalize_function(function, internal_call_type)
                for function in raw_functions
                if not str(getattr(function, "name", "")).startswith("slitherConstructor")
            ),
            key=lambda function: (_source_sort_key(function.source), function.name, function.key),
        )
    )
    function_identities = [
        (
            function.name,
            function.source.absolute,
            function.source.used,
            function.source.short,
            function.source.start,
            function.source.length,
        )
        for function in functions
    ]
    if len(function_identities) != len(set(function_identities)):
        raise BackendUnavailable("Slither returned functions without distinct source identities")
    state = tuple(
        sorted(
            (
                AnalyzedStateVariable(name=str(variable.name), type_name=str(variable.type))
                for variable in getattr(contract, "state_variables", ())
            ),
            key=lambda variable: (variable.name, variable.type_name),
        )
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
        key=id(contract),
        bases=tuple(
            AnalyzedBaseReference(target_key=id(base), target_name=str(getattr(base, "name", "")))
            for base in sorted(
                getattr(contract, "immediate_inheritance", ()) or getattr(contract, "inheritance", ()),
                key=_raw_identity,
            )
            if getattr(base, "name", "")
        ),
    )


def _contract_identity(name: str, source: AnalyzedSource) -> str:
    location = (source.absolute or source.used or source.short).replace("\\", "/")
    return f"{location}::{name}" if location else name


def _normalize_function(function: object, internal_call_type: type) -> AnalyzedFunction:
    targets = _call_targets(function, internal_call_type)
    calls = tuple(
        AnalyzedCall(target_key=id(target), target_name=str(target.full_name))
        for target in targets
        if getattr(target, "full_name", "")
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
    targets.extend(getattr(function, "modifiers", ()))
    unique: dict[int, object] = {}
    for target in targets:
        unique.setdefault(id(target), target)
    return tuple(sorted(unique.values(), key=_raw_identity))


def _raw_identity(value: object) -> tuple[str, int, int, str, str]:
    source = _source(value)
    owner = getattr(value, "contract_declarer", None) or getattr(value, "contract", None)
    return (
        source.absolute or source.used or source.short,
        source.start if isinstance(source.start, int) else -1,
        source.length if isinstance(source.length, int) else -1,
        str(getattr(owner, "name", "")),
        str(getattr(value, "full_name", "") or getattr(value, "name", "")),
    )


def _source_sort_key(source: AnalyzedSource) -> tuple[str, int, int]:
    return (
        source.absolute or source.used or source.short,
        source.start if isinstance(source.start, int) else -1,
        source.length if isinstance(source.length, int) else -1,
    )
