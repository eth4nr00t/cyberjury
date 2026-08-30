"""Build and render the EVM profile's typed resolved graph."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cyberjury.profiles.base import content_paths
from cyberjury.profiles.evm.facts.resolver import (
    ResolvedContract,
    ResolvedFunction,
    ResolvedProject,
)
from cyberjury.review.definitions import DefinitionDependency, DefinitionFragment, dependencies_data
from cyberjury.review.facts import FactFragment, FactLimitation, Facts, FactUnitSpec
from cyberjury.review.failures import BackendUnavailable

type FactFocusFlag = Literal["external_call", "sends_eth", "can_reenter"]

_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file
_FOCUS_FLAGS = frozenset({"external_call", "sends_eth", "can_reenter"})


@dataclass(frozen=True, kw_only=True)
class EvmUnitPolicy:
    """Validated EVM attention policy supplied by the profile backend."""

    focus_flags: tuple[FactFocusFlag, ...]
    target_source_chars: int


def load_unit_policy(path: Path = _DETECTION_FILE) -> EvmUnitPolicy:
    """Load EVM unit policy without coupling graph serialization to global profile state."""
    from cyberjury.detection import load_detection_mapping

    data = load_detection_mapping(path)
    raw_flags = data.get("fact_focus_flags", [])
    if (
        not isinstance(raw_flags, list)
        or not raw_flags
        or not all(isinstance(flag, str) and flag in _FOCUS_FLAGS for flag in raw_flags)
        or len(raw_flags) != len(set(raw_flags))
    ):
        raise ValueError(f"{path} fact_focus_flags must contain unique supported EVM fact fields")
    target_chars = data.get("target_fact_unit_source_chars")
    if isinstance(target_chars, bool) or not isinstance(target_chars, int) or target_chars < 1:
        raise ValueError(f"{path} target_fact_unit_source_chars must be a positive integer")
    return EvmUnitPolicy(
        focus_flags=tuple(raw_flags),
        target_source_chars=target_chars,
    )


@dataclass(frozen=True, kw_only=True)
class Graph:
    """Store typed contract facts and exact definition dependencies."""

    contracts: tuple[ResolvedContract, ...]
    dependencies: tuple[DefinitionDependency, ...]
    limitations: tuple[FactLimitation, ...] = ()


def build_graph(resolved: ResolvedProject) -> Graph:
    """Build the typed graph from repository resolved EVM facts."""
    return Graph(
        contracts=resolved.contracts,
        dependencies=resolved.dependencies,
        limitations=resolved.limitations,
    )


def facts_from_graph(graph: Graph, *, unit_policy: EvmUnitPolicy) -> Facts:
    """Serialize one typed graph into the shared Facts dictionary contract."""
    if not graph.contracts and not graph.dependencies and not graph.limitations:
        return Facts()
    contracts = contracts_data(graph.contracts)
    data = {
        "contracts": contracts,
        "by_file": render_by_file(graph.contracts),
        "unit_specs": unit_specs_data(
            graph.contracts,
            graph.dependencies,
            focus_flags=unit_policy.focus_flags,
            max_source_chars=unit_policy.target_source_chars,
        ),
        "graph": {
            "callgraph": callgraph_data(graph.contracts),
            "syntax_imports": {},
            "imports": {},
            "references": {},
            "import_targets": {},
            "dependencies": dependencies_data(graph.dependencies),
            "unresolved_dependencies": [],
        },
    }
    return Facts(summary=render_summary(graph.contracts), data=data, limitations=graph.limitations)


def unit_specs_data(
    contracts: tuple[ResolvedContract, ...],
    dependencies: tuple[DefinitionDependency, ...],
    *,
    focus_flags: tuple[FactFocusFlag, ...],
    max_source_chars: int,
) -> list[FactUnitSpec]:
    """Pack risk functions with exact source-qualified dependency neighbors."""
    specs: list[FactUnitSpec] = []
    seen: set[frozenset[DefinitionFragment]] = set()
    for contract in contracts:
        if not contract.file:
            continue
        for function in contract.functions:
            if function.span is None or not any(getattr(function, flag) for flag in focus_flags):
                continue
            seed = DefinitionFragment(contract.file, function.name, *function.span)
            neighbors = tuple(
                dict.fromkeys(
                    endpoint
                    for dependency in dependencies
                    for endpoint in ((dependency.target,) if dependency.source == seed else ())
                    + ((dependency.source,) if dependency.target == seed and dependency.source is not None else ())
                )
            )
            fragments = [seed]
            total = seed.end - seed.start
            for neighbor in sorted(neighbors):
                size = neighbor.end - neighbor.start
                if total + size <= max_source_chars:
                    fragments.append(neighbor)
                    total += size
            identity = frozenset(fragments)
            if identity in seen:
                continue
            seen.add(identity)
            specs.append(
                {
                    "name": f"{contract.identity}.{function.name}",
                    "files": list(dict.fromkeys(fragment.file for fragment in fragments)),
                    "fragments": [FactFragment(fragment.file, fragment.start, fragment.end) for fragment in fragments],
                }
            )
    return specs


def contracts_data(contracts: tuple[ResolvedContract, ...]) -> dict[str, dict[str, object]]:
    """Serialize typed contract facts for the shared Facts payload."""
    output: dict[str, dict[str, object]] = {}
    for contract in contracts:
        if contract.identity in output:
            raise BackendUnavailable(f"multiple Solidity contracts share identity {contract.identity}")
        output[contract.identity] = {
            "name": contract.name,
            "file": contract.file,
            "range": list(contract.span) if contract.span is not None else None,
            "state": [{"name": value.name, "type": value.type_name} for value in contract.state],
            "functions": {
                function.name: {
                    "visibility": function.visibility,
                    "modifiers": list(function.modifiers),
                    "reads": list(function.reads),
                    "writes": list(function.writes),
                    "calls": list(function.calls),
                    "external_call": function.external_call,
                    "sends_eth": function.sends_eth,
                    "can_reenter": function.can_reenter,
                    "range": list(function.span) if function.span is not None else None,
                }
                for function in contract.functions
            },
        }
    return output


def render_by_file(contracts: tuple[ResolvedContract, ...]) -> dict[str, str]:
    """Render one facts block per resolved source file for unit grounding."""
    grouped: dict[str, list[ResolvedContract]] = {}
    for contract in contracts:
        if contract.file:
            grouped.setdefault(contract.file, []).append(contract)
    return {rel: render_summary(tuple(subset)) for rel, subset in grouped.items()}


def callgraph_data(
    contracts: tuple[ResolvedContract, ...],
) -> dict[str, dict[str, list[dict[str, object]]]]:
    """Serialize typed functions into the shared definition graph shape."""
    graph: dict[str, dict[str, list[dict[str, object]]]] = {}
    for contract in contracts:
        if not contract.file:
            continue
        definitions = graph.setdefault(contract.file, {})
        if contract.span is not None:
            definitions.setdefault(contract.name, []).append({"range": list(contract.span), "calls": []})
        for function in contract.functions:
            if function.span is None:
                continue
            definitions.setdefault(function.name, []).append(
                {"range": list(function.span), "calls": list(dict.fromkeys(function.calls))}
            )
    return graph


def render_summary(contracts: tuple[ResolvedContract, ...]) -> str:
    """Render compact contract facts with storage before active function flags."""
    lines: list[str] = []
    for contract in contracts:
        lines.append(f"contract {contract.name}")
        if contract.state:
            entries = ", ".join(f"{value.name} {value.type_name}" for value in contract.state)
            lines.append(f"  state: {entries}")
        for function in contract.functions:
            flags = _function_flags(function)
            modifier_text = f" [{','.join(function.modifiers)}]" if function.modifiers else ""
            lines.append(f"  {function.visibility} {function.name}{modifier_text}  {' '.join(flags)}".rstrip())
    return "\n".join(lines)


def _function_flags(function: ResolvedFunction) -> list[str]:
    flags = [
        f"{name}[{','.join(values)}]" for name in ("reads", "writes", "calls") if (values := getattr(function, name))
    ]
    flags.extend(
        label
        for name, label in (
            ("external_call", "ext-call"),
            ("sends_eth", "sends-eth"),
            ("can_reenter", "reenter"),
        )
        if getattr(function, name)
    )
    return flags
