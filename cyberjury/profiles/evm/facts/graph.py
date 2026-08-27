"""Build and render the EVM profile's typed resolved graph."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.profiles.evm.facts.resolver import ResolvedContract, ResolvedFunction, ResolvedProject
from cyberjury.review.definitions import DefinitionDependency, dependencies_data
from cyberjury.review.facts import FactLimitation, Facts, FactUnitSpec, pack_unit_specs
from cyberjury.review.failures import BackendUnavailable

RISK_FLAGS = ("external_call", "sends_eth", "can_reenter")
TARGET_FACT_UNIT_SOURCE_CHARS = 16_000


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


def facts_from_graph(graph: Graph) -> Facts:
    """Serialize one typed graph into the shared Facts dictionary contract."""
    contracts = contracts_data(graph.contracts)
    data = {
        "contracts": contracts,
        "by_file": render_by_file(graph.contracts),
        "unit_specs": unit_specs_data(contracts),
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


def unit_specs_data(contracts: dict[str, dict[str, object]]) -> list[FactUnitSpec]:
    """Pack each source qualified contract without cross-contract name collapse."""
    return [
        spec
        for identity, contract in contracts.items()
        for spec in pack_unit_specs(
            {identity: contract},
            focus_flags=RISK_FLAGS,
            max_source_chars=TARGET_FACT_UNIT_SOURCE_CHARS,
        )
    ]


def contracts_data(contracts: tuple[ResolvedContract, ...]) -> dict[str, dict[str, object]]:
    """Serialize typed contract facts for the shared Facts payload."""
    output: dict[str, dict[str, object]] = {}
    for contract in contracts:
        if contract.identity in output:
            raise BackendUnavailable(f"multiple Solidity contracts share identity {contract.identity}")
        output[contract.identity] = {
            "name": contract.name,
            "file": contract.file,
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
