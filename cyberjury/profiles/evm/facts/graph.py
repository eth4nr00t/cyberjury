"""Build and render the EVM profile's typed resolved graph."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cyberjury.profiles.base import content_paths
from cyberjury.profiles.evm.facts.resolver import (
    ResolvedCallArgument,
    ResolvedContract,
    ResolvedFunction,
    ResolvedParameter,
    ResolvedProject,
)
from cyberjury.review.definitions import (
    CallCandidate,
    DefinitionFragment,
    StructuralCandidate,
    call_candidates_data,
    structural_candidates_data,
)
from cyberjury.review.facts import FactFragment, FactLimitation, Facts, FactUnitSpec
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.relationships import (
    AnalysisObservation,
    ArgumentEvidence,
    CallsiteEvidence,
    DefinitionEvidence,
    ParameterEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
    StructuralRelationshipEvidence,
)

type FactFocusFlag = Literal["external_call", "sends_eth", "can_reenter"]

_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file
_FOCUS_FLAGS = frozenset({"external_call", "sends_eth", "can_reenter"})


@dataclass(frozen=True, kw_only=True)
class EvmUnitPolicy:
    """Validated EVM attention policy supplied by the profile backend."""

    focus_flags: tuple[FactFocusFlag, ...]


def load_unit_policy(path: Path = _DETECTION_FILE) -> EvmUnitPolicy:
    """Load EVM unit policy without coupling graph serialization to global profile state."""
    from cyberjury.detection import load_detection_mapping

    data = load_detection_mapping(path)
    raw_flags = data.get("fact_focus_flags", [])
    if (
        not isinstance(raw_flags, tuple)
        or not raw_flags
        or not all(isinstance(flag, str) and flag in _FOCUS_FLAGS for flag in raw_flags)
        or len(raw_flags) != len(set(raw_flags))
    ):
        raise ValueError(f"{path} fact_focus_flags must contain unique supported EVM fact fields")
    return EvmUnitPolicy(focus_flags=tuple(raw_flags))


@dataclass(frozen=True, kw_only=True)
class Graph:
    """Store typed contract facts plus call and structure candidates."""

    contracts: tuple[ResolvedContract, ...]
    call_candidates: tuple[CallCandidate, ...] = ()
    structural_candidates: tuple[StructuralCandidate, ...] = ()
    limitations: tuple[FactLimitation, ...] = ()
    sources: dict[str, str] | None = None
    producer_version: str = "unknown"


def build_graph(resolved: ResolvedProject) -> Graph:
    """Build the typed graph from repository resolved EVM facts."""
    return Graph(
        contracts=resolved.contracts,
        call_candidates=resolved.call_candidates,
        structural_candidates=resolved.structural_candidates,
        limitations=resolved.limitations,
        sources=resolved.sources,
        producer_version=resolved.producer_version,
    )


def facts_from_graph(graph: Graph, *, unit_policy: EvmUnitPolicy) -> Facts:
    """Serialize one typed graph into the shared Facts dictionary contract."""
    if not graph.contracts and not graph.call_candidates and not graph.structural_candidates and not graph.limitations:
        return Facts()
    contracts = contracts_data(graph.contracts)
    data = {
        "relationship_evidence": relationship_evidence(graph).to_data(),
        "contracts": contracts,
        "by_file": render_by_file(graph.contracts),
        "unit_specs": unit_specs_data(
            graph.contracts,
            focus_flags=unit_policy.focus_flags,
        ),
        "graph": {
            "callgraph": callgraph_data(graph.contracts),
            "syntax_imports": {},
            "imports": {},
            "references": {},
            "import_targets": {},
            "call_candidates": call_candidates_data(graph.call_candidates),
            "structural_candidates": structural_candidates_data(graph.structural_candidates),
            "structural_gaps": [],
            "dependencies": [],
            "unresolved_dependencies": [],
        },
    }
    return Facts(summary=render_summary(graph.contracts), data=data, limitations=graph.limitations)


def relationship_evidence(graph: Graph) -> RelationshipEvidenceBundle:
    """Render Slither definitions and operations as evidence, never final relations."""
    if graph.sources is None:
        return RelationshipEvidenceBundle()
    definitions: list[DefinitionEvidence] = []
    function_definitions: dict[int, DefinitionEvidence] = {}
    for contract in graph.contracts:
        if not contract.file or contract.span is None:
            continue
        owner = _source_definition(
            sources=graph.sources,
            file=contract.file,
            span=contract.span,
            kind="contract",
            name=contract.name,
            signature=contract.name,
        )
        definitions.append(owner)
        for function in contract.functions:
            if function.span is None:
                continue
            evidence = _source_definition(
                sources=graph.sources,
                file=contract.file,
                span=function.span,
                kind="modifier" if function.kind == "modifier" else "function",
                name=function.name,
                signature=function.name,
                owner_id=owner.id,
                parameters=tuple(_parameter_evidence(parameter, graph.sources) for parameter in function.parameters),
            )
            definitions.append(evidence)
            function_definitions[function.key] = evidence
    callsites: list[CallsiteEvidence] = []
    observations: list[AnalysisObservation] = []
    producer_version = graph.producer_version
    for contract in graph.contracts:
        for function in contract.functions:
            caller = function_definitions.get(function.key)
            if caller is None:
                continue
            for call in function.callsites:
                if not call.file or call.span is None or call.file not in graph.sources:
                    continue
                source = graph.sources[call.file]
                start, end = call.span
                expression = source[start:end]
                call_source = SourceReference.create(
                    path=call.file,
                    start=start,
                    end=end,
                    content=source[start:end],
                )
                arguments = tuple(_argument_evidence(argument, graph.sources) for argument in call.arguments)
                callsite = CallsiteEvidence.create(
                    caller_definition_id=caller.id,
                    source=call_source,
                    expression=expression,
                    callee_spelling=call.callee,
                    receiver_expression=call.receiver,
                    arguments=arguments,
                )
                callsites.append(callsite)
                target = function_definitions.get(call.target_key) if call.target_key is not None else None
                candidates = (target.id,) if target is not None else ()
                observations.append(
                    AnalysisObservation.create(
                        producer="slither",
                        producer_version=producer_version,
                        kind="dynamic_call" if call.kind == "low_level" else "static_call_target",
                        subject_ids=(callsite.id,),
                        candidate_target_ids=candidates,
                        provenance_source_ids=(caller.source.id, call_source.id),
                        label=f"{call.kind}: {call.target_name or call.callee}",
                    )
                )
    return RelationshipEvidenceBundle(
        sources=tuple(
            SourceReference.create(path=path, start=0, end=len(content), content=content)
            for path, content in sorted(graph.sources.items())
            if content
        ),
        definitions=tuple(definitions),
        callsites=tuple(callsites),
        observations=tuple(observations),
        structural_subjects=_structural_subjects(graph, tuple(definitions)),
    )


def _structural_subjects(
    graph: Graph,
    definitions: tuple[DefinitionEvidence, ...],
) -> tuple[StructuralRelationshipEvidence, ...]:
    by_fragment = {
        DefinitionFragment(
            definition.source.path,
            definition.name,
            definition.source.start,
            definition.source.end,
        ): definition
        for definition in definitions
    }
    grouped: dict[tuple[str, str, str], tuple[DefinitionEvidence, list[str]]] = {}
    for candidate in graph.structural_candidates:
        source = by_fragment.get(candidate.source) if candidate.source is not None else None
        target = by_fragment.get(candidate.target)
        if source is None or target is None:
            continue
        key = (candidate.source_file, candidate.kind, candidate.reference)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = (source, [target.id])
        else:
            existing[1].append(target.id)
    return tuple(
        StructuralRelationshipEvidence.create(
            kind=kind,
            source_file=source_file,
            source=source.source,
            reference=reference,
            source_definition_id=source.id,
            candidate_target_definition_ids=tuple(dict.fromkeys(target_ids)),
        )
        for (source_file, kind, reference), (source, target_ids) in sorted(grouped.items())
    )


def _argument_evidence(argument: ResolvedCallArgument, sources: dict[str, str]) -> ArgumentEvidence:
    file = argument.file
    span = argument.span
    source = None
    selected = ""
    if file in sources and isinstance(span, tuple) and len(span) == 2:
        start, end = span
        selected = sources[file][start:end]
        source = SourceReference.create(path=file, start=start, end=end, content=selected)
    expression = argument.expression or selected or None
    return ArgumentEvidence(
        position=argument.position,
        expression=expression,
        name=argument.name,
        type_name=argument.type_name,
        source=source,
    )


def _source_definition(
    *,
    sources: dict[str, str],
    file: str,
    span: tuple[int, int],
    kind: str,
    name: str,
    signature: str,
    owner_id: str = "",
    parameters: tuple[ParameterEvidence, ...] = (),
) -> DefinitionEvidence:
    if file not in sources:
        raise BackendUnavailable(f"missing normalized Solidity source for {file}")
    start, end = span
    source = SourceReference.create(path=file, start=start, end=end, content=sources[file][start:end])
    return DefinitionEvidence.create(
        source=source,
        kind=kind,
        name=name,
        signature=signature,
        owner_id=owner_id,
        parameters=parameters,
    )


def _parameter_evidence(parameter: ResolvedParameter, sources: dict[str, str]) -> ParameterEvidence:
    if not parameter.file or parameter.span is None or parameter.file not in sources:
        raise BackendUnavailable(f"missing source range for Solidity parameter {parameter.name}")
    start, end = parameter.span
    source_text = sources[parameter.file]
    selected = source_text[start:end]
    source = SourceReference.create(path=parameter.file, start=start, end=end, content=selected)
    return ParameterEvidence.create(
        position=parameter.position,
        name=parameter.name,
        source=source,
        declaration=selected or parameter.declaration,
        type_name=parameter.type_name,
    )


def unit_specs_data(
    contracts: tuple[ResolvedContract, ...],
    *,
    focus_flags: tuple[FactFocusFlag, ...],
) -> list[FactUnitSpec]:
    """Emit risk function seeds before model relationships add neighbors."""
    specs: list[FactUnitSpec] = []
    seen: set[frozenset[DefinitionFragment]] = set()
    for contract in contracts:
        if not contract.file:
            continue
        for function in contract.functions:
            if function.span is None or not any(getattr(function, flag) for flag in focus_flags):
                continue
            seed = DefinitionFragment(contract.file, function.name, *function.span)
            fragments = [seed]
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
        (f"call-target-clues[{','.join(values)}]" if name == "calls" else f"{name}[{','.join(values)}]")
        for name in ("reads", "writes", "calls")
        if (values := getattr(function, name))
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
