"""Ground EVM reviews with call graphs, storage layouts, and access facts from Slither."""

from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury.profiles.base import content_paths
from cyberjury.review.facts import BackendUnavailable, Facts, FactsBackend, pack_unit_specs

if TYPE_CHECKING:
    from cyberjury.detection import Detection

_INSTALL_HINT = "install slither-analyzer and a Solidity compiler such as solc or Foundry to enable it"
_RISK_FLAGS = ("external_call", "sends_eth", "can_reenter")
_TARGET_FACT_UNIT_SOURCE_CHARS = 16_000
_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file


class SlitherFacts(FactsBackend):
    """Extract a call graph, storage layout, and read and write sets with Slither."""

    install_hint = _INSTALL_HINT

    def available(self) -> bool:
        """Report whether the Slither package can be imported."""
        return find_spec("slither") is not None

    def extract(self, root: str | Path) -> Facts:
        """Extract deterministic facts from the source tree."""
        if not self.available():
            raise BackendUnavailable(_INSTALL_HINT)
        from slither import Slither
        from slither.slithir.operations import InternalCall

        root_abs = Path(root).resolve()
        compile_root = _compile_root(root_abs)
        compile_input = _slither_target(root_abs, compile_root)
        widened = compile_root != root_abs
        try:
            sl = Slither(str(compile_input))
        except Exception as exc:
            raise BackendUnavailable(
                f"the Solidity compile of {compile_input} failed, so check that a compiler matching the "
                f"pragma is selected and that the project's own dependencies are installed ({exc})"
            ) from exc
        from cyberjury.detection import load_detection

        detection = load_detection(_DETECTION_FILE)
        contracts: dict = {}
        for c in sl.contracts:
            if c.is_interface:
                continue
            if not _reviewable_contract(c, root_abs, detection):
                continue
            rel_file = _rel_file(c, root_abs)
            functions: dict = {}
            for f in c.functions_declared:
                if f.name.startswith("slitherConstructor"):
                    continue
                callees = sorted(
                    {
                        op.function.full_name
                        for op in f.internal_calls
                        if isinstance(op, InternalCall) and op.function is not None
                    }
                )
                functions[f.full_name] = {
                    "visibility": f.visibility,
                    "modifiers": [m.name for m in f.modifiers],
                    "reads": sorted(v.name for v in f.state_variables_read),
                    "writes": sorted(v.name for v in f.state_variables_written),
                    "calls": callees,
                    "external_call": bool(f.high_level_calls or f.low_level_calls),
                    "sends_eth": f.can_send_eth(),
                    "can_reenter": f.can_reenter(),
                    "range": _fn_range(f),
                }
            contracts[c.name] = {
                "file": rel_file,
                "state": [{"name": v.name, "type": str(v.type)} for v in c.state_variables],
                "functions": functions,
            }
        if widened and not contracts:
            raise BackendUnavailable(
                f"the compile at {compile_root} succeeded but produced no contract under the review "
                f"scope {root_abs}, so check that the project compiles the reviewed directory"
            )
        data = {
            "contracts": contracts,
            "by_file": _by_file(contracts),
            "unit_specs": pack_unit_specs(
                contracts,
                focus_flags=_RISK_FLAGS,
                max_source_chars=_TARGET_FACT_UNIT_SOURCE_CHARS,
            ),
            "graph": {"callgraph": _callgraph(contracts), "imports": {}},
        }
        return Facts(summary=_render(contracts), data=data)


def _compile_root(review_root: Path) -> Path:
    """Use the nearest repository bounded framework root so scoped reviews retain facts."""
    from cyberjury.detection import load_detection

    markers = load_detection(_DETECTION_FILE).compile_roots
    if not markers:
        return review_root
    ancestors = [review_root, *review_root.parents]
    repository = next((d for d in ancestors if (d / ".git").exists()), None)
    if repository is None:
        return review_root
    for d in ancestors:
        if any((d / m).is_file() for m in markers):
            return d
        if d == repository:
            break
    return review_root


def _slither_target(root_abs: Path, compile_root: Path) -> Path:
    if compile_root != root_abs or root_abs.is_file() or _has_compile_config(root_abs):
        return compile_root
    sols = sorted(p for p in root_abs.rglob("*.sol") if p.is_file())
    return sols[0] if len(sols) == 1 else compile_root


def _has_compile_config(root: Path) -> bool:
    from cyberjury.detection import load_detection

    return any((root / marker).is_file() for marker in load_detection(_DETECTION_FILE).compile_roots)


def _source_path(contract) -> Path | None:
    absolute = getattr(getattr(getattr(contract, "source_mapping", None), "filename", None), "absolute", "")
    return Path(absolute).resolve() if absolute else None


def _in_scope(contract, root_abs: Path) -> bool:
    """Keep contracts without readable paths because recall outranks path precision."""
    p = _source_path(contract)
    return p is None or p.is_relative_to(root_abs)


def _reviewable_contract(contract, root_abs: Path, detection: Detection) -> bool:
    """Apply review scope and profile noise rules before emitting fact units."""
    if not _in_scope(contract, root_abs):
        return False
    rel = _rel_file(contract, root_abs)
    return not rel or not detection.is_noise_path(rel)


def _rel_file(contract, root_abs: Path) -> str:
    """Return a relative source path, with a basename fallback for pathless sources."""
    mapping = getattr(contract, "source_mapping", None)
    filename = getattr(mapping, "filename", None)
    if filename is None:
        return ""
    abs_p = _source_path(contract)
    if abs_p is not None:
        try:
            rel = abs_p.relative_to(root_abs).as_posix()
        except ValueError:
            rel = ""
        return rel if rel and rel != "." else abs_p.name
    return getattr(filename, "short", "") or getattr(filename, "used", "")


def _fn_range(function) -> list | None:
    """Expose Slither byte offsets so the engine can slice focused facts units."""
    mapping = getattr(function, "source_mapping", None)
    start = getattr(mapping, "start", None)
    length = getattr(mapping, "length", None)
    if isinstance(start, int) and isinstance(length, int):
        return [start, start + length]
    return None


def _by_file(contracts: dict) -> dict:
    """Render one facts block per resolved source file for unit grounding."""
    grouped: dict[str, dict] = {}
    for name, c in contracts.items():
        rel = c.get("file") or ""
        if not rel:
            continue
        grouped.setdefault(rel, {})[name] = c
    return {rel: _render(sub) for rel, sub in grouped.items()}


def _callgraph(contracts: dict) -> dict:
    """Project Slither's contract facts into the shared definition graph shape."""
    graph: dict[str, dict[str, list[dict]]] = {}
    for c in contracts.values():
        rel = c.get("file") or ""
        if not rel:
            continue
        defs = graph.setdefault(rel, {})
        for name, info in (c.get("functions") or {}).items():
            defs.setdefault(_graph_name(name), []).append(
                {
                    "range": info.get("range"),
                    "calls": list(dict.fromkeys(_graph_name(call) for call in info.get("calls") or ())),
                }
            )
    return graph


def _graph_name(full_name: str) -> str:
    return full_name.split("(", 1)[0]


def _render(contracts: dict) -> str:
    """Render compact contract facts with storage first and active function flags second."""
    lines: list[str] = []
    for name, c in contracts.items():
        lines.append(f"contract {name}")
        if c["state"]:
            state = ", ".join(f"{v['name']} {v['type']}" for v in c["state"])
            lines.append(f"  state: {state}")
        for fn, info in c["functions"].items():
            flags: list[str] = []
            if info["reads"]:
                flags.append(f"reads[{','.join(info['reads'])}]")
            if info["writes"]:
                flags.append(f"writes[{','.join(info['writes'])}]")
            if info["calls"]:
                flags.append(f"calls[{','.join(info['calls'])}]")
            if info["external_call"]:
                flags.append("ext-call")
            if info["sends_eth"]:
                flags.append("sends-eth")
            if info["can_reenter"]:
                flags.append("reenter")
            mods = f" [{','.join(info['modifiers'])}]" if info["modifiers"] else ""
            lines.append(f"  {info['visibility']} {fn}{mods}  {' '.join(flags)}".rstrip())
    return "\n".join(lines)
