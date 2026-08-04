"""Slither-backed facts for the evm domain, grounding contract review in a call graph,
storage layout, and per-function read and write sets. It needs a Solidity compiler at runtime,
availability is lazy-checked so importing the domain never needs the compiler, and Slither
itself is imported only inside extract.

A backend that cannot run fails loud rather than returning empty facts that would read as a
clean review, invariant 4. A missing toolchain and a compile that produces nothing usable both
raise BackendUnavailable, the second carrying the compiler's own message.
"""

from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path

from cyberjury.domains.base import BackendUnavailable, Facts, FactsBackend
from cyberjury.domains.evm.facts.call_path import call_path_units

_INSTALL_HINT = "install slither-analyzer and a Solidity compiler such as solc or Foundry to enable it"


class SlitherFacts(FactsBackend):
    """Extract a call graph, storage layout, and read and write sets with Slither."""

    install_hint = _INSTALL_HINT

    def available(self) -> bool:
        return find_spec("slither") is not None

    def extract(self, root: str | Path) -> Facts:
        if not self.available():
            raise BackendUnavailable(_INSTALL_HINT)
        from slither import Slither
        from slither.slithir.operations import InternalCall

        root_abs = Path(root).resolve()
        try:
            sl = Slither(str(root))
        except Exception as exc:
            # Slither is installed but the Solidity compile produced nothing usable, an absent or
            # broken solc, a solc-select shim with no version selected, or a pragma mismatch. That
            # is an unusable toolchain, not a clean empty review, so fail loud as unavailable
            # rather than crash the caller with the raw compiler error, invariant 4.
            raise BackendUnavailable(
                f"the Solidity compile failed, install a Solidity compiler such as solc or Foundry, or "
                f"select a version matching the pragma ({exc})"
            ) from exc
        contracts: dict = {}
        for c in sl.contracts:
            if c.is_interface:
                continue
            functions: dict = {}
            for f in c.functions_declared:
                # skip the pseudo functions Slither synthesizes for state variable initializers
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
                "file": _rel_file(c, root_abs),
                "state": [{"name": v.name, "type": str(v.type)} for v in c.state_variables],
                "functions": functions,
            }
        data = {
            "contracts": contracts,
            "by_file": _by_file(contracts),
            "units": call_path_units(contracts),
        }
        return Facts(summary=_render(contracts), data=data)


def _rel_file(contract, root_abs: Path) -> str:
    """The contract's source file relative to the review root, the key the engine joins a
    unit's files on. Falls back to the basename when the file is the root itself, a
    review of a single file, or lies outside the root, such as a dependency, so the entry
    is still labeled and a basename match still grounds the unit."""
    mapping = getattr(contract, "source_mapping", None)
    filename = getattr(mapping, "filename", None)
    if filename is None:
        return ""
    absolute = getattr(filename, "absolute", "")
    if absolute:
        abs_p = Path(absolute).resolve()
        try:
            rel = abs_p.relative_to(root_abs).as_posix()
        except ValueError:
            rel = ""
        # relative_to yields "." when the root is the file itself, then the name relative to
        # the repository is just the basename, the form a unit's files take
        return rel if rel and rel != "." else abs_p.name
    return getattr(filename, "short", "") or getattr(filename, "used", "")


def _fn_range(function) -> list | None:
    """A function's source range as [start, end] char offsets in its file, so the engine can
    slice the body for a call-path unit without parsing Solidity. None when Slither recorded
    no mapping, then the function cannot be packed by source."""
    mapping = getattr(function, "source_mapping", None)
    start = getattr(mapping, "start", None)
    length = getattr(mapping, "length", None)
    if isinstance(start, int) and isinstance(length, int):
        return [start, start + length]
    return None


def _by_file(contracts: dict) -> dict:
    """Group the contracts by source file and render one facts block per file, so the engine
    can ground a unit with only the facts for the files it owns. A file with no resolved path
    is dropped from the map, it has no unit to join."""
    grouped: dict[str, dict] = {}
    for name, c in contracts.items():
        rel = c.get("file") or ""
        if not rel:
            continue
        grouped.setdefault(rel, {})[name] = c
    return {rel: _render(sub) for rel, sub in grouped.items()}


def _render(contracts: dict) -> str:
    """A compact, model-readable rendering of the facts, one block per contract. It leads
    with the storage layout, then a line per function carrying only the flags that hold, so
    the reentrancy, access-control, and accounting signals are visible without the model
    rereading the whole tree."""
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
