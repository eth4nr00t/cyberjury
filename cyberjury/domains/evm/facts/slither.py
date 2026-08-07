"""Slither-backed facts for the evm domain, grounding contract review in a call graph.

storage layout, and per-function read and write sets. It needs a Solidity compiler at
runtime, availability is lazy-checked so importing the domain never needs the compiler,
and Slither itself is imported only inside extract. A backend that cannot run fails loud
rather than returning empty facts that would read as a clean review, invariant 4. A
missing toolchain and a compile that produces nothing usable both raise
BackendUnavailable, the second carrying the compiler's own message.
"""

from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path

from cyberjury.domains.base import BackendUnavailable, Facts, FactsBackend, content_paths
from cyberjury.domains.evm.facts.call_path import call_path_units

_INSTALL_HINT = "install slither-analyzer and a Solidity compiler such as solc or Foundry to enable it"
_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file


class SlitherFacts(FactsBackend):
    """Extract a call graph, storage layout, and read and write sets with Slither."""

    install_hint = _INSTALL_HINT

    def available(self) -> bool:
        """Return whether the result."""
        return find_spec("slither") is not None

    def extract(self, root: str | Path) -> Facts:
        """Extract deterministic facts from the source tree."""
        if not self.available():
            raise BackendUnavailable(_INSTALL_HINT)
        from slither import Slither
        from slither.slithir.operations import InternalCall

        root_abs = Path(root).resolve()
        compile_root = _compile_root(root_abs)
        widened = compile_root != root_abs
        try:
            sl = Slither(str(compile_root))
        except Exception as exc:
            raise BackendUnavailable(
                f"the Solidity compile of {compile_root} failed, so check that a compiler matching the "
                f"pragma is selected and that the project's own dependencies are installed ({exc})"
            ) from exc
        contracts: dict = {}
        for c in sl.contracts:
            if c.is_interface:
                continue
            if widened and not _in_scope(c, root_abs):
                continue
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
                "file": _rel_file(c, root_abs),
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
            "units": call_path_units(contracts),
        }
        return Facts(summary=_render(contracts), data=data)


def _compile_root(review_root: Path) -> Path:
    """Where the toolchain has to compile from, which is not always what is under review.

    crytic-compile recognizes a framework by its config file, so a review scoped to a
    subdirectory of a Hardhat or Foundry project compiles nothing and the review silently
    loses its facts. Walk up to the nearest ancestor carrying one of the domain's
    `compile_roots`. The repository, the directory holding `.git`, bounds the walk. Without
    one there is nothing to say where the project ends, so a tree that has no repository is
    compiled where it sits rather than risk selecting a config that belongs to something
    else. A framework project unpacked without its history and reviewed at a subdirectory
    therefore still loses its facts, which is the safe half of that trade.
    """
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


def _source_path(contract) -> Path | None:
    absolute = getattr(getattr(getattr(contract, "source_mapping", None), "filename", None), "absolute", "")
    return Path(absolute).resolve() if absolute else None


def _in_scope(contract, root_abs: Path) -> bool:
    """A contract Slither recorded no path for counts as in scope.

    Recall is the first red line, so an entry whose location cannot be read is kept rather
    than dropped on an assumption, invariant 2.
    """
    p = _source_path(contract)
    return p is None or p.is_relative_to(root_abs)


def _rel_file(contract, root_abs: Path) -> str:
    """The contract's source file relative to the review root.

    the key the engine joins a unit's files on. Falls back to the basename when the file is
    the root itself, a review of a single file, or lies outside the root, such as a
    dependency, so the entry is still labeled and a basename match still grounds the unit.
    """
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
    """A function's source range as [start, end] char offsets in its file.

    so the engine can slice the body for a call-path unit without parsing Solidity. None
    when Slither recorded no mapping, then the function cannot be packed by source.
    """
    mapping = getattr(function, "source_mapping", None)
    start = getattr(mapping, "start", None)
    length = getattr(mapping, "length", None)
    if isinstance(start, int) and isinstance(length, int):
        return [start, start + length]
    return None


def _by_file(contracts: dict) -> dict:
    """Group the contracts by source file and render one facts block per file.

    so the engine can ground a unit with only the facts for the files it owns. A file with
    no resolved path is dropped from the map, it has no unit to join.
    """
    grouped: dict[str, dict] = {}
    for name, c in contracts.items():
        rel = c.get("file") or ""
        if not rel:
            continue
        grouped.setdefault(rel, {})[name] = c
    return {rel: _render(sub) for rel, sub in grouped.items()}


def _render(contracts: dict) -> str:
    """A compact, model-readable rendering of the facts, one block per contract.

    It leads with the storage layout, then a line per function carrying only the flags that
    hold, so the reentrancy, access-control, and accounting signals are visible without the
    model rereading the whole tree.
    """
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
