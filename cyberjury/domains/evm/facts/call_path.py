"""Call-path unit packing from the facts call graph.

A whole-repository review splits a large file into char windows, but a cross-function logic bug
lives on a call path, not in a window, so the path is split across units or buried in a
file too large to focus on. A focused probe showed the model frames such a bug reliably
when its call path is co-located in one small window, and not when the whole file is in one
window, the dilution loses the subtle path. This module builds those focused units from the
call graph: one unit per risk-flagged function, packed with its one-hop neighborhood, the
functions it calls and the functions that call it in the same contract. Coverage of the
rest stays with the file units, this is additive.

It is a pure function over the extracted facts, so it carries no Solidity parsing and no
tool dependency, the facts backend records the source ranges and this groups them.
"""

from __future__ import annotations

# a function carrying one of these is where cross-function logic bugs live, an external
# call, value movement, or a reentrancy surface, so a focused unit anchors on it. A pure
# getter or math helper needs none, the file units already cover it
_RISK_FLAGS = ("external_call", "sends_eth", "can_reenter")

# a unit's code stays small, so the model focuses rather than diluting across a large window.
# Set above one large function plus a few callees, below the file size that loses the path
_UNIT_CHAR_CAP = 16_000


def _range(info: dict) -> list | None:
    """A function's source range, [start, end] char offsets in its file, or None when the
    backend recorded none, then the function cannot be packed by source and is skipped."""
    r = info.get("range")
    if isinstance(r, (list, tuple)) and len(r) == 2:
        return [int(r[0]), int(r[1])]
    return None


def _short(full_name: str) -> str:
    return full_name.split("(", 1)[0]


def call_path_units(contracts: dict) -> list[dict]:
    """The focused call-path units, one per risk-flagged function. Each is the anchor plus
    its one-hop callees and callers in the same contract, bounded so it stays focused, with
    a unit whose function set is contained in a larger one dropped as redundant. Returns a
    list of specs, each `{name, files, fragments}` where fragments are `[file, start, end]`
    source slices the engine reads, so the packing knowledge lives here and the engine only
    materializes units from the spec."""
    raw: list[tuple[frozenset, dict]] = []
    for cname, c in contracts.items():
        file = c.get("file") or ""
        funcs = c.get("functions") or {}
        if not file:
            continue
        callers: dict[str, list[str]] = {}
        for fn, info in funcs.items():
            for callee in info.get("calls") or ():
                callers.setdefault(callee, []).append(fn)
        for fn, info in funcs.items():
            if not any(info.get(flag) for flag in _RISK_FLAGS):
                continue
            if _range(info) is None:
                continue
            # anchor first, then its callees, then its callers, so the core path survives the
            # char cap and only the farther neighbors are dropped when a unit would grow large
            ordered = [fn]
            ordered += [c2 for c2 in (info.get("calls") or ()) if c2 in funcs and c2 not in ordered]
            ordered += [c2 for c2 in callers.get(fn, ()) if c2 in funcs and c2 not in ordered]
            picked: list[str] = []
            total = 0
            for nm in ordered:
                rng = _range(funcs[nm])
                if rng is None:
                    continue
                size = rng[1] - rng[0]
                if picked and total + size > _UNIT_CHAR_CAP:
                    continue
                picked.append(nm)
                total += size
            fragments = sorted(([file, *_range(funcs[nm])] for nm in picked), key=lambda t: t[1])
            spec = {"name": f"{file}#{cname}.{_short(fn)}", "files": [file], "fragments": fragments}
            raw.append((frozenset(picked), spec))
    # drop a unit whose function set is contained in a larger one, so a small anchor folded
    # into a bigger neighbor is not reviewed twice
    raw.sort(key=lambda x: len(x[0]), reverse=True)
    kept: list[dict] = []
    kept_sets: list[frozenset] = []
    for nameset, spec in raw:
        if any(nameset <= s for s in kept_sets):
            continue
        kept_sets.append(nameset)
        kept.append(spec)
    return kept
