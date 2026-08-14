"""Pack risk flagged EVM call paths into focused additive review units."""

from __future__ import annotations

_RISK_FLAGS = ("external_call", "sends_eth", "can_reenter")

_TARGET_CALL_PATH_SOURCE_CHARS = 16_000


def _range(info: dict) -> list | None:
    r = info.get("range")
    if isinstance(r, (list, tuple)) and len(r) == 2:
        return [int(r[0]), int(r[1])]
    return None


def _short(full_name: str) -> str:
    return full_name.split("(", 1)[0]


def call_path_units(contracts: dict) -> list[dict]:
    """Pack each risk flagged function with its bounded one hop call neighborhood."""
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
                if picked and total + size > _TARGET_CALL_PATH_SOURCE_CHARS:
                    continue
                picked.append(nm)
                total += size
            fragments = sorted(([file, *_range(funcs[nm])] for nm in picked), key=lambda t: t[1])
            spec = {"name": f"{file}#{cname}.{_short(fn)}", "files": [file], "fragments": fragments}
            raw.append((frozenset(picked), spec))
    raw.sort(key=lambda x: len(x[0]), reverse=True)
    kept: list[dict] = []
    kept_sets: list[frozenset] = []
    for nameset, spec in raw:
        if any(nameset <= s for s in kept_sets):
            continue
        kept_sets.append(nameset)
        kept.append(spec)
    return kept
