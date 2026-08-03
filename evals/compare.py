"""Compare two eval results, the heart of judging a change.

A single score cannot tell an improvement from noise between runs, the review is not
deterministic. The standard is a move that holds across repeated runs: recall up or level
and precision level or up, beyond the noise band, with the per-issue flips naming exactly
which planted issues were newly caught or newly lost. This reads two `Result` json files
and reports those flips and the deltas, so a knowledge or prompt change is judged on what
actually moved, not on one aggregate number. With `--by` it groups the flips by an axis,
vulnerability, language, framework, protocol, or tag, so a move concentrated in one class
is visible. When both sides carry run frequency it also reports a sub-threshold catch-rate
move, an issue that grew flakier or steadier without the majority verdict flipping.
"""

from __future__ import annotations

import json
from pathlib import Path

_AXES = ("vulnerability", "language", "framework", "protocol", "tag")


def _load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _catch_rate(d: dict) -> dict[str, float] | None:
    """Per-issue fraction of runs that caught it, or None for a single-run result."""
    freq, runs = d.get("found_freq"), d.get("runs")
    if not freq or not runs:
        return None
    return {i: c / runs for i, c in freq.items()}


def compare(before: dict, after: dict) -> dict:
    bf, af = set(before.get("found", [])), set(after.get("found", []))
    bfp, afp = set(before.get("false_positives", [])), set(after.get("false_positives", []))
    out = {
        "target": after.get("target", before.get("target", "")),
        "recall_before": before.get("recall", 0.0),
        "recall_after": after.get("recall", 0.0),
        "precision_before": before.get("precision_known", 0.0),
        "precision_after": after.get("precision_known", 0.0),
        "newly_found": sorted(af - bf),
        "newly_missed": sorted(bf - af),
        "newly_false_positive": sorted(afp - bfp),
        "fixed_false_positive": sorted(bfp - afp),
    }
    rb, ra = _catch_rate(before), _catch_rate(after)
    if rb is not None and ra is not None:
        flipped = set(out["newly_found"]) | set(out["newly_missed"])
        moved = []
        for i in sorted(set(rb) | set(ra)):
            x, y = round(rb.get(i, 0.0), 3), round(ra.get(i, 0.0), 3)
            if i not in flipped and x != y:
                moved.append({"id": i, "before": x, "after": y})
        out["catch_rate_changed"] = moved
    return out


def _axis_values(refs, tags, axis: str) -> set[str]:
    """The axis labels a single issue carries, from its knowledge refs and tags. A guide ref
    like guide:frameworks/python/fastapi yields the framework fastapi, guide:languages/python
    the language python, so a flip can be grouped by what it exercises."""
    if axis == "tag":
        return set(tags)
    if axis == "vulnerability":
        return {r.split(":", 1)[1] for r in refs if r.startswith("vuln:")}
    bucket = {"language": "languages", "framework": "frameworks", "protocol": "protocols"}.get(axis)
    out: set[str] = set()
    for r in refs:
        if not r.startswith("guide:"):
            continue
        parts = r.split(":", 1)[1].split("/")
        if parts[0] == bucket:
            out.add(parts[-1])
    return out


def _attribution(target: str) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """Map each issue id to its knowledge refs and tags. A diff or suite result attributes
    from the shipped case library, a repository result from its benchmark answer key."""
    from evals.diff_cases import default_cases

    idx: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {c.name: (c.knowledge, c.tags) for c in default_cases()}
    try:
        from evals.registry import find_benchmark
        from evals.schema import load_answer_key

        bench = find_benchmark(target)
        key = load_answer_key(bench.answer_key)
        for e in (*key.planted, *key.safe):
            idx[e.id] = (e.knowledge, bench.tags)
    except ValueError:
        pass  # the target is the diff probe or a suite, not a benchmark name
    return idx


def compare_by(before: dict, after: dict, axis: str) -> dict:
    """The flips from compare, grouped by an axis label so a move concentrated in one class
    is visible. An issue with no label on the axis groups under unattributed."""
    if axis not in _AXES:
        raise ValueError(f"unknown axis '{axis}'. Known: {', '.join(_AXES)}")
    d = compare(before, after)
    idx = _attribution(d["target"])

    def group(ids: list[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for i in ids:
            refs, tags = idx.get(i, ((), ()))
            for v in _axis_values(refs, tags, axis) or {"unattributed"}:
                out.setdefault(v, []).append(i)
        return {k: sorted(v) for k, v in sorted(out.items())}

    return {
        "axis": axis,
        "target": d["target"],
        "newly_found": group(d["newly_found"]),
        "newly_missed": group(d["newly_missed"]),
        "newly_false_positive": group(d["newly_false_positive"]),
    }


def format_compare(d: dict) -> str:
    lines = [
        f"=== compare: {d['target']} ===",
        f"  recall    {d['recall_before']:.0%} -> {d['recall_after']:.0%}",
        f"  precision {d['precision_before']:.0%} -> {d['precision_after']:.0%}",
    ]
    for label, key in (
        ("newly found", "newly_found"),
        ("newly MISSED", "newly_missed"),
        ("new false positive", "newly_false_positive"),
        ("fixed false positive", "fixed_false_positive"),
    ):
        if d[key]:
            lines.append(f"  {label}: {', '.join(d[key])}")
    for m in d.get("catch_rate_changed", []):
        lines.append(f"  catch rate moved: {m['id']} {m['before']:.0%} -> {m['after']:.0%}")
    return "\n".join(lines)


def format_compare_by(d: dict) -> str:
    lines = [f"=== compare: {d['target']} by {d['axis']} ==="]
    for label, key in (
        ("newly found", "newly_found"),
        ("newly MISSED", "newly_missed"),
        ("new false positive", "newly_false_positive"),
    ):
        groups = d[key]
        if not groups:
            continue
        lines.append(f"  {label}:")
        for value, ids in groups.items():
            lines.append(f"    {value}: {', '.join(ids)}")
    if len(lines) == 1:
        lines.append("  no flips")
    return "\n".join(lines)


def compare_files(before: str | Path, after: str | Path, axis: str | None = None) -> dict:
    b, a = _load(before), _load(after)
    return compare_by(b, a, axis) if axis else compare(b, a)
