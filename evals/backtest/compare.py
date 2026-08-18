"""Compare two evaluation results and report detection quality changes.

The comparison reports aggregate deltas, check level flips, and optional attribution
axes. When both results include run frequencies, it also reports catch rate changes
that do not cross the strict majority threshold. The Detection Quality Backtest owns
decision policy.
"""

from __future__ import annotations

import json
from pathlib import Path

_AXES = ("vulnerability", "language", "framework", "protocol")


def _load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _catch_rate(d: dict) -> dict[str, float] | None:
    """Per-issue fraction of runs that caught it, or None for a single-run result."""
    freq, runs = d.get("found_freq"), d.get("runs")
    if not freq or not runs:
        return None
    return {i: c / runs for i, c in freq.items()}


def compare(before: dict, after: dict) -> dict:
    """Return issue flips and aggregate quality deltas."""
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


def _axis_values(refs, axis: str) -> set[str]:
    """The axis labels a single issue carries from its knowledge refs.

    A guide ref like guide:frameworks/python/fastapi yields the framework fastapi,
    guide:languages/python the language python, so a flip can be grouped by what it
    exercises.
    """
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


def _attribution(target: str) -> dict[str, tuple[str, ...]]:
    """Map each issue id to its knowledge refs.

    A diff or repeated result attributes from the shipped diff benchmark library, a repository
    result from its benchmark answer key.
    """
    from evals.benchmarks.cases import diff_cases, repository_cases

    cases = diff_cases()
    idx: dict[str, tuple[str, ...]] = {c.name: c.knowledge for c in cases}
    for c in cases:
        if c.answer_key is None:
            continue
        for e in (*c.answer_key.findings, *c.answer_key.clean):
            idx[e.id] = e.knowledge or c.knowledge
    from evals.benchmarks.contract import load_answer_key

    bench = repository_cases().get(target)
    if bench is not None:
        key = load_answer_key(bench.answer_key, task_id=bench.task_id)
        for e in (*key.findings, *key.clean):
            idx[e.id] = e.knowledge
    return idx


def compare_by(before: dict, after: dict, axis: str) -> dict:
    """The flips from compare, grouped by an axis label.

    A move concentrated in one class is visible. An issue with no label on the axis groups
    under unattributed.
    """
    if axis not in _AXES:
        raise ValueError(f"unknown axis '{axis}'. Known: {', '.join(_AXES)}")
    d = compare(before, after)
    idx = _attribution(d["target"])

    def group(ids: list[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for i in ids:
            refs = idx.get(i, ())
            for v in _axis_values(refs, axis) or {"unattributed"}:
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
    """Render a comparison summary for the terminal."""
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
    """Render a comparison summary grouped by one axis."""
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
    """Load two result files and return their comparison."""
    b, a = _load(before), _load(after)
    return compare_by(b, a, axis) if axis else compare(b, a)
