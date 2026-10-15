"""Compare two evaluation results and report detection quality changes.

The comparison reports aggregate deltas and check level flips of strict results. When
both results include run frequencies, it also reports catch rate changes that do not
cross the strict majority threshold. The gate owns decision policy.
"""

from __future__ import annotations

import json
from pathlib import Path


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
    if before.get("target") != after.get("target") or not before.get("target"):
        raise ValueError("comparison arms must identify the same nonempty target")
    if "n_findings" in before and "n_findings" in after and before["n_findings"] != after["n_findings"]:
        raise ValueError("comparison arms use different findings denominators")
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


def format_compare(d: dict) -> str:
    """Render a comparison summary for the terminal."""
    lines = [
        f"=== compare: {d['target']} ===",
        "  raw location matches, not source reviewed; adjudication is the measure of record",
        f"  raw match rate {d['recall_before']:.0%} -> {d['recall_after']:.0%}",
        f"  raw known-check precision {d['precision_before']:.0%} -> {d['precision_after']:.0%}",
    ]
    for label, key in (
        ("newly raw matched", "newly_found"),
        ("newly raw unmatched", "newly_missed"),
        ("new raw match on clean check", "newly_false_positive"),
        ("cleared raw match on clean check", "fixed_false_positive"),
    ):
        if d[key]:
            lines.append(f"  {label}: {', '.join(d[key])}")
    for m in d.get("catch_rate_changed", []):
        lines.append(f"  raw match rate moved: {m['id']} {m['before']:.0%} -> {m['after']:.0%}")
    return "\n".join(lines)


def compare_files(before: str | Path, after: str | Path) -> dict:
    """Load two result files and return their comparison."""
    return compare(_load(before), _load(after))
