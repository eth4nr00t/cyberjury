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
        pass
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


_FAILED_CALLS = ("errors", "verify_errors")
_KEPT_FINDINGS = ("incomplete", "unlocatable")
_COMPLETENESS_KEYS = _FAILED_CALLS + _KEPT_FINDINGS

_COST_KEYS = (
    "model_requests",
    "total_input_tokens",
    "uncached_input_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "output_tokens",
    "unit_review_calls",
)


_STAGE_FILES = (("run", "_run.json"), ("finalize", "_finalize.json"))


def _arm_artifacts(workspace: str | Path) -> dict:
    """One arm's completeness and cost, per stage and in total.

    Per stage as well as summed, because the stages answer different questions: a change to the
    reviewer moves the run's cost while a change to verification moves finalize's, and a single
    total hides which one moved.

    A review scoped to a subdirectory writes under a leaf directory, so the files are found by
    search rather than at a fixed path."""
    ws = Path(workspace)
    stages: dict = {}
    totals: dict = {"completeness": dict.fromkeys(_COMPLETENESS_KEYS, 0), "cost": {}}
    files: list[str] = []
    for stage, name in _STAGE_FILES:
        for path in sorted(ws.rglob(name)):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            files.append(name)
            entry = stages.setdefault(stage, {"completeness": {}, "cost": {}})
            for key in _COMPLETENESS_KEYS:
                if key in data:
                    value = int(data.get(key) or 0)
                    entry["completeness"][key] = entry["completeness"].get(key, 0) + value
                    if key in _FAILED_CALLS:
                        totals["completeness"][key] += value
                    else:
                        totals["completeness"][key] = value
            usage = data.get("usage") or {}
            for key in _COST_KEYS:
                if key in usage:
                    value = int(usage[key] or 0)
                    entry["cost"][key] = entry["cost"].get(key, 0) + value
                    totals["cost"][key] = totals["cost"].get(key, 0) + value
            seconds = (data.get("timing") or {}).get("total_seconds")
            if seconds is not None:
                entry["cost"]["seconds"] = round(entry["cost"].get("seconds", 0) + float(seconds), 1)
                totals["cost"]["seconds"] = round(totals["cost"].get("seconds", 0) + float(seconds), 1)
    return {"stages": stages, "timeline": _timeline_seconds(ws), **totals, "files": files}


def _timeline_seconds(ws: Path) -> dict[str, float]:
    """Elapsed per pipeline stage, so scaffold and gate are visible too, not only the two stages
    that write a usage record."""
    out: dict[str, float] = {}
    for path in sorted(ws.rglob("_timeline.json")):
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            stage = str(record.get("stage") or "?")
            out[stage] = round(out.get(stage, 0.0) + float(record.get("seconds") or 0), 1)
    return out


def with_arms(result: dict, before_workspace: str | Path | None, after_workspace: str | Path | None) -> dict:
    """Fold each arm's completeness and cost into a quality comparison.

    Recall alone cannot judge a change: one that holds recall while multiplying spend is a
    different decision than one that holds both, so the cost travels with the verdict rather than
    being looked up separately afterwards."""
    out = dict(result)
    for side, ws in (("before", before_workspace), ("after", after_workspace)):
        if ws is None:
            continue
        arm = _arm_artifacts(ws)
        out[f"{side}_completeness"] = arm["completeness"]
        out[f"{side}_cost"] = arm["cost"]
        out[f"{side}_stages"] = arm["stages"]
        out[f"{side}_timeline"] = arm["timeline"]
        out[f"{side}_artifacts"] = arm["files"]
    out["comparable"], out["not_comparable_because"] = _comparable(out)
    return out


def _comparable(d: dict) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    for side in ("before", "after"):
        counts = d.get(f"{side}_completeness")
        if counts is None:
            continue
        if f"{side}_artifacts" in d and not d[f"{side}_artifacts"]:
            reasons.append(f"{side} arm wrote no _run.json or _finalize.json, so it may not have run")
            continue
        for key, value in counts.items():
            if value:
                reasons.append(f"{side} arm records {value} {key}")
    return not reasons, reasons


def _fmt_cost(cost: dict) -> str:
    """One stage's spend on one line. `seconds` is left out, the caller prints it in its own column
    so a stage that spends no tokens still shows its elapsed."""
    parts = [f"{key}={cost[key]}" for key in _COST_KEYS if key in cost]
    return " ".join(parts) if parts else "no model calls"


def _stage_seconds(d: dict, side: str, stage: str) -> float | None:
    """A stage's elapsed, from the workspace timeline or else from the stage's own record.

    The timeline is preferred because it spans every command including scaffold and gate, but only
    the CLI writes it, and a workspace produced any other way still records its own elapsed."""
    secs = (d.get(f"{side}_timeline") or {}).get(stage)
    if secs is not None:
        return float(secs)
    own = ((d.get(f"{side}_stages") or {}).get(stage) or {}).get("cost") or {}
    return float(own["seconds"]) if "seconds" in own else None


def format_arms(d: dict) -> str:
    """The cost and completeness half of the record, printed under the quality half."""
    lines: list[str] = []
    for stage in ("scaffold", "run", "finalize", "gate"):
        block: list[str] = []
        for side in ("before", "after"):
            secs = _stage_seconds(d, side, stage)
            cost = ((d.get(f"{side}_stages") or {}).get(stage) or {}).get("cost") or {}
            if not cost and secs is None:
                continue
            elapsed = f"{secs}s" if secs is not None else "?s"
            block.append(f"    {side:6} {elapsed:>10}  {_fmt_cost(cost)}")
        if not block:
            continue
        lines.append(f"  [{stage}]")
        lines += block
        ratios = []
        for key in ("model_requests", "total_input_tokens", "output_tokens"):
            b = ((d.get("before_stages") or {}).get(stage) or {}).get("cost", {}).get(key)
            a = ((d.get("after_stages") or {}).get(stage) or {}).get("cost", {}).get(key)
            if b and a and a != b:
                ratios.append(f"{key} x{a / b:.2f}")
        bs = _stage_seconds(d, "before", stage)
        as_ = _stage_seconds(d, "after", stage)
        if bs and as_ and bs != as_:
            ratios.append(f"seconds x{as_ / bs:.2f}")
        if ratios:
            lines.append("    ratio  " + ", ".join(ratios))
    for side in ("before", "after"):
        counts = d.get(f"{side}_completeness")
        if counts and any(counts.values()):
            lines.append(f"  completeness {side}: {counts}")
    if d.get("comparable") is False:
        lines.append("  NOT COMPARABLE, re-run rather than reading this as a result:")
        lines += [f"    - {r}" for r in d["not_comparable_because"]]
    elif "comparable" in d:
        lines.append("  both arms ran clean, the comparison stands")
    return "\n".join(lines)
