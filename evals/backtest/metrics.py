"""Collect and render backtest completeness, cost, and timing metrics."""

from __future__ import annotations

import json
from pathlib import Path

_FAILED_CALLS = ("errors", "verify_errors")
_KEPT_FINDINGS = ("incomplete", "unlocatable")
_INCOMPLETE_STEPS = ("run_incomplete",)
_COMPLETENESS_KEYS = _FAILED_CALLS + _KEPT_FINDINGS + _INCOMPLETE_STEPS

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
    """Collect one arm's completeness and cost by stage and in total."""
    workspace_path = Path(workspace)
    stages: dict = {}
    totals: dict = {"completeness": dict.fromkeys(_COMPLETENESS_KEYS, 0), "cost": {}}
    files: list[str] = []
    for stage, name in _STAGE_FILES:
        for path in sorted(workspace_path.rglob(name)):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            files.append(name)
            stage_data = stages.setdefault(stage, {"completeness": {}, "cost": {}})
            for key in _COMPLETENESS_KEYS:
                if key in data:
                    value = int(data.get(key) or 0)
                    stage_data["completeness"][key] = stage_data["completeness"].get(key, 0) + value
                    if key in _FAILED_CALLS:
                        totals["completeness"][key] += value
                    else:
                        totals["completeness"][key] = value
            if stage == "run" and data.get("complete") is False:
                stage_data["completeness"]["run_incomplete"] = stage_data["completeness"].get("run_incomplete", 0) + 1
                totals["completeness"]["run_incomplete"] += 1
            usage = data.get("usage") or {}
            for key in _COST_KEYS:
                if key in usage:
                    value = int(usage[key] or 0)
                    stage_data["cost"][key] = stage_data["cost"].get(key, 0) + value
                    totals["cost"][key] = totals["cost"].get(key, 0) + value
            seconds = (data.get("timing") or {}).get("total_seconds")
            if seconds is not None:
                stage_data["cost"]["seconds"] = round(stage_data["cost"].get("seconds", 0) + float(seconds), 1)
                totals["cost"]["seconds"] = round(totals["cost"].get("seconds", 0) + float(seconds), 1)
    return {"stages": stages, "timeline": _timeline_seconds(workspace_path), **totals, "files": files}


def _timeline_seconds(workspace: Path) -> dict[str, float]:
    """Collect elapsed time for every pipeline stage in a workspace."""
    elapsed_by_stage: dict[str, float] = {}
    for path in sorted(workspace.rglob("_timeline.json")):
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
            elapsed_by_stage[stage] = round(elapsed_by_stage.get(stage, 0.0) + float(record.get("seconds") or 0), 1)
    return elapsed_by_stage


def with_arms(result: dict, before_workspace: str | Path | None, after_workspace: str | Path | None) -> dict:
    """Add each arm's completeness and cost to a quality comparison."""
    comparison = dict(result)
    for side, workspace in (("before", before_workspace), ("after", after_workspace)):
        if workspace is None:
            continue
        arm = _arm_artifacts(workspace)
        comparison[f"{side}_completeness"] = arm["completeness"]
        comparison[f"{side}_cost"] = arm["cost"]
        comparison[f"{side}_stages"] = arm["stages"]
        comparison[f"{side}_timeline"] = arm["timeline"]
        comparison[f"{side}_artifacts"] = arm["files"]
    comparison["comparable"], comparison["not_comparable_because"] = _comparable(comparison)
    return comparison


def _comparable(comparison: dict) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    for side in ("before", "after"):
        counts = comparison.get(f"{side}_completeness")
        if counts is None:
            continue
        if f"{side}_artifacts" in comparison and not comparison[f"{side}_artifacts"]:
            reasons.append(f"{side} arm wrote no _run.json or _finalize.json, so it may not have run")
            continue
        for key, value in counts.items():
            if value:
                reasons.append(f"{side} arm records {value} {key}")
    return not reasons, reasons


def _format_cost(cost: dict) -> str:
    """Format one stage's model usage without its separately rendered time."""
    parts = [f"{key}={cost[key]}" for key in _COST_KEYS if key in cost]
    return " ".join(parts) if parts else "no model calls"


def _stage_seconds(comparison: dict, side: str, stage: str) -> float | None:
    """Read elapsed time from the workspace timeline or stage record."""
    seconds = (comparison.get(f"{side}_timeline") or {}).get(stage)
    if seconds is not None:
        return float(seconds)
    stage_cost = ((comparison.get(f"{side}_stages") or {}).get(stage) or {}).get("cost") or {}
    return float(stage_cost["seconds"]) if "seconds" in stage_cost else None


def format_arms(comparison: dict) -> str:
    """Render cost and completeness below a quality comparison."""
    lines: list[str] = []
    for stage in ("scaffold", "run", "finalize", "gate"):
        block: list[str] = []
        for side in ("before", "after"):
            seconds = _stage_seconds(comparison, side, stage)
            cost = ((comparison.get(f"{side}_stages") or {}).get(stage) or {}).get("cost") or {}
            if not cost and seconds is None:
                continue
            elapsed = f"{seconds}s" if seconds is not None else "?s"
            block.append(f"    {side:6} {elapsed:>10}  {_format_cost(cost)}")
        if not block:
            continue
        lines.append(f"  [{stage}]")
        lines += block
        ratios = []
        for key in ("model_requests", "total_input_tokens", "output_tokens"):
            before = ((comparison.get("before_stages") or {}).get(stage) or {}).get("cost", {}).get(key)
            after = ((comparison.get("after_stages") or {}).get(stage) or {}).get("cost", {}).get(key)
            if before and after and after != before:
                ratios.append(f"{key} x{after / before:.2f}")
        before_seconds = _stage_seconds(comparison, "before", stage)
        after_seconds = _stage_seconds(comparison, "after", stage)
        if before_seconds and after_seconds and before_seconds != after_seconds:
            ratios.append(f"seconds x{after_seconds / before_seconds:.2f}")
        if ratios:
            lines.append("    ratio  " + ", ".join(ratios))
    for side in ("before", "after"):
        counts = comparison.get(f"{side}_completeness")
        if counts and any(counts.values()):
            lines.append(f"  completeness {side}: {counts}")
    if comparison.get("comparable") is False:
        lines.append("  NOT COMPARABLE, re-run rather than reading this as a result:")
        lines += [f"    - {reason}" for reason in comparison["not_comparable_because"]]
    elif "comparable" in comparison:
        lines.append("  both arms ran clean, the comparison stands")
    return "\n".join(lines)
