"""Compare observed model work by trigger and role across review runs."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from cyberjury.providers.metering import validate_model_calls_document

SCHEMA = "cyberjury.eval-model-call-stages/v1"
_COUNT_FIELDS = (
    "requests",
    "metered_requests",
    "failed_requests",
    "prompt_chars",
    "max_prompt_chars",
    "input_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "output_tokens",
    "source_queries",
    "evidence_requests",
)


def summarize_model_calls(document: dict[str, object]) -> dict[str, object]:
    """Group validated call receipts without treating a run total as one prompt."""
    artifact = validate_model_calls_document(document)
    grouped: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: dict.fromkeys(_COUNT_FIELDS, 0))
    stage_models: dict[tuple[str, str], set[str]] = defaultdict(set)
    for call in artifact["calls"]:
        key = (call["trigger"], call["role"])
        bucket = grouped[key]
        stage_models[key].add(call["model"])
        bucket["requests"] += 1
        bucket["failed_requests"] += call["status"] == "failed"
        bucket["prompt_chars"] += call["prompt_chars"]
        bucket["max_prompt_chars"] = max(bucket["max_prompt_chars"], call["prompt_chars"])
        bucket["source_queries"] += call["source_query_count"]
        bucket["evidence_requests"] += call["evidence_request_count"]
        if "input_tokens" in call:
            bucket["metered_requests"] += 1
            for field in ("input_tokens", "cache_read_tokens", "cache_write_tokens", "output_tokens"):
                bucket[field] += call[field]
    stages = [
        {
            "trigger": trigger,
            "role": role,
            "models": sorted(stage_models[(trigger, role)]),
            **counts,
            "total_input_tokens": counts["input_tokens"] + counts["cache_read_tokens"] + counts["cache_write_tokens"],
        }
        for (trigger, role), counts in sorted(grouped.items())
    ]
    return {
        "schema": SCHEMA,
        "source_schema": artifact["schema"],
        "source_sha256": artifact["content_sha256"],
        "models": sorted({model for models in stage_models.values() for model in models}),
        "usage": artifact["usage"],
        "stages": stages,
    }


def load_model_call_summary(path: str | Path) -> dict[str, object]:
    """Read and verify a persisted model-call artifact before summarizing it."""
    return summarize_model_calls(json.loads(Path(path).read_text(encoding="utf-8")))


def compare_model_call_summaries(before: dict[str, object], after: dict[str, object]) -> dict[str, object]:
    """Show exact stage deltas with absent roles counted as zero."""
    if before.get("schema") != SCHEMA or after.get("schema") != SCHEMA:
        raise ValueError("model call comparison needs validated stage summaries")
    prior = {(item["trigger"], item["role"]): item for item in before["stages"]}
    changed = {(item["trigger"], item["role"]): item for item in after["stages"]}
    stages = []
    for trigger, role in sorted(prior.keys() | changed.keys()):
        baseline = prior.get((trigger, role), {})
        current = changed.get((trigger, role), {})
        stages.append(
            {
                "trigger": trigger,
                "role": role,
                "before_models": baseline.get("models", []),
                "after_models": current.get("models", []),
                "before_requests": baseline.get("requests", 0),
                "after_requests": current.get("requests", 0),
                "delta_requests": current.get("requests", 0) - baseline.get("requests", 0),
                "before_max_prompt_chars": baseline.get("max_prompt_chars", 0),
                "after_max_prompt_chars": current.get("max_prompt_chars", 0),
                "delta_max_prompt_chars": current.get("max_prompt_chars", 0) - baseline.get("max_prompt_chars", 0),
                "before_failed_requests": baseline.get("failed_requests", 0),
                "after_failed_requests": current.get("failed_requests", 0),
                "delta_failed_requests": current.get("failed_requests", 0) - baseline.get("failed_requests", 0),
                "before_input_tokens": baseline.get("total_input_tokens", 0),
                "after_input_tokens": current.get("total_input_tokens", 0),
                "delta_input_tokens": current.get("total_input_tokens", 0) - baseline.get("total_input_tokens", 0),
                "before_output_tokens": baseline.get("output_tokens", 0),
                "after_output_tokens": current.get("output_tokens", 0),
                "delta_output_tokens": current.get("output_tokens", 0) - baseline.get("output_tokens", 0),
                "before_cache_read_tokens": baseline.get("cache_read_tokens", 0),
                "after_cache_read_tokens": current.get("cache_read_tokens", 0),
                "delta_cache_read_tokens": current.get("cache_read_tokens", 0) - baseline.get("cache_read_tokens", 0),
            }
        )
    return {
        "schema": SCHEMA,
        "before_sha256": before["source_sha256"],
        "after_sha256": after["source_sha256"],
        "before_models": before["models"],
        "after_models": after["models"],
        "comparable_models": before["models"] == after["models"],
        "stages": stages,
    }
