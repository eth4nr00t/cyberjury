"""Factories shared by score tests."""

from pathlib import Path

import yaml


def answer_key(tmp_path, body: str) -> Path:
    path = tmp_path / "answer-key.yaml"
    data = yaml.safe_load(body) or {}
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("answer key fixture must use schema version 1")
    if not isinstance(data.get("benchmark_id"), str) or not isinstance(data.get("checks"), list):
        raise ValueError("answer key fixture must declare benchmark_id and checks")
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path
