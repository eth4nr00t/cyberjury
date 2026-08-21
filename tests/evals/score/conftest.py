"""Score fixtures build validated version 1 answer keys."""

import pytest
import yaml


@pytest.fixture
def answer_key_file():
    def write(tmp_path, body: str):
        path = tmp_path / "answer-key.yaml"
        data = yaml.safe_load(body) or {}
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            raise ValueError("answer key fixture must use schema version 1")
        if not isinstance(data.get("benchmark_id"), str) or not isinstance(data.get("checks"), list):
            raise ValueError("answer key fixture must declare benchmark_id and checks")
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return path

    return write
