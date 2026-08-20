"""Repository run completion, timing, and usage accounting tests."""

import json

from cyberjury.providers.mock import MockProvider
from cyberjury.review.repository.engine import (
    RepositoryExecutionOptions,
    RepositoryLifecycleOptions,
    RepositoryOutputOptions,
    RepositoryRoleOptions,
    RepositoryRunOptions,
    RepositoryVerificationOptions,
    run_repository_review,
)


def _options(provider, *, execution=None, meter=None):
    return RepositoryRunOptions(
        roles=RepositoryRoleOptions(provider=provider, model="mock"),
        verification=RepositoryVerificationOptions(enabled=False),
        execution=execution or RepositoryExecutionOptions(),
        lifecycle=RepositoryLifecycleOptions(),
        output=RepositoryOutputOptions(meter=meter),
    )


def test_run_writes_timing_and_state_to_run_json(tmp_path):
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    (repo / "b.py").write_text("def other():\n    return 1\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    provider = MockProvider(default='{"findings": []}')
    run_repository_review(str(repo), str(ws), options=_options(provider))
    run = json.loads((ws / "svc" / "_run.json").read_text())
    assert run["state"] == "complete"
    timing = run["timing"]
    assert isinstance(timing["total_seconds"], (int, float))
    assert timing["per_pass"]
    assert all("seconds" in p for p in timing["per_pass"])
    names = [u["unit"] for u in timing["unit_seconds"]]
    assert names
    assert len(names) == len(set(names))
    assert set(names) <= {"a.py", "b.py", "dependencies:combined"}


def test_standard_run_status_distinguishes_completion_from_convergence(tmp_path):
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    provider = MockProvider(default='{"findings": []}')
    run_repository_review(
        str(repo),
        str(ws),
        options=_options(
            provider,
            execution=RepositoryExecutionOptions(max_passes=1, min_rounds=1),
        ),
    )
    run = json.loads((ws / "svc" / "_run.json").read_text())
    assert run["complete"] is True
    assert run["converged"] is False
    assert run["state"] == "complete"


def _run_with_meter(tmp_path):
    from cyberjury.providers.metering import MeteringProvider, UsageMeter
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default='{"findings": []}'), meter)
    run_repository_review(
        str(repo),
        str(ws),
        options=_options(provider, meter=meter),
    )
    return json.loads((ws / "svc" / "_run.json").read_text()), meter


def test_run_writes_its_spend_to_run_json_so_cost_survives_uncaptured_stderr(tmp_path):
    run, meter = _run_with_meter(tmp_path)
    usage = run["usage"]
    assert usage["model_requests"] == meter.model_requests
    components = usage["uncached_input_tokens"] + usage["cache_read_tokens"] + usage["cache_write_tokens"]
    assert usage["total_input_tokens"] == components
    assert usage["unit_review_calls"] >= run["units_reviewed"]


def test_each_pass_records_its_own_spend_so_an_expensive_pass_can_be_named(tmp_path):
    run, _ = _run_with_meter(tmp_path)
    per_pass = run["timing"]["per_pass"]
    assert all("usage" in p for p in per_pass)
    assert sum(p["usage"]["model_requests"] for p in per_pass) == run["usage"]["model_requests"]


def test_a_run_without_a_meter_writes_no_usage_rather_than_zeros(tmp_path):
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    provider = MockProvider(default='{"findings": []}')
    run_repository_review(str(repo), str(ws), options=_options(provider))
    assert "usage" not in json.loads((ws / "svc" / "_run.json").read_text())
