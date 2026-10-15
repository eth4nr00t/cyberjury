"""Diff evaluation fixtures provide product result and target builders."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from evals.review.diff import execution


@pytest.fixture(autouse=True)
def repository_target_for_direct_cases(monkeypatch, tmp_path):
    """Give isolated direct cases the repository boundary required by production."""
    original = execution.source_root

    @contextmanager
    def source_root(target):
        if target:
            with original(target) as root:
                yield root
            return
        yield tmp_path

    monkeypatch.setattr(execution, "source_root", source_root)


@pytest.fixture
def diff_result():
    def make(findings=None, *, degraded=False, failures=None, errors=0, incomplete=None, failure_reason=""):
        outcome = SimpleNamespace(
            findings=list(findings or []),
            failures=list(failures or []),
            degraded=degraded,
            errors=errors,
            incomplete=list(incomplete or []),
            failure_reason=failure_reason,
        )
        return SimpleNamespace(result=SimpleNamespace(outcome=outcome))

    return make


@pytest.fixture
def provider_configuration():
    def make(*, finder_model="finder-model", skeptic_model=None, confirmer_model=None):
        from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat

        finder = ProviderSeat(provider="openai", model=finder_model, api_key="key")
        return ProviderConfiguration(
            base=finder,
            finder=finder,
            skeptic=ProviderSeat(provider="openai", model=skeptic_model or finder_model, api_key="key"),
            confirmer=ProviderSeat(provider="openai", model=confirmer_model or finder_model, api_key="key"),
            retries=0,
            timeout=10,
        )

    return make


@pytest.fixture
def diff_options(provider_configuration):
    def make(*, finder_model="m", concurrency=8):
        from cyberjury.providers.metering import UsageMeter
        from evals.review.diff import DiffRunOptions

        return DiffRunOptions(
            configuration=provider_configuration(finder_model=finder_model),
            meter=UsageMeter(),
            concurrency=concurrency,
        )

    return make


@pytest.fixture
def diff_case(monkeypatch):
    """Build keyed cases whose patch text is served without materializing a git target."""
    from evals.benchmarks.cases import DiffCase
    from evals.benchmarks.contract import AnswerKey, ExpectedLocation, KeyCheck

    diffs: dict[str, str] = {}
    monkeypatch.setattr(execution, "diff_text", lambda case: diffs[case.name])

    def make(name, diff="diff", *, expectation="findings", checks=None, **fields):
        diffs[name] = diff
        if checks is None:
            checks = (
                KeyCheck(
                    id=f"{name}-check",
                    expectation=expectation,
                    applies_to=(name,),
                    locations=(ExpectedLocation(file="app.py", line=1),),
                ),
            )
        key = AnswerKey(benchmark_id=name, checks=tuple(checks))
        return DiffCase(name=name, answer_key=key, expectation=expectation, **fields)

    return make
