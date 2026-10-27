"""Recorder tests cover how each stage ends, which usage it counts, and when its record is written."""

import io

import pytest

from cyberjury.providers.base import CompletionResult, Message, Provider, Usage
from cyberjury.providers.metering import MeteringProvider, UsageMeter, model_call_context, model_call_scope
from cyberjury.record import RecordError
from cyberjury.review.recorder import INTERRUPTED, Recorder
from tests.support import EMPTY_SCHEMA


class _Provider(Provider):
    def complete(self, **_kwargs):
        return CompletionResult(text="{}", usage=Usage(input_tokens=10, output_tokens=2))


def _call(meter: UsageMeter) -> None:
    MeteringProvider(_Provider(), meter).complete(
        system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=8, response_schema=EMPTY_SCHEMA
    )


def test_a_stage_that_raises_is_recorded_failed_with_the_classified_error_and_reraises():
    """A stage raising ValueError("bad") records failed with the classifier's error and lets the error through."""
    recorder = Recorder(meter=UsageMeter(), classify=lambda exc: RecordError(code="input", message=str(exc)))

    with pytest.raises(ValueError, match="bad"), recorder.stage("target"):
        raise ValueError("bad")

    [record] = recorder.stages
    assert (record.status, record.error) == ("failed", RecordError(code="input", message="bad"))


def test_an_interrupted_stage_is_recorded_interrupted_with_the_operator_reason():
    """A KeyboardInterrupt inside a stage records it interrupted with the operator reason and re-raises."""
    recorder = Recorder(meter=UsageMeter())

    with pytest.raises(KeyboardInterrupt), recorder.stage("source"):
        raise KeyboardInterrupt

    [record] = recorder.stages
    assert record.status == "interrupted"
    assert record.attributes == {"reason": INTERRUPTED}


def test_a_stage_marked_incomplete_ends_incomplete_with_a_model_error():
    """Calling incomplete("unit failed") ends the stage incomplete with a model error carrying that reason."""
    recorder = Recorder(meter=UsageMeter())

    with recorder.stage("review") as measure:
        measure.incomplete("unit failed")

    [record] = recorder.stages
    assert (record.status, record.error) == ("incomplete", RecordError(code="model", message="unit failed"))


def test_a_usage_stage_counts_only_the_model_calls_made_inside_it():
    """One call before and one call inside a usage stage leave that stage with one call of 10 input tokens."""
    meter = UsageMeter()
    recorder = Recorder(meter=meter)
    _call(meter)

    with recorder.stage("review", usage=True):
        _call(meter)

    [record] = recorder.stages
    assert record.metrics == {"calls": 1, "input_tokens": 10, "cached_tokens": 0, "output_tokens": 2}


def test_unit_usage_counts_only_the_calls_of_that_unit():
    """Two calls for unit-a and one for unit-b give unit-a two calls and 20 input tokens."""
    meter = UsageMeter()
    for unit in ("unit-a", "unit-a", "unit-b"):
        with model_call_scope(unit_id=unit), model_call_context(role="finder", trigger="initial_judgment"):
            _call(meter)

    assert Recorder(meter=meter).unit_usage("unit-a") == {
        "calls": 2,
        "input_tokens": 20,
        "cached_tokens": 0,
        "output_tokens": 4,
    }


def test_stages_finished_before_attach_are_written_on_attach_with_their_held_artifacts():
    """A config stage binding a value before attach is written on attach, listing the path the binder returns."""
    recorder = Recorder(meter=UsageMeter())
    with recorder.stage("config") as measure:
        measure.bind("value")
    written = []

    recorder.attach(bind=lambda value: f"config/{value}.json", sink=written.append)

    assert [record.id for record in written] == ["config"]
    assert written[0].artifacts == ("config/value.json",)
    assert recorder.stages == written


def test_each_record_prints_its_line_to_the_stream():
    """A finished stage prints exactly its one-line view to the stream."""
    stream = io.StringIO()
    recorder = Recorder(meter=UsageMeter(), stream=stream)

    with recorder.stage("plan"):
        pass

    assert stream.getvalue() == recorder.stages[0].line() + "\n"
