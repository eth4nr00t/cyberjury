"""The shared record schema keeps one field order, rejects records outside it, and never persists credentials."""

import pytest

from cyberjury.record import Record, RecordError, error_message, render


def test_error_messages_redact_credentials_and_stay_bounded():
    """Bearer headers, api key, token, and sk- values are redacted, other words are kept, and length stays 2000."""
    message = error_message(
        "Authorization: Bearer super-secret headers={'Authorization': 'Bearer dict-secret'} "
        "api key loose-secret token token-secret sk-abcdefghijkl, "
        "the openai provider has no API key, set CYBERJURY_API_KEY. "
        "tokens=abcdefghij CYBERJURY_API_KEY=abcdefghijklmnop tokenization_failed "
        f"{'x' * 3000}"
    )

    assert "secret" not in message
    assert "abcdefghij" not in message
    assert (
        "the openai provider has no API key, set CYBERJURY_API_KEY. "
        "tokens=[redacted] CYBERJURY_API_KEY=[redacted] tokenization_failed" in message
    )
    assert len(message) == 2000


def test_a_record_round_trips_through_its_rendered_text_in_field_order():
    """An incomplete record renders its fields in schema order and parses back to an equal record."""
    record = Record(
        id="review/unit-1",
        status="incomplete",
        started_at="2026-01-01T00:00:00Z",
        duration_seconds=1.5,
        metrics={"findings": 2, "items": 1},
        attributes={"paths": "app.py"},
        artifacts=("review/findings/unit-1.json",),
        error=RecordError(code="model", message="one finding has no location"),
    )
    data = record.to_dict()

    assert list(data) == [
        "schema",
        "id",
        "status",
        "started_at",
        "duration_seconds",
        "metrics",
        "attributes",
        "artifacts",
        "error",
    ]
    assert list(data["metrics"]) == ["items", "findings"]
    assert Record.from_dict(data) == record
    assert render(record).endswith("}\n")


def test_a_record_line_lists_its_fields_and_quotes_values_with_spaces():
    """The line holds id, status, duration, metrics in vocabulary order, attributes, then the error."""
    record = Record(
        id="review/unit-1",
        status="incomplete",
        started_at="2026-01-01T00:00:00Z",
        duration_seconds=1.5,
        metrics={"findings": 2, "items": 1},
        attributes={"paths": "app.py, lib.py", "source_changed": None},
        error=RecordError(code="model", message="one finding has no location"),
    )

    assert record.line() == (
        'review/unit-1 incomplete 1.5s items=1 findings=2 paths="app.py, lib.py" source_changed=null '
        "error: model one finding has no location"
    )


@pytest.mark.parametrize(
    ("fields", "match"),
    [
        ({"status": "failed"}, "error is set exactly"),
        ({"status": "ok", "error": RecordError(code="model", message="m")}, "error is set exactly"),
        ({"status": "running"}, "duration is set exactly"),
        ({"metrics": {"tokens": 1}}, "not in the vocabulary"),
        ({"id": "unknown-stage"}, "id is invalid"),
        ({"status": "interrupted"}, "reason is set exactly"),
        ({"attributes": {"reason": "late"}}, "reason is set exactly"),
    ],
)
def test_a_record_outside_the_schema_is_rejected(fields, match):
    """A missing or misplaced error or reason, a running duration, an unknown metric, or an unknown id raises."""
    values = {"id": "review", "status": "ok", "started_at": "2026-01-01T00:00:00Z", "duration_seconds": 1.0}

    with pytest.raises(ValueError, match=match):
        Record(**(values | fields))
