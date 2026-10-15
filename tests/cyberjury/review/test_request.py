"""Review request tests cover strict contracts, routing, and stable identity."""

from dataclasses import replace

import pytest

from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ProviderSeatRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    TargetInput,
    VerificationRecord,
    endpoint_identity,
    seat_identity,
)


def _seat(provider: str = "openai", model: str = "model") -> ProviderSeatRecord:
    endpoint = endpoint_identity(None)
    return ProviderSeatRecord(
        seat_id=seat_identity(provider, model, endpoint, "responses"),
        provider=provider,
        model=model,
        endpoint_identity=endpoint,
        wire_api="responses",
    )


def _request() -> ReviewAttemptRequest:
    seat = _seat()
    return ReviewAttemptRequest(
        action="run",
        engine_version="test",
        concurrency=ConcurrencyRecord(review=8, verification=8),
        dry_run=False,
        fresh=False,
        providers=ProviderPlanRecord(
            retries=2,
            timeout_seconds=120,
            seats=(seat,),
            base_seat_id=seat.seat_id,
            finder_seat_id=seat.seat_id,
        ),
        verification=VerificationRecord(
            enabled=True,
            skeptic_seat_id=seat.seat_id,
            confirmer_seat_ids=(),
        ),
        poc=False,
    )


def test_review_intent_identity_is_stable_and_target_specific():
    first = ReviewIntent(
        target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"),
        requested_profile="web",
    )
    second = ReviewIntent.from_dict(first.to_dict())

    assert second == first
    assert second.intent_sha256 == first.intent_sha256
    assert replace(first, requested_profile="evm").intent_sha256 != first.intent_sha256


def test_attempt_request_round_trips():
    request = _request()

    assert ReviewAttemptRequest.from_dict(request.to_dict()) == request


def test_legacy_attempt_request_schema_is_rejected():
    data = _request().to_dict()
    data["schema"] = "cyberjury.review-attempt-request/v2"

    with pytest.raises(ValueError, match="schema is unsupported"):
        ReviewAttemptRequest.from_dict(data)


def test_scaffold_request_keeps_poc_policy_absent():
    request = replace(
        _request(),
        action="scaffold",
        concurrency=None,
        dry_run=None,
        providers=None,
        verification=None,
        poc=None,
    )
    data = request.to_dict()

    restored = ReviewAttemptRequest.from_dict(data)

    assert data["schema"] == "cyberjury.review-attempt-request/v4"
    assert data["poc"] is None
    assert restored.poc is None
    assert restored.to_dict() == data


def test_attempt_request_hash_changes_only_with_effective_behavior():
    request = _request()

    assert ReviewAttemptRequest.from_dict(request.to_dict()).request_sha256 == request.request_sha256
    assert len({_request().request_sha256 for _ in range(3)}) == 1
    assert replace(request, fresh=True).request_sha256 != request.request_sha256
    assert replace(request, poc=True).request_sha256 != request.request_sha256


def test_unsupported_attempt_schema_fails_loud():
    payload = _request().to_dict()
    payload["schema"] = "cyberjury.review-attempt-request/v3"
    with pytest.raises(ValueError, match="schema is unsupported"):
        ReviewAttemptRequest.from_dict(payload)


def test_attempt_request_rejects_unknown_fields_and_hash_drift():
    data = _request().to_dict()
    data["unknown"] = True
    with pytest.raises(ValueError, match="must contain exactly"):
        ReviewAttemptRequest.from_dict(data)

    data = _request().to_dict()
    data["dry_run"] = True
    with pytest.raises(ValueError, match="dry run cannot enable verification"):
        ReviewAttemptRequest.from_dict(data)


def test_attempt_request_rejects_poc_generation_during_a_dry_run():
    request = _request()
    verification = VerificationRecord(
        enabled=False,
        skeptic_seat_id=None,
        confirmer_seat_ids=(),
    )

    with pytest.raises(ValueError, match="dry run cannot enable PoC"):
        replace(
            request,
            dry_run=True,
            concurrency=ConcurrencyRecord(review=8, verification=None),
            verification=verification,
            poc=True,
        )


def test_non_run_action_has_no_judgment_policy():
    request = _request()

    with pytest.raises(ValueError, match="cannot have model execution policy"):
        replace(request, action="gate")


def test_provider_endpoint_identity_preserves_configuration_compatibility():
    assert endpoint_identity("https://example.test/v1?api_key=secret").startswith("sha256:")


def test_wire_request_contains_no_credential_fields():
    serialized = str(_request().to_dict()).lower()

    assert "api_key" not in serialized
    assert "authorization" not in serialized
    assert "bearer" not in serialized


def test_provider_seat_rejects_an_unknown_wire_api():
    seat = _seat()

    with pytest.raises(ValueError, match="fields are invalid"):
        replace(seat, wire_api="unknown")


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), float("-inf")])
def test_provider_plan_rejects_nonfinite_timeout(timeout):
    request = _request()
    assert request.providers is not None

    with pytest.raises(ValueError, match="timeout"):
        replace(request.providers, timeout_seconds=timeout)
