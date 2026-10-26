"""Review request tests cover stable identity and credential-free endpoint records."""

from dataclasses import replace

from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ProviderSeatRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    TargetInput,
    endpoint_identity,
    seat_identity,
)


def _seat(provider: str = "openai", model: str = "model") -> ProviderSeatRecord:
    endpoint = endpoint_identity(None)
    return ProviderSeatRecord(
        seat_id=seat_identity(provider, model, endpoint),
        provider=provider,
        model=model,
        endpoint_identity=endpoint,
    )


def _request() -> ReviewAttemptRequest:
    seat = _seat()
    return ReviewAttemptRequest(
        engine_version="test",
        concurrency=ConcurrencyRecord(review=8),
        dry_run=False,
        fresh=False,
        providers=ProviderPlanRecord(
            retries=2,
            timeout_seconds=120,
            seat=seat,
        ),
    )


def test_review_intent_identity_is_stable_and_target_specific():
    """Equal base..HEAD intents share a hash under intent/v1, while base...HEAD gets a different one."""
    first = ReviewIntent(target=TargetInput(kind="diff", repository="/repo", git_range="base..HEAD"))
    second = ReviewIntent(target=first.target)
    other = ReviewIntent(target=TargetInput(kind="diff", repository="/repo", git_range="base...HEAD"))

    assert second.intent_sha256 == first.intent_sha256
    assert first.to_dict()["intent_sha256"] == first.intent_sha256
    assert first.to_dict()["schema"] == "cyberjury.intent/v1"
    assert other.intent_sha256 != first.intent_sha256


def test_attempt_request_hash_changes_only_with_effective_behavior():
    """Identically built requests share request_sha256, and setting fresh=True changes it."""
    request = _request()

    assert request.to_dict()["request_sha256"] == request.request_sha256
    assert len({_request().request_sha256 for _ in range(3)}) == 1
    assert replace(request, fresh=True).request_sha256 != request.request_sha256


def test_provider_endpoint_identity_names_one_endpoint_without_persisting_it():
    """A URL with api_key=secret hashes to a sha256: id with no host or secret, and None and empty give default."""
    secret_url = "https://example.test/v1?api_key=secret"
    identity = endpoint_identity(secret_url)

    assert identity.startswith("sha256:")
    assert "secret" not in identity
    assert "example.test" not in identity
    assert endpoint_identity(secret_url) == identity
    assert endpoint_identity("https://other.test/v1") != identity
    assert endpoint_identity(None) == endpoint_identity("") == "default"


def test_wire_request_contains_no_credential_fields():
    """The serialized attempt request has no api_key, authorization, or bearer text."""
    serialized = str(_request().to_dict()).lower()

    assert "api_key" not in serialized
    assert "authorization" not in serialized
    assert "bearer" not in serialized
