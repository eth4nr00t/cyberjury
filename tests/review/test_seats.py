"""Seat identities hide endpoints, and every review calls one finder seat for issue links too."""

from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat
from cyberjury.providers.metering import UsageMeter
from cyberjury.review.issues import ModelIssueJudge
from cyberjury.review.seats import provider_seat_record, review_seats
from tests.support import MockProvider


def test_seat_identity_names_the_transport_without_its_endpoint_value():
    """A base_url changes the seat- prefixed id while the gateway hostname stays out of it."""
    seat_id = provider_seat_record(
        ProviderSeat(provider="openai", model="m", base_url="https://gateway.example.test/v1")
    ).seat_id
    official = ProviderSeat(provider="openai", model="m", base_url="https://api.openai.com/v1")

    assert seat_id.startswith("seat-")
    assert seat_id != provider_seat_record(official).seat_id
    assert "gateway" not in seat_id


def test_review_seats_judge_issue_links_on_the_configured_finder(monkeypatch):
    """The issue judge reuses the finder provider, model, and seat id."""
    provider = MockProvider(default='{"same_fix": true, "rationale": "one change"}')
    monkeypatch.setattr(configuration_module, "make_provider", lambda *args, **kwargs: provider)
    finder = ProviderSeat(provider="openai", model="finder", base_url="https://api.openai.com/v1")
    configuration = ProviderConfiguration(seat=finder, api_key="k", retries=0, timeout=10)

    seats = review_seats(configuration, meter=UsageMeter())

    assert seats.finder_model == "finder"
    assert (
        seats.issue_judge.fingerprint
        == ModelIssueJudge(
            provider=seats.finder, model="finder", seat_id=provider_seat_record(finder).seat_id
        ).fingerprint
    )
    seats.issue_judge.judge("prompt", pair=("candidate-a", "candidate-b"))
    assert [(call["prompt"], call["model"]) for call in provider.calls] == [("prompt", "finder")]
