"""Seat identities and the seats every review entry calls."""

from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat
from cyberjury.providers.metering import UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.issues import ModelIssueJudge
from cyberjury.review.seats import DRY_RUN_SEAT, provider_seat_id, review_seats


def test_seat_identity_names_the_transport_without_its_endpoint_value():
    """An api_base changes the seat- prefixed id while the gateway hostname stays out of it."""
    seat = ProviderSeat(provider="openai", model="m", api_base="https://gateway.example.test/v1")

    assert provider_seat_id(seat).startswith("seat-")
    assert provider_seat_id(seat) != provider_seat_id(ProviderSeat(provider="openai", model="m"))
    assert "gateway" not in provider_seat_id(seat)


def test_review_seats_label_the_configured_finder_and_judge_issue_links_on_it(monkeypatch):
    """Live seats reuse the finder model for the issue judge, and dry-run seats use mock and have no judge."""
    monkeypatch.setattr(configuration_module, "make_provider", lambda *args, **kwargs: MockProvider(default="{}"))
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    finder = ProviderSeat(provider="openai", model="finder")
    configuration = ProviderConfiguration(seat=finder, retries=0, timeout=10)

    seats = review_seats(configuration, meter=UsageMeter())
    dry = review_seats(configuration, meter=UsageMeter(), dry_run_provider=MockProvider(default="{}"))

    assert (seats.finder_model, seats.finder_label) == ("finder", provider_seat_id(finder))
    assert seats.issue_judge is not None
    assert (
        seats.issue_judge.fingerprint
        == ModelIssueJudge(provider=seats.finder, model="finder", seat_id=provider_seat_id(finder)).fingerprint
    )
    assert (dry.finder_model, dry.finder_label) == ("mock", provider_seat_id(DRY_RUN_SEAT))
    assert dry.issue_judge is None
