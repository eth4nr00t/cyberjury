"""Seat identities and the verification route are shared by every review entry."""

from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat
from cyberjury.providers.metering import UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.seats import DRY_RUN_SEAT, confirmer_seats, provider_seat_id, review_seats


def _configuration(*, skeptic: ProviderSeat, confirmer: ProviderSeat, finder: ProviderSeat) -> ProviderConfiguration:
    return ProviderConfiguration(
        base=finder, finder=finder, skeptic=skeptic, confirmer=confirmer, retries=0, timeout=10
    )


def test_confirmer_seats_exclude_the_skeptic_and_the_finder():
    skeptic = ProviderSeat(provider="anthropic", model="skeptic", api_key="k", wire_api="chat")
    confirmer = ProviderSeat(provider="anthropic", model="confirmer", api_key="k", wire_api="chat")
    finder = ProviderSeat(provider="anthropic", model="finder", api_key="k", wire_api="chat")

    assert confirmer_seats(_configuration(skeptic=skeptic, confirmer=confirmer, finder=finder)) == [confirmer]
    assert confirmer_seats(_configuration(skeptic=skeptic, confirmer=finder, finder=finder)) == []
    assert confirmer_seats(_configuration(skeptic=skeptic, confirmer=skeptic, finder=finder)) == []


def test_seat_identity_ignores_credentials():
    seat = ProviderSeat(provider="openai", model="m", api_key="one")

    assert provider_seat_id(seat) == provider_seat_id(ProviderSeat(provider="openai", model="m", api_key="two"))
    assert provider_seat_id(seat).startswith("seat-")


def test_review_seats_label_the_configured_finder_and_route_independent_confirmers(monkeypatch):
    monkeypatch.setattr(configuration_module, "make_provider", lambda *args, **kwargs: MockProvider(default="{}"))
    skeptic = ProviderSeat(provider="openai", model="skeptic", api_key="k")
    confirmer = ProviderSeat(provider="openai", model="confirmer", api_key="k")
    finder = ProviderSeat(provider="openai", model="finder", api_key="k")
    configuration = _configuration(skeptic=skeptic, confirmer=confirmer, finder=finder)

    seats = review_seats(configuration, meter=UsageMeter())
    dry = review_seats(configuration, meter=UsageMeter(), dry_run_provider=MockProvider(default="{}"))

    assert (seats.finder_model, seats.finder_label) == ("finder", provider_seat_id(finder))
    assert [label for label, _checker in seats.confirmers] == [provider_seat_id(confirmer)]
    assert seats.verifier is not None
    assert (dry.finder_model, dry.finder_label) == ("mock", provider_seat_id(DRY_RUN_SEAT))
    assert dry.verifier is None
    assert dry.confirmers == ()
