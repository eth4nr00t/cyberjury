"""Seat identities and the verification route are shared by every review entry."""

from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat
from cyberjury.review.seats import confirmer_seats, provider_seat_id


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
