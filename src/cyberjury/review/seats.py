"""Provider seat identities and the seats every review entry calls."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.providers.base import Provider
from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat, provider_for_seat
from cyberjury.providers.metering import UsageMeter
from cyberjury.review.issues import IssueJudge, ModelIssueJudge
from cyberjury.review.request import ProviderSeatRecord, endpoint_identity, seat_identity


def provider_seat_record(seat: ProviderSeat) -> ProviderSeatRecord:
    """Describe one effective provider transport without credentials."""
    endpoint = endpoint_identity(seat.base_url)
    return ProviderSeatRecord(
        seat_id=seat_identity(seat.provider, seat.model, endpoint),
        provider=seat.provider,
        model=seat.model,
        endpoint_identity=endpoint,
    )


@dataclass(frozen=True, kw_only=True)
class ReviewSeats:
    """The finder and the issue link judge of one review."""

    finder: Provider
    finder_model: str
    issue_judge: IssueJudge


def review_seats(configuration: ProviderConfiguration, *, meter: UsageMeter) -> ReviewSeats:
    """Resolve the seats one review calls."""
    seat = configuration.seat
    provider = provider_for_seat(configuration, meter=meter)
    return ReviewSeats(
        finder=provider,
        finder_model=seat.model,
        issue_judge=ModelIssueJudge(provider=provider, model=seat.model, seat_id=provider_seat_record(seat).seat_id),
    )
