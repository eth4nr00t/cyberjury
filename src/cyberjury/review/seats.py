"""Resolve provider seat identities and the seats every review entry calls."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.providers.base import Provider
from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat, provider_for_seat
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.review.issues import IssueJudge, ModelIssueJudge
from cyberjury.review.request import ProviderSeatRecord, endpoint_identity, seat_identity

DRY_RUN_SEAT = ProviderSeat(provider="mock", model="mock")


def provider_seat_record(seat: ProviderSeat) -> ProviderSeatRecord:
    """Describe one effective provider transport without credentials."""
    endpoint = endpoint_identity(seat.api_base)
    return ProviderSeatRecord(
        seat_id=seat_identity(seat.provider, seat.model, endpoint, seat.wire_api),
        provider=seat.provider,
        model=seat.model,
        endpoint_identity=endpoint,
        wire_api=seat.wire_api,
    )


def provider_seat_id(seat: ProviderSeat) -> str:
    """Identify one effective provider transport without credentials."""
    return provider_seat_record(seat).seat_id


@dataclass(frozen=True, kw_only=True)
class ReviewSeats:
    """The finder and the issue link judge of one review, identified as they are recorded."""

    finder: Provider
    finder_model: str
    finder_label: str
    issue_judge: IssueJudge | None = None


def review_seats(
    configuration: ProviderConfiguration,
    *,
    meter: UsageMeter,
    dry_run_provider: Provider | None = None,
) -> ReviewSeats:
    """Resolve the seats one review calls; a dry run provider replaces the finder and disables model judgments."""
    if dry_run_provider is not None:
        return ReviewSeats(
            finder=MeteringProvider(dry_run_provider, meter),
            finder_model=DRY_RUN_SEAT.model,
            finder_label=provider_seat_id(DRY_RUN_SEAT),
        )
    finder = configuration.finder
    provider = provider_for_seat(configuration, finder, meter=meter)
    seat_id = provider_seat_id(finder)
    return ReviewSeats(
        finder=provider,
        finder_model=finder.model,
        finder_label=seat_id,
        issue_judge=ModelIssueJudge(provider=provider, model=finder.model, seat_id=seat_id),
    )
