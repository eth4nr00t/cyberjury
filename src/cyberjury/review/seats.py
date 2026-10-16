"""Resolve provider seat identities and the verification route shared by every review entry."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.providers.base import Provider
from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat, provider_for_seat
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.review.request import ProviderSeatRecord, endpoint_identity, seat_identity
from cyberjury.review.verification import Confirmer, ModelRefutationChecker, ModelVerifier

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


def confirmer_seats(configuration: ProviderConfiguration) -> list[ProviderSeat]:
    """The independent confirmer seats a drop needs.

    A refuted finding is dropped only when every applicable confirmer upholds the
    refutation. The skeptic never confirms its own refutation, and the finder never
    confirms a deletion of its own finding, so the confirmer seat counts only when it
    differs from both. With no distinct confirmer the list is empty and nothing is
    dropped, the recall-safe default.
    """
    if provider_seat_id(configuration.confirmer) in {
        provider_seat_id(configuration.skeptic),
        provider_seat_id(configuration.finder),
    }:
        return []
    return [configuration.confirmer]


def verification_route(
    configuration: ProviderConfiguration,
    *,
    meter: UsageMeter | None,
) -> tuple[ModelVerifier, list[Confirmer]]:
    """Build the skeptic and every independent confirmer for model verification.

    Without a confirmer no refutation can drop a finding, so the skeptic is never called
    and its seat needs no reachable key.
    """
    confirmers: list[Confirmer] = [
        (
            provider_seat_id(seat),
            ModelRefutationChecker(
                provider=provider_for_seat(configuration, seat, meter=meter),
                model=seat.model,
                seat_id=provider_seat_id(seat),
            ),
        )
        for seat in confirmer_seats(configuration)
    ]
    skeptic = configuration.skeptic
    verifier = ModelVerifier(
        provider=provider_for_seat(configuration, skeptic, meter=meter, require_key=bool(confirmers)),
        model=skeptic.model,
        seat_id=provider_seat_id(skeptic),
    )
    return verifier, confirmers


@dataclass(frozen=True, kw_only=True)
class ReviewSeats:
    """The finder and verification route of one review, identified as they are recorded."""

    finder: Provider
    finder_model: str
    finder_label: str
    verifier: ModelVerifier | None
    confirmers: tuple[Confirmer, ...]


def review_seats(
    configuration: ProviderConfiguration,
    *,
    meter: UsageMeter,
    dry_run_provider: Provider | None = None,
) -> ReviewSeats:
    """Resolve the seats one review calls; a dry run provider replaces the finder and disables verification."""
    if dry_run_provider is not None:
        return ReviewSeats(
            finder=MeteringProvider(dry_run_provider, meter),
            finder_model=DRY_RUN_SEAT.model,
            finder_label=provider_seat_id(DRY_RUN_SEAT),
            verifier=None,
            confirmers=(),
        )
    finder = configuration.finder
    verifier, confirmers = verification_route(configuration, meter=meter)
    return ReviewSeats(
        finder=provider_for_seat(configuration, finder, meter=meter),
        finder_model=finder.model,
        finder_label=provider_seat_id(finder),
        verifier=verifier,
        confirmers=tuple(confirmers),
    )
