"""Immutable review intent and effective command configuration."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from cyberjury.canonical import canonical_sha256

type ReviewTargetKind = Literal["diff", "repository"]

INTENT_SCHEMA = "cyberjury.intent/v1"
REQUEST_SCHEMA = "cyberjury.request/v1"


@dataclass(frozen=True, kw_only=True)
class TargetInput:
    """Operator target input before source acquisition."""

    kind: ReviewTargetKind
    repository: str
    git_range: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the strict target input wire form."""
        return {"kind": self.kind, "repository": self.repository, "git_range": self.git_range}


@dataclass(frozen=True, kw_only=True)
class ReviewIntent:
    """Stable target intent used to correlate independent review sessions."""

    target: TargetInput

    @property
    def intent_sha256(self) -> str:
        """Identify equivalent target intent without becoming a session id."""
        return canonical_sha256({"target": self.target.to_dict()})

    def to_dict(self) -> dict[str, object]:
        """Return the complete immutable review intent."""
        return {
            "schema": INTENT_SCHEMA,
            "target": self.target.to_dict(),
            "intent_sha256": self.intent_sha256,
        }


@dataclass(frozen=True, kw_only=True)
class ConcurrencyRecord:
    """Explicit concurrency for unit judgment and issue link calls."""

    review: int

    def to_dict(self) -> dict[str, int]:
        """Return the strict concurrency wire form."""
        return {"review": self.review}


def endpoint_identity(base_url: str | None) -> str:
    """Identify the exact configured endpoint without persisting its value."""
    if not base_url:
        return "default"
    return f"sha256:{hashlib.sha256(base_url.encode()).hexdigest()}"


def seat_identity(provider: str, model: str, endpoint: str) -> str:
    """Identify one effective model transport without any credential value."""
    material = "\x1f".join((provider, model, endpoint))
    return f"seat-{hashlib.sha256(material.encode()).hexdigest()[:20]}"


@dataclass(frozen=True, kw_only=True)
class ProviderSeatRecord:
    """One effective provider transport without credentials."""

    seat_id: str
    provider: str
    model: str
    endpoint_identity: str

    def to_dict(self) -> dict[str, object]:
        """Return the strict provider seat wire form."""
        return {
            "seat_id": self.seat_id,
            "provider": self.provider,
            "model": self.model,
            "endpoint_identity": self.endpoint_identity,
        }


@dataclass(frozen=True, kw_only=True)
class ProviderPlanRecord:
    """Observable effective model seat and client policy."""

    retries: int
    timeout_seconds: float
    seat: ProviderSeatRecord

    def to_dict(self) -> dict[str, object]:
        """Return the strict provider plan wire form."""
        return {
            "retries": self.retries,
            "timeout_seconds": self.timeout_seconds,
            "seat": self.seat.to_dict(),
        }


@dataclass(frozen=True, kw_only=True)
class ReviewAttemptRequest:
    """One immutable review execution request."""

    engine_version: str
    concurrency: ConcurrencyRecord
    fresh: bool | None
    providers: ProviderPlanRecord

    @property
    def request_sha256(self) -> str:
        """Identify effective behavior independently from attempt identity and time."""
        return canonical_sha256(self.semantic_dict())

    @property
    def judgment_configuration_sha256(self) -> str:
        """Identify policy that controls reusable repository judgment results."""
        return canonical_sha256({"provider_seat": self.providers.seat.to_dict(), "engine_version": self.engine_version})

    def semantic_dict(self) -> dict[str, object]:
        """Return the command fields that request_sha256 covers."""
        return {
            "engine_version": self.engine_version,
            "concurrency": self.concurrency.to_dict(),
            "fresh": self.fresh,
            "providers": self.providers.to_dict(),
        }

    def to_dict(self) -> dict[str, object]:
        """Return the complete strict attempt request."""
        return {"schema": REQUEST_SCHEMA, **self.semantic_dict(), "request_sha256": self.request_sha256}
