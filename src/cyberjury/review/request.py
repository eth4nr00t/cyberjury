"""Immutable review intent and effective command configuration."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from cyberjury.canonical import canonical_sha256

type ReviewAction = Literal["run", "scaffold"]
type ReviewTargetKind = Literal["diff", "repository"]

INTENT_SCHEMA = "cyberjury.review-intent/v1"
REQUEST_SCHEMA = "cyberjury.review-attempt-request/v1"


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

    review: int | None

    def to_dict(self) -> dict[str, int | None]:
        """Return the strict concurrency wire form."""
        return {"review": self.review}


def endpoint_identity(api_base: str | None) -> str:
    """Identify the exact configured endpoint without persisting its value."""
    if not api_base:
        return "default"
    if not isinstance(api_base, str):
        raise ValueError("api base must be a string or null")
    return f"sha256:{hashlib.sha256(api_base.encode()).hexdigest()}"


def seat_identity(provider: str, model: str, endpoint: str, wire_api: str | None) -> str:
    """Identify one effective model transport without any credential value."""
    material = "\x1f".join((provider, model, endpoint, wire_api or ""))
    return f"seat-{hashlib.sha256(material.encode()).hexdigest()[:20]}"


@dataclass(frozen=True, kw_only=True)
class ProviderSeatRecord:
    """One effective provider transport without credentials."""

    seat_id: str
    provider: str
    model: str
    endpoint_identity: str
    wire_api: str | None

    def to_dict(self) -> dict[str, object]:
        """Return the strict provider seat wire form."""
        return {
            "seat_id": self.seat_id,
            "provider": self.provider,
            "model": self.model,
            "endpoint_identity": self.endpoint_identity,
            "wire_api": self.wire_api,
        }


@dataclass(frozen=True, kw_only=True)
class ProviderPlanRecord:
    """Observable effective model seat and client policy."""

    retries: int | None
    timeout_seconds: float | None
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

    action: ReviewAction
    engine_version: str
    concurrency: ConcurrencyRecord | None
    dry_run: bool | None
    fresh: bool | None
    providers: ProviderPlanRecord | None

    @property
    def request_sha256(self) -> str:
        """Identify effective behavior independently from attempt identity and time."""
        return canonical_sha256(self.semantic_dict())

    @property
    def judgment_configuration_sha256(self) -> str:
        """Identify policy that controls reusable repository judgment results."""
        if self.action != "run" or self.providers is None:
            raise ValueError("only run requests have reusable judgment configuration")
        providers = self.providers.to_dict()
        semantic = {
            "provider_seat": providers["seat"],
            "dry_run": self.dry_run,
            "engine_version": self.engine_version,
        }
        return canonical_sha256(semantic)

    def semantic_dict(self) -> dict[str, object]:
        """Return the stable command semantics consumed by target adapters."""
        semantic = {
            "action": self.action,
            "engine_version": self.engine_version,
            "concurrency": self.concurrency.to_dict() if self.concurrency is not None else None,
            "dry_run": self.dry_run,
            "fresh": self.fresh,
            "providers": self.providers.to_dict() if self.providers is not None else None,
        }
        return semantic

    def to_dict(self) -> dict[str, object]:
        """Return the complete strict attempt request."""
        return {"schema": REQUEST_SCHEMA, **self.semantic_dict(), "request_sha256": self.request_sha256}
