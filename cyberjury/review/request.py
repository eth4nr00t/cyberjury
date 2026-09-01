"""Immutable review intent and effective command configuration."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Literal

from cyberjury.review.engine import ReviewSchedule

type ReviewAction = Literal["run", "scaffold", "finalize", "gate"]
type ReviewTargetKind = Literal["diff", "repository"]

INTENT_SCHEMA = "cyberjury.review-intent/v1"
REQUEST_SCHEMA = "cyberjury.review-attempt-request/v1"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} must contain exactly: {', '.join(sorted(fields))}")
    return value


@dataclass(frozen=True, kw_only=True)
class TargetInput:
    """Operator target input before source acquisition and profile resolution."""

    kind: ReviewTargetKind
    repository: str
    git_range: str | None = None

    def __post_init__(self) -> None:
        """Reject target combinations that cannot identify one requested scope."""
        if self.kind not in {"diff", "repository"}:
            raise ValueError("target kind must be diff or repository")
        if not isinstance(self.repository, str) or not self.repository.strip():
            raise ValueError("target repository must be nonempty")
        if self.kind == "diff" and (not isinstance(self.git_range, str) or not self.git_range.strip()):
            raise ValueError("diff target requires a git range")
        if self.kind == "repository" and self.git_range is not None:
            raise ValueError("repository target cannot have a git range")

    def to_dict(self) -> dict[str, object]:
        """Return the strict target input wire form."""
        return {"kind": self.kind, "repository": self.repository, "git_range": self.git_range}

    @classmethod
    def from_dict(cls, value: object) -> TargetInput:
        """Parse one strict target input wire form."""
        data = _exact(value, {"kind", "repository", "git_range"}, "target")
        return cls(kind=data["kind"], repository=data["repository"], git_range=data["git_range"])


@dataclass(frozen=True, kw_only=True)
class ReviewIntent:
    """Stable target intent used to correlate independent review sessions."""

    target: TargetInput
    requested_profile: str

    def __post_init__(self) -> None:
        """Require a profile request without resolving it early."""
        if not isinstance(self.requested_profile, str) or not self.requested_profile.strip():
            raise ValueError("requested profile must be nonempty")

    @property
    def intent_sha256(self) -> str:
        """Identify equivalent target intent without becoming a session id."""
        return _sha256({"target": self.target.to_dict(), "requested_profile": self.requested_profile})

    def to_dict(self) -> dict[str, object]:
        """Return the complete immutable review intent."""
        return {
            "schema": INTENT_SCHEMA,
            "target": self.target.to_dict(),
            "requested_profile": self.requested_profile,
            "intent_sha256": self.intent_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> ReviewIntent:
        """Parse and verify one immutable review intent."""
        data = _exact(value, {"schema", "target", "requested_profile", "intent_sha256"}, "review intent")
        if data["schema"] != INTENT_SCHEMA:
            raise ValueError("review intent schema is unsupported")
        intent = cls(target=TargetInput.from_dict(data["target"]), requested_profile=data["requested_profile"])
        if data["intent_sha256"] != intent.intent_sha256:
            raise ValueError("review intent hash does not match its content")
        return intent


@dataclass(frozen=True, kw_only=True)
class ScheduleRecord:
    """Complete shared round and completion policy."""

    mode: str
    max_rounds: int
    min_rounds: int
    converge_after: int | None
    completion: str
    stop_on_failure: bool

    def __post_init__(self) -> None:
        """Reuse the engine policy validator for observable schedules."""
        if self.completion == "converge" and self.converge_after is None:
            raise ValueError("converging schedule requires converge_after")
        if self.completion == "single" and self.converge_after is not None:
            raise ValueError("single schedule cannot have converge_after")
        ReviewSchedule(
            mode=self.mode,
            max_rounds=self.max_rounds,
            min_rounds=self.min_rounds,
            converge_after=self.converge_after or 1,
            completion=self.completion,
            stop_on_failure=self.stop_on_failure,
        )

    @classmethod
    def from_schedule(cls, schedule: ReviewSchedule) -> ScheduleRecord:
        """Project the canonical engine schedule without changing it."""
        return cls(
            mode=schedule.mode,
            max_rounds=schedule.max_rounds,
            min_rounds=schedule.min_rounds,
            converge_after=schedule.converge_after if schedule.completion == "converge" else None,
            completion=schedule.completion,
            stop_on_failure=schedule.stop_on_failure,
        )

    def to_schedule(self) -> ReviewSchedule:
        """Restore the canonical engine schedule consumed by target adapters."""
        return ReviewSchedule(
            mode=self.mode,
            max_rounds=self.max_rounds,
            min_rounds=self.min_rounds,
            converge_after=self.converge_after or 1,
            completion=self.completion,
            stop_on_failure=self.stop_on_failure,
        )

    def to_dict(self) -> dict[str, object]:
        """Return the strict schedule wire form."""
        return {
            "mode": self.mode,
            "max_rounds": self.max_rounds,
            "min_rounds": self.min_rounds,
            "converge_after": self.converge_after,
            "completion": self.completion,
            "stop_on_failure": self.stop_on_failure,
        }

    @classmethod
    def from_dict(cls, value: object) -> ScheduleRecord:
        """Parse one strict schedule record."""
        fields = {"mode", "max_rounds", "min_rounds", "converge_after", "completion", "stop_on_failure"}
        return cls(**_exact(value, fields, "schedule"))


@dataclass(frozen=True, kw_only=True)
class ConcurrencyRecord:
    """Explicit concurrency for judgment and verification calls."""

    review: int | None
    verification: int | None

    def __post_init__(self) -> None:
        """Reject nonpositive active concurrency values."""
        for name, value in (("review", self.review), ("verification", self.verification)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
                raise ValueError(f"{name} concurrency must be positive or null")

    def to_dict(self) -> dict[str, int | None]:
        """Return the strict concurrency wire form."""
        return {"review": self.review, "verification": self.verification}

    @classmethod
    def from_dict(cls, value: object) -> ConcurrencyRecord:
        """Parse one strict concurrency record."""
        data = _exact(value, {"review", "verification"}, "concurrency")
        return cls(review=data["review"], verification=data["verification"])


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

    def __post_init__(self) -> None:
        """Require the published seat id to match its observable transport."""
        if (
            not isinstance(self.provider, str)
            or not self.provider
            or not isinstance(self.model, str)
            or not self.model
            or not isinstance(self.endpoint_identity, str)
            or not self.endpoint_identity
            or self.wire_api not in {None, "chat", "responses"}
        ):
            raise ValueError("provider seat fields are invalid")
        expected = seat_identity(self.provider, self.model, self.endpoint_identity, self.wire_api)
        if self.seat_id != expected:
            raise ValueError("provider seat id does not match its transport")

    def to_dict(self) -> dict[str, object]:
        """Return the strict provider seat wire form."""
        return {
            "seat_id": self.seat_id,
            "provider": self.provider,
            "model": self.model,
            "endpoint_identity": self.endpoint_identity,
            "wire_api": self.wire_api,
        }

    @classmethod
    def from_dict(cls, value: object) -> ProviderSeatRecord:
        """Parse one strict provider seat record."""
        fields = {"seat_id", "provider", "model", "endpoint_identity", "wire_api"}
        return cls(**_exact(value, fields, "provider seat"))


@dataclass(frozen=True, kw_only=True)
class ProviderPlanRecord:
    """Observable effective seats and role routing."""

    retries: int | None
    timeout_seconds: float | None
    seats: tuple[ProviderSeatRecord, ...]
    base_seat_id: str | None
    finder_seat_id: str | None
    challenger_seat_id: str | None
    judge_seat_id: str | None

    def __post_init__(self) -> None:
        """Require every active role to reference one published seat."""
        if self.retries is not None and (
            isinstance(self.retries, bool) or not isinstance(self.retries, int) or self.retries < 0
        ):
            raise ValueError("provider retries must be nonnegative or null")
        if self.timeout_seconds is not None and (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("provider timeout must be positive or null")
        if not isinstance(self.seats, tuple) or not all(isinstance(seat, ProviderSeatRecord) for seat in self.seats):
            raise ValueError("provider seats must be a tuple of seat records")
        ids = {seat.seat_id for seat in self.seats}
        if len(ids) != len(self.seats):
            raise ValueError("provider seats must be unique")
        for label, seat_id in (
            ("base", self.base_seat_id),
            ("finder", self.finder_seat_id),
            ("challenger", self.challenger_seat_id),
            ("judge", self.judge_seat_id),
        ):
            if seat_id is not None and seat_id not in ids:
                raise ValueError(f"{label} references an unknown provider seat")

    def to_dict(self) -> dict[str, object]:
        """Return the strict provider plan wire form."""
        return {
            "retries": self.retries,
            "timeout_seconds": self.timeout_seconds,
            "seats": [seat.to_dict() for seat in self.seats],
            "roles": {
                "base": self.base_seat_id,
                "finder": self.finder_seat_id,
                "challenger": self.challenger_seat_id,
                "judge": self.judge_seat_id,
            },
        }

    @classmethod
    def from_dict(cls, value: object) -> ProviderPlanRecord:
        """Parse one strict provider plan record."""
        data = _exact(value, {"retries", "timeout_seconds", "seats", "roles"}, "providers")
        roles = _exact(data["roles"], {"base", "finder", "challenger", "judge"}, "provider roles")
        if not isinstance(data["seats"], list):
            raise ValueError("provider seats must be a list")
        return cls(
            retries=data["retries"],
            timeout_seconds=data["timeout_seconds"],
            seats=tuple(ProviderSeatRecord.from_dict(seat) for seat in data["seats"]),
            base_seat_id=roles["base"],
            finder_seat_id=roles["finder"],
            challenger_seat_id=roles["challenger"],
            judge_seat_id=roles["judge"],
        )


@dataclass(frozen=True, kw_only=True)
class VerificationRecord:
    """Observable skeptic and confirmer route."""

    enabled: bool
    votes_required: int | None
    skeptic_seat_id: str | None
    confirmer_seat_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        """Keep disabled verification free of active policy fields."""
        if not isinstance(self.enabled, bool):
            raise ValueError("verification enabled must be boolean")
        if self.votes_required is not None and (
            isinstance(self.votes_required, bool) or not isinstance(self.votes_required, int) or self.votes_required < 1
        ):
            raise ValueError("verification votes must be a positive integer or null")
        if self.skeptic_seat_id is not None and not isinstance(self.skeptic_seat_id, str):
            raise ValueError("verification skeptic seat id must be a string or null")
        if not isinstance(self.confirmer_seat_ids, tuple) or not all(
            isinstance(seat_id, str) for seat_id in self.confirmer_seat_ids
        ):
            raise ValueError("verification confirmer seat ids must be a tuple of strings")
        if len(set(self.confirmer_seat_ids)) != len(self.confirmer_seat_ids):
            raise ValueError("verification confirmer seat ids must be unique")
        if self.enabled:
            if self.votes_required is None or self.skeptic_seat_id is None:
                raise ValueError("enabled verification requires votes and a skeptic seat")
        elif self.votes_required is not None or self.skeptic_seat_id is not None or self.confirmer_seat_ids:
            raise ValueError("disabled verification cannot have active policy fields")

    def to_dict(self) -> dict[str, object]:
        """Return the strict verification route wire form."""
        return {
            "enabled": self.enabled,
            "votes_required": self.votes_required,
            "skeptic_seat_id": self.skeptic_seat_id,
            "confirmer_seat_ids": list(self.confirmer_seat_ids),
        }

    @classmethod
    def from_dict(cls, value: object) -> VerificationRecord:
        """Parse one strict verification route record."""
        fields = {"enabled", "votes_required", "skeptic_seat_id", "confirmer_seat_ids"}
        data = _exact(value, fields, "verification")
        if not isinstance(data["confirmer_seat_ids"], list):
            raise ValueError("verification confirmer seat ids must be a list")
        return cls(
            enabled=data["enabled"],
            votes_required=data["votes_required"],
            skeptic_seat_id=data["skeptic_seat_id"],
            confirmer_seat_ids=tuple(data["confirmer_seat_ids"]),
        )


@dataclass(frozen=True, kw_only=True)
class ReviewAttemptRequest:
    """One immutable review execution request."""

    action: ReviewAction
    engine_version: str
    schedule: ScheduleRecord | None
    concurrency: ConcurrencyRecord | None
    dry_run: bool | None
    fresh: bool | None
    providers: ProviderPlanRecord | None
    verification: VerificationRecord | None

    def __post_init__(self) -> None:
        """Reject action and policy combinations the engine cannot execute."""
        if self.action not in {"run", "scaffold", "finalize", "gate"}:
            raise ValueError("review action is invalid")
        if not isinstance(self.engine_version, str) or not self.engine_version:
            raise ValueError("engine version must be nonempty")
        if self.action == "run":
            if not isinstance(self.dry_run, bool):
                raise ValueError("run action requires an explicit dry run policy")
            if (
                self.schedule is None
                or self.concurrency is None
                or self.concurrency.review is None
                or self.providers is None
                or self.providers.finder_seat_id is None
                or self.verification is None
            ):
                raise ValueError("run action requires schedule, review concurrency, and finder seat")
            if self.schedule.mode == "adversarial" and (
                self.providers.challenger_seat_id is None or self.providers.judge_seat_id is None
            ):
                raise ValueError("adversarial run requires challenger and judge seats")
        elif self.action == "finalize":
            if (
                self.schedule is not None
                or self.dry_run is not None
                or self.concurrency is None
                or self.concurrency.review is not None
                or self.providers is None
                or self.verification is None
            ):
                raise ValueError("finalize action requires only verification execution policy")
        elif any(
            value is not None
            for value in (self.schedule, self.concurrency, self.dry_run, self.providers, self.verification)
        ):
            raise ValueError("scaffold and gate cannot have model execution policy")
        if self.action in {"run", "scaffold"}:
            if self.fresh is not None and not isinstance(self.fresh, bool):
                raise ValueError("fresh must be boolean or null")
        elif self.fresh is not None:
            raise ValueError("fresh applies only to run or scaffold")
        if self.verification is not None and self.concurrency is not None and self.providers is not None:
            if self.verification.enabled and self.concurrency.verification is None:
                raise ValueError("enabled verification requires explicit concurrency")
            if not self.verification.enabled and self.concurrency.verification is not None:
                raise ValueError("disabled verification cannot have concurrency")
            known = {seat.seat_id for seat in self.providers.seats}
            referenced = {self.verification.skeptic_seat_id, *self.verification.confirmer_seat_ids} - {None}
            if not referenced.issubset(known):
                raise ValueError("verification references an unknown provider seat")
            if self.dry_run is True and self.verification.enabled:
                raise ValueError("dry run cannot enable verification")
            if self.dry_run is True and (
                self.providers.retries is not None or self.providers.timeout_seconds is not None
            ):
                raise ValueError("dry run cannot have provider retry or timeout policy")

    @property
    def request_sha256(self) -> str:
        """Identify effective behavior independently from attempt identity and time."""
        return _sha256(self.semantic_dict())

    @property
    def judgment_configuration_sha256(self) -> str:
        """Identify policy that controls reusable repository judgment results."""
        if self.schedule is None or self.providers is None or self.verification is None:
            raise ValueError("only run requests have reusable judgment configuration")
        providers = self.providers.to_dict()
        return _sha256(
            {
                "schedule": self.schedule.to_dict() if self.schedule is not None else None,
                "provider_seats": providers["seats"],
                "provider_roles": providers["roles"],
                "verification": self.verification.to_dict(),
                "dry_run": self.dry_run,
                "engine_version": self.engine_version,
            }
        )

    def semantic_dict(self) -> dict[str, object]:
        """Return the stable command semantics consumed by target adapters."""
        return {
            "action": self.action,
            "engine_version": self.engine_version,
            "schedule": self.schedule.to_dict() if self.schedule is not None else None,
            "concurrency": self.concurrency.to_dict() if self.concurrency is not None else None,
            "dry_run": self.dry_run,
            "fresh": self.fresh,
            "providers": self.providers.to_dict() if self.providers is not None else None,
            "verification": self.verification.to_dict() if self.verification is not None else None,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the complete strict attempt request."""
        return {"schema": REQUEST_SCHEMA, **self.semantic_dict(), "request_sha256": self.request_sha256}

    @classmethod
    def from_dict(cls, value: object) -> ReviewAttemptRequest:
        """Parse and verify one complete attempt request."""
        fields = {
            "schema",
            "action",
            "engine_version",
            "schedule",
            "concurrency",
            "dry_run",
            "fresh",
            "providers",
            "verification",
            "request_sha256",
        }
        data = _exact(value, fields, "review attempt request")
        if data["schema"] != REQUEST_SCHEMA:
            raise ValueError("review attempt request schema is unsupported")
        request = cls(
            action=data["action"],
            engine_version=data["engine_version"],
            schedule=ScheduleRecord.from_dict(data["schedule"]) if data["schedule"] is not None else None,
            concurrency=ConcurrencyRecord.from_dict(data["concurrency"]) if data["concurrency"] is not None else None,
            dry_run=data["dry_run"],
            fresh=data["fresh"],
            providers=ProviderPlanRecord.from_dict(data["providers"]) if data["providers"] is not None else None,
            verification=(
                VerificationRecord.from_dict(data["verification"]) if data["verification"] is not None else None
            ),
        )
        if data["request_sha256"] != request.request_sha256:
            raise ValueError("review attempt request hash does not match its content")
        return request
