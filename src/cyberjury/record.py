"""One record shape for every attempt, stage, and item, shared by the files and the CLI output."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

RECORD_SCHEMA = "cyberjury.record/v1"
STATUSES = ("running", "ok", "incomplete", "failed", "interrupted")
ERROR_CODES = ("config", "input", "busy", "model", "internal")
STAGES = ("config", "target", "session", "source", "facts", "plan", "grounding", "review", "link", "result")
METRICS = (
    "files",
    "bytes",
    "skipped_files",
    "limitations",
    "items",
    "finished",
    "restored",
    "failed",
    "findings",
    "unlocated",
    "issues",
    "critical",
    "high",
    "medium",
    "low",
    "calls",
    "input_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "output_tokens",
)
_ATTEMPT_ID = re.compile(r"attempt-\d{8}-\d{6}-[0-9a-f]{8}")
_ITEM_NAME = re.compile(r"[A-Za-z0-9._-]+")
_TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"
_MAX_MESSAGE_CHARS = 2_000
_SECRETS = (
    re.compile(r"(?i)(authorization['\"]?\s*[:=]\s*['\"]?)(?:bearer\s+)?[^\s'\",}]+"),
    re.compile(r"(?i)(bearer\s+)[^\s'\",}]+"),
    re.compile(r"(?i)((?:\b|_)(?:api[_ -]?key|token|secret|password)s?\b['\"]?\s*[:=]?\s*['\"]?)[^\s'\",}]{8,}"),
    re.compile(r"()\bsk-[A-Za-z0-9_-]{8,}"),
)
_FIELDS = ("schema", "id", "status", "started_at", "duration_seconds", "metrics", "attributes", "artifacts", "error")


def utc_timestamp(value: datetime | None = None) -> str:
    """Return one second precision UTC timestamp."""
    return (value or datetime.now(UTC)).astimezone(UTC).strftime(_TIMESTAMP)


def parse_timestamp(value: str) -> datetime:
    """Parse one second precision UTC timestamp written by `utc_timestamp`."""
    return datetime.strptime(value, _TIMESTAMP).replace(tzinfo=UTC)


def is_attempt_id(value: str) -> bool:
    """Return whether the value names one attempt."""
    return _ATTEMPT_ID.fullmatch(value) is not None


def _valid_id(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if is_attempt_id(value) or value in STAGES:
        return True
    stage, separator, item = value.partition("/")
    return bool(separator) and stage in STAGES and _ITEM_NAME.fullmatch(item) is not None


def error_message(text: str) -> str:
    """Return an error text safe to persist: credentials redacted and the length bounded."""
    for pattern in _SECRETS:
        text = pattern.sub(lambda match: f"{match.group(1)}[redacted]", text)
    text = " ".join(text.split()) or "unknown error"
    return text if len(text) <= _MAX_MESSAGE_CHARS else text[: _MAX_MESSAGE_CHARS - 1] + "…"


@dataclass(frozen=True, slots=True, kw_only=True)
class RecordError:
    """Why a record did not finish ok."""

    code: str
    message: str

    def __post_init__(self) -> None:
        """Require a known code and a message."""
        if self.code not in ERROR_CODES or not isinstance(self.message, str) or not self.message:
            raise ValueError("record error needs a known code and a message")

    def to_dict(self) -> dict[str, str]:
        """Return the error in field order."""
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True, slots=True, kw_only=True)
class Record:
    """The state of one attempt, stage, or item."""

    id: str
    status: str
    started_at: str
    duration_seconds: float | None
    metrics: Mapping[str, int] = field(default_factory=dict)
    attributes: Mapping[str, str | int | float | bool | None] = field(default_factory=dict)
    artifacts: tuple[str, ...] = ()
    error: RecordError | None = None

    def __post_init__(self) -> None:
        """Reject a record outside the shared schema."""
        if not _valid_id(self.id):
            raise ValueError(f"record id is invalid: {self.id!r}")
        if self.status not in STATUSES:
            raise ValueError(f"record status is invalid: {self.status!r}")
        parse_timestamp(self.started_at)
        if (self.duration_seconds is None) != (self.status == "running"):
            raise ValueError("record duration is set exactly when the record is no longer running")
        if self.duration_seconds is not None and (isinstance(self.duration_seconds, bool) or self.duration_seconds < 0):
            raise ValueError("record duration must be nonnegative")
        unknown = set(self.metrics) - set(METRICS)
        if unknown:
            raise ValueError(f"record metrics are not in the vocabulary: {sorted(unknown)}")
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in self.metrics.values()):
            raise ValueError("record metrics must be nonnegative integers")
        if any(not isinstance(value, (str, int, float, bool, type(None))) for value in self.attributes.values()):
            raise ValueError("record attributes must be scalars")
        if not isinstance(self.artifacts, tuple) or len(set(self.artifacts)) != len(self.artifacts):
            raise ValueError("record artifacts must be unique paths")
        if (self.error is not None) != (self.status in {"failed", "incomplete"}):
            raise ValueError("record error is set exactly when the record failed or is incomplete")
        if ("reason" in self.attributes) != (self.status == "interrupted"):
            raise ValueError("record reason is set exactly when the record was interrupted")
        if "reason" in self.attributes and (
            not isinstance(self.attributes["reason"], str) or not self.attributes["reason"]
        ):
            raise ValueError("record reason must be a nonempty string")

    def to_dict(self) -> dict[str, object]:
        """Return the record in field order, metrics in vocabulary order."""
        return {
            "schema": RECORD_SCHEMA,
            "id": self.id,
            "status": self.status,
            "started_at": self.started_at,
            "duration_seconds": self.duration_seconds,
            "metrics": {name: self.metrics[name] for name in METRICS if name in self.metrics},
            "attributes": dict(self.attributes),
            "artifacts": list(self.artifacts),
            "error": self.error.to_dict() if self.error is not None else None,
        }

    @classmethod
    def from_dict(cls, value: object) -> Record:
        """Parse one record written by `to_dict`."""
        if not isinstance(value, dict) or tuple(value) != _FIELDS or value["schema"] != RECORD_SCHEMA:
            raise ValueError("record does not follow the record schema")
        error = value["error"]
        if error is not None and (not isinstance(error, dict) or tuple(error) != ("code", "message")):
            raise ValueError("record error does not follow the record schema")
        if not isinstance(value["metrics"], dict) or not isinstance(value["attributes"], dict):
            raise ValueError("record metrics and attributes must be objects")
        if not isinstance(value["artifacts"], list):
            raise ValueError("record artifacts must be a list")
        return cls(
            id=value["id"],
            status=value["status"],
            started_at=value["started_at"],
            duration_seconds=value["duration_seconds"],
            metrics=value["metrics"],
            attributes=value["attributes"],
            artifacts=tuple(value["artifacts"]),
            error=RecordError(**error) if error is not None else None,
        )

    def line(self) -> str:
        """Return the one line view: the record fields in order, without schema, start time, and artifacts."""
        data = self.to_dict()
        parts = [self.id, self.status]
        if self.duration_seconds is not None:
            parts.append(f"{self.duration_seconds}s")
        parts += [f"{name}={value}" for name, value in data["metrics"].items()]
        parts += [f"{name}={_scalar(value)}" for name, value in self.attributes.items()]
        if self.error is not None:
            parts.append(f"error: {self.error.code} {self.error.message}")
        return " ".join(parts)


def _scalar(value: object) -> str:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return json.dumps(text, ensure_ascii=False) if not text or any(character.isspace() for character in text) else text


def render(record: Record) -> str:
    """Return the pretty JSON text a record file holds and the CLI prints."""
    return json.dumps(record.to_dict(), indent=2, ensure_ascii=False, allow_nan=False) + "\n"
