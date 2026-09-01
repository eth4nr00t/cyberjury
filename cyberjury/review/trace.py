"""Optional, best-effort trace events for review diagnostics."""

from __future__ import annotations

import hashlib
from typing import Protocol


class Trace(Protocol):
    """Callable sink for bounded, structured diagnostic events."""

    def __call__(self, event: dict[str, object]) -> None:
        """Consume one structured event."""
        ...


def finding_id(finding: object) -> str:
    """Return a stable diagnostic identity without changing Finding semantics."""
    candidate_id = getattr(finding, "candidate_id", "")
    if isinstance(candidate_id, str) and candidate_id:
        return candidate_id
    category = str(getattr(finding, "category", "")).strip().lower().replace("_", "-")
    parts = (
        str(getattr(finding, "file", "")).strip().replace("\\", "/"),
        category,
        str(getattr(finding, "description", "")).strip(),
        str(getattr(finding, "exploit_scenario", "")).strip(),
        str(getattr(finding, "recommendation", "")).strip(),
    )
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"finding-{digest}"


def bind_trace(trace: Trace | None, **base: object) -> Trace | None:
    """Attach invocation metadata to every event emitted by one review."""
    if trace is None:
        return None

    def emit(event: dict[str, object]) -> None:
        try:
            trace({**base, **event})
        except Exception:
            return

    return emit


def emit_trace(trace: Trace | None, event: str, **fields: object) -> None:
    """Send one diagnostic event without allowing a trace sink to affect review."""
    if trace is None:
        return
    try:
        trace({"schema": 1, "event": event, **fields})
    except Exception:
        return
