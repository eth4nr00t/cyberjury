"""Item records of one stage: each item's record and payload, written when the item finishes."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from cyberjury.record import Record
from cyberjury.workspace import WorkspaceCorruptionError, read_json_object, read_record, write_json_atomic, write_record


class ItemStore:
    """The `<stage>/items` directory of one review, read back to resume finished items."""

    def __init__(self, review: Path, stage: str, *, payload: str = "") -> None:
        """Bind the store to its review directory, stage, and the directory name of its optional payloads."""
        self._review = review
        self._stage = stage
        self._payload = payload

    def artifact(self, name: str) -> str:
        """Return the payload path of one item relative to the review directory."""
        return f"{self._stage}/{self._payload}/{name}.json"

    def restore[V](self, name: str, parse: Callable[[Record, object], V]) -> V | None:
        """Return the parsed record and payload of one finished item, or None when it has no record."""
        path = self._review / self._stage / "items" / f"{name}.json"
        if not path.is_file():
            return None
        try:
            record = read_record(path)
            if record.id != f"{self._stage}/{name}":
                raise ValueError("item record identity does not match its file")
            payload = read_json_object(self._review / self.artifact(name)) if self._payload else None
            return parse(record, payload)
        except (LookupError, TypeError, ValueError, WorkspaceCorruptionError) as exc:
            raise WorkspaceCorruptionError(
                f"resume record {path} is unreadable or corrupt: {exc}, start again with --fresh"
            ) from exc

    def save(self, record: Record, payload: dict[str, object] | None = None) -> None:
        """Write one item's payload, then its record."""
        name = record.id.partition("/")[2]
        if payload is not None:
            path = self._review / self.artifact(name)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_json_atomic(path, payload)
        write_record(self._review / self._stage / "items" / f"{name}.json", record)
