"""Persist completed review work one item at a time so a resume repeats only open work."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from cyberjury.workspace import WorkspaceCorruptionError, read_json_object, write_json_atomic


class CheckpointStore:
    """One directory of atomically written records, one file per completed item key."""

    def __init__(self, directory: Path, schema: str) -> None:
        """Bind the store to its directory and record schema."""
        self._directory = directory
        self._schema = schema

    def restore[V](self, key: str, parse: Callable[[object], V]) -> V | None:
        """Return the parsed record of one completed item, or None when it has none."""
        path = self._directory / f"{key}.json"
        if not path.is_file():
            return None
        try:
            document = read_json_object(path)
            if set(document) != {"schema", "value"} or document["schema"] != self._schema:
                raise ValueError("checkpoint schema is unsupported")
            return parse(document["value"])
        except (LookupError, TypeError, ValueError, WorkspaceCorruptionError) as exc:
            raise ValueError(
                f"resume checkpoint {path} is unreadable or corrupt: {exc}. "
                "Remove the workspace to discard prior state and start over."
            ) from exc

    def save(self, key: str, value: object) -> None:
        """Durably replace the record of one completed item."""
        self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_json_atomic(self._directory / f"{key}.json", {"schema": self._schema, "value": value})
