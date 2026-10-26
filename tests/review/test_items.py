"""Item store tests cover saving one item's record and payload and reading them back to resume."""

import pytest

from cyberjury.record import Record
from cyberjury.review.items import ItemStore
from cyberjury.workspace import WorkspaceCorruptionError, write_record


def _record(name: str) -> Record:
    return Record(id=f"review/{name}", status="ok", started_at="2026-01-01T00:00:00Z", duration_seconds=0.5)


def test_an_item_without_a_record_restores_nothing(tmp_path):
    """Restoring unit-a before anything was saved returns None without calling the parser."""
    store = ItemStore(tmp_path, "review", payload="findings")

    assert store.restore("unit-a", lambda record, payload: pytest.fail("parsed a missing item")) is None


def test_a_saved_item_restores_its_record_and_payload(tmp_path):
    """Saving unit-a with a findings payload writes both files, and restore hands both to the parser."""
    store = ItemStore(tmp_path, "review", payload="findings")
    record = _record("unit-a")

    store.save(record, {"findings": []})

    assert store.restore("unit-a", lambda restored, payload: (restored, payload)) == (record, {"findings": []})
    assert (tmp_path / store.artifact("unit-a")).is_file()


def test_an_item_record_filed_under_another_name_is_corrupt_and_names_fresh(tmp_path):
    """A record for unit-b stored as unit-a raises WorkspaceCorruptionError that tells the operator to use --fresh."""
    store = ItemStore(tmp_path, "review")
    write_record(tmp_path / "review" / "items" / "unit-a.json", _record("unit-b"))

    with pytest.raises(WorkspaceCorruptionError, match="--fresh"):
        store.restore("unit-a", lambda record, payload: record)
