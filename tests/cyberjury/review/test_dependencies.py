"""Dependency source receipts must remain exact and outside repository location scope."""

import hashlib
import zipfile

import pytest

from cyberjury.review.context import SourceEvidence
from cyberjury.review.dependencies import (
    DependencyCatalog,
    DependencySource,
    DependencySourceError,
    load_dependency_receipts,
    save_dependency_receipts,
    verify_dependency_catalog,
)
from cyberjury.workspace import write_json_atomic


def _selection(tmp_path):
    lock = tmp_path / "selected.lock"
    lock.write_text("selected version", encoding="utf-8")
    return lock, hashlib.sha256(lock.read_bytes()).hexdigest()


@pytest.mark.parametrize("ecosystem", ["python", "javascript", "typescript", "go", "evm"])
def test_exact_zip_source_receipt_keeps_ecosystem_identity(tmp_path, ecosystem):
    selection, selection_hash = _selection(tmp_path)
    archive = tmp_path / "dependency.zip"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("package/src/entry.txt", "def execute():\n    return False\n")
    source = DependencySource(
        ecosystem=ecosystem,
        package="example",
        version="1.0",
        archive=archive,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        member="package/src/entry.txt",
        selection_file=selection.name,
        selection_sha256=selection_hash,
    )
    assert source.id.startswith("dep-")
    assert (
        source.read(tmp_path, check_selection=lambda _selection, _artifact: None)
        == "def execute():\n    return False\n"
    )


def test_artifact_mutation_fails_instead_of_reusing_stale_source(tmp_path):
    selection, selection_hash = _selection(tmp_path)
    archive = tmp_path / "dependency.zip"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("entry.txt", "original")
    source = DependencySource(
        ecosystem="python",
        package="example",
        version="1.0",
        archive=archive,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        member="entry.txt",
        selection_file=selection.name,
        selection_sha256=selection_hash,
    )
    assert source.read(tmp_path, check_selection=lambda _selection, _artifact: None) == "original"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("entry.txt", "changed")
    with pytest.raises(DependencySourceError, match="archive changed"):
        source.read(tmp_path, check_selection=lambda _selection, _artifact: None)


def test_selection_mutation_fails_even_when_archive_is_unchanged(tmp_path):
    selection, selection_hash = _selection(tmp_path)
    archive = tmp_path / "dependency.zip"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("entry.txt", "original")
    source = DependencySource(
        ecosystem="python",
        package="example",
        version="1.0",
        archive=archive,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        member="entry.txt",
        selection_file=selection.name,
        selection_sha256=selection_hash,
    )
    selection.write_text("other version", encoding="utf-8")
    with pytest.raises(DependencySourceError, match="selection changed"):
        source.read(tmp_path, check_selection=lambda _selection, _artifact: None)


@pytest.mark.parametrize("path", ["../other", "/absolute", "a/../../other", "a\\b", "C:foo"])
def test_rejects_unsafe_member_and_selection_paths(tmp_path, path):
    with pytest.raises(DependencySourceError, match="unsafe path"):
        DependencySource(
            ecosystem="python",
            package="example",
            version="1.0",
            archive=tmp_path / "archive.zip",
            archive_sha256="a" * 64,
            member=path,
            selection_file="selected.lock",
            selection_sha256="b" * 64,
        )


def test_workspace_replays_dependency_evidence_without_persisting_source_text(tmp_path):
    selection, selection_hash = _selection(tmp_path)
    archive = tmp_path / "dependency.zip"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("package/entry.py", "def checked():\n    return False\n")
    source = DependencySource(
        ecosystem="python",
        package="example",
        version="1.0",
        archive=archive,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        member="package/entry.py",
        selection_file=selection.name,
        selection_sha256=selection_hash,
    )
    catalog = DependencyCatalog(
        repository=tmp_path,
        sources=(source,),
        reader=lambda entry, root: entry.read(root, check_selection=lambda _lock, _archive: None),
    )
    match = catalog.search("example", "checked")[0]
    receipt = match.receipt(catalog.read(source))
    evidence = SourceEvidence(
        id=receipt.id,
        identity=f"{source.identity}:{receipt.start}:{receipt.end}",
        text="the source is not persisted",
        dependency_receipt=receipt,
    )
    ws = tmp_path / "workspace"
    ws.mkdir()
    write_json_atomic(
        ws / "_dependency_sources.json",
        {"schema": "cyberjury.dependency-selection/v1", "revision": catalog.revision},
    )
    verify_dependency_catalog(ws, catalog)
    save_dependency_receipts(ws, catalog, (evidence,))
    raw = (ws / "_dependency_evidence.json").read_text(encoding="utf-8")
    assert "the source is not persisted" not in raw
    assert "return False" not in raw
    assert load_dependency_receipts(ws, catalog)[0].dependency_receipt == receipt
    archive.write_bytes(b"replaced")
    with pytest.raises(DependencySourceError, match="changed"):
        load_dependency_receipts(ws, catalog)
    with pytest.raises(DependencySourceError, match="changed"):
        catalog.validate()


def test_dependency_search_keeps_the_bounded_body_after_a_declaration(tmp_path):
    selection, selection_hash = _selection(tmp_path)
    archive = tmp_path / "dependency.zip"
    source_text = (
        "\n".join(
            (
                "def gate(value):",
                '    """A short API summary.',
                "",
                "    The effective condition follows the summary",
                '    after several lines of ordinary source text."""',
                "    enabled = True",
                "    available = value is not None",
                "    if enabled and available:",
                "        return False",
                "    return True",
            )
        )
        + "\n"
    )
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("package/gate.py", source_text)
    entry = DependencySource(
        ecosystem="python",
        package="example",
        version="1.0",
        archive=archive,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        member="package/gate.py",
        selection_file=selection.name,
        selection_sha256=selection_hash,
    )
    reads = []

    def read(source, root):
        reads.append(source.member)
        return source.read(root, check_selection=lambda _lock, _archive: None)

    catalog = DependencyCatalog(
        repository=tmp_path,
        sources=(entry,),
        reader=read,
    )
    match = catalog.search("example", "def gate(")[0]
    assert "return False" in match.receipt(source_text).read(catalog)
    assert reads == [entry.member, entry.member]
