"""Web dependency selection never upgrades a plausible package name into proof."""

import base64
import hashlib
import io
import json
import tarfile
import zipfile

import pytest

from cyberjury.profiles.web import dependencies as web_dependencies
from cyberjury.profiles.web.dependencies import catalog_from_archives, read_locked_source
from cyberjury.review.dependencies import DependencySource, DependencySourceError


def _source(tmp_path, *, ecosystem, package, version, archive, member, selection):
    lock = tmp_path / ("Pipfile.lock" if ecosystem == "python" else "package-lock.json")
    lock.write_text(json.dumps(selection), encoding="utf-8")
    return DependencySource(
        ecosystem=ecosystem,
        package=package,
        version=version,
        archive=archive,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        member=member,
        selection_file=lock.name,
        selection_sha256=hashlib.sha256(lock.read_bytes()).hexdigest(),
    )


def test_python_wheel_requires_matching_lock_hash_and_distribution_metadata(tmp_path):
    archive = tmp_path / "sample-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("sample/__init__.py", "VALUE = 1\n")
        opened.writestr("sample-1.0.dist-info/METADATA", "Name: sample\nVersion: 1.0\n")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    source = _source(
        tmp_path,
        ecosystem="python",
        package="sample",
        version="1.0",
        archive=archive,
        member="sample/__init__.py",
        selection={"default": {"sample": {"version": "==1.0", "hashes": [f"sha256:{digest}"]}}},
    )
    assert read_locked_source(source, tmp_path) == "VALUE = 1\n"


def test_python_wheel_metadata_size_is_bounded(tmp_path):
    archive = tmp_path / "sample-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("sample/__init__.py", "VALUE = 1\n")
        opened.writestr(
            "sample-1.0.dist-info/METADATA",
            "Name: sample\nVersion: 1.0\n" + ("Description: x\n" * 20_000),
        )
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    source = _source(
        tmp_path,
        ecosystem="python",
        package="sample",
        version="1.0",
        archive=archive,
        member="sample/__init__.py",
        selection={"default": {"sample": {"version": "==1.0", "hashes": [f"sha256:{digest}"]}}},
    )
    with pytest.raises(DependencySourceError, match="metadata"):
        read_locked_source(source, tmp_path)


def test_identical_default_and_develop_entries_share_one_locked_archive(tmp_path):
    archive = tmp_path / "sample-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("sample/__init__.py", "VALUE = 1\n")
        opened.writestr("sample-1.0.dist-info/METADATA", "Name: sample\nVersion: 1.0\n")
    locked = {"version": "==1.0", "hashes": [f"sha256:{hashlib.sha256(archive.read_bytes()).hexdigest()}"]}
    source = _source(
        tmp_path,
        ecosystem="python",
        package="sample",
        version="1.0",
        archive=archive,
        member="sample/__init__.py",
        selection={"default": {"sample": locked}, "develop": {"sample": locked}},
    )
    assert read_locked_source(source, tmp_path) == "VALUE = 1\n"
    archive_dir = tmp_path / "archives"
    archive_dir.mkdir()
    selected_archive = archive_dir / archive.name
    selected_archive.write_bytes(archive.read_bytes())
    assert catalog_from_archives(tmp_path, archive_dir).selections[0].package == "sample"


def test_conflicting_default_and_develop_entries_are_not_silently_ignored(tmp_path):
    archive_dir = tmp_path / "archives"
    archive_dir.mkdir()
    archive = archive_dir / "sample-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("sample/__init__.py", "VALUE = 1\n")
        opened.writestr("sample-1.0.dist-info/METADATA", "Name: sample\nVersion: 1.0\n")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps(
            {
                "default": {"sample": {"version": "==1.0", "hashes": [f"sha256:{digest}"]}},
                "develop": {"sample": {"version": "==2.0", "hashes": [f"sha256:{digest}"]}},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(
        DependencySourceError, match="no verified selection: Python dependency has no unique lock entry"
    ):
        catalog_from_archives(tmp_path, archive_dir)


def test_archive_catalog_indexes_exact_source_without_eager_prompt_text(tmp_path):
    archive_dir = tmp_path / "archives"
    archive_dir.mkdir()
    archive = archive_dir / "sample-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("sample/__init__.py", "VALUE = 1\n")
        opened.writestr("sample-1.0.dist-info/METADATA", "Name: sample\nVersion: 1.0\n")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps({"default": {"sample": {"version": "==1.0", "hashes": [f"sha256:{digest}"]}}}),
        encoding="utf-8",
    )
    catalog = catalog_from_archives(tmp_path, archive_dir)
    assert catalog is not None
    assert len(catalog.sources) == 1
    matches = catalog.search("sample", "VALUE")
    assert len(matches) == 1
    assert matches[0].preview == "VALUE = 1"


def test_uv_lock_resolves_one_exact_wheel_without_guessing_installed_source(tmp_path):
    archive_dir = tmp_path / "archives"
    archive_dir.mkdir()
    archive = archive_dir / "sample-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("sample/__init__.py", "VALUE = 2\n")
        opened.writestr("sample-1.0.dist-info/METADATA", "Name: sample\nVersion: 1.0\n")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (tmp_path / "uv.lock").write_text(
        f'[[package]]\nname = "sample"\nversion = "1.0"\nwheels = [{{ hash = "sha256:{digest}" }}]\n',
        encoding="utf-8",
    )
    catalog = catalog_from_archives(tmp_path, archive_dir)
    assert catalog is not None
    assert len(catalog.sources) == 1
    assert catalog.search("sample", "VALUE")[0].preview == "VALUE = 2"
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "sample"\nversion = "2.0"\n')
    with pytest.raises(DependencySourceError, match="selection changed"):
        catalog.read(catalog.sources[0])


def test_explicit_archive_without_a_supported_lock_fails_loud(tmp_path):
    archive_dir = tmp_path / "archives"
    archive_dir.mkdir()
    archive = archive_dir / "sample-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("sample/__init__.py", "VALUE = 1\n")
        opened.writestr("sample-1.0.dist-info/METADATA", "Name: sample\nVersion: 1.0\n")
    with pytest.raises(DependencySourceError, match="no verified selection: no matching project lock"):
        catalog_from_archives(tmp_path, archive_dir)


def test_unrelated_files_in_archive_directory_are_ignored(tmp_path):
    archive_dir = tmp_path / "archives"
    archive_dir.mkdir()
    (archive_dir / "README.txt").write_text("not a package archive", encoding="utf-8")

    assert catalog_from_archives(tmp_path, archive_dir) is None


@pytest.mark.parametrize("mismatch", ["version", "hash"])
def test_python_wheel_rejects_unselected_artifact(tmp_path, mismatch):
    archive = tmp_path / "sample-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr("sample/__init__.py", "VALUE = 1\n")
        opened.writestr("sample-1.0.dist-info/METADATA", "Name: sample\nVersion: 1.0\n")
    source = _source(
        tmp_path,
        ecosystem="python",
        package="sample",
        version="1.0",
        archive=archive,
        member="sample/__init__.py",
        selection={
            "default": {
                "sample": {
                    "version": "==2.0" if mismatch == "version" else "==1.0",
                    "hashes": [
                        "sha256:"
                        + ("a" * 64 if mismatch == "hash" else hashlib.sha256(archive.read_bytes()).hexdigest())
                    ],
                }
            }
        },
    )
    with pytest.raises(DependencySourceError, match="does not match"):
        read_locked_source(source, tmp_path)


@pytest.mark.parametrize("ecosystem", ["javascript", "typescript"])
def test_npm_package_requires_matching_integrity_and_embedded_metadata(tmp_path, ecosystem):
    archive = tmp_path / "sample-1.0.tgz"
    with tarfile.open(archive, "w:gz") as opened:
        metadata = json.dumps({"name": "sample", "version": "1.0"}).encode()
        source = b"export function execute() {}\n"
        for name, content in (("package/package.json", metadata), ("package/src/index.js", source)):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            opened.addfile(info, io.BytesIO(content))
    integrity = base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
    source = _source(
        tmp_path,
        ecosystem=ecosystem,
        package="sample",
        version="1.0",
        archive=archive,
        member="package/src/index.js",
        selection={"packages": {"node_modules/sample": {"version": "1.0", "integrity": f"sha512-{integrity}"}}},
    )
    assert read_locked_source(source, tmp_path) == "export function execute() {}\n"


def test_missing_npm_integrity_cannot_authorize_external_source(tmp_path):
    archive = tmp_path / "sample-1.0.tgz"
    with tarfile.open(archive, "w:gz") as opened:
        metadata = b'{"name":"sample","version":"1.0"}'
        info = tarfile.TarInfo("package/package.json")
        info.size = len(metadata)
        opened.addfile(info, io.BytesIO(metadata))
    source = _source(
        tmp_path,
        ecosystem="javascript",
        package="sample",
        version="1.0",
        archive=archive,
        member="package/package.json",
        selection={"packages": {"node_modules/sample": {"version": "1.0"}}},
    )
    with pytest.raises(DependencySourceError, match="no artifact integrity"):
        read_locked_source(source, tmp_path)


def test_go_archive_needs_selected_module_and_canonical_sum(tmp_path, monkeypatch):
    archive = tmp_path / "example.com/example@v1.0.0.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    member = "example.com/example@v1.0.0/entry.go"
    with zipfile.ZipFile(archive, "w") as opened:
        opened.writestr(member, "package example\n")
    lock = tmp_path / "go.sum"
    lock.write_text(f"example.com/example v1.0.0 {web_dependencies._go_archive_hash(archive.read_bytes())}\n")
    source = DependencySource(
        ecosystem="go",
        package="example.com/example",
        version="v1.0.0",
        archive=archive,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        member=member,
        selection_file=lock.name,
        selection_sha256=hashlib.sha256(lock.read_bytes()).hexdigest(),
    )

    class Result:
        returncode = 0
        stdout = '{"Path":"example.com/example","Version":"v1.0.0"}'

    monkeypatch.setattr(web_dependencies.subprocess, "run", lambda *args, **kwargs: Result())
    assert read_locked_source(source, tmp_path) == "package example\n"

    class Replaced:
        returncode = 0
        stdout = '{"Path":"example.com/example","Version":"v1.0.0","Replace":{"Path":"../local"}}'

    monkeypatch.setattr(web_dependencies.subprocess, "run", lambda *args, **kwargs: Replaced())
    with pytest.raises(DependencySourceError, match="not the selected module"):
        read_locked_source(source, tmp_path)
    (tmp_path / "go.work").write_text("go 1.22\n", encoding="utf-8")
    with pytest.raises(DependencySourceError, match="Go workspaces"):
        read_locked_source(source, tmp_path)
