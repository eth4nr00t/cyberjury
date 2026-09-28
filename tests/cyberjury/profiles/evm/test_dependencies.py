"""EVM dependency source uses the same npm proof and shared evidence shape."""

import base64
import hashlib
import io
import json
import tarfile

import pytest

from cyberjury.profiles.evm.dependencies import catalog_from_archives
from cyberjury.review.dependencies import DependencySourceError


def test_evm_npm_archive_indexes_only_locked_solidity_source(tmp_path):
    directory = tmp_path / "archives"
    directory.mkdir()
    archive = directory / "contracts-1.0.tgz"
    with tarfile.open(archive, "w:gz") as opened:
        for name, content in (
            ("package/package.json", json.dumps({"name": "contracts", "version": "1.0"}).encode()),
            ("package/src/Guard.sol", b"contract Guard { function check() public pure {} }\n"),
            ("package/src/index.js", b"module.exports = {}\n"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            opened.addfile(info, io.BytesIO(content))
    integrity = base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps({"packages": {"node_modules/contracts": {"version": "1.0", "integrity": f"sha512-{integrity}"}}}),
        encoding="utf-8",
    )
    catalog = catalog_from_archives(tmp_path, directory)
    assert catalog is not None
    assert [source.member for source in catalog.sources] == ["package/src/Guard.sol"]
    assert catalog.sources[0].ecosystem == "evm"
    assert catalog.search("contracts", "check")[0].line == 1
    lock.write_text('{"packages": {}}', encoding="utf-8")
    with pytest.raises(DependencySourceError, match="selection changed"):
        catalog.read(catalog.sources[0])
