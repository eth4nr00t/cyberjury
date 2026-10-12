"""Fetch a verified source tree for a contract address and write it to disk.

The one place that combines the network, the pure parser, and the filesystem for the
`fetch source` command. It never runs a review, that is a separate explicit step, so a
fetch that fails leaves no half-written tree passed off as complete.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from cyberjury.sources.explorer import UrlOpen, chain_for, fetch_getsourcecode
from cyberjury.sources.metadata import (
    SOURCE_ACQUISITION_FILE,
    SOURCE_METADATA_FILE,
    SOURCE_RAW_FILE,
    SourceAcquisition,
    SourceError,
    SourceMeta,
    read_source_acquisition,
)
from cyberjury.sources.reconstruct import parse_getsourcecode
from cyberjury.sources.snapshot import SourceSnapshot

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_RECOVERY_SUFFIX = re.compile(r"^[0-9a-f]{32}$")


@dataclass(frozen=True)
class FetchResult:
    """Fetched source tree root plus its block explorer provenance."""

    out_dir: Path
    meta: SourceMeta
    file_count: int
    metadata_path: Path
    acquisition_path: Path


def _write_tree(out_dir: Path, files: dict[str, str]) -> None:
    """Write each reconstructed file under out_dir, refusing any path that would escape it.

    The parser already checked, this is defense in depth at the last step before a write.
    """
    base = out_dir.resolve()
    for rel, content in sorted(files.items()):
        dest = (out_dir / rel).resolve()
        if dest != base and base not in dest.parents:
            raise SourceError(f"unsafe source path: {rel!r}")
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _write_text(dest, content)


def _write_text(path: Path, value: str) -> None:
    """Write and sync one staging file before its tree can be published."""
    with path.open("x", encoding="utf-8") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_tree(root: Path) -> None:
    for current, directories, _files in os.walk(root, topdown=False):
        for directory in directories:
            _fsync_directory(Path(current) / directory)
        _fsync_directory(Path(current))


def _publish_tree(staging: Path, out_dir: Path) -> None:
    """Publish staging as one directory entry and restore an old tree on failure."""
    backup: Path | None = None
    if out_dir.exists() or out_dir.is_symlink():
        backup = out_dir.parent / f".{out_dir.name}.backup-{uuid.uuid4().hex}"
        os.replace(out_dir, backup)
    published = False
    try:
        os.replace(staging, out_dir)
        published = True
        _fsync_directory(out_dir.parent)
    except BaseException:
        failed = out_dir.parent / f".{out_dir.name}.failed-{uuid.uuid4().hex}"
        if published and out_dir.exists():
            os.replace(out_dir, failed)
        if backup is not None and backup.exists():
            os.replace(backup, out_dir)
            _fsync_directory(out_dir.parent)
        with contextlib.suppress(OSError):
            if failed.is_dir() and not failed.is_symlink():
                shutil.rmtree(failed)
            else:
                failed.unlink(missing_ok=True)
        raise
    if backup is not None:
        with contextlib.suppress(OSError):
            if backup.is_dir() and not backup.is_symlink():
                shutil.rmtree(backup)
            else:
                backup.unlink(missing_ok=True)


def _remove_owned_recovery_path(path: Path) -> None:
    """Remove one exact recovery path created by this user and naming scheme."""
    suffix = path.name.rsplit("-", 1)[-1]
    if not _RECOVERY_SUFFIX.fullmatch(suffix) or path.is_symlink() or path.stat().st_uid != os.getuid():
        raise SourceError(f"untrusted source recovery path requires manual inspection: {path}")
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _valid_publication(path: Path) -> bool:
    if not path.is_dir() or path.is_symlink():
        return False
    try:
        return read_source_acquisition(path) is not None
    except SourceError:
        return False


def _recover_publication(out_dir: Path) -> None:
    """Recover one old tree and remove unpublished staging left by a dead process."""
    backups = sorted(out_dir.parent.glob(f".{out_dir.name}.backup-*"))
    if len(backups) > 1:
        raise SourceError(f"multiple stale source backups exist for {out_dir}")
    if backups:
        backup = backups[0]
        if out_dir.exists() or out_dir.is_symlink():
            current_valid = _valid_publication(out_dir)
            backup_valid = _valid_publication(backup)
            if not backup_valid:
                raise SourceError(f"stale source backup is invalid and requires manual inspection: {backup}")
            if current_valid:
                _remove_owned_recovery_path(backup)
            else:
                failed = out_dir.parent / f".{out_dir.name}.failed-{uuid.uuid4().hex}"
                os.replace(out_dir, failed)
                os.replace(backup, out_dir)
                _fsync_directory(out_dir.parent)
                _remove_owned_recovery_path(failed)
        else:
            if not _valid_publication(backup):
                raise SourceError(f"stale source backup is invalid and requires manual inspection: {backup}")
            os.replace(backup, out_dir)
            _fsync_directory(out_dir.parent)
    for staging in out_dir.parent.glob(f".{out_dir.name}.staging-*"):
        _remove_owned_recovery_path(staging)


def _validate_output_target(out: str) -> Path:
    raw = Path(out).expanduser()
    if raw.is_symlink():
        raise SourceError(f"output path {raw} cannot be a symlink")
    out_dir = raw.resolve(strict=False)
    protected = {Path(out_dir.anchor), Path.home().resolve(), Path.cwd().resolve()}
    if out_dir in protected:
        raise SourceError(f"output path {out_dir} is too broad to replace")
    return out_dir


def _validate_existing_output(out_dir: Path, *, overwrite: bool) -> None:
    if not out_dir.exists():
        return
    if out_dir.is_dir() and not any(out_dir.iterdir()):
        return
    if not overwrite:
        raise SourceError(f"output directory {out_dir} is not empty, pass --overwrite to replace it")
    if not _valid_publication(out_dir):
        raise SourceError("--overwrite only replaces a valid source acquisition published by this command")


def fetch_source(
    *,
    chain_key: str,
    address: str,
    api_key: str,
    out: str,
    fetched_at: str,
    overwrite: bool = False,
    opener: UrlOpen | None = None,
) -> FetchResult:
    """Fetch verified source for an address and write the tree plus metadata.

    Fail loud on a bad address, a missing key, an unverified contract, or a non-empty
    output directory, invariant 4.
    """
    address = address.strip()
    if not _ADDRESS.match(address):
        raise SourceError(f"not a contract address: {address!r}")
    if not api_key.strip():
        raise SourceError("no Etherscan API key, set CYBERJURY_ETHERSCAN_API_KEY or pass --api-key")
    chain = chain_for(chain_key)
    out_dir = _validate_output_target(out)
    out_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = os.open(out_dir.parent, os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _recover_publication(out_dir)
        _validate_existing_output(out_dir, overwrite=overwrite)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)

    payload = fetch_getsourcecode(chain, address, api_key.strip(), opener=opener)
    source_url = chain.address_url.format(address=address)
    meta, files = parse_getsourcecode(
        payload,
        source=chain.source,
        chain=chain.key,
        chain_id=chain.chain_id,
        address=address,
        source_url=source_url,
        fetched_at=fetched_at,
    )

    lock = os.open(out_dir.parent, os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _recover_publication(out_dir)
        _validate_existing_output(out_dir, overwrite=overwrite)
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{out_dir.name}.staging-",
                suffix=uuid.uuid4().hex,
                dir=out_dir.parent,
            )
        )
        os.chmod(staging, 0o700)
        try:
            _write_tree(staging, files)
            raw_text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
            _write_text(staging / SOURCE_RAW_FILE, raw_text)
            metadata_text = meta.to_json() + "\n"
            _write_text(staging / SOURCE_METADATA_FILE, metadata_text)
            snapshot = SourceSnapshot.capture(staging, tuple(sorted(files)))
            acquisition = SourceAcquisition.create(
                metadata=meta,
                published_response_sha256=hashlib.sha256(raw_text.encode()).hexdigest(),
                source_snapshot=snapshot,
            )
            _write_text(
                staging / SOURCE_ACQUISITION_FILE,
                json.dumps(acquisition.to_dict(), indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
            )
            _fsync_tree(staging)
            _publish_tree(staging, out_dir)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)
    return FetchResult(
        out_dir=out_dir,
        meta=meta,
        file_count=len(files),
        metadata_path=out_dir / SOURCE_METADATA_FILE,
        acquisition_path=out_dir / SOURCE_ACQUISITION_FILE,
    )
