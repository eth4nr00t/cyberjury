"""Locate the one review contract shipped with the package and identify its exact content."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cyberjury.canonical import canonical_sha256

CONTRACT_SCHEMA = "cyberjury.review-contract/v1"
CONTRACT_DIR = Path(__file__).resolve().parent
_PACKAGE_ROOT = CONTRACT_DIR.parents[1]
SECURITY_KERNEL_FILE = CONTRACT_DIR / "security-kernel.md"
SEVERITY_RUBRIC_FILE = CONTRACT_DIR / "severity-rubric.md"
DETECTION_FILE = CONTRACT_DIR / "detection.yaml"
QUERIES_FILE = CONTRACT_DIR.parent / "syntax" / "queries.yaml"
_CONTRACT_FILES = (SECURITY_KERNEL_FILE, SEVERITY_RUBRIC_FILE, DETECTION_FILE, QUERIES_FILE)


@dataclass(frozen=True, kw_only=True)
class ContractReceipt:
    """Identify the kernel, rubric, file classification, and syntax queries one review used."""

    files: tuple[tuple[str, str], ...]
    contract_sha256: str

    @classmethod
    def capture(cls) -> ContractReceipt:
        """Hash every shipped contract file by its package relative path."""
        files = tuple(
            (path.relative_to(_PACKAGE_ROOT).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
            for path in _CONTRACT_FILES
        )
        return cls(files=files, contract_sha256=canonical_sha256(dict(files)))

    def to_dict(self) -> dict[str, object]:
        """Return the strict contract artifact."""
        return {"schema": CONTRACT_SCHEMA, "files": dict(self.files), "contract_sha256": self.contract_sha256}
