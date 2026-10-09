"""Retain each original model claim through exact finding identity folding."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ClaimRecord:
    """One exact model report before later identity or evidence folding."""

    candidate_id: str
    content_json: str
    content_sha256: str

    def __post_init__(self) -> None:
        """Reject a claim whose encoded source report has changed."""
        if not isinstance(self.candidate_id, str) or not self.candidate_id:
            raise ValueError("claim candidate id must be nonempty")
        if not isinstance(self.content_json, str) or not isinstance(self.content_sha256, str):
            raise ValueError("claim content and hash must be strings")
        expected = hashlib.sha256(self.content_json.encode()).hexdigest()
        if self.content_sha256 != expected:
            raise ValueError("claim content hash does not match its report")
        try:
            decoded = json.loads(self.content_json)
        except json.JSONDecodeError as exc:
            raise ValueError("claim content is not JSON") from exc
        if not isinstance(decoded, dict) or decoded.get("candidate_id") != self.candidate_id:
            raise ValueError("claim content does not identify its candidate")
        if (
            json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
            != self.content_json
        ):
            raise ValueError("claim content must use canonical JSON")

    @classmethod
    def create(cls, candidate_id: str, record: Mapping[str, object]) -> ClaimRecord:
        """Capture a report without relying on its summary or union identity."""
        body = {**record, "candidate_id": candidate_id}
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return cls(
            candidate_id=candidate_id,
            content_json=encoded,
            content_sha256=hashlib.sha256(encoded.encode()).hexdigest(),
        )

    @property
    def claim_id(self) -> str:
        """Identify one exact original claim independently from its folded parent."""
        return f"claim-{self.content_sha256[:20]}"

    @property
    def record(self) -> dict[str, object]:
        """Return a detached structured report for evidence review."""
        return json.loads(self.content_json)

    @property
    def report(self) -> dict[str, object]:
        """Return the model report without its later assigned candidate identity."""
        record = self.record
        record.pop("candidate_id")
        return record

    def to_dict(self) -> dict[str, str]:
        """Persist the complete original report and its content identity."""
        return {
            "candidate_id": self.candidate_id,
            "content_json": self.content_json,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> ClaimRecord:
        """Reject missing or additional checkpoint fields."""
        if not isinstance(value, dict) or set(value) != {"candidate_id", "content_json", "content_sha256"}:
            raise ValueError("claim checkpoint has an invalid shape")
        return cls(**value)


def merge_claims(*groups: tuple[ClaimRecord, ...]) -> tuple[ClaimRecord, ...]:
    """Keep one copy of each exact model report in stable identity order."""
    by_id: dict[str, ClaimRecord] = {}
    for group in groups:
        for claim in group:
            previous = by_id.get(claim.claim_id)
            if previous is not None and previous != claim:
                raise ValueError("claim identity collision")
            by_id[claim.claim_id] = claim
    return tuple(by_id[identity] for identity in sorted(by_id))
