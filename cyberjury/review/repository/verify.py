"""Adapt repository findings and checkpoints to shared verification."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import TypedDict

from cyberjury.detection import load_detection
from cyberjury.profiles.base import ContentPaths
from cyberjury.providers.base import Provider
from cyberjury.review.paths import resolve_source_path
from cyberjury.review.repository.union import Candidate
from cyberjury.review.storage import SourceSnapshot
from cyberjury.review.verification import (
    ModelVerifier,
    RefutationChecker,
    VerificationRecord,
    VerificationVote,
    Verifier,
    VerifyResult,
    verify_findings,
)


def candidate_key(candidate: Candidate, by_file: bool = False) -> str:
    """Serialize the configured repository identity for a checkpoint key."""
    return "|".join(str(part) for part in candidate.key(by_file))


def _verification_policy_fingerprint(
    verifier: Verifier,
    confirmers: list[tuple[str, RefutationChecker]] | None,
    votes: int,
) -> str:
    value = {
        "schema": 2,
        "votes": votes,
        "verifier": verifier.checkpoint_fingerprint().to_data(),
        "confirmers": [
            {"label": label, "checker": checker.checkpoint_fingerprint().to_data()}
            for label, checker in (confirmers or [])
        ],
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _candidate_checkpoint_key(
    candidate: Candidate,
    *,
    root: str,
    detection,
    by_file: bool,
    policy_fingerprint: str,
    source_revision: str,
) -> str:
    path = resolve_source_path(root, candidate.file, detection=detection)
    source_hash = hashlib.sha256(path.read_bytes()).hexdigest() if path is not None else ""
    value = {
        "schema": 2,
        "identity": candidate.key(by_file),
        "title": candidate.title,
        "category": candidate.category,
        "endpoint": candidate.endpoint,
        "symbol": candidate.symbol,
        "file": candidate.file,
        "line": candidate.line,
        "severity": candidate.severity,
        "evidence": candidate.evidence,
        "status": candidate.status,
        "found_by": candidate.found_by,
        "source_sha256": source_hash,
        "policy_sha256": policy_fingerprint,
        "source_revision": source_revision,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"verify-v2-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _checkpoint_error(path: Path, exc: Exception) -> ValueError:
    return ValueError(
        f"resume checkpoint {path} is unreadable or corrupt: {exc}. "
        "Remove the workspace to discard prior state and start over."
    )


class _VerifiedCheckpoint(TypedDict):
    real: bool
    reason: str
    record: dict[str, object]


def _load_verified(workspace: Path) -> dict[str, _VerifiedCheckpoint]:
    path = workspace / "_verified.json"
    if not path.is_file():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or set(document) != {"schema", "candidates"} or document["schema"] != 2:
            raise TypeError("expected a schema 2 verification checkpoint")
        data = document["candidates"]
        if not isinstance(data, dict):
            raise TypeError("verification checkpoint candidates must be an object")
        verified: dict[str, _VerifiedCheckpoint] = {}
        for key, record in data.items():
            if not isinstance(key, str) or not key or not isinstance(record, dict):
                raise TypeError("candidate checkpoints must map string keys to objects")
            if set(record) != {"real", "reason", "record"}:
                raise TypeError(f"checkpoint {key!r} must contain real, reason, and record")
            real = record["real"]
            reason = record["reason"]
            verification_record = record["record"]
            if not isinstance(real, bool) or not isinstance(reason, str) or not isinstance(verification_record, dict):
                raise TypeError(f"checkpoint {key!r} requires real, reason, and a record object")
            parsed_record = _record_from_data(verification_record, candidate=None)
            if real != (parsed_record.outcome == "retained"):
                raise TypeError(f"checkpoint {key!r} real flag conflicts with its verification record")
            verified[key] = {"real": real, "reason": reason, "record": verification_record}
        return verified
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise _checkpoint_error(path, exc) from exc


def _save_verified(workspace: Path, verified: dict) -> None:
    (workspace / "_verified.json").write_text(
        json.dumps({"schema": 2, "candidates": verified}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _write_refuted(
    workspace: Path,
    refuted: list[tuple[Candidate, str]],
    records: list[VerificationRecord],
) -> None:
    """Keep every verifier deletion visible for operator review."""
    lines = [
        "# Refuted candidates",
        "",
        "Surfaced by a review pass, then refuted by the adversarial verifier on a "
        "named controlling fact. Recorded so a wrong refutation is visible.",
        "",
    ]
    records_by_candidate = {id(record.candidate): record for record in records}
    for candidate, reason in refuted:
        lines.append(
            f"- **{candidate.title}** ({candidate.severity} {candidate.category}) "
            f"`{candidate.endpoint or candidate.file}`: {reason}"
        )
        record = records_by_candidate.get(id(candidate))
        if record is not None:
            for vote in record.votes:
                control = (
                    f" at `{vote.control_file}:{vote.control_line}`"
                    if vote.control_file and vote.control_line is not None
                    else ""
                )
                lines.append(
                    f"  - {vote.role} `{vote.actor_id}` on `{vote.seat_id}`: {vote.verdict}{control}. {vote.reason}"
                )
    (workspace / "_refuted.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def apply_verification(
    workspace: Path,
    findings: list[Candidate],
    *,
    root: str,
    verifier: Verifier | None,
    provider: Provider | None,
    model: str,
    votes: int,
    concurrency: int,
    fresh: bool,
    content: ContentPaths | None = None,
    confirmers: list[tuple[str, RefutationChecker]] | None = None,
    by_file: bool = False,
    on_verify: Callable[[int, int, float], None] | None = None,
    source_snapshot: SourceSnapshot | None = None,
) -> tuple[list[Candidate], VerifyResult]:
    """Preserve resumable repository verification without freezing failed checks."""
    if verifier is None:
        if provider is None:
            raise ValueError("verification needs a provider, or an injected verifier")
        verifier = ModelVerifier(provider=provider, model=model, content=content)
    verified = {} if fresh else _load_verified(workspace)
    detection = load_detection(content.detection_file) if content else None
    policy_fingerprint = _verification_policy_fingerprint(verifier, confirmers, votes)
    source_revision = source_snapshot.key if source_snapshot is not None else ""
    checkpoint_keys = {
        id(candidate): _candidate_checkpoint_key(
            candidate,
            root=root,
            detection=detection,
            by_file=by_file,
            policy_fingerprint=policy_fingerprint,
            source_revision=source_revision,
        )
        for candidate in findings
    }
    unlocatable = [
        candidate for candidate in findings if resolve_source_path(root, candidate.file, detection=detection) is None
    ]
    unlocatable_ids = {id(candidate) for candidate in unlocatable}
    locatable = [
        candidate
        for candidate in findings
        if checkpoint_keys[id(candidate)] not in verified and id(candidate) not in unlocatable_ids
    ]
    result = verify_findings(
        locatable,
        verifier,
        root,
        confirmers=confirmers,
        votes=votes,
        concurrency=concurrency,
        on_verify=on_verify,
        source_snapshot=source_snapshot,
    )
    records_by_candidate = {id(record.candidate): record for record in result.records}
    for candidate in result.verified:
        key = checkpoint_keys[id(candidate)]
        verified[key] = {
            "real": True,
            "reason": "",
            "record": _record_to_data(records_by_candidate[id(candidate)]),
        }
    for candidate, reason in result.refuted:
        verified[checkpoint_keys[id(candidate)]] = {
            "real": False,
            "reason": reason,
            "record": _record_to_data(records_by_candidate[id(candidate)]),
        }
    _save_verified(workspace, verified)
    retained = [
        candidate
        for candidate in findings
        if id(candidate) not in unlocatable_ids and verified.get(checkpoint_keys[id(candidate)], {"real": True})["real"]
    ]
    refuted = [
        (candidate, verified[checkpoint_keys[id(candidate)]]["reason"])
        for candidate in findings
        if not verified.get(checkpoint_keys[id(candidate)], {"real": True})["real"]
    ]
    incomplete_ids = {id(candidate) for candidate in result.incomplete}
    completed = [candidate for candidate in retained if id(candidate) not in incomplete_ids]
    current_record_ids = {id(record.candidate) for record in result.records}
    records = list(result.records)
    records.extend(
        _record_from_data(verified[checkpoint_keys[id(candidate)]]["record"], candidate=candidate)
        for candidate in findings
        if id(candidate) not in unlocatable_ids
        and id(candidate) not in current_record_ids
        and checkpoint_keys[id(candidate)] in verified
    )
    _write_refuted(workspace, refuted, records)
    return retained, VerifyResult(
        retained=retained,
        verified=completed,
        refuted=refuted,
        errors=result.errors,
        error_details=result.error_details,
        incomplete=result.incomplete,
        unlocatable=unlocatable,
        records=records,
    )


def _record_to_data(record: VerificationRecord) -> dict[str, object]:
    return {
        "outcome": record.outcome,
        "reason": record.reason,
        "votes": [
            {
                "role": vote.role,
                "actor_id": vote.actor_id,
                "seat_id": vote.seat_id,
                "verdict": vote.verdict,
                "reason": vote.reason,
                "control_file": vote.control_file,
                "control_line": vote.control_line,
            }
            for vote in record.votes
        ],
    }


def _record_from_data(data: dict[str, object], candidate) -> VerificationRecord:
    if set(data) != {"outcome", "reason", "votes"}:
        raise TypeError("verification record must contain outcome, reason, and votes")
    outcome = data["outcome"]
    reason = data["reason"]
    raw_votes = data["votes"]
    if outcome not in {"retained", "refuted", "incomplete"} or not isinstance(reason, str):
        raise TypeError("verification record outcome or reason is invalid")
    if not isinstance(raw_votes, list):
        raise TypeError("verification record votes must be a list")
    votes: list[VerificationVote] = []
    fields = {"role", "actor_id", "seat_id", "verdict", "reason", "control_file", "control_line"}
    for raw in raw_votes:
        if not isinstance(raw, dict) or set(raw) != fields:
            raise TypeError("verification vote has an invalid shape")
        role = raw["role"]
        verdict = raw["verdict"]
        if role not in {"skeptic", "confirmer"}:
            raise TypeError("verification vote role is invalid")
        allowed_verdicts = {"real", "refuted", "error"} if role == "skeptic" else {"upheld", "rejected", "error"}
        if verdict not in allowed_verdicts:
            raise TypeError("verification vote verdict is invalid for its role")
        if any(not isinstance(raw[field], str) or not raw[field] for field in ("actor_id", "seat_id")):
            raise TypeError("verification vote identities must be nonempty strings")
        if not isinstance(raw["reason"], str) or (verdict != "real" and not raw["reason"]):
            raise TypeError("verification vote reason is invalid")
        if not isinstance(raw["control_file"], str):
            raise TypeError("verification vote control_file must be a string")
        control_line = raw["control_line"]
        if control_line is not None and (
            isinstance(control_line, bool) or not isinstance(control_line, int) or control_line < 1
        ):
            raise TypeError("verification vote control_line must be positive or null")
        votes.append(VerificationVote(**raw))
    if outcome == "refuted" and (
        not any(vote.role == "skeptic" and vote.verdict == "refuted" for vote in votes)
        or not any(vote.role == "confirmer" and vote.verdict == "upheld" for vote in votes)
    ):
        raise TypeError("a refuted verification record requires skeptic and confirmer support")
    return VerificationRecord(candidate=candidate, outcome=outcome, votes=tuple(votes), reason=reason)
