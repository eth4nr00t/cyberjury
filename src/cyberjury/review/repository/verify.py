"""Adapt repository findings and checkpoints to shared verification."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

from cyberjury.review.paths import resolve_source_path
from cyberjury.review.repository.union import Candidate
from cyberjury.review.verification import (
    RefutationChecker,
    VerificationRecord,
    VerificationVote,
    Verifier,
    VerifyResult,
    verification_candidate_id,
    verify_findings,
)
from cyberjury.sources.snapshot import SourceSnapshot


def _verification_policy_fingerprint(
    verifier: Verifier,
    confirmers: list[tuple[str, RefutationChecker]] | None,
) -> str:
    value = {
        "schema": 7,
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
    policy_fingerprint: str,
    source_revision: str,
) -> str:
    value = {
        "schema": 6,
        "identity": candidate.key(),
        "title": candidate.title,
        "category": candidate.category,
        "endpoint": candidate.endpoint,
        "symbol": candidate.symbol,
        "file": candidate.file,
        "line": candidate.line,
        "severity": candidate.severity,
        "evidence": candidate.evidence,
        "found_by": candidate.found_by,
        "evidence_refs": candidate.evidence_refs,
        "policy_sha256": policy_fingerprint,
        "source_revision": source_revision,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"verify-v7-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _checkpoint_error(path: Path, exc: Exception) -> ValueError:
    return ValueError(
        f"resume checkpoint {path} is unreadable or corrupt: {exc}. "
        "Remove the workspace to discard prior state and start over."
    )


def _load_verified(workspace: Path) -> dict[str, dict[str, object]]:
    path = workspace / "_verified.json"
    if not path.is_file():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or set(document) != {"schema", "candidates"}:
            raise TypeError("expected a verification checkpoint")
        data = document["candidates"]
        if not isinstance(data, dict):
            raise TypeError("verification checkpoint candidates must be an object")
        if document["schema"] != 7:
            raise TypeError("verification checkpoint schema is unsupported")
        for key, record in data.items():
            if not isinstance(key, str) or not key or not isinstance(record, dict):
                raise TypeError("candidate checkpoints must map string keys to verification records")
            if _record_from_data(record, candidate=None).outcome not in {"retained", "refuted"}:
                raise TypeError(f"checkpoint {key!r} must hold a retained or refuted verification record")
        return data
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise _checkpoint_error(path, exc) from exc


def _save_verified(workspace: Path, verified: dict) -> None:
    (workspace / "_verified.json").write_text(
        json.dumps({"schema": 7, "candidates": verified}, indent=2, ensure_ascii=False),
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
        "Surfaced by unit review, then refuted by verification on a named controlling "
        "fact. Recorded so a wrong refutation is visible.",
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
    verifier: Verifier,
    concurrency: int,
    fresh: bool,
    confirmers: list[tuple[str, RefutationChecker]] | None = None,
    on_verify: Callable[[int, int, float], None] | None = None,
    source_snapshot: SourceSnapshot | None = None,
) -> tuple[list[Candidate], VerifyResult]:
    """Preserve resumable repository verification without freezing failed checks."""
    verified = {} if fresh else _load_verified(workspace)
    policy_fingerprint = _verification_policy_fingerprint(verifier, confirmers)
    source_revision = source_snapshot.snapshot_id if source_snapshot is not None else ""
    checkpoint_keys = {
        id(candidate): _candidate_checkpoint_key(
            candidate,
            root=root,
            policy_fingerprint=policy_fingerprint,
            source_revision=source_revision,
        )
        for candidate in findings
    }
    unlocatable = [candidate for candidate in findings if resolve_source_path(root, candidate.file) is None]
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
        concurrency=concurrency,
        on_verify=on_verify,
        source_snapshot=source_snapshot,
    )
    records_by_candidate = {id(record.candidate): record for record in result.records}
    for candidate in (*result.verified, *(candidate for candidate, _reason in result.refuted)):
        verified[checkpoint_keys[id(candidate)]] = _record_to_data(records_by_candidate[id(candidate)])
    _save_verified(workspace, verified)

    def refuted_reason(candidate: Candidate) -> str | None:
        record = verified.get(checkpoint_keys[id(candidate)])
        return str(record["reason"]) if record is not None and record["outcome"] == "refuted" else None

    retained = [
        candidate
        for candidate in findings
        if id(candidate) not in unlocatable_ids and refuted_reason(candidate) is None
    ]
    refuted = [(candidate, reason) for candidate in findings if (reason := refuted_reason(candidate)) is not None]
    incomplete_ids = {id(candidate) for candidate in result.incomplete}
    current_record_ids = {id(record.candidate) for record in result.records}
    records = list(result.records)
    records.extend(
        _record_from_data(verified[checkpoint_keys[id(candidate)]], candidate=candidate)
        for candidate in findings
        if id(candidate) not in unlocatable_ids
        and id(candidate) not in current_record_ids
        and checkpoint_keys[id(candidate)] in verified
    )
    verified_ids = {
        id(record.candidate)
        for record in records
        if record.outcome == "retained" and record.votes and id(record.candidate) not in incomplete_ids
    }
    completed = [candidate for candidate in retained if id(candidate) in verified_ids]
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
        candidate_ids=tuple(verification_candidate_id(candidate) for candidate in findings),
    )


def _record_to_data(record: VerificationRecord) -> dict[str, object]:
    return {
        "outcome": record.outcome,
        "reason": record.reason,
        "required_confirmer_seat_ids": list(record.required_confirmer_seat_ids),
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


def _record_from_data(
    data: dict[str, object],
    candidate,
) -> VerificationRecord:
    if set(data) != {"outcome", "reason", "required_confirmer_seat_ids", "votes"}:
        raise TypeError("verification record must contain outcome, reason, required confirmers, and votes")
    outcome = data["outcome"]
    reason = data["reason"]
    raw_votes = data["votes"]
    required = data["required_confirmer_seat_ids"]
    if outcome not in {"retained", "refuted", "incomplete"} or not isinstance(reason, str):
        raise TypeError("verification record outcome or reason is invalid")
    if not isinstance(raw_votes, list):
        raise TypeError("verification record votes must be a list")
    if not isinstance(required, list) or not all(isinstance(seat_id, str) and seat_id for seat_id in required):
        raise TypeError("verification record required confirmer seats must be a string list")
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
    try:
        return VerificationRecord(
            candidate=candidate,
            outcome=outcome,
            votes=tuple(votes),
            reason=reason,
            required_confirmer_seat_ids=tuple(required),
        )
    except ValueError as exc:
        raise TypeError(str(exc)) from exc
