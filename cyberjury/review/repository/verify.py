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
from cyberjury.review.verification import (
    ModelVerifier,
    RefutationChecker,
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


def _load_verified(workspace: Path) -> dict[str, _VerifiedCheckpoint]:
    path = workspace / "_verified.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError("expected an object keyed by candidate identity")
        verified: dict[str, _VerifiedCheckpoint] = {}
        for key, record in data.items():
            if not isinstance(key, str) or not key or not isinstance(record, dict):
                raise TypeError("candidate checkpoints must map string keys to objects")
            if set(record) != {"real", "reason"}:
                raise TypeError(f"checkpoint {key!r} must contain only real and reason")
            real = record["real"]
            reason = record["reason"]
            if not isinstance(real, bool) or not isinstance(reason, str):
                raise TypeError(f"checkpoint {key!r} requires a boolean real and string reason")
            verified[key] = {"real": real, "reason": reason}
        return verified
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise _checkpoint_error(path, exc) from exc


def _save_verified(workspace: Path, verified: dict) -> None:
    (workspace / "_verified.json").write_text(
        json.dumps(verified, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _write_refuted(workspace: Path, refuted: list[tuple[Candidate, str]]) -> None:
    """Keep every verifier deletion visible for operator review."""
    lines = [
        "# Refuted candidates",
        "",
        "Surfaced by a review pass, then refuted by the adversarial verifier on a "
        "named controlling fact. Recorded so a wrong refutation is visible.",
        "",
    ]
    for candidate, reason in refuted:
        lines.append(
            f"- **{candidate.title}** ({candidate.severity} {candidate.category}) "
            f"`{candidate.endpoint or candidate.file}`: {reason}"
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
) -> tuple[list[Candidate], VerifyResult]:
    """Preserve resumable repository verification without freezing failed checks."""
    if verifier is None:
        if provider is None:
            raise ValueError("verification needs a provider, or an injected verifier")
        verifier = ModelVerifier(provider=provider, model=model, content=content)
    verified = {} if fresh else _load_verified(workspace)
    detection = load_detection(content.detection_file) if content else None
    policy_fingerprint = _verification_policy_fingerprint(verifier, confirmers, votes)
    checkpoint_keys = {
        id(candidate): _candidate_checkpoint_key(
            candidate,
            root=root,
            detection=detection,
            by_file=by_file,
            policy_fingerprint=policy_fingerprint,
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
    )
    for candidate in result.verified:
        key = checkpoint_keys[id(candidate)]
        verified[key] = {"real": True, "reason": ""}
    for candidate, reason in result.refuted:
        verified[checkpoint_keys[id(candidate)]] = {"real": False, "reason": reason}
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
    _write_refuted(workspace, refuted)
    incomplete_ids = {id(candidate) for candidate in result.incomplete}
    completed = [candidate for candidate in retained if id(candidate) not in incomplete_ids]
    return retained, VerifyResult(
        retained=retained,
        verified=completed,
        refuted=refuted,
        errors=result.errors,
        error_details=result.error_details,
        incomplete=result.incomplete,
        unlocatable=unlocatable,
    )
