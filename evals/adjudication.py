"""Bind human source assessments to one immutable repository review result."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from evals.benchmarks import registry
from evals.benchmarks.cases import find_repository_case
from evals.benchmarks.contract import load_answer_key
from evals.score.engine import score
from evals.score.report import reports_from_json

SCHEMA = "cyberjury.eval-adjudication/v1"
_VERDICTS = {"supported", "not_actionable", "duplicate", "needs_review"}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_CANDIDATE = re.compile(r"candidate-[0-9a-f]{20}")


@dataclass(frozen=True, kw_only=True)
class AdjudicationResult:
    """Expose reviewed conclusions without replacing the original score."""

    target: str
    source_commit: str
    findings_sha256: str
    ledger_sha256: str
    machine_confirmed: int
    independent_verified: int | None
    counts: dict[str, int]
    extra_dispositions: dict[str, int]
    matched_dispositions: dict[str, int]
    pending: tuple[str, ...]
    known_found: tuple[str, ...]
    known_missed: tuple[str, ...]
    new_supported: tuple[str, ...]
    mismatched_assignments: tuple[tuple[str, str, str], ...]
    missing_introductions: tuple[str, ...]
    introduction_not_ancestor: tuple[str, ...]
    cross_path_checks: tuple[dict[str, object], ...]

    @property
    def report_precision(self) -> float | None:
        """Count unique source-supported reports only after every report is assessed."""
        if self.pending:
            return None
        total = sum(self.counts.values())
        return self.counts["supported"] / total if total else 1.0

    @property
    def introduction_check_count(self) -> int:
        """Count historical finding projections, including repeated introductions."""
        return sum(len(check["introduction_tasks"]) for check in self.cross_path_checks)

    @property
    def machine_status_mismatch(self) -> bool | None:
        """Compare output labels with the independent verification receipt when supplied."""
        return self.machine_confirmed != self.independent_verified if self.independent_verified is not None else None

    def to_dict(self) -> dict[str, object]:
        """Return a stable summary that preserves unresolved work."""
        return {
            "schema": SCHEMA,
            "target": self.target,
            "source_commit": self.source_commit,
            "findings_sha256": self.findings_sha256,
            "ledger_sha256": self.ledger_sha256,
            "machine_confirmed": self.machine_confirmed,
            "independent_verified": self.independent_verified,
            "machine_status_mismatch": self.machine_status_mismatch,
            "counts": self.counts,
            "extra_dispositions": self.extra_dispositions,
            "matched_dispositions": self.matched_dispositions,
            "pending": list(self.pending),
            "known_found": list(self.known_found),
            "known_missed": list(self.known_missed),
            "new_supported": list(self.new_supported),
            "mismatched_assignments": [
                {"check_id": check, "location_match": location, "source_assessment": assessed}
                for check, location, assessed in self.mismatched_assignments
            ],
            "missing_introductions": list(self.missing_introductions),
            "introduction_not_ancestor": list(self.introduction_not_ancestor),
            "cross_path_checks": list(self.cross_path_checks),
            "repository_check_count": len(self.cross_path_checks),
            "introduction_check_count": self.introduction_check_count,
            "adjudication_complete": not self.pending,
            "report_precision": round(self.report_precision, 4) if self.report_precision is not None else None,
        }


def _read_object(path: str | Path) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _source_commit(root: Path) -> str:
    changes = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True, check=True
    )
    if changes.stdout.strip():
        raise ValueError("adjudication source checkout has uncommitted changes")
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _source_line(root: Path, value: object, candidate_id: str) -> None:
    if not isinstance(value, dict) or set(value) != {"file", "line"}:
        raise ValueError(f"{candidate_id} evidence location must have file and line")
    file, line = value["file"], value["line"]
    if not isinstance(file, str) or not file or Path(file).is_absolute() or ".." in Path(file).parts:
        raise ValueError(f"{candidate_id} evidence file must stay inside the source")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise ValueError(f"{candidate_id} evidence line must be positive")
    path = (root / file).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"{candidate_id} evidence file does not exist: {file}")
    if line > sum(1 for _ in path.open(encoding="utf-8", errors="replace")):
        raise ValueError(f"{candidate_id} evidence line does not exist: {file}:{line}")


def _validate_record(record: object, root: Path, candidates: dict, checks: dict) -> None:
    fields = {"candidate_id", "verdict", "canonical_id", "check_id", "reason", "proof_gap", "evidence"}
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError("adjudication record has an invalid shape")
    identity = record["candidate_id"]
    if not isinstance(identity, str) or _CANDIDATE.fullmatch(identity) is None or identity not in candidates:
        raise ValueError(f"adjudication references an unknown candidate: {identity}")
    verdict = record["verdict"]
    if verdict not in _VERDICTS:
        raise ValueError(f"{identity} has an invalid verdict")
    if not isinstance(record["reason"], str) or not record["reason"].strip():
        raise ValueError(f"{identity} needs a source assessment reason")
    gap = record["proof_gap"]
    if not isinstance(gap, str) or (verdict == "needs_review" and not gap.strip()):
        raise ValueError(f"{identity} needs a concrete proof gap")
    evidence = record["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ValueError(f"{identity} needs a source location")
    for location in evidence:
        _source_line(root, location, identity)
    canonical = record["canonical_id"]
    if verdict == "duplicate":
        if canonical not in candidates or canonical == identity:
            raise ValueError(f"{identity} needs a distinct existing canonical candidate")
    elif canonical is not None:
        raise ValueError(f"{identity} cannot name a canonical candidate")
    check_id = record["check_id"]
    if check_id is not None:
        if verdict != "supported" or check_id not in checks:
            raise ValueError(f"{identity} cannot credit check {check_id!r}")
        if candidates[identity].category != checks[check_id].category:
            raise ValueError(f"{identity} category disagrees with check {check_id}")


def _validate_duplicates(records: dict[str, dict]) -> None:
    for identity in records:
        seen = {identity}
        current = identity
        while records[current]["verdict"] == "duplicate":
            current = records[current]["canonical_id"]
            if current in seen:
                raise ValueError(f"duplicate relationship contains a cycle at {identity}")
            seen.add(current)


def _canonical_id(identity: str, records: dict[str, dict]) -> str:
    while records[identity]["verdict"] == "duplicate":
        identity = records[identity]["canonical_id"]
    return identity


def _introduction_lineage(case, source_root: Path, commit: str, task_ids: set[str]) -> tuple[str, ...]:
    """Check that paired finding introductions precede the reviewed repository revision."""
    if case.manifest is None:
        return ()
    manifest = registry.load_project_manifest(case.manifest)
    tasks = {task["id"]: task for task in manifest["tasks"]}
    invalid = []
    for task_id in sorted(task_ids):
        task = tasks.get(task_id)
        if task is None or task["kind"] != "diff" or task["expectation"] != "findings":
            raise ValueError(f"introduction task {task_id} is absent or is not a findings diff")
        introduced = task["revision"]["commit"]
        result = subprocess.run(
            ["git", "-C", str(source_root), "merge-base", "--is-ancestor", introduced, commit],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode not in (0, 1):
            raise ValueError(f"cannot resolve introduction task {task_id}: {result.stderr.strip()}")
        if result.returncode == 1:
            invalid.append(task_id)
    return tuple(invalid)


def adjudicate(
    target: str,
    *,
    findings_json: str | Path,
    ledger_json: str | Path,
    source_root: str | Path,
    run_status: str | Path | None = None,
) -> AdjudicationResult:
    """Validate one full ledger and compare source judgments with location scoring."""
    case = find_repository_case(target)
    root = Path(source_root).resolve()
    expected_commit = str(case.target.get("ref") or "")
    commit = _source_commit(root)
    if not expected_commit or commit != expected_commit:
        raise ValueError(f"source commit {commit} does not match benchmark commit {expected_commit}")
    findings_path = Path(findings_json)
    digest = hashlib.sha256(findings_path.read_bytes()).hexdigest()
    findings = FindingsArtifact.from_dict(_read_object(findings_path))
    candidates = {item.id: item for item in findings.findings}
    machine_confirmed = sum(item.status == "confirmed" for item in findings.findings)
    independent_verified = None
    if run_status is not None:
        status_path = Path(run_status)
        if status_path.name != "_run.json" or status_path.resolve().parent != findings_path.resolve().parent:
            raise ValueError("run status must come from the findings workspace")
        status = _read_object(status_path)
        expected_hash = status.get("content_sha256")
        semantic_status = {key: value for key, value in status.items() if key != "content_sha256"}
        status_hash = hashlib.sha256(
            json.dumps(semantic_status, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        if expected_hash != status_hash:
            raise ValueError("run status content hash does not match")
        outcome = OutcomeArtifact.from_dict(_read_object(status_path.parent / "outcome.json"))
        if outcome.findings_sha256 != findings.content_sha256 or outcome.source_revision != status.get(
            "source_revision"
        ):
            raise ValueError("run status and outcome do not identify these findings")
        count = status.get("verified", 0)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0 or count > len(candidates):
            raise ValueError("verification status has no valid independent verified count")
        independent_verified = count
    ledger_path = Path(ledger_json)
    ledger_digest = hashlib.sha256(ledger_path.read_bytes()).hexdigest()
    ledger = _read_object(ledger_path)
    if set(ledger) != {"schema", "target", "source_commit", "findings_sha256", "records"}:
        raise ValueError("adjudication ledger has an invalid shape")
    if ledger["schema"] != SCHEMA or ledger["target"] != target or ledger["source_commit"] != commit:
        raise ValueError("adjudication ledger target or source does not match")
    if not isinstance(ledger["findings_sha256"], str) or _DIGEST.fullmatch(ledger["findings_sha256"]) is None:
        raise ValueError("adjudication ledger findings hash is invalid")
    if ledger["findings_sha256"] != digest:
        raise ValueError("adjudication ledger does not identify these findings")
    key = load_answer_key(case.answer_key, task_id=case.task_id)
    checks = {item.id: item for item in key.findings}
    raw_records = ledger["records"]
    if not isinstance(raw_records, list):
        raise ValueError("adjudication records must be a list")
    records: dict[str, dict] = {}
    for record in raw_records:
        _validate_record(record, root, candidates, checks)
        identity = record["candidate_id"]
        if identity in records:
            raise ValueError(f"candidate {identity} is adjudicated twice")
        records[identity] = record
    if set(records) != set(candidates):
        raise ValueError("adjudication ledger must cover every finding exactly once")
    _validate_duplicates(records)
    credited = [record["check_id"] for record in raw_records if record["check_id"] is not None]
    if len(credited) != len(set(credited)):
        raise ValueError("one benchmark check cannot be credited by two candidate assessments")
    introductions: dict[str, set[str]] = {}
    for check in load_answer_key(case.answer_key).findings:
        for task_id in check.applies_to:
            if task_id.startswith("diff-"):
                introductions.setdefault(check.id, set()).add(task_id)
    introduction_tasks = set().union(*introductions.values()) if introductions else set()
    introduction_not_ancestor = _introduction_lineage(case, root, commit, introduction_tasks)
    observed: list[dict] = []
    raw_score = score(key, reports_from_json(findings_path), source_root=str(root), trace=observed.append)
    if not set(raw_score.extra).issubset(candidates):
        raise ValueError("location score named an unknown report")
    location_matches = {event["key"]: event["report"] for event in observed if event.get("kind") == "findings"}
    source_matches = {record["check_id"]: record["candidate_id"] for record in raw_records if record["check_id"]}
    mismatched = tuple(
        (check, location_matches.get(check, ""), source_matches.get(check, ""))
        for check in sorted(set(location_matches) | set(source_matches))
        if (_canonical_id(location_matches[check], records) if check in location_matches else "")
        != source_matches.get(check, "")
    )
    counts = Counter(record["verdict"] for record in raw_records)
    extra_counts = Counter(records[identity]["verdict"] for identity in raw_score.extra)
    matched_counts = Counter(records[identity]["verdict"] for identity in set(candidates) - set(raw_score.extra))
    new_supported = tuple(
        sorted(
            record["candidate_id"]
            for record in raw_records
            if record["verdict"] == "supported" and not record["check_id"]
        )
    )
    cross_path_checks = tuple(
        {
            "check_id": check_id,
            "introduction_tasks": sorted(introductions.get(check_id, set())),
            "source_supported_candidate": source_matches.get(check_id),
            "location_matched_candidate": location_matches.get(check_id),
            "location_canonical_candidate": _canonical_id(location_matches[check_id], records)
            if check_id in location_matches
            else None,
            "location_match_verdict": records[location_matches[check_id]]["verdict"]
            if check_id in location_matches
            else None,
        }
        for check_id in sorted(checks)
    )
    return AdjudicationResult(
        target=target,
        source_commit=commit,
        findings_sha256=digest,
        ledger_sha256=ledger_digest,
        machine_confirmed=machine_confirmed,
        independent_verified=independent_verified,
        counts={verdict: counts[verdict] for verdict in sorted(_VERDICTS)},
        extra_dispositions={verdict: extra_counts[verdict] for verdict in sorted(_VERDICTS)},
        matched_dispositions={verdict: matched_counts[verdict] for verdict in sorted(_VERDICTS)},
        pending=tuple(sorted(record["candidate_id"] for record in raw_records if record["verdict"] == "needs_review")),
        known_found=tuple(sorted(source_matches)),
        known_missed=tuple(sorted(set(checks) - set(source_matches))),
        new_supported=new_supported,
        mismatched_assignments=mismatched,
        missing_introductions=tuple(sorted(set(checks) - set(introductions))),
        introduction_not_ancestor=introduction_not_ancestor,
        cross_path_checks=cross_path_checks,
    )
