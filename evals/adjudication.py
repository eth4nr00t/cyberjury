"""Bind source assessment ledgers to recorded review attempts.

An attempt is one review of one benchmark case, recorded as `<project>/<task>/attempt-NN.json`
under a runs directory. Its ledger, `ledger-NN.json` beside it, assesses every report exactly once
at the case's pinned source commit and is bound to the attempt bytes, the current answer key, the
adjudication round that produced it, and the rubric that round used.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.sources.snapshot import capture_source_snapshot
from evals.benchmarks.cases import BenchmarkCase, expected_checks
from evals.benchmarks.validate import validate_document
from evals.review.source import review_scope, source_root

LEDGER_SCHEMA = "cyberjury.eval-ledger/v2"
VERDICTS = ("duplicate", "needs_review", "not_actionable", "supported")
_CANDIDATE = re.compile(r"candidate-[0-9a-f]{20}")


@dataclass(frozen=True, kw_only=True)
class Attempt:
    """One recorded review attempt and the sha256 of its exact bytes."""

    path: Path
    sha256: str
    case: str
    number: int
    complete: bool
    error: str
    expected_checks: list
    findings: dict[str, dict]

    @property
    def ledger_path(self) -> Path:
        """Return where the source assessment ledger of this attempt lives."""
        return self.path.with_name(f"ledger-{self.number:02d}.json")


@dataclass(frozen=True, kw_only=True)
class Adjudication:
    """Reviewed check credit and report verdicts of one attempt."""

    case: str
    attempt: int
    found: tuple[str, ...]
    missed: tuple[str, ...]
    pending: tuple[str, ...]
    counts: dict[str, int]
    round_id: str = ""
    rubric_sha256: str = ""


def attempt_path(directory: Path, case: str, number: int) -> Path:
    """Return the attempt record path of one case and run under a runs directory."""
    project, task = case.split(":", 1)
    return directory / project / task / f"attempt-{number:02d}.json"


def read_json(path: str | Path) -> object:
    """Read one JSON document."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_attempt(path: str | Path) -> Attempt:
    """Read one attempt record and check the identities a ledger binds to."""
    path = Path(path)
    data = read_json(path)
    number = data.get("attempt") if isinstance(data, dict) else None
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("case"), str)
        or isinstance(number, bool)
        or not isinstance(number, int)
        or number < 1
        or path.name != f"attempt-{number:02d}.json"
        or not isinstance(data.get("complete"), bool)
        or not isinstance(data.get("expected_checks"), list)
        or not isinstance(data.get("findings"), list)
        or not all(isinstance(item, dict) for item in data["findings"])
    ):
        raise ValueError(f"{path} is not an attempt record")
    findings = {item.get("candidate_id"): item for item in data["findings"]}
    if len(findings) != len(data["findings"]) or not all(
        isinstance(identity, str) and _CANDIDATE.fullmatch(identity) for identity in findings
    ):
        raise ValueError(f"{path} candidate ids must be unique and valid")
    return Attempt(
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        case=data["case"],
        number=number,
        complete=data["complete"],
        error=str(data.get("error") or ""),
        expected_checks=data["expected_checks"],
        findings=findings,
    )


def find_attempts(directory: str | Path) -> list[Attempt]:
    """Load every attempt record under a runs directory."""
    attempts = [load_attempt(path) for path in sorted(Path(directory).rglob("attempt-*.json"))]
    if not attempts:
        raise ValueError(f"{directory} has no attempt records")
    return attempts


def collect_attempts(directories: Sequence[str | Path]) -> list[Attempt]:
    """Load the attempts under several runs directories once each, even when the directories overlap."""
    unique: dict[Path, Attempt] = {}
    for directory in directories:
        for attempt in find_attempts(directory):
            unique.setdefault(attempt.path.resolve(), attempt)
    return list(unique.values())


def recorded_attempt(case: BenchmarkCase, directory: Path, number: int, *, error: str = "") -> dict[str, object]:
    """Record the product output of one review attempt directory as an adjudicable attempt.

    Diff and Repository Review attempts are recorded the same way, from `findings.json` and
    `outcome.json`. The review must have read exactly the task source, so its findings can be
    judged against that revision. An attempt without a result is recorded as incomplete with
    `error`, the failure the review reported.
    """
    findings_path = directory / "findings.json"
    if not findings_path.is_file():
        return {
            "case": case.name,
            "attempt": number,
            "complete": False,
            "error": error or f"{directory} has no review result",
            "expected_checks": expected_checks(case),
            "findings": [],
        }
    findings = read_json(findings_path)
    artifact = FindingsArtifact.from_dict(findings)
    outcome = OutcomeArtifact.from_dict(read_json(directory / "outcome.json"))
    if outcome.target != case.kind or outcome.findings_sha256 != artifact.content_sha256:
        raise ValueError(f"{directory} outcome does not identify its {case.kind} findings")
    _require_task_source(case, directory, outcome.source_revision)
    return {
        "case": case.name,
        "attempt": number,
        "complete": outcome.complete,
        "error": "" if outcome.complete else outcome.failure_reason or error or "review incomplete",
        "expected_checks": expected_checks(case),
        "findings": [{**item, "candidate_id": item["id"]} for item in findings["findings"]],
    }


def _require_task_source(case: BenchmarkCase, directory: Path, source_revision: str) -> None:
    session = directory.resolve().parent.parent
    if directory.resolve().parent.name != "attempts":
        raise ValueError(f"{directory} is not a review attempt directory inside its review session")
    target, snapshot = read_json(session / "target.json"), read_json(session / "snapshot.json")
    if not isinstance(target, dict) or target.get("kind") != case.kind:
        raise ValueError(f"{session} is not a {case.kind} review session")
    if not isinstance(snapshot, dict) or snapshot.get("snapshot_id") != source_revision:
        raise ValueError(f"{session} snapshot.json does not identify the reviewed source of {directory}")
    if case.kind == "diff":
        git = target.get("git") if isinstance(target.get("git"), dict) else {}
        if (git.get("patch_base_revision"), git.get("right_revision")) != (case.target["base"], case.target["ref"]):
            raise ValueError(
                f"{directory} did not review the change of {case.name}: the task is {case.target['base']}.."
                f"{case.target['ref']}, but the review compared {git.get('patch_base_revision')}.."
                f"{git.get('right_revision')}"
            )
        return
    with source_root(case.target) as root:
        expected = capture_source_snapshot(review_scope(root, case.target))
    if expected.snapshot_id == source_revision:
        return
    wanted = {entry.path: entry.to_dict() for entry in expected.entries}
    reviewed = {entry["path"]: entry for entry in snapshot["files"]}
    changed = sorted(path for path in wanted.keys() & reviewed.keys() if wanted[path] != reviewed[path])
    missing, extra = sorted(wanted.keys() - reviewed.keys()), sorted(reviewed.keys() - wanted.keys())
    examples = ", ".join([*changed[:2], *missing[:2], *extra[:2]])
    raise ValueError(
        f"{directory} did not review the source of {case.name}: the task is commit {case.target['ref']} "
        f"scope {case.target['path']!r}, but the review read {_describe_root(str(target.get('repository_root')))}. "
        f"Its source differs in {len(changed)} changed, {len(missing)} missing, and {len(extra)} extra files"
        + (f", for example {examples}" if examples else "")
    )


def _describe_root(root: str) -> str:
    path = Path(root)
    if not path.is_dir():
        return f"{root}, which no longer exists"

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(path), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    try:
        top = Path(git("rev-parse", "--show-toplevel")).resolve()
        head = git("rev-parse", "HEAD")
    except (OSError, subprocess.CalledProcessError):
        return f"{root}, a plain directory outside any git checkout"
    scope = path.resolve().relative_to(top).as_posix() if path.resolve().is_relative_to(top) else str(path)
    dirty = bool(git("status", "--porcelain", "--untracked-files=all", "--", "."))
    state = " with uncommitted or untracked changes" if dirty else ""
    return f"{root}, a git checkout of commit {head} scope {scope!r}{state}"


def adjudicate(case: BenchmarkCase, attempt: Attempt, ledger: object, source: Path | None) -> Adjudication:
    """Validate one ledger against its attempt and case, and count reviewed credit and verdicts.

    `source` is the review scope inside a checkout at the pinned commit. When given, every
    evidence location must name an existing line there.
    """
    validate_document(ledger, "ledger-v2.schema.json", attempt.ledger_path)
    if (
        ledger["case"] != case.name
        or attempt.case != case.name
        or ledger["attempt"] != attempt.number
        or ledger["source_commit"] != case.target["ref"]
        or ledger["attempt_sha256"] != attempt.sha256
    ):
        raise ValueError(f"{attempt.ledger_path} does not identify this attempt and pinned source")
    if not attempt.complete:
        raise ValueError(f"{attempt.path} is not a complete review")
    if attempt.expected_checks != expected_checks(case):
        raise ValueError(f"{attempt.path} answer key differs from the current pinned case")
    records = {record["candidate_id"]: record for record in ledger["records"]}
    if len(records) != len(ledger["records"]) or set(records) != set(attempt.findings):
        raise ValueError(f"{attempt.ledger_path} must assess every report of the attempt exactly once")
    checks = {check.id for check in case.findings}
    credited = [check_id for record in ledger["records"] for check_id in record["check_ids"]]
    if not set(credited) <= checks:
        raise ValueError(f"{attempt.ledger_path} credits checks outside the case: {sorted(set(credited) - checks)}")
    if len(credited) != len(set(credited)):
        raise ValueError(f"{attempt.ledger_path} credits one check from two reports")
    for identity, record in records.items():
        canonical = record["canonical_id"]
        if canonical is not None and (
            canonical == identity or canonical not in records or records[canonical]["verdict"] == "duplicate"
        ):
            raise ValueError(f"{identity} needs a distinct canonical report that is not itself a duplicate")
        if source is not None:
            for location in record["evidence"]:
                _source_line(source, location, identity)
    counts = Counter(record["verdict"] for record in ledger["records"])
    return Adjudication(
        case=case.name,
        attempt=attempt.number,
        found=tuple(sorted(credited)),
        missed=tuple(sorted(checks - set(credited))),
        pending=tuple(sorted(identity for identity, record in records.items() if record["verdict"] == "needs_review")),
        counts={verdict: counts[verdict] for verdict in VERDICTS},
        round_id=ledger["round_id"],
        rubric_sha256=ledger["rubric_sha256"],
    )


def _source_line(root: Path, location: dict, identity: str) -> None:
    file, line = location["file"], location["line"]
    path = (root / file).resolve()
    if Path(file).is_absolute() or not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"{identity} evidence file does not exist in the pinned source: {file}")
    with path.open(encoding="utf-8", errors="replace") as lines:
        if line > sum(1 for _ in lines):
            raise ValueError(f"{identity} evidence line does not exist in the pinned source: {file}:{line}")
