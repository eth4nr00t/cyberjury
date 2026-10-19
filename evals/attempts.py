"""Record and load review attempts of benchmark cases.

An attempt is one review of one benchmark case, recorded as `<project>/<case>/attempt-NN.json`
under a runs directory from the product review output of that case.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.sources.snapshot import capture_source_snapshot
from evals.benchmarks.cases import BenchmarkCase
from evals.benchmarks.targets import source_root

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
    findings: dict[str, dict]
    issues: tuple[tuple[str, ...], ...]

    @property
    def ledger_path(self) -> Path:
        """Return where the source assessment ledger of this attempt lives."""
        return self.path.with_name(f"ledger-{self.number:02d}.json")


def attempt_path(directory: Path, case: str, number: int) -> Path:
    """Return the attempt record path of one case and run under a runs directory."""
    project, case_id = case.split(":", 1)
    return directory / project / case_id / f"attempt-{number:02d}.json"


def read_json(path: str | Path) -> object:
    """Return the UTF-8 JSON document at the path, and malformed JSON raises `json.JSONDecodeError`."""
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
        or not isinstance(data.get("findings"), list)
        or not all(isinstance(item, dict) for item in data["findings"])
    ):
        raise ValueError(f"{path} is not an attempt record")
    findings = {item.get("candidate_id"): item for item in data["findings"]}
    if len(findings) != len(data["findings"]) or not all(
        isinstance(identity, str) and _CANDIDATE.fullmatch(identity) for identity in findings
    ):
        raise ValueError(f"{path} candidate ids must be unique and valid")
    issues = _issues(path, data, findings)
    return Attempt(
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        case=data["case"],
        number=number,
        complete=data["complete"],
        error=str(data.get("error") or ""),
        findings=findings,
        issues=issues,
    )


def _issues(path: Path, data: dict, findings: dict[str, dict]) -> tuple[tuple[str, ...], ...]:
    if "issues" not in data:
        return tuple((identity,) for identity in findings)
    issues = data["issues"]
    if not isinstance(issues, list) or not all(
        isinstance(issue, dict) and isinstance(issue.get("members"), list) and issue["members"] for issue in issues
    ):
        raise ValueError(f"{path} issues must be records with members")
    members = tuple(tuple(issue["members"]) for issue in issues)
    flat = [identity for group in members for identity in group]
    if len(flat) != len(set(flat)) or set(flat) != set(findings):
        raise ValueError(f"{path} issues must partition its reports")
    return members


def find_attempts(directory: str | Path) -> list[Attempt]:
    """Load every attempt record under a runs directory."""
    attempts = [load_attempt(path) for path in sorted(Path(directory).rglob("attempt-*.json"))]
    if not attempts:
        raise ValueError(f"{directory} has no attempt records")
    return attempts


def unique_attempts(attempts: Iterable[Attempt]) -> list[Attempt]:
    """Keep the first attempt loaded from each resolved record path."""
    unique: dict[Path, Attempt] = {}
    for attempt in attempts:
        unique.setdefault(attempt.path.resolve(), attempt)
    return list(unique.values())


def collect_attempts(directories: Sequence[str | Path]) -> list[Attempt]:
    """Load the attempts under several runs directories once each, even when the directories overlap."""
    return unique_attempts(attempt for directory in directories for attempt in find_attempts(directory))


def recorded_attempt(case: BenchmarkCase, directory: Path, number: int, *, error: str = "") -> dict[str, object]:
    """Record the product output of one review attempt directory as an adjudicable attempt.

    Diff and Repository Review attempts are recorded the same way, from `findings.json` and
    `outcome.json`. The review must have read exactly the case source, so its findings can be
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
            "findings": [],
        }
    findings = read_json(findings_path)
    artifact = FindingsArtifact.from_dict(findings)
    outcome = OutcomeArtifact.from_dict(read_json(directory / "outcome.json"))
    if outcome.target != case.kind or outcome.findings_sha256 != artifact.content_sha256:
        raise ValueError(f"{directory} outcome does not identify its {case.kind} findings")
    _require_case_source(case, directory, outcome.source_revision)
    return {
        "case": case.name,
        "attempt": number,
        "complete": outcome.complete,
        "error": "" if outcome.complete else outcome.failure_reason or error or "review incomplete",
        "findings": [{**item, "candidate_id": item["id"]} for item in findings["findings"]],
        "issues": findings["issues"],
    }


def _require_case_source(case: BenchmarkCase, directory: Path, source_revision: str) -> None:
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
        if (git.get("patch_base_revision"), git.get("right_revision")) != (case.target["base"], case.target["commit"]):
            raise ValueError(
                f"{directory} did not review the change of {case.name}: the case is {case.target['base']}.."
                f"{case.target['commit']}, but the review compared {git.get('patch_base_revision')}.."
                f"{git.get('right_revision')}"
            )
        return
    with source_root(case.target) as root:
        expected = capture_source_snapshot(root)
    if expected.snapshot_id == source_revision:
        return
    wanted = {entry.path: entry.to_dict() for entry in expected.entries}
    reviewed = {entry["path"]: entry for entry in snapshot["files"]}
    changed = sorted(path for path in wanted.keys() & reviewed.keys() if wanted[path] != reviewed[path])
    missing, extra = sorted(wanted.keys() - reviewed.keys()), sorted(reviewed.keys() - wanted.keys())
    examples = ", ".join([*changed[:2], *missing[:2], *extra[:2]])
    raise ValueError(
        f"{directory} did not review the source of {case.name}: the case is commit {case.target['commit']}, "
        f"but the review read {_describe_root(str(target.get('repository_root')))}. "
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
    relative = path.resolve().relative_to(top).as_posix() if path.resolve().is_relative_to(top) else str(path)
    dirty = bool(git("status", "--porcelain", "--untracked-files=all", "--", "."))
    state = " with uncommitted or untracked changes" if dirty else ""
    return f"{root}, a git checkout of commit {head} path {relative!r}{state}"
