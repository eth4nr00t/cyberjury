"""Build blind adjudication packets from attempts and turn adjudicator results into ledgers.

`build_packets` writes `packet-N.json` and the versioned rubric as `INSTRUCTIONS.md` into the
adjudicator directory, and the private `mapping.json` outside it. Every report is adjudicated on
its own and without its issue, so issue grouping never changes check credit. The mapping resolves
each anonymous report label to its attempt and candidate and names the adjudication round.
Adjudicators write `result-N.json` for each packet. `write_ledgers` checks the results against the
mapping, validates each ledger at a fresh checkout of the pinned commit, and writes `ledger-NN.json`
beside each attempt, bound to the round, the rubric sha256, and the answer key checks.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import string
from collections.abc import Sequence
from pathlib import Path

from evals.adjudication import (
    LEDGER_SCHEMA,
    Attempt,
    adjudicate,
    collect_attempts,
    find_attempts,
    load_attempt,
    read_json,
)
from evals.benchmarks.cases import BenchmarkCase, checks_sha256, expected_checks, target_repository
from evals.benchmarks.validate import validate_document
from evals.review.source import review_scope, source_root

RUBRIC = Path(__file__).resolve().parent / "adjudication-rubric-v1.md"
_PROVENANCE = frozenset({"candidate_id", "id", "supporting_reviewers", "evidence_refs", "status", "issue_id"})
_INDEX = ("label", "run", "file", "line", "title")


def _report(finding: dict) -> dict:
    return {key: value for key, value in finding.items() if key not in _PROVENANCE}


def _checks(case: BenchmarkCase) -> list[dict]:
    return [
        {
            "id": check["id"],
            "locations": [{key: value for key, value in item.items() if value} for item in check["locations"]],
            "changes": check["changes"],
        }
        for check in expected_checks(case)
    ]


def default_mapping_path(out: Path) -> Path:
    """Return the private mapping location beside, never inside, an adjudicator directory."""
    return out.parent / f"{out.name}.private" / "mapping.json"


def _reference_attempts(references: Sequence[Path]) -> list[Attempt]:
    """Load reference attempts from runs directories or from the private mapping of an earlier round."""
    unique: dict[Path, Attempt] = {}
    for reference in references:
        if reference.is_file():
            mapping = read_json(reference)
            if not isinstance(mapping, dict) or not isinstance(mapping.get("attempts"), dict):
                raise ValueError(f"reference {reference} is neither a runs directory nor a packets mapping")
            attempts = [load_attempt(path) for path in mapping["attempts"]]
        else:
            attempts = find_attempts(reference)
        for attempt in attempts:
            unique.setdefault(attempt.path.resolve(), attempt)
    return list(unique.values())


def _references(case: BenchmarkCase, attempts: Sequence[Attempt]) -> list[dict]:
    references = []
    for attempt in attempts:
        if attempt.case != case.name or not attempt.ledger_path.is_file():
            continue
        ledger = read_json(attempt.ledger_path)
        try:
            adjudicate(case, attempt, ledger, None)
        except ValueError as exc:
            raise ValueError(f"reference ledger {attempt.ledger_path} cannot be used: {exc}") from exc
        references.extend(
            _report(attempt.findings[record["candidate_id"]])
            | {"verdict": record["verdict"], "check_ids": record["check_ids"], "reason": record["reason"]}
            for record in ledger["records"]
        )
    return references


def build_packets(
    cases: dict[str, BenchmarkCase],
    runs: Sequence[Path],
    out: Path,
    *,
    groups: int,
    max_reports: int | None = None,
    mapping_path: Path | None = None,
    references: Sequence[Path] = (),
) -> dict[str, object]:
    """Write anonymized packets for every complete attempt under the runs directories.

    Run letters within a case follow the attempt sha256, so they do not reveal which runs directory
    or configuration produced an attempt. An attempt reached through overlapping runs directories is
    packaged once. Earlier verdicts are included only from `references`, which are runs directories
    or private mappings of earlier rounds. The mapping is written to `mapping_path`, outside `out`.
    With `max_reports`, a case with more reports is split into entries of at most that many reports,
    and each entry lists the case's other reports under `other_reports`, so a duplicate can name a
    canonical report in another entry.
    """
    if groups < 1:
        raise ValueError("adjudication packets need at least one group")
    if max_reports is not None and max_reports < 1:
        raise ValueError("adjudication entries need room for at least one report")
    mapping_path = mapping_path or default_mapping_path(out)
    if mapping_path.resolve().is_relative_to(out.resolve()):
        raise ValueError("the private mapping must be written outside the adjudicator packet directory")
    attempts = collect_attempts(runs)
    complete = [attempt for attempt in attempts if attempt.complete]
    prior = _reference_attempts(references)
    by_case: dict[str, list[Attempt]] = {}
    for attempt in complete:
        case = cases.get(attempt.case)
        if case is None:
            raise ValueError(f"{attempt.path} names an unknown case {attempt.case!r}")
        by_case.setdefault(attempt.case, []).append(attempt)
    entries, labels, reference_counts = [], {}, {}
    for name, case_attempts in sorted(by_case.items()):
        case = cases[name]
        ordered = sorted(case_attempts, key=lambda attempt: attempt.sha256)
        if len(ordered) > len(string.ascii_uppercase):
            raise ValueError(f"{name} has more attempts than run letters")
        reports = []
        for letter, attempt in zip(string.ascii_uppercase, ordered, strict=False):
            for identity, finding in attempt.findings.items():
                label = f"{name}#{len(reports) + 1}"
                labels[label] = {"attempt": str(attempt.path.resolve()), "candidate_id": identity}
                reports.append({"label": label, "run": letter} | _report(finding))
        entry = {
            "case": name,
            "repository": str(target_repository(case.target)),
            "commit": case.target["ref"],
            "scope": case.target["path"],
            "checks": _checks(case),
        }
        if "base" in case.target:
            entry["base_commit"] = case.target["base"]
        if references:
            entry["reference_decisions"] = _references(case, prior)
            reference_counts[name] = len(entry["reference_decisions"])
        size = max_reports or len(reports) or 1
        chunks = [reports[start : start + size] for start in range(0, len(reports), size)] or [[]]
        for chunk in chunks:
            part = entry | {"reports": chunk}
            if len(chunks) > 1:
                part["other_reports"] = [
                    {key: report.get(key) for key in _INDEX} for report in reports if report not in chunk
                ]
            entries.append(part)
    rubric = RUBRIC.read_bytes()
    mapping = {
        "round_id": f"round-{secrets.token_hex(8)}",
        "rubric": RUBRIC.name,
        "rubric_sha256": hashlib.sha256(rubric).hexdigest(),
        "attempts": {str(attempt.path.resolve()): attempt.sha256 for attempt in complete},
        "checks_sha256": {name: checks_sha256(cases[name]) for name in sorted(by_case)},
        "labels": labels,
    }
    out.mkdir(parents=True, exist_ok=True)
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    with mapping_path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(mapping, indent=1))
    (out / "INSTRUCTIONS.md").write_bytes(rubric)
    for group in range(groups):
        (out / f"packet-{group + 1}.json").write_text(
            json.dumps(entries[group::groups], indent=1, ensure_ascii=False), encoding="utf-8"
        )
    return {
        "cases": len(by_case),
        "attempts": len(complete),
        "skipped": len(attempts) - len(complete),
        "reports": len(labels),
        "round_id": mapping["round_id"],
        "mapping": str(mapping_path),
        "references": reference_counts if references else None,
        "reference_attempts_without_ledger": sum(not attempt.ledger_path.is_file() for attempt in prior),
    }


def write_ledgers(
    cases: dict[str, BenchmarkCase],
    packets: Path,
    *,
    mapping_path: Path | None = None,
    supersede: bool = False,
) -> tuple[int, list[str]]:
    """Convert adjudicator results into ledgers, writing each one only after it validates.

    A ledger written by another adjudication round is never mixed in silently. Unless `supersede`
    is set, an existing ledger of another round for any attempt of this round stops the command.
    With `supersede`, those ledgers are removed first, so an attempt rejected in this round keeps
    no ledger at all.
    """
    mapping = read_json(mapping_path or default_mapping_path(packets))
    rubric_sha256 = hashlib.sha256(RUBRIC.read_bytes()).hexdigest()
    if rubric_sha256 != mapping["rubric_sha256"]:
        raise ValueError("the adjudication rubric changed after these packets were built")
    round_id = mapping["round_id"]
    results: dict[str, dict] = {}
    for path in sorted(packets.glob("result-*.json")):
        result = read_json(path)
        validate_document(result, "adjudicator-result-v1.schema.json", path)
        for entry in result:
            for record in entry["records"]:
                if record["label"] in results:
                    raise ValueError(f"report {record['label']} is assessed twice")
                results[record["label"]] = record | {"case": entry["case"]}
    labels = mapping["labels"]
    if set(results) != set(labels):
        missing, unknown = sorted(set(labels) - set(results)), sorted(set(results) - set(labels))
        raise ValueError(f"adjudicator results must cover every label once; missing {missing}, unknown {unknown}")
    by_attempt: dict[str, list[str]] = {path: [] for path in mapping["attempts"]}
    for label, where in labels.items():
        by_attempt[where["attempt"]].append(label)
    attempts = []
    for path, sha256 in mapping["attempts"].items():
        attempt = load_attempt(path)
        if attempt.sha256 != sha256:
            raise ValueError(f"{path} changed after these packets were built")
        if attempt.case not in cases:
            raise ValueError(f"{path} names an unknown case {attempt.case!r}")
        case = cases[attempt.case]
        if checks_sha256(case) != mapping.get("checks_sha256", {}).get(attempt.case):
            raise ValueError(f"the answer key of {attempt.case} changed after these packets were built")
        ledger = _ledger(attempt, case.target["ref"], by_attempt[path], labels, results)
        attempts.append(
            (
                attempt,
                ledger | {"round_id": round_id, "rubric_sha256": rubric_sha256, "checks_sha256": checks_sha256(case)},
            )
        )
    stale = [
        attempt.ledger_path for attempt, _ in attempts if _ledger_round(attempt.ledger_path) not in {None, round_id}
    ]
    if stale and not supersede:
        raise ValueError(
            f"{len(stale)} attempts already have a ledger from another adjudication round, for example {stale[0]}; "
            "pass --supersede to replace every ledger of this round's attempts"
        )
    for path in stale:
        path.unlink()
    written, failures = 0, []
    for name in sorted({attempt.case for attempt, _ in attempts}):
        case = cases[name]
        with source_root(case.target) as root:
            scope = review_scope(root, case.target)
            for attempt, ledger in attempts:
                if attempt.case != name:
                    continue
                try:
                    adjudicate(case, attempt, ledger, scope)
                except ValueError as exc:
                    failures.append(f"{attempt.path}: {exc}")
                    continue
                attempt.ledger_path.write_text(json.dumps(ledger, indent=1, ensure_ascii=False), encoding="utf-8")
                written += 1
    return written, failures


def _ledger_round(path: Path) -> str | None:
    """Return the round of an existing ledger, or an empty id for a ledger of an unknown format."""
    if not path.is_file():
        return None
    try:
        ledger = read_json(path)
    except ValueError:
        return ""
    round_id = ledger.get("round_id") if isinstance(ledger, dict) else None
    return round_id if isinstance(round_id, str) else ""


def _root_canonical(label: str, results: dict, labels: dict) -> str | None:
    """Follow a duplicate's canonical through other duplicates of its run to the report that is not one.

    Adjudicators of a split case name canonicals in other entries, so a canonical may itself be a
    duplicate of an earlier report with the same root cause.
    """
    seen = {label}
    canonical = results[label]["canonical"]
    while canonical is not None:
        if labels.get(canonical, {}).get("attempt") != labels[label]["attempt"]:
            raise ValueError(f"report {label} names a canonical report outside its run: {canonical!r}")
        if results[canonical]["verdict"] != "duplicate":
            return canonical
        if canonical in seen:
            raise ValueError(f"report {label} has a cycle of duplicate canonicals")
        seen.add(canonical)
        canonical = results[canonical]["canonical"]
    return None


def _ledger(attempt: Attempt, commit: str, attempt_labels: list[str], labels: dict, results: dict) -> dict:
    records = []
    for label in attempt_labels:
        result = results[label]
        if result["case"] != attempt.case:
            raise ValueError(f"report {label} is assessed under another case {result['case']!r}")
        canonical = _root_canonical(label, results, labels)
        records.append(
            {
                "candidate_id": labels[label]["candidate_id"],
                "verdict": result["verdict"],
                "canonical_id": labels[canonical]["candidate_id"] if canonical is not None else None,
                "check_ids": result["check_ids"],
                "reason": result["reason"],
                "proof_gap": result["proof_gap"] or "",
                "evidence": result["evidence"],
            }
        )
    return {
        "schema": LEDGER_SCHEMA,
        "case": attempt.case,
        "attempt": attempt.number,
        "source_commit": commit,
        "attempt_sha256": attempt.sha256,
        "records": records,
    }
