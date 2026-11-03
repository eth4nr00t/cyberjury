"""Blind adjudication packets built from attempts, and the ledgers made from adjudicator results."""

from __future__ import annotations

import hashlib
import json
import secrets
import string
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from evals.adjudication import EVAL_LEDGER_SCHEMA, adjudicate
from evals.attempts import Attempt, collect_attempts, load_attempt, read_json, write_new_json
from evals.benchmarks.cases import BenchmarkCase, checks_sha256, expected_checks
from evals.benchmarks.targets import source_root, target_repository
from evals.schemas import validate_document

RUBRIC = Path(__file__).resolve().parent / "adjudication-rubric-v1.md"
_PROVENANCE = frozenset({"id", "evidence_refs", "issue_id", "unit_complete"})
_INDEX = ("label", "run", "file", "line", "title")


@dataclass(frozen=True, kw_only=True)
class PacketRound:
    """What one packet build wrote: its counts, round identity, and private mapping."""

    cases: int
    attempts: int
    skipped: int
    reports: int
    round_id: str
    mapping: Path


def _report(finding: dict) -> dict:
    return {key: value for key, value in finding.items() if key not in _PROVENANCE}


def mapping_file(out: Path) -> Path:
    """Return the private mapping location beside, never inside, an adjudicator directory."""
    return out.parent / f"{out.name}.private" / "mapping.json"


def build_packets(
    cases: dict[str, BenchmarkCase],
    runs: Sequence[Path],
    out: Path,
    *,
    groups: int,
    max_reports: int | None = None,
) -> PacketRound:
    """Write anonymized packets for every complete attempt under the runs directories."""
    mapping_path = mapping_file(out)
    attempts = collect_attempts(runs)
    complete = [attempt for attempt in attempts if attempt.complete]
    by_case: dict[str, list[Attempt]] = {}
    for attempt in complete:
        if attempt.case not in cases:
            raise ValueError(f"{attempt.path} names an unknown case {attempt.case!r}")
        by_case.setdefault(attempt.case, []).append(attempt)
    entries, labels = [], {}
    for name, case_attempts in sorted(by_case.items()):
        reports = _case_reports(name, case_attempts, labels)
        entries.extend(_case_entries(cases[name], reports, max_reports))
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
    write_new_json(mapping_path, mapping)
    (out / "INSTRUCTIONS.md").write_bytes(rubric)
    for group in range(groups):
        (out / f"packet-{group + 1}.json").write_text(
            json.dumps(entries[group::groups], indent=1, ensure_ascii=False), encoding="utf-8"
        )
    return PacketRound(
        cases=len(by_case),
        attempts=len(complete),
        skipped=len(attempts) - len(complete),
        reports=len(labels),
        round_id=mapping["round_id"],
        mapping=mapping_path,
    )


def _case_reports(name: str, attempts: list[Attempt], labels: dict[str, dict]) -> list[dict]:
    ordered = sorted(attempts, key=lambda attempt: attempt.sha256)
    if len(ordered) > len(string.ascii_uppercase):
        raise ValueError(f"{name} has more attempts than run letters")
    reports = []
    for letter, attempt in zip(string.ascii_uppercase, ordered, strict=False):
        for identity, finding in attempt.findings.items():
            label = f"{name}#{len(reports) + 1}"
            labels[label] = {"attempt": str(attempt.path.resolve()), "candidate_id": identity}
            reports.append({"label": label, "run": letter} | _report(finding))
    return reports


def _case_entries(case: BenchmarkCase, reports: list[dict], max_reports: int | None) -> list[dict]:
    entry = {
        "case": case.name,
        "repository": str(target_repository(case.target)),
        "commit": case.target["commit"],
        **({"base": case.target["base"]} if "base" in case.target else {}),
        "checks": expected_checks(case),
    }
    size = max_reports or len(reports) or 1
    located = sorted(reports, key=lambda report: (report["file"], report["line"]))
    chunks = [located[start : start + size] for start in range(0, len(located), size)] or [[]]
    if len(chunks) == 1:
        return [entry | {"reports": chunks[0]}]
    return [
        entry
        | {
            "reports": chunk,
            "other_reports": [{key: report.get(key) for key in _INDEX} for report in reports if report not in chunk],
        }
        for chunk in chunks
    ]


def write_ledgers(
    cases: dict[str, BenchmarkCase],
    packets: Path,
    *,
    supersede: bool = False,
) -> tuple[int, list[str]]:
    """Validate every ledger, then remove other-round ledgers of these attempts and write only the valid ones."""
    mapping = read_json(mapping_file(packets))
    rubric_sha256 = hashlib.sha256(RUBRIC.read_bytes()).hexdigest()
    if rubric_sha256 != mapping["rubric_sha256"]:
        raise ValueError("the adjudication rubric changed after these packets were built")
    results = _read_results(packets, mapping["labels"])
    ledgers = _build_ledgers(cases, mapping, results, rubric_sha256)
    stale = _ledgers_of_other_rounds(ledgers, mapping["round_id"], supersede=supersede)
    valid, failures = _validate_ledgers(cases, ledgers)
    for path in stale:
        path.unlink()
    for attempt, ledger in valid:
        attempt.ledger_path.write_text(json.dumps(ledger, indent=1, ensure_ascii=False), encoding="utf-8")
    return len(valid), failures


def _read_results(packets: Path, labels: dict) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for path in sorted(packets.glob("result-*.json")):
        result = read_json(path)
        validate_document(result, "adjudicator-result-v1.schema.json", path)
        for entry in result:
            for record in entry["records"]:
                if record["label"] in results:
                    raise ValueError(f"report {record['label']} is assessed twice")
                results[record["label"]] = record | {"case": entry["case"]}
    if set(results) != set(labels):
        missing, unknown = sorted(set(labels) - set(results)), sorted(set(results) - set(labels))
        raise ValueError(f"adjudicator results must cover every label once, missing {missing}, unknown {unknown}")
    return results


def _build_ledgers(
    cases: dict[str, BenchmarkCase], mapping: dict, results: dict[str, dict], rubric_sha256: str
) -> list[tuple[Attempt, dict]]:
    labels = mapping["labels"]
    by_attempt: dict[str, list[str]] = {path: [] for path in mapping["attempts"]}
    for label, where in labels.items():
        by_attempt[where["attempt"]].append(label)
    ledgers = []
    for path, sha256 in mapping["attempts"].items():
        attempt = load_attempt(path)
        if attempt.sha256 != sha256:
            raise ValueError(f"{path} changed after these packets were built")
        if attempt.case not in cases:
            raise ValueError(f"{path} names an unknown case {attempt.case!r}")
        digest = checks_sha256(cases[attempt.case])
        if digest != mapping["checks_sha256"].get(attempt.case):
            raise ValueError(f"the checks of {attempt.case} changed after these packets were built")
        ledger = _ledger(attempt, cases[attempt.case].target["commit"], by_attempt[path], labels, results)
        bound = {"round_id": mapping["round_id"], "rubric_sha256": rubric_sha256, "checks_sha256": digest}
        ledgers.append((attempt, ledger | bound))
    return ledgers


def _ledgers_of_other_rounds(ledgers: list[tuple[Attempt, dict]], round_id: str, *, supersede: bool) -> list[Path]:
    stale = [
        attempt.ledger_path for attempt, _ in ledgers if _ledger_round(attempt.ledger_path) not in {None, round_id}
    ]
    if stale and not supersede:
        raise ValueError(
            f"{len(stale)} attempts already have a ledger from another adjudication round, for example {stale[0]}, "
            "pass --supersede to replace every ledger of this round's attempts"
        )
    return stale


def _validate_ledgers(
    cases: dict[str, BenchmarkCase], ledgers: list[tuple[Attempt, dict]]
) -> tuple[list[tuple[Attempt, dict]], list[str]]:
    valid, failures = [], []
    for name in sorted({attempt.case for attempt, _ in ledgers}):
        case = cases[name]
        with source_root(case.target) as root:
            for attempt, ledger in ledgers:
                if attempt.case != name:
                    continue
                try:
                    adjudicate(case, attempt, ledger, root)
                except ValueError as exc:
                    failures.append(f"{attempt.path}: {exc}")
                    continue
                valid.append((attempt, ledger))
    return valid, failures


def _ledger_round(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        ledger = read_json(path)
    except ValueError:
        return ""
    round_id = ledger.get("round_id") if isinstance(ledger, dict) else None
    return round_id if isinstance(round_id, str) else ""


def _root_canonical(label: str, results: dict, labels: dict) -> str | None:
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
                "proof_gap": result["proof_gap"],
                "evidence": result["evidence"],
            }
        )
    return {
        "schema": EVAL_LEDGER_SCHEMA,
        "case": attempt.case,
        "attempt": attempt.number,
        "source_commit": commit,
        "attempt_sha256": attempt.sha256,
        "records": records,
    }
