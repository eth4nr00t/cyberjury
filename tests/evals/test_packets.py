"""Adjudication packets stay blind, and adjudicator results become validated ledgers."""

from __future__ import annotations

import hashlib
import json

import pytest

from evals.benchmarks.cases import load_cases
from evals.packets import RUBRIC, build_packets, default_mapping_path, write_ledgers

A, B, C = ("candidate-" + letter * 20 for letter in "abc")


@pytest.fixture
def cases(benchmark_project):
    return load_cases([benchmark_project.manifest])


@pytest.fixture
def arms(tmp_path, write_attempt):
    changed, baseline = tmp_path / "changed", tmp_path / "baseline"
    write_attempt(changed, 1, (A, B))
    write_attempt(changed, 2, (), complete=False)
    write_attempt(baseline, 1, (C,))
    return changed, baseline


def _result(packets, verdicts):
    entries = json.loads((packets / "packet-1.json").read_text(encoding="utf-8"))
    result = [
        {
            "case": entry["case"],
            "records": [
                {
                    "label": report["label"],
                    "verdict": verdicts.get(report["title"], "not_actionable"),
                    "canonical": None,
                    "check_ids": ["object-authorization"] if verdicts.get(report["title"]) == "supported" else [],
                    "evidence": [{"file": "views.py", "line": 2}],
                    "reason": "The view saves without an ownership check at views.py:2.",
                    "proof_gap": None,
                }
                for report in entry["reports"]
            ],
            "key_notes": {"object-authorization": "valid"},
        }
        for entry in entries
    ]
    (packets / "result-1.json").write_text(json.dumps(result), encoding="utf-8")
    return result


def test_packets_hide_report_provenance_and_include_no_earlier_verdicts(tmp_path, cases, arms, benchmark_project):
    out = tmp_path / "adjudication"

    counts = build_packets(cases, list(arms), out, groups=1)

    assert {key: counts[key] for key in ("cases", "attempts", "skipped", "reports")} == {
        "cases": 1,
        "attempts": 2,
        "skipped": 1,
        "reports": 3,
    }
    assert counts["references"] is None
    (entry,) = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    assert entry["commit"] == benchmark_project.ref
    assert entry["base_commit"] == benchmark_project.base
    assert entry["repository"] == str(benchmark_project.repo)
    assert entry["checks"] == [
        {
            "id": "object-authorization",
            "locations": [{"file": "views.py", "symbol": "create"}],
            "changes": [{"file": "views.py", "line": 2, "side": "new"}],
        }
    ]
    assert "reference_decisions" not in entry
    assert {report["run"] for report in entry["reports"]} == {"A", "B"}
    assert all(not {"id", "candidate_id", "supporting_reviewers"} & set(report) for report in entry["reports"])
    assert (out / "INSTRUCTIONS.md").read_bytes() == RUBRIC.read_bytes()
    assert sorted(path.name for path in out.iterdir()) == ["INSTRUCTIONS.md", "packet-1.json"]
    mapping = json.loads(default_mapping_path(out).read_text(encoding="utf-8"))
    assert default_mapping_path(out) == tmp_path / "adjudication.private" / "mapping.json"
    assert mapping["round_id"] == counts["round_id"]
    assert {where["candidate_id"] for where in mapping["labels"].values()} == {A, B, C}


def test_the_private_mapping_cannot_be_written_inside_the_packet_directory(tmp_path, cases, arms):
    out = tmp_path / "adjudication"

    with pytest.raises(ValueError, match="outside the adjudicator packet directory"):
        build_packets(cases, list(arms), out, groups=1, mapping_path=out / "private" / "mapping.json")

    assert not out.exists()


def test_overlapping_runs_directories_package_each_attempt_once(tmp_path, cases, arms):
    counts = build_packets(cases, [arms[0], arms[0], tmp_path], tmp_path / "adjudication", groups=1)

    assert (counts["attempts"], counts["reports"]) == (2, 3)
    mapping = json.loads(default_mapping_path(tmp_path / "adjudication").read_text(encoding="utf-8"))
    assert len(mapping["attempts"]) == 2


def test_packets_include_earlier_verdicts_only_from_requested_references(
    tmp_path, cases, arms, write_ledger, write_attempt
):
    reference = write_attempt(tmp_path / "earlier", 1, (A,))
    write_ledger(reference, {A: ("supported", ("object-authorization",))})

    counts = build_packets(cases, [arms[0]], tmp_path / "adjudication", groups=1, references=[tmp_path / "earlier"])

    (entry,) = json.loads((tmp_path / "adjudication" / "packet-1.json").read_text(encoding="utf-8"))
    assert [item["verdict"] for item in entry["reference_decisions"]] == ["supported"]
    assert "candidate_id" not in entry["reference_decisions"][0]
    assert counts["references"] == {entry["case"]: 1}


def test_references_follow_the_private_mapping_of_an_earlier_round(tmp_path, cases, arms):
    first = tmp_path / "round-one"
    build_packets(cases, list(arms), first, groups=1)
    _result(first, {f"Claim {A}": "supported"})
    assert write_ledgers(cases, first) == (2, [])

    counts = build_packets(cases, [arms[0]], tmp_path / "round-two", groups=1, references=[default_mapping_path(first)])

    (entry,) = json.loads((tmp_path / "round-two" / "packet-1.json").read_text(encoding="utf-8"))
    assert sorted(item["verdict"] for item in entry["reference_decisions"]) == [
        "not_actionable",
        "not_actionable",
        "supported",
    ]
    assert counts["references"] == {entry["case"]: 3}


def test_references_without_ledgers_are_counted_as_empty(tmp_path, cases, arms):
    counts = build_packets(cases, [arms[0]], tmp_path / "adjudication", groups=1, references=[arms[1]])

    (entry,) = json.loads((tmp_path / "adjudication" / "packet-1.json").read_text(encoding="utf-8"))
    assert entry["reference_decisions"] == []
    assert counts["references"] == {entry["case"]: 0}
    assert counts["reference_attempts_without_ledger"] == 1


def test_results_become_ledgers_beside_each_attempt(tmp_path, cases, arms, benchmark_project):
    out = tmp_path / "adjudication"
    build_packets(cases, list(arms), out, groups=1)
    _result(out, {f"Claim {A}": "supported", f"Claim {C}": "supported"})

    written, failures = write_ledgers(cases, out)

    assert (written, failures) == (2, [])
    task = arms[0] / "demo" / benchmark_project.diff_case.split(":", 1)[1]
    changed = json.loads((task / "ledger-01.json").read_text(encoding="utf-8"))
    mapping = json.loads(default_mapping_path(out).read_text(encoding="utf-8"))
    assert changed["round_id"] == mapping["round_id"]
    assert changed["rubric_sha256"] == hashlib.sha256(RUBRIC.read_bytes()).hexdigest()
    assert {record["candidate_id"]: record["verdict"] for record in changed["records"]} == {
        A: "supported",
        B: "not_actionable",
    }
    assert not (task / "ledger-02.json").exists()


def test_a_ledger_with_evidence_outside_the_pinned_source_is_rejected_and_not_written(tmp_path, cases, arms):
    out = tmp_path / "adjudication"
    build_packets(cases, [arms[1]], out, groups=1)
    result = _result(out, {})
    result[0]["records"][0]["evidence"] = [{"file": "views.py", "line": 30}]
    (out / "result-1.json").write_text(json.dumps(result), encoding="utf-8")

    written, failures = write_ledgers(cases, out)

    assert written == 0
    assert "evidence line does not exist" in failures[0]
    assert not list(arms[1].rglob("ledger-*.json"))


def test_results_must_cover_every_label(tmp_path, cases, arms):
    out = tmp_path / "adjudication"
    build_packets(cases, list(arms), out, groups=1)
    result = _result(out, {})
    result[0]["records"].pop()
    (out / "result-1.json").write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(ValueError, match="cover every label once"):
        write_ledgers(cases, out)


def test_a_duplicate_must_name_a_report_of_its_own_run(tmp_path, cases, arms):
    out = tmp_path / "adjudication"
    build_packets(cases, list(arms), out, groups=1)
    result = _result(out, {})
    mapping = json.loads(default_mapping_path(out).read_text(encoding="utf-8"))
    by_candidate = {where["candidate_id"]: label for label, where in mapping["labels"].items()}
    record = next(item for item in result[0]["records"] if item["label"] == by_candidate[A])
    record.update(verdict="duplicate", canonical=by_candidate[C])
    (out / "result-1.json").write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(ValueError, match="outside its run"):
        write_ledgers(cases, out)


def test_a_later_round_does_not_silently_mix_with_ledgers_of_an_earlier_round(tmp_path, cases, arms):
    first, second = tmp_path / "round-one", tmp_path / "round-two"
    build_packets(cases, list(arms), first, groups=1)
    _result(first, {f"Claim {A}": "supported", f"Claim {C}": "supported"})
    assert write_ledgers(cases, first) == (2, [])
    baseline_ledger = next(arms[1].rglob("ledger-01.json"))
    build_packets(cases, list(arms), second, groups=1)
    result = _result(second, {f"Claim {A}": "supported"})
    mapping = json.loads(default_mapping_path(second).read_text(encoding="utf-8"))
    by_candidate = {where["candidate_id"]: label for label, where in mapping["labels"].items()}
    record = next(item for item in result[0]["records"] if item["label"] == by_candidate[C])
    record["evidence"] = [{"file": "views.py", "line": 30}]
    (second / "result-1.json").write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(ValueError, match=r"ledger from another adjudication round.*--supersede"):
        write_ledgers(cases, second)
    written, failures = write_ledgers(cases, second, supersede=True)

    assert written == 1
    assert "evidence line does not exist" in failures[0]
    assert not baseline_ledger.exists()
    (ledger,) = arms[0].rglob("ledger-*.json")
    assert json.loads(ledger.read_text(encoding="utf-8"))["round_id"] == mapping["round_id"]
