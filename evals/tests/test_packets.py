"""Adjudication packets stay blind, and adjudicator results become validated ledgers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from evals.benchmarks.cases import checks_sha256
from evals.packets import RUBRIC, build_packets, default_mapping_path, write_ledgers

A, B, C, D = ("candidate-" + letter * 20 for letter in "abcd")


@pytest.fixture
def runs_dirs(tmp_path, write_attempt):
    """Write two runs directories, the first with a complete and a failed attempt."""
    first_runs, second_runs = tmp_path / "first_runs", tmp_path / "second_runs"
    write_attempt(first_runs, 1, (A, B))
    write_attempt(first_runs, 2, (), complete=False)
    write_attempt(second_runs, 1, (C,))
    return first_runs, second_runs


def _labels_by_candidate(packets):
    mapping = json.loads(default_mapping_path(packets).read_text(encoding="utf-8"))
    return {where["candidate_id"]: label for label, where in mapping["labels"].items()}


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
                    "check_ids": ["create-missing-owner"] if verdicts.get(report["title"]) == "supported" else [],
                    "evidence": [{"file": "views.py", "line": 2}],
                    "reason": "The view saves without an ownership check at views.py:2.",
                    "proof_gap": None,
                }
                for report in entry["reports"]
            ],
            "check_notes": {"create-missing-owner": "valid"},
        }
        for entry in entries
    ]
    (packets / "result-1.json").write_text(json.dumps(result), encoding="utf-8")
    return result


def test_packets_hide_report_provenance_and_include_no_earlier_verdicts(tmp_path, cases, runs_dirs):
    """Two runs give reports labelled by run A/B, without candidate ids, reviewers, or earlier verdicts."""
    out = tmp_path / "adjudication"

    counts = build_packets(cases, list(runs_dirs), out, groups=1)

    assert counts["references"] is None
    (entry,) = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    assert "reference_decisions" not in entry
    assert {report["run"] for report in entry["reports"]} == {"A", "B"}
    assert all(not {"id", "candidate_id", "supporting_reviewers"} & set(report) for report in entry["reports"])


def test_packets_carry_the_case_and_keep_the_label_mapping_outside(tmp_path, cases, runs_dirs, benchmark_project):
    """Two runs give one packet of three reports with the case target and checks, and a private sibling mapping."""
    out = tmp_path / "adjudication"

    counts = build_packets(cases, list(runs_dirs), out, groups=1)

    assert {key: counts[key] for key in ("cases", "attempts", "skipped", "reports")} == {
        "cases": 1,
        "attempts": 2,
        "skipped": 1,
        "reports": 3,
    }
    (entry,) = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    assert entry["commit"] == benchmark_project.commit
    assert entry["base"] == benchmark_project.base
    assert entry["repository"] == str(benchmark_project.repo)
    assert entry["checks"] == [
        {
            "id": "create-missing-owner",
            "root_cause": "create saves without an owner check",
            "locations": [{"file": "views.py", "symbol": "create"}],
            "change_anchors": [{"file": "views.py", "line": 2, "side": "new"}],
        }
    ]
    assert (out / "INSTRUCTIONS.md").read_bytes() == RUBRIC.read_bytes()
    assert sorted(path.name for path in out.iterdir()) == ["INSTRUCTIONS.md", "packet-1.json"]
    mapping = json.loads(default_mapping_path(out).read_text(encoding="utf-8"))
    assert default_mapping_path(out) == tmp_path / "adjudication.private" / "mapping.json"
    assert mapping["round_id"] == counts["round_id"]
    assert {where["candidate_id"] for where in mapping["labels"].values()} == {A, B, C}


def test_grouped_reports_are_adjudicated_one_by_one_without_their_issue(tmp_path, cases, write_attempt):
    """Three reports grouped into two issues reach the packet with no issue keys and get one verdict each."""
    runs = tmp_path / "grouped"
    write_attempt(runs, 1, (A, B, C), issues=((B, A), (C,)))
    out = tmp_path / "adjudication"

    counts = build_packets(cases, [runs], out, groups=1)

    assert counts["reports"] == 3
    (entry,) = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    assert all("issue" not in key for report in entry["reports"] for key in report)
    _result(out, {f"Claim {B}": "supported"})

    assert write_ledgers(cases, out) == (1, [])
    ledger = json.loads(next(runs.rglob("ledger-01.json")).read_text(encoding="utf-8"))
    assert {record["candidate_id"]: record["verdict"] for record in ledger["records"]} == {
        A: "not_actionable",
        B: "supported",
        C: "not_actionable",
    }


def test_a_large_case_is_split_into_entries_that_index_each_other(tmp_path, cases, runs_dirs):
    """With max_reports=2, three reports split into entries of 2 and 1 that list each other's labels."""
    out = tmp_path / "adjudication"

    counts = build_packets(cases, list(runs_dirs), out, groups=1, max_reports=2)

    entries = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    assert (counts["cases"], counts["reports"]) == (1, 3)
    assert [len(entry["reports"]) for entry in entries] == [2, 1]
    for entry in entries:
        held = {report["label"] for report in entry["reports"]}
        listed = {report["label"] for report in entry["other_reports"]}
        assert not held & listed
        assert held | listed == set(json.loads(default_mapping_path(out).read_text(encoding="utf-8"))["labels"])
        assert set(entry["other_reports"][0]) == {"label", "run", "file", "line", "title"}
    _result(out, {f"Claim {A}": "supported"})

    assert write_ledgers(cases, out) == (2, [])


def test_split_entries_keep_reports_of_the_same_place_from_every_run_together(tmp_path, cases, write_attempt):
    """Reports at lines 2 and 9 from two runs split into one entry per line, each holding both runs."""
    runs = tmp_path / "runs"
    lines = {A: 2, B: 9, C: 9, D: 2}
    for number, candidates in ((1, (A, B)), (2, (C, D))):
        path = write_attempt(runs, number, candidates)
        record = json.loads(path.read_text(encoding="utf-8"))
        for finding in record["findings"]:
            finding["line"] = lines[finding["id"]]
        path.write_text(json.dumps(record), encoding="utf-8")
    out = tmp_path / "adjudication"

    build_packets(cases, [runs], out, groups=1, max_reports=2)

    entries = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    assert [sorted(report["line"] for report in entry["reports"]) for entry in entries] == [[2, 2], [9, 9]]
    assert all({report["run"] for report in entry["reports"]} == {"A", "B"} for entry in entries)


def test_a_duplicate_of_a_duplicate_resolves_to_the_first_canonical(tmp_path, cases, write_attempt):
    """C marked duplicate of B, itself a duplicate of A, is written with canonical_id A."""
    runs = tmp_path / "runs"
    write_attempt(runs, 1, (A, B, C))
    out = tmp_path / "adjudication"
    build_packets(cases, [runs], out, groups=1)
    result = _result(out, {f"Claim {A}": "supported"})
    by_title = {
        report["title"]: report["label"] for report in json.loads((out / "packet-1.json").read_text())[0]["reports"]
    }
    for record in result[0]["records"]:
        if record["label"] == by_title[f"Claim {B}"]:
            record.update(verdict="duplicate", canonical=by_title[f"Claim {A}"])
        if record["label"] == by_title[f"Claim {C}"]:
            record.update(verdict="duplicate", canonical=by_title[f"Claim {B}"])
    (out / "result-1.json").write_text(json.dumps(result), encoding="utf-8")

    assert write_ledgers(cases, out) == (1, [])
    ledger = json.loads(next(runs.rglob("ledger-01.json")).read_text(encoding="utf-8"))
    assert {record["candidate_id"]: record["canonical_id"] for record in ledger["records"]} == {A: None, B: A, C: A}


def test_the_private_mapping_cannot_be_written_inside_the_packet_directory(tmp_path, cases, runs_dirs):
    """A mapping_path under the packet directory raises ValueError and creates no packet directory."""
    out = tmp_path / "adjudication"

    with pytest.raises(ValueError, match="outside the adjudicator packet directory"):
        build_packets(cases, list(runs_dirs), out, groups=1, mapping_path=out / "private" / "mapping.json")

    assert not out.exists()


def test_overlapping_runs_directories_package_each_attempt_once(tmp_path, cases, runs_dirs):
    """Passing one runs directory twice plus its parent still packages 2 attempts and 3 reports."""
    counts = build_packets(cases, [runs_dirs[0], runs_dirs[0], tmp_path], tmp_path / "adjudication", groups=1)

    assert (counts["attempts"], counts["reports"]) == (2, 3)
    mapping = json.loads(default_mapping_path(tmp_path / "adjudication").read_text(encoding="utf-8"))
    assert len(mapping["attempts"]) == 2


def test_packets_include_earlier_verdicts_only_from_requested_references(
    tmp_path, cases, runs_dirs, write_ledger, write_attempt
):
    """A ledger under a reference directory adds its "supported" verdict without the candidate id."""
    reference = write_attempt(tmp_path / "earlier", 1, (A,))
    write_ledger(reference, {A: ("supported", ("create-missing-owner",))})

    counts = build_packets(
        cases, [runs_dirs[0]], tmp_path / "adjudication", groups=1, references=[tmp_path / "earlier"]
    )

    (entry,) = json.loads((tmp_path / "adjudication" / "packet-1.json").read_text(encoding="utf-8"))
    assert [item["verdict"] for item in entry["reference_decisions"]] == ["supported"]
    assert "candidate_id" not in entry["reference_decisions"][0]
    assert counts["references"] == {entry["case"]: 1}


def test_references_follow_the_private_mapping_of_an_earlier_round(tmp_path, cases, runs_dirs):
    """A round-one mapping as reference carries its three ledger verdicts into the round-two packet."""
    first = tmp_path / "round-one"
    build_packets(cases, list(runs_dirs), first, groups=1)
    _result(first, {f"Claim {A}": "supported"})
    assert write_ledgers(cases, first) == (2, [])

    counts = build_packets(
        cases, [runs_dirs[0]], tmp_path / "round-two", groups=1, references=[default_mapping_path(first)]
    )

    (entry,) = json.loads((tmp_path / "round-two" / "packet-1.json").read_text(encoding="utf-8"))
    assert sorted(item["verdict"] for item in entry["reference_decisions"]) == [
        "not_actionable",
        "not_actionable",
        "supported",
    ]
    assert counts["references"] == {entry["case"]: 3}


def test_references_without_ledgers_are_counted_as_empty(tmp_path, cases, runs_dirs):
    """A reference runs directory with no ledgers adds zero decisions and counts one ledgerless attempt."""
    counts = build_packets(cases, [runs_dirs[0]], tmp_path / "adjudication", groups=1, references=[runs_dirs[1]])

    (entry,) = json.loads((tmp_path / "adjudication" / "packet-1.json").read_text(encoding="utf-8"))
    assert entry["reference_decisions"] == []
    assert counts["references"] == {entry["case"]: 0}
    assert counts["reference_attempts_without_ledger"] == 1


def test_results_become_ledgers_beside_each_attempt(tmp_path, cases, runs_dirs, benchmark_project):
    """Each case directory gets ledger-01.json with round, rubric, and checks hashes plus verdicts."""
    out = tmp_path / "adjudication"
    build_packets(cases, list(runs_dirs), out, groups=1)
    _result(out, {f"Claim {A}": "supported", f"Claim {C}": "supported"})

    written, failures = write_ledgers(cases, out)

    assert (written, failures) == (2, [])
    case_dir = runs_dirs[0] / "demo" / benchmark_project.diff_case.split(":", 1)[1]
    ledger = json.loads((case_dir / "ledger-01.json").read_text(encoding="utf-8"))
    mapping = json.loads(default_mapping_path(out).read_text(encoding="utf-8"))
    assert ledger["round_id"] == mapping["round_id"]
    assert ledger["rubric_sha256"] == hashlib.sha256(RUBRIC.read_bytes()).hexdigest()
    assert ledger["checks_sha256"] == checks_sha256(cases[benchmark_project.diff_case])
    assert {record["candidate_id"]: record["verdict"] for record in ledger["records"]} == {
        A: "supported",
        B: "not_actionable",
    }
    assert not (case_dir / "ledger-02.json").exists()


def test_a_ledger_with_evidence_outside_the_pinned_source_is_rejected_and_not_written(tmp_path, cases, runs_dirs):
    """Evidence at views.py:30, past the pinned file's end, reports a failure and writes no ledger."""
    out = tmp_path / "adjudication"
    build_packets(cases, [runs_dirs[1]], out, groups=1)
    result = _result(out, {})
    result[0]["records"][0]["evidence"] = [{"file": "views.py", "line": 30}]
    (out / "result-1.json").write_text(json.dumps(result), encoding="utf-8")

    written, failures = write_ledgers(cases, out)

    assert written == 0
    assert "evidence line does not exist" in failures[0]
    assert not list(runs_dirs[1].rglob("ledger-*.json"))


def test_attempts_recorded_before_a_check_fix_are_adjudicated_against_the_fixed_checks(
    tmp_path, cases, runs_dirs, benchmark_project
):
    """Packets built from edited checks write ledgers carrying the edited checks hash."""
    name = benchmark_project.diff_case
    fixed = cases | {
        name: replace(cases[name], checks=tuple(replace(check, locations=()) for check in cases[name].checks))
    }
    out = tmp_path / "adjudication"
    build_packets(fixed, list(runs_dirs), out, groups=1)
    _result(out, {f"Claim {A}": "supported"})

    assert write_ledgers(fixed, out) == (2, [])
    case_dir = runs_dirs[0] / "demo" / name.split(":", 1)[1]
    ledger = json.loads((case_dir / "ledger-01.json").read_text(encoding="utf-8"))
    assert ledger["checks_sha256"] == checks_sha256(fixed[name]) != checks_sha256(cases[name])


def test_checks_changed_after_the_packets_were_built_stop_the_ledgers(tmp_path, cases, runs_dirs, benchmark_project):
    """Editing check locations between building packets and writing ledgers raises ValueError."""
    out = tmp_path / "adjudication"
    build_packets(cases, list(runs_dirs), out, groups=1)
    _result(out, {})
    name = benchmark_project.diff_case
    changed = cases | {
        name: replace(cases[name], checks=tuple(replace(check, locations=()) for check in cases[name].checks))
    }

    with pytest.raises(ValueError, match="changed after these packets were built"):
        write_ledgers(changed, out)


def test_results_must_cover_every_label(tmp_path, cases, runs_dirs):
    """A result missing one record raises "cover every label once"."""
    out = tmp_path / "adjudication"
    build_packets(cases, list(runs_dirs), out, groups=1)
    result = _result(out, {})
    result[0]["records"].pop()
    (out / "result-1.json").write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(ValueError, match="cover every label once"):
        write_ledgers(cases, out)


def test_a_duplicate_must_name_a_report_of_its_own_run(tmp_path, cases, runs_dirs):
    """Marking run A's report a duplicate of run B's report raises "outside its run"."""
    out = tmp_path / "adjudication"
    build_packets(cases, list(runs_dirs), out, groups=1)
    result = _result(out, {})
    by_candidate = _labels_by_candidate(out)
    record = next(item for item in result[0]["records"] if item["label"] == by_candidate[A])
    record.update(verdict="duplicate", canonical=by_candidate[C])
    (out / "result-1.json").write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(ValueError, match="outside its run"):
        write_ledgers(cases, out)


def test_a_later_round_does_not_silently_mix_with_ledgers_of_an_earlier_round(tmp_path, cases, runs_dirs):
    """Round-one ledgers block round two until supersede, which deletes a stale ledger even if its replacement fails."""
    first, second = tmp_path / "round-one", tmp_path / "round-two"
    build_packets(cases, list(runs_dirs), first, groups=1)
    _result(first, {f"Claim {A}": "supported", f"Claim {C}": "supported"})
    assert write_ledgers(cases, first) == (2, [])
    second_ledger = next(runs_dirs[1].rglob("ledger-01.json"))
    build_packets(cases, list(runs_dirs), second, groups=1)
    result = _result(second, {f"Claim {A}": "supported"})
    record = next(item for item in result[0]["records"] if item["label"] == _labels_by_candidate(second)[C])
    record["evidence"] = [{"file": "views.py", "line": 30}]
    (second / "result-1.json").write_text(json.dumps(result), encoding="utf-8")

    with pytest.raises(ValueError, match=r"ledger from another adjudication round.*--supersede"):
        write_ledgers(cases, second)
    written, failures = write_ledgers(cases, second, supersede=True)

    assert written == 1
    assert "evidence line does not exist" in failures[0]
    assert not second_ledger.exists()
    (ledger,) = runs_dirs[0].rglob("ledger-*.json")
    round_id = json.loads(default_mapping_path(second).read_text(encoding="utf-8"))["round_id"]
    assert json.loads(ledger.read_text(encoding="utf-8"))["round_id"] == round_id
