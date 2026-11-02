"""Adjudication packets stay blind, and adjudicator results become validated ledgers."""

import hashlib
import json
from dataclasses import replace

import pytest

from evals.benchmarks.cases import checks_sha256
from evals.packets import RUBRIC, build_packets, mapping_file, write_ledgers

A, B, C, D = ("candidate-" + letter * 20 for letter in "abcd")


@pytest.fixture
def runs_dirs(tmp_path, write_attempt):
    """Write two runs directories, the first with a complete and an incomplete attempt."""
    first_runs, second_runs = tmp_path / "first_runs", tmp_path / "second_runs"
    write_attempt(first_runs, 1, (A, B))
    write_attempt(first_runs, 2, (), complete=False)
    write_attempt(second_runs, 1, (C,))
    return first_runs, second_runs


def _labels_by_candidate(packets):
    mapping = json.loads(mapping_file(packets).read_text(encoding="utf-8"))
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
                    "proof_gap": "",
                }
                for report in entry["reports"]
            ],
            "check_notes": {"create-missing-owner": "valid"},
        }
        for entry in entries
    ]
    (packets / "result-1.json").write_text(json.dumps(result), encoding="utf-8")
    return result


def test_packets_hide_report_provenance(tmp_path, cases, runs_dirs):
    """Two runs give reports labelled by run A/B that keep the claim and drop ids, refs, and issues."""
    out = tmp_path / "adjudication"

    build_packets(cases, list(runs_dirs), out, groups=1)

    (entry,) = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    assert {report["run"] for report in entry["reports"]} == {"A", "B"}
    assert all(set(report) == {"label", "run", "file", "line", "title", "category"} for report in entry["reports"])


def test_packets_carry_the_case_and_keep_the_label_mapping_outside(tmp_path, cases, runs_dirs, benchmark_project):
    """Two runs give one packet of three reports with the case target and checks, and a private sibling mapping."""
    out = tmp_path / "adjudication"

    built = build_packets(cases, list(runs_dirs), out, groups=1)

    assert (built.cases, built.attempts, built.skipped, built.reports) == (1, 2, 1, 3)
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
    mapping = json.loads(mapping_file(out).read_text(encoding="utf-8"))
    assert mapping_file(out) == tmp_path / "adjudication.private" / "mapping.json"
    assert mapping["round_id"] == built.round_id
    assert {where["candidate_id"] for where in mapping["labels"].values()} == {A, B, C}


def test_grouped_reports_are_adjudicated_one_by_one_without_their_issue(tmp_path, cases, write_attempt):
    """Three reports grouped into two issues each reach the packet and get their own verdict."""
    runs = tmp_path / "grouped"
    write_attempt(runs, 1, (A, B, C), issues=((B, A), (C,)))
    out = tmp_path / "adjudication"

    built = build_packets(cases, [runs], out, groups=1)

    assert built.reports == 3
    (entry,) = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    assert len(entry["reports"]) == 3
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

    built = build_packets(cases, list(runs_dirs), out, groups=1, max_reports=2)

    entries = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    assert (built.cases, built.reports) == (1, 3)
    assert [len(entry["reports"]) for entry in entries] == [2, 1]
    for entry in entries:
        held = {report["label"] for report in entry["reports"]}
        listed = {report["label"] for report in entry["other_reports"]}
        assert not held & listed
        assert held | listed == set(json.loads(mapping_file(out).read_text(encoding="utf-8"))["labels"])
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


def _duplicate_round(tmp_path, cases, write_attempt, canonicals):
    runs = tmp_path / "runs"
    write_attempt(runs, 1, (A, B, C))
    out = tmp_path / "adjudication"
    build_packets(cases, [runs], out, groups=1)
    result = _result(out, {f"Claim {A}": "supported"})
    by_candidate = _labels_by_candidate(out)
    for record in result[0]["records"]:
        for duplicate, canonical in canonicals.items():
            if record["label"] == by_candidate[duplicate]:
                record.update(verdict="duplicate", canonical=by_candidate[canonical])
    (out / "result-1.json").write_text(json.dumps(result), encoding="utf-8")
    return out


def test_a_duplicate_of_a_duplicate_resolves_to_the_first_canonical(tmp_path, cases, write_attempt):
    """C marked duplicate of B, itself a duplicate of A, is written with canonical_id A."""
    runs = tmp_path / "runs"
    out = _duplicate_round(tmp_path, cases, write_attempt, {B: A, C: B})

    assert write_ledgers(cases, out) == (1, [])
    ledger = json.loads(next(runs.rglob("ledger-01.json")).read_text(encoding="utf-8"))
    assert {record["candidate_id"]: record["canonical_id"] for record in ledger["records"]} == {A: None, B: A, C: A}


def test_duplicates_that_name_each_other_are_rejected_as_a_cycle(tmp_path, cases, write_attempt):
    """B a duplicate of C and C a duplicate of B raise a cycle error and write no ledger."""
    runs = tmp_path / "runs"
    out = _duplicate_round(tmp_path, cases, write_attempt, {B: C, C: B})

    with pytest.raises(ValueError, match="cycle of duplicate canonicals"):
        write_ledgers(cases, out)

    assert not list(runs.rglob("ledger-*.json"))


def test_results_become_ledgers_beside_each_attempt(tmp_path, cases, runs_dirs, benchmark_project):
    """Each case directory gets ledger-01.json with round, rubric, and checks hashes plus verdicts."""
    out = tmp_path / "adjudication"
    build_packets(cases, list(runs_dirs), out, groups=1)
    _result(out, {f"Claim {A}": "supported", f"Claim {C}": "supported"})

    written, failures = write_ledgers(cases, out)

    assert (written, failures) == (2, [])
    case_dir = runs_dirs[0] / "demo" / benchmark_project.diff_case.split(":", 1)[1]
    ledger = json.loads((case_dir / "ledger-01.json").read_text(encoding="utf-8"))
    mapping = json.loads(mapping_file(out).read_text(encoding="utf-8"))
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
    round_id = json.loads(mapping_file(second).read_text(encoding="utf-8"))["round_id"]
    assert json.loads(ledger.read_text(encoding="utf-8"))["round_id"] == round_id


@pytest.mark.parametrize("change", ["attempt", "rubric"])
def test_ledgers_refuse_packets_whose_attempt_or_rubric_changed(tmp_path, cases, write_attempt, change):
    """Rewriting the attempt or recording a different rubric hash after packaging fails the ledger write."""
    runs = tmp_path / "runs"
    attempt = write_attempt(runs, 1, (A,))
    out = tmp_path / "adjudication"
    build_packets(cases, [runs], out, groups=1)
    _result(out, {})
    if change == "attempt":
        attempt.write_text(attempt.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    else:
        mapping_path = mapping_file(out)
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        mapping_path.write_text(json.dumps(mapping | {"rubric_sha256": "0" * 64}), encoding="utf-8")

    with pytest.raises(ValueError, match="changed after these packets were built"):
        write_ledgers(cases, out)
