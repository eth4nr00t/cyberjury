"""Issue grouping keeps independent candidates and every source claim visible."""

import json
from dataclasses import dataclass, replace
from itertools import combinations

import pytest

from cyberjury.finding import Finding
from cyberjury.review.consolidation import (
    CandidateSignal,
    ConsolidationReceipt,
    CoverageDecision,
    CoverageLink,
    ExecutionWitness,
    IssueNeighborhood,
    issue_neighborhoods,
    issue_source_from_dict,
    issue_source_to_dict,
    project_issues,
    project_receipt,
)
from cyberjury.review.context import SourceEvidence, SourceSpan
from cyberjury.review.repository.union import Candidate


@dataclass(frozen=True)
class _Candidate:
    id: str
    file: str
    line: int
    evidence: str


def test_local_execution_witness_has_one_strict_source_shape():
    local = ExecutionWitness(kind="same_local_control", start_line=10, end_line=24)

    assert ExecutionWitness.from_dict(local.to_dict()) == local
    with pytest.raises(ValueError, match="invalid relation shape"):
        ExecutionWitness(kind="same_local_control", start_line=10, end_line=42)
    with pytest.raises(ValueError, match="invalid relation shape"):
        ExecutionWitness(kind="same_local_control", start_line=True, end_line=24)
    with pytest.raises(ValueError, match="invalid relation shape"):
        ExecutionWitness(kind="shared_implementation", start_line=10, end_line=24)
    with pytest.raises(ValueError, match="invalid shape"):
        ExecutionWitness.from_dict({**local.to_dict(), "call_path": []})


def test_issue_source_receipt_requires_one_exact_repository_span():
    evidence = SourceEvidence(
        id="src-exact",
        identity="app.py:4",
        text="4 | unsafe_write()",
        source_span=SourceSpan(file="app.py", start_line=4, end_line=4),
    )

    assert issue_source_from_dict(issue_source_to_dict(evidence)) == evidence
    with pytest.raises(ValueError, match="invalid shape"):
        issue_source_from_dict({"id": "src-exact", "identity": "app.py:4", "text": "4 | unsafe_write()"})


def test_issue_neighborhood_requires_one_canonical_pair_and_signal():
    neighborhood = IssueNeighborhood(candidate_ids=("a", "b"), signals=(("source-category", "src-id:other"),))

    assert IssueNeighborhood.from_dict(neighborhood.to_dict()) == neighborhood
    with pytest.raises(ValueError, match="members or signals"):
        IssueNeighborhood.from_dict(
            {"candidate_ids": ["a", "b", "c"], "signals": [["source-category", "src-id:other"]]}
        )
    with pytest.raises(ValueError, match="canonical"):
        IssueNeighborhood(candidate_ids=("a", "b"), signals=(("source-category", "src-id:other"),) * 2)


def test_issue_neighborhoods_cover_every_shared_clue_pair_deterministically():
    signals = (
        CandidateSignal(candidate_id="a", source_refs=("src-common",), category="shared"),
        CandidateSignal(candidate_id="b", source_refs=("src-common",), category="shared"),
        CandidateSignal(candidate_id="c", source_refs=("src-common",), category="shared"),
        CandidateSignal(candidate_id="d"),
    )

    forward = issue_neighborhoods(signals)
    backward = issue_neighborhoods(tuple(reversed(signals)))
    retrieved = {pair for group in forward.neighborhoods for pair in combinations(group.candidate_ids, 2)}

    assert forward == backward
    assert retrieved == {("a", "b"), ("a", "c"), ("b", "c")}
    assert all("d" not in group.candidate_ids for group in forward.neighborhoods)
    assert forward.uncovered_pairs == ()


def test_shared_exact_source_requires_matching_category_or_attack_path():
    signals = (
        CandidateSignal(candidate_id="a", source_refs=("src-shared",), category="category-a"),
        CandidateSignal(candidate_id="b", source_refs=("src-shared",), category="category-a"),
        CandidateSignal(candidate_id="c", source_refs=("src-shared",), category="category-b", attack_path_id="path"),
        CandidateSignal(candidate_id="d", source_refs=("src-shared",), category="category-c", attack_path_id="path"),
        CandidateSignal(candidate_id="e", source_refs=("src-other",), category="category-a"),
        CandidateSignal(candidate_id="f", source_refs=("seed",), category="category-a"),
    )

    search = issue_neighborhoods(signals)
    pairs = {pair for group in search.neighborhoods for pair in combinations(group.candidate_ids, 2)}

    assert pairs == {("a", "b"), ("c", "d")}
    assert search.uncovered_pairs == ()


def test_issue_search_records_pairs_lost_to_source_budget():
    signals = tuple(
        CandidateSignal(candidate_id=identity, source_refs=("src-shared",), category="shared")
        for identity in ("a", "b", "c")
    )

    result = issue_neighborhoods(signals, eligible_group=lambda _members: False)

    assert result.neighborhoods == ()
    assert result.uncovered_pairs == (("a", "b"), ("a", "c"), ("b", "c"))


def test_issue_search_checks_identical_member_sets_once():
    signals = tuple(
        CandidateSignal(candidate_id=identity, source_refs=("src-first", "src-second"), category="shared")
        for identity in ("a", "b")
    )
    inspected = []

    result = issue_neighborhoods(signals, eligible_group=lambda members: inspected.append(members) or True)

    assert inspected == [("a", "b")]
    assert len(result.neighborhoods) == 1
    assert result.neighborhoods[0].signals == (
        ("source-category", "src-first:shared"),
        ("source-category", "src-second:shared"),
    )


def test_issue_search_rejects_more_source_linked_pairs_than_its_budget():
    signals = tuple(
        CandidateSignal(candidate_id=f"candidate-{index}", source_refs=("src-hot",), category="shared")
        for index in range(4)
    )

    with pytest.raises(ValueError, match="bounded pair count"):
        issue_neighborhoods(signals, max_pairs=5)


def test_issue_search_keeps_each_admissible_pair_separate():
    signals = tuple(
        CandidateSignal(candidate_id=f"candidate-{index}", source_refs=("src-shared",), category="shared")
        for index in range(10)
    )

    result = issue_neighborhoods(signals)
    covered = {pair for group in result.neighborhoods for pair in combinations(group.candidate_ids, 2)}

    assert len(covered) == 45
    assert result.uncovered_pairs == ()
    assert all(len(group.candidate_ids) == 2 for group in result.neighborhoods)


def _decision(child: str, root: str) -> CoverageDecision:
    return CoverageDecision(
        candidate_id=child,
        reason="the same source control and repair boundary cover this claim",
        root_link=CoverageLink(
            root_id=root,
            operation_file="app.py",
            operation_line=10,
            evidence_refs=("src-control",),
            reason="this root repairs one child claim",
        ),
    )


def _project(candidates, decisions, *, unresolved=frozenset(), surviving=None):
    receipts = tuple(
        SourceEvidence(
            id=f"src-{index}",
            identity=f"{candidate.file}:{candidate.line}",
            text=f"{candidate.file}:{candidate.line}: {candidate.evidence}",
            source_span=SourceSpan(
                file=candidate.file,
                start_line=candidate.line,
                end_line=candidate.line,
            ),
        )
        for index, candidate in enumerate(candidates)
    )
    cited = tuple(item.id for item in receipts)
    by_id = {candidate.id: candidate for candidate in candidates}
    return project_issues(
        candidates,
        tuple(
            replace(
                decision,
                root_link=replace(
                    decision.root_link,
                    operation_file=(
                        by_id[decision.root_link.root_id].file
                        if decision.root_link.root_id in by_id
                        else decision.root_link.operation_file
                    ),
                    operation_line=(
                        by_id[decision.root_link.root_id].line
                        if decision.root_link.root_id in by_id
                        else decision.root_link.operation_line
                    ),
                    evidence_refs=(
                        cited
                        if decision.root_link.evidence_refs == ("src-control",)
                        else decision.root_link.evidence_refs
                    ),
                ),
            )
            for decision in decisions
        ),
        candidate_id=lambda candidate: candidate.id,
        candidate_location=lambda candidate: (candidate.file, candidate.line),
        source_evidence=receipts,
        unresolved_ids=unresolved,
        surviving_ids=surviving,
    )


def test_issue_projection_retains_locations_and_evidence_across_files():
    root = _Candidate("root", "source.py", 10, "entry and source")
    downstream = _Candidate("downstream", "consumer.py", 42, "later sink")

    groups = _project((root, downstream), (_decision("downstream", "root"),))

    assert groups == (type(groups[0])(representative=root, members=(root, downstream)),)
    assert groups[0].members[1].file == "consumer.py"
    assert groups[0].members[1].evidence == "later sink"


def test_issue_link_cites_the_shared_operation_while_delivery_covers_both_member_locations():
    root = _Candidate("root", "root.py", 10, "shared control")
    child = _Candidate("child", "child.py", 20, "downstream report")
    delivered = (
        SourceEvidence(
            id="src-control",
            identity="root.py:10",
            text="10 | check_access()",
            source_span=SourceSpan(file="root.py", start_line=10, end_line=10),
        ),
        SourceEvidence(
            id="src-child",
            identity="child.py:20",
            text="20 | call_shared_control()",
            source_span=SourceSpan(file="child.py", start_line=20, end_line=20),
        ),
    )
    decision = CoverageDecision(
        candidate_id="child",
        root_link=CoverageLink(
            root_id="root",
            operation_file="root.py",
            operation_line=10,
            evidence_refs=("src-control",),
            reason="same failed control",
        ),
        reason="one repair covers the downstream report",
    )

    groups = project_issues(
        (root, child),
        (decision,),
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
        source_evidence=delivered,
    )

    assert len(groups) == 1
    assert {item.id for item in groups[0].members} == {"root", "child"}
    with pytest.raises(ValueError, match="read every linked member"):
        project_issues(
            (root, child),
            (decision,),
            candidate_id=lambda item: item.id,
            candidate_location=lambda item: (item.file, item.line),
            source_evidence=delivered[:1],
        )


def test_aggregate_with_two_distinct_repairs_stays_separate():
    grant = _Candidate("grant", "serializer.py", 20, "grant control")
    owner = _Candidate("owner", "serializer.py", 25, "owner control")
    aggregate = _Candidate("aggregate", "serializer.py", 35, "both effects")

    with pytest.raises(ValueError, match="invalid shape"):
        CoverageDecision.from_dict(
            {
                "candidate_id": aggregate.id,
                "links": [
                    _decision(aggregate.id, grant.id).root_link.to_dict(),
                    _decision(aggregate.id, owner.id).root_link.to_dict(),
                ],
                "reason": "two separate repairs",
            }
        )
    groups = _project((aggregate, grant, owner), ())

    assert [group.representative.id for group in groups] == ["aggregate", "grant", "owner"]
    assert all(group.members == (group.representative,) for group in groups)


@pytest.mark.parametrize("unresolved", [frozenset({"child"}), frozenset({"root"})])
def test_unresolved_member_keeps_its_own_report(unresolved):
    root = _Candidate("root", "app.py", 10, "first claim")
    child = _Candidate("child", "app.py", 11, "second claim")

    groups = _project((root, child), (_decision("child", "root"),), unresolved=unresolved)

    assert [group.representative.id for group in groups] == ["child", "root"]
    assert all(len(group.members) == 1 for group in groups)


def test_partial_coverage_cannot_hide_an_aggregate_candidate():
    first = _Candidate("first", "app.py", 10, "first root")
    second = _Candidate("second", "app.py", 20, "second root")
    aggregate = _Candidate("aggregate", "app.py", 30, "both roots")

    groups = _project(
        (first, second, aggregate),
        (_decision("aggregate", "first"),),
        unresolved=frozenset({"aggregate"}),
    )

    assert [group.representative.id for group in groups] == ["aggregate", "first", "second"]


def test_coverage_requires_final_independent_roots_not_an_intermediate_member():
    root = _Candidate("root", "app.py", 10, "root claim")
    intermediate = _Candidate("intermediate", "app.py", 20, "same claim")
    child = _Candidate("child", "helper.py", 30, "downstream claim")

    with pytest.raises(ValueError, match="another covered candidate"):
        _project(
            (root, intermediate, child),
            (_decision("intermediate", "root"), _decision("child", "intermediate")),
        )

    groups = _project(
        (root, intermediate, child),
        (_decision("intermediate", "root"), _decision("child", "root")),
    )
    assert [member.id for member in groups[0].members] == ["root", "child", "intermediate"]


def test_refuted_root_cannot_hide_a_surviving_member():
    root = _Candidate("root", "app.py", 10, "refuted root")
    child = _Candidate("child", "app.py", 20, "surviving claim")

    groups = _project(
        (root, child),
        (_decision("child", "root"),),
        surviving=frozenset({"child"}),
    )

    assert [group.representative.id for group in groups] == ["child"]
    assert groups[0].members == (child,)


@pytest.mark.parametrize(
    "decisions",
    [
        (_decision("missing", "root"),),
        (_decision("child", "missing"),),
        (_decision("child", "root"), _decision("child", "root")),
        (_decision("child", "child"),),
        (_decision("child", "root"), _decision("root", "child")),
        (replace(_decision("child", "root"), reason=""),),
        (
            replace(
                _decision("child", "root"),
                root_link=replace(_decision("child", "root").root_link, evidence_refs=("seed",)),
            ),
        ),
    ],
)
def test_invalid_or_unproven_coverage_fails_loud(decisions):
    root = _Candidate("root", "app.py", 10, "root")
    child = _Candidate("child", "app.py", 20, "child")

    with pytest.raises(ValueError, match="issue coverage"):
        _project((root, child), decisions)


def test_candidate_order_does_not_change_group_membership():
    root = _Candidate("root", "app.py", 10, "root")
    first = _Candidate("first", "a.py", 20, "first")
    second = _Candidate("second", "b.py", 30, "second")
    decisions = (_decision("first", "root"), _decision("second", "root"))

    left = _project((root, first, second), decisions)
    right = _project((second, root, first), tuple(reversed(decisions)))

    assert left == right


def test_unrelated_delivered_source_cannot_justify_coverage():
    root = _Candidate("root", "app.py", 10, "root")
    child = _Candidate("child", "other.py", 20, "child")
    receipt = SourceEvidence(
        id="src-root",
        identity="app.py:10",
        text="app.py:10: root",
        source_span=SourceSpan(file="app.py", start_line=10, end_line=10),
    )

    with pytest.raises(ValueError, match="every linked member location"):
        project_issues(
            (root, child),
            (
                CoverageDecision(
                    candidate_id="child",
                    reason="claimed same control",
                    root_link=CoverageLink(
                        root_id="root",
                        operation_file="app.py",
                        operation_line=10,
                        evidence_refs=(receipt.id,),
                        reason="claimed same repair",
                    ),
                ),
            ),
            candidate_id=lambda candidate: candidate.id,
            candidate_location=lambda candidate: (candidate.file, candidate.line),
            source_evidence=(receipt,),
        )


@pytest.mark.parametrize(
    "candidates",
    [
        (
            Finding(file="app.py", line=10, category="idor", description="foreign object mutation"),
            Finding(file="helper.py", line=20, category="missing-authorization", description="same mutation"),
        ),
        (
            Candidate(title="foreign object mutation", file="app.py", line=10, category="idor"),
            Candidate(title="same mutation", file="helper.py", line=20, category="missing-authorization"),
        ),
    ],
)
def test_diff_and_repository_use_the_same_cross_category_projection(candidates):
    root, child = candidates
    evidence = SourceEvidence(
        id="src-control",
        identity="app.py:1:30",
        text="app.py:10: missing scope check",
        source_span=SourceSpan(file="app.py", start_line=1, end_line=30),
    )
    child_evidence = SourceEvidence(
        id="src-helper",
        identity="helper.py:20",
        text="helper.py:20: same mutation",
        source_span=SourceSpan(file="helper.py", start_line=20, end_line=20),
    )

    groups = project_issues(
        candidates,
        (
            CoverageDecision(
                candidate_id=child.candidate_id,
                reason="both reports name one target authorization boundary",
                root_link=CoverageLink(
                    root_id=root.candidate_id,
                    operation_file="app.py",
                    operation_line=10,
                    evidence_refs=(evidence.id, child_evidence.id),
                    reason="same target authorization boundary",
                ),
            ),
        ),
        candidate_id=lambda candidate: candidate.candidate_id,
        candidate_location=lambda candidate: (candidate.file, candidate.line),
        source_evidence=(evidence, child_evidence),
    )

    assert len(groups) == 1
    assert groups[0].representative is root
    assert set(groups[0].members) == set(candidates)


def test_consolidation_receipt_is_deterministic_and_bound_to_review_inputs():
    root = _Candidate("root", "app.py", 10, "original root evidence")
    child = _Candidate("child", "app.py", 20, "original child evidence")
    evidence = SourceEvidence(
        id="src-control",
        identity="app.py:1:30",
        text="app.py:1-30: exact source",
        source_span=SourceSpan(file="app.py", start_line=1, end_line=30),
    )

    receipt = ConsolidationReceipt.create(
        (root, child),
        (_decision("child", "root"),),
        source_revision="a" * 64,
        adjudicator_revision="b" * 64,
        candidate_id=lambda candidate: candidate.id,
        source_evidence=(evidence,),
    )
    replayed = ConsolidationReceipt.from_dict(json.loads(json.dumps(receipt.to_dict())))
    reordered = ConsolidationReceipt.create(
        (child, root),
        (_decision("child", "root"),),
        source_revision="a" * 64,
        adjudicator_revision="b" * 64,
        candidate_id=lambda candidate: candidate.id,
        source_evidence=(evidence,),
    )
    assert replayed == receipt == reordered

    def apply(candidates=(root, child), source_revision="a" * 64, adjudicator_revision="b" * 64, refs=(evidence,)):
        return project_receipt(
            candidates,
            replayed,
            source_revision=source_revision,
            adjudicator_revision=adjudicator_revision,
            candidate_id=lambda candidate: candidate.id,
            candidate_location=lambda candidate: (candidate.file, candidate.line),
            source_evidence=refs,
        )

    assert [group.representative.id for group in apply()] == ["root"]
    with pytest.raises(ValueError, match="does not match"):
        apply(candidates=(root, replace(child, evidence="changed")))
    with pytest.raises(ValueError, match="does not match"):
        apply(source_revision="c" * 64)
    with pytest.raises(ValueError, match="does not match"):
        apply(adjudicator_revision="d" * 64)
    with pytest.raises(ValueError, match="does not match"):
        apply(refs=(replace(evidence, text="changed source"),))

    corrupted = receipt.to_dict()
    corrupted["decisions"][0]["reason"] = "changed claim"
    with pytest.raises(ValueError, match="hash does not match"):
        ConsolidationReceipt.from_dict(corrupted)
    with pytest.raises(ValueError, match="hash does not match"):
        replace(receipt, decisions=())
    with pytest.raises(ValueError, match="SHA-256"):
        replace(receipt, source_revision="not-a-snapshot")
