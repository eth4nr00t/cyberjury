"""Issue grouping keeps every finding, folds one location and category, and links others only on a same-fix judgment."""

import json
from dataclasses import replace

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review import issues as issues_module
from cyberjury.review.checkpoint import CheckpointStore
from cyberjury.review.context import SourceSpan
from cyberjury.review.finding import Finding
from cyberjury.review.issues import (
    LinkDecision,
    ModelIssueJudge,
    group_issues,
    link_candidates,
    link_issues,
    link_prompt,
)
from tests.review.support import StubIssueJudge


def _finding(title: str, *, file: str = "views.py", line: int = 2, cites=()) -> Finding:
    return Finding(
        title=title,
        category="broken-object-level-authorization",
        severity="HIGH",
        entrypoint="POST /records",
        file=file,
        line=line,
        evidence=f"{file}:{line} skips the owner check",
        attack_path="a member writes another member's record",
        cited_spans=tuple(SourceSpan(file=path, start_line=start, end_line=end) for path, start, end in cites),
    )


def _source(root, file="views.py", lines=40):
    (root / file).write_text("".join(f"line_{number} = {number}\n" for number in range(1, lines + 1)))


def test_findings_at_one_line_with_one_category_form_one_issue_and_keep_every_member():
    first = _finding("save skips the owner check", line=2)
    second = _finding("record save lacks authorization", file="./views.py", line=2)
    other = _finding("load skips the owner check", line=9)

    issues = group_issues([first, second, other])

    assert [issue.members for issue in issues] == [(first, second), (other,)]
    assert issues[0].representative is first
    assert [issue.linked_by for issue in issues] == [("location",), ()]


def test_findings_on_different_lines_of_one_function_are_separate_issues():
    findings = [_finding("save checks no owner", line=2), _finding("save checks no quota", line=3)]

    assert [len(issue.members) for issue in group_issues(findings)] == [1, 1]


def test_findings_at_one_line_with_different_categories_are_separate_issues():
    first = _finding("missing owner check", line=2)
    second = replace(_finding("unbounded size", line=2), category="denial-of-service")

    assert [len(issue.members) for issue in group_issues([first, second])] == [1, 1]


GATE = ("gate.py", 1, 9)


def test_one_function_with_two_lines_is_two_issues_until_a_judgment_links_them():
    first = _finding("missing owner check", line=2, cites=[("views.py", 1, 9)])
    second = _finding("unbounded size", line=4, cites=[("views.py", 1, 9)])

    assert [len(issue.members) for issue in group_issues([first, second])] == [1, 1]
    assert [{item.title for item in pair} for pair in link_candidates([first, second])] == [
        {"missing owner check", "unbounded size"}
    ]


def test_issue_ids_membership_and_link_candidates_are_stable_under_input_permutation():
    findings = [
        _finding("a", line=2, cites=[("views.py", 1, 30)]),
        _finding("b", line=2, cites=[("views.py", 1, 30)]),
        _finding("c", line=12, cites=[("views.py", 1, 30)]),
        _finding("d", line=20),
    ]
    reordered = [findings[3], findings[1], findings[2], findings[0]]

    def shape(items):
        return {issue.id: {item.candidate_id for item in issue.members} for issue in group_issues(items)}

    def pairs(items):
        return [(first.candidate_id, second.candidate_id) for first, second in link_candidates(items)]

    assert shape(findings) == shape(reordered)
    assert pairs(findings) == pairs(reordered)
    assert len(pairs(findings)) == 1


def test_link_candidates_need_mutual_coverage_or_one_sided_coverage_with_a_common_cited_span():
    caller = _finding("caller", file="views.py", line=5, cites=[("models.py", 10, 20), GATE])
    sink = _finding("sink", file="models.py", line=12, cites=[GATE])
    mutual = _finding("mutual", file="tasks.py", line=3, cites=[("views.py", 1, 9)])
    reader = _finding("reader", file="views.py", line=7, cites=[("tasks.py", 1, 5)])
    lonely = _finding("lonely", file="models.py", line=30, cites=[("views.py", 1, 9)])

    pairs = link_candidates([caller, sink, mutual, reader, lonely])

    assert {frozenset(item.title for item in pair) for pair in pairs} == {
        frozenset({"caller", "sink"}),
        frozenset({"mutual", "reader"}),
    }
    assert all(first.candidate_id < second.candidate_id for first, second in pairs)


def test_overlapping_cited_spans_in_one_file_count_as_common_source():
    caller = _finding("caller", file="views.py", line=5, cites=[("models.py", 10, 20), ("gate.py", 1, 9)])
    sink = _finding("sink", file="models.py", line=12, cites=[("gate.py", 6, 14)])
    adjacent = _finding("adjacent", file="models.py", line=14, cites=[("gate.py", 10, 14)])
    elsewhere = _finding("elsewhere", file="models.py", line=16, cites=[("other.py", 1, 9)])

    pairs = link_candidates([caller, sink, adjacent, elsewhere])

    assert {frozenset(item.title for item in pair) for pair in pairs} == {frozenset({"caller", "sink"})}


def test_link_candidates_ask_once_per_pair_of_groups():
    caller = _finding("caller", file="views.py", line=5, cites=[("models.py", 1, 40), GATE])
    caller_again = _finding("caller again", file="views.py", line=5, cites=[("models.py", 1, 40), GATE])
    sink = _finding("sink", file="models.py", line=12, cites=[GATE])

    assert len(link_candidates([caller, caller_again, sink])) == 1


def _linked_pair(root):
    _source(root, "views.py")
    _source(root, "models.py")
    view = _finding("view", file="views.py", line=5, cites=[("models.py", 10, 20), GATE])
    model = _finding("model", file="models.py", line=12, cites=[GATE])
    return view, model


def test_a_judgment_links_two_issues_only_when_one_change_fixes_both(tmp_path):
    view, model = _linked_pair(tmp_path)
    separate = _finding("separate", file="models.py", line=30, cites=[("views.py", 1, 9), GATE])
    judge = StubIssueJudge(lambda pair: model.candidate_id in pair and view.candidate_id in pair)

    links = link_issues([view, model, separate], judge, str(tmp_path))
    issues = group_issues([view, model, separate], links.links)

    assert len(judge.pairs) == 2
    assert links.links == (tuple(sorted((view.candidate_id, model.candidate_id))),)
    assert [len(issue.members) for issue in issues] == [2, 1]
    assert issues[0].members == (view, model)
    assert issues[0].linked_by == ("judgment",)


def test_the_model_judge_asks_one_closed_schema_question_from_structured_fields_and_cited_source(tmp_path):
    view, model = _linked_pair(tmp_path)
    provider = MockProvider(default=json.dumps({"same_fix": True, "reason": "the save owner check fixes both"}))
    judge = ModelIssueJudge(provider=provider, model="mock", seat_id="seat-test")

    links = link_issues([view, model], judge, str(tmp_path))

    (call,) = provider.calls
    prompt = call["messages"][0].content
    first, second = sorted((view, model), key=lambda item: item.candidate_id)
    assert prompt == link_prompt(first, second, str(tmp_path))
    assert prompt.startswith("Finding A:\n- title: ")
    assert "- location: models.py:12" in prompt
    assert "- location: views.py:5" in prompt
    assert "12 | line_12 = 12" in prompt
    assert " 5 | line_5 = 5" in prompt
    assert call["response_schema"].schema["required"] == ["same_fix", "reason"]
    assert call["response_schema"].schema["additionalProperties"] is False
    assert "one code change fixes both findings" in call["system"]
    assert links.links == ((first.candidate_id, second.candidate_id),)


def test_the_same_fix_contract_counts_containment_but_not_shared_context():
    system = issues_module._SYSTEM

    assert "One change at one place removes the defect that each finding describes." in system
    assert "One finding's defect is one of the places the other finding already requires changing" in system
    assert "distinct defects that each need their own change" in system
    assert "share an entrypoint, a file, a sink, or cited code" in system


def test_decisions_under_an_earlier_judge_contract_are_asked_again(tmp_path, monkeypatch):
    findings = list(_linked_pair(tmp_path))
    store = CheckpointStore(tmp_path / "work" / "issue-links", "cyberjury.issue-link-decision/v1")
    provider = MockProvider(default=json.dumps({"same_fix": False, "reason": "each needs its own change"}))
    judge = ModelIssueJudge(provider=provider, model="mock", seat_id="seat-test")

    with monkeypatch.context() as patch:
        patch.setattr(issues_module, "_SYSTEM", "an earlier same-fix contract")
        link_issues(findings, judge, str(tmp_path), checkpoint=store)
    link_issues(findings, judge, str(tmp_path), checkpoint=store)
    link_issues(findings, judge, str(tmp_path), checkpoint=store)

    assert len(provider.calls) == 2
    assert provider.calls[0]["system"] == "an earlier same-fix contract"
    assert provider.calls[1]["system"] == issues_module._SYSTEM


def test_link_decisions_are_reused_from_their_checkpoint(tmp_path):
    findings = list(_linked_pair(tmp_path))
    store = CheckpointStore(tmp_path / "work" / "issue-links", "cyberjury.issue-link-decision/v1")
    first, resumed = StubIssueJudge(), StubIssueJudge(lambda pair: False)

    linked = link_issues(findings, first, str(tmp_path), checkpoint=store)
    reused = link_issues(findings, resumed, str(tmp_path), checkpoint=store)

    assert (len(first.pairs), len(resumed.pairs)) == (1, 0)
    assert reused.links == linked.links != ()


def test_a_failed_judgment_links_nothing_and_is_retried_on_resume(tmp_path):
    findings = list(_linked_pair(tmp_path))
    store = CheckpointStore(tmp_path / "work" / "issue-links", "cyberjury.issue-link-decision/v1")

    failed = link_issues(findings, StubIssueJudge(error=RuntimeError("rate limited")), str(tmp_path), checkpoint=store)
    retried = StubIssueJudge()
    linked = link_issues(findings, retried, str(tmp_path), checkpoint=store)

    assert failed.links == ()
    assert "rate limited" in failed.errors[0]
    assert [len(issue.members) for issue in group_issues(findings, failed.links)] == [1, 1]
    assert len(retried.pairs) == 1
    assert len(linked.links) == 1


@pytest.mark.parametrize(
    "value", [{"same_fix": "yes", "reason": "r"}, {"same_fix": True}, {"same_fix": True, "reason": ""}]
)
def test_a_checkpointed_decision_must_keep_its_closed_shape(value):
    with pytest.raises(ValueError, match="issue link decision"):
        LinkDecision.from_dict(value)


def test_grouping_never_drops_a_finding():
    findings = [_finding(f"report {number}", line=number % 3 + 1) for number in range(7)]

    issues = group_issues(findings, [(findings[0].candidate_id, findings[1].candidate_id)])

    assert sorted(item.candidate_id for issue in issues for item in issue.members) == sorted(
        item.candidate_id for item in findings
    )
    assert [len(issue.members) for issue in issues] == [5, 2]
    assert issues[0].linked_by == ("judgment", "location")
