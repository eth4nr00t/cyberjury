"""Issue grouping keeps every finding, folds one location and category, and links others only on a same-fix judgment."""

import json
from dataclasses import replace

import pytest

from cyberjury.review import issues as issues_module
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
from cyberjury.review.items import ItemStore
from tests.review.support import StubIssueJudge, recorder
from tests.support import MockProvider


def _link(findings, judge, root, *, store=None):
    store = store or ItemStore(root / "review", "link")
    return link_issues(findings, judge, str(root), store=store, concurrency=1, recorder=recorder())


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
    """Two line-2 views.py reports fold by location, and the line-9 report stays alone."""
    first = _finding("save skips the owner check", line=2)
    second = _finding("record save lacks authorization", line=2)
    other = _finding("load skips the owner check", line=9)

    issues = group_issues([first, second, other], ())

    assert [set(issue.members) for issue in issues] == [{first, second}, {other}]
    assert [issue.linked_by for issue in issues] == [("location",), ()]


def test_the_representative_is_the_most_severe_member_in_any_union_order():
    """A LOW line-2 report listed before a HIGH line-9 report it is linked to still yields the HIGH representative."""
    low = replace(_finding("verbose error", line=2), severity="LOW")
    high = _finding("owner check missing", line=9)
    link = [(low.candidate_id, high.candidate_id)]

    for order in ([low, high], [high, low]):
        (issue,) = group_issues(order, link)
        assert issue.members == (high, low)


def test_findings_on_different_lines_of_one_function_are_separate_issues():
    """Owner and quota reports at views.py lines 2 and 3 give two single-member issues."""
    findings = [_finding("save checks no owner", line=2), _finding("save checks no quota", line=3)]

    assert [len(issue.members) for issue in group_issues(findings, ())] == [1, 1]


def test_findings_at_one_line_with_different_categories_are_separate_issues():
    """An authorization and a denial-of-service report at line 2 do not fold into one issue."""
    first = _finding("missing owner check", line=2)
    second = replace(_finding("unbounded size", line=2), category="denial-of-service")

    assert [len(issue.members) for issue in group_issues([first, second], ())] == [1, 1]


GATE = ("gate.py", 1, 9)


def test_one_function_with_two_lines_is_two_issues_until_a_judgment_links_them():
    """Line 2 and 4 reports citing views.py 1-9 stay two issues but form one link candidate pair."""
    first = _finding("missing owner check", line=2, cites=[("views.py", 1, 9)])
    second = _finding("unbounded size", line=4, cites=[("views.py", 1, 9)])

    assert [len(issue.members) for issue in group_issues([first, second], ())] == [1, 1]
    assert [{item.title for item in pair} for pair in link_candidates([first, second])] == [
        {"missing owner check", "unbounded size"}
    ]


def test_issue_ids_membership_and_link_candidates_are_stable_under_input_permutation():
    """Reordering four findings keeps issue ids, member candidate ids, and the single link pair identical."""
    findings = [
        _finding("a", line=2, cites=[("views.py", 1, 30)]),
        _finding("b", line=2, cites=[("views.py", 1, 30)]),
        _finding("c", line=12, cites=[("views.py", 1, 30)]),
        _finding("d", line=20),
    ]
    reordered = [findings[3], findings[1], findings[2], findings[0]]

    def shape(items):
        return {issue.id: {item.candidate_id for item in issue.members} for issue in group_issues(items, ())}

    def pairs(items):
        return [(first.candidate_id, second.candidate_id) for first, second in link_candidates(items)]

    assert shape(findings) == shape(reordered)
    assert pairs(findings) == pairs(reordered)
    assert len(pairs(findings)) == 1


def test_link_candidates_need_mutual_coverage_or_one_sided_coverage_with_a_common_cited_span():
    """Pairs form for a caller/sink sharing gate.py and for files citing each other, and a lone citer stays out."""
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
    """Only gate.py spans 1-9 and 6-14 overlap and pair, and spans 10-14 and other.py citations stay unpaired."""
    caller = _finding("caller", file="views.py", line=5, cites=[("models.py", 10, 20), ("gate.py", 1, 9)])
    sink = _finding("sink", file="models.py", line=12, cites=[("gate.py", 6, 14)])
    adjacent = _finding("adjacent", file="models.py", line=14, cites=[("gate.py", 10, 14)])
    elsewhere = _finding("elsewhere", file="models.py", line=16, cites=[("other.py", 1, 9)])

    pairs = link_candidates([caller, sink, adjacent, elsewhere])

    assert {frozenset(item.title for item in pair) for pair in pairs} == {frozenset({"caller", "sink"})}


def test_link_candidates_ask_once_per_pair_of_groups():
    """Two callers folded at views.py:5 and one sink yield a single link candidate, not two."""
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
    """The judge sees two pairs, links only view and model, and the issue is marked linked by judgment."""
    view, model = _linked_pair(tmp_path)
    separate = _finding("separate", file="models.py", line=30, cites=[("views.py", 1, 9), GATE])
    judge = StubIssueJudge(lambda pair: model.candidate_id in pair and view.candidate_id in pair)

    links = _link([view, model, separate], judge, tmp_path)
    issues = group_issues([view, model, separate], links.links)

    assert len(judge.pairs) == 2
    assert links.links == (tuple(sorted((view.candidate_id, model.candidate_id))),)
    assert [len(issue.members) for issue in issues] == [2, 1]
    assert set(issues[0].members) == {view, model}
    assert issues[0].linked_by == ("judgment",)


def test_the_model_judge_asks_one_closed_schema_question_from_structured_fields_and_cited_source(tmp_path):
    """One mock call carries both locations and numbered cited lines with a strict same_fix/rationale schema."""
    view, model = _linked_pair(tmp_path)
    provider = MockProvider(default=json.dumps({"same_fix": True, "rationale": "the save owner check fixes both"}))
    judge = ModelIssueJudge(provider=provider, model="mock", seat_id="seat-test")

    links = _link([view, model], judge, tmp_path)

    (call,) = provider.calls
    prompt = call["prompt"]
    first, second = sorted((view, model), key=lambda item: item.candidate_id)
    assert prompt == link_prompt(first, second, str(tmp_path))
    assert prompt.startswith("Finding A:\n- title: ")
    assert "- location: models.py:12" in prompt
    assert "- location: views.py:5" in prompt
    assert "12 | line_12 = 12" in prompt
    assert " 5 | line_5 = 5" in prompt
    assert call["response_schema"].schema["required"] == ["same_fix", "rationale"]
    assert call["response_schema"].schema["additionalProperties"] is False
    assert "one code change fixes both findings" in call["system"]
    assert links.links == ((first.candidate_id, second.candidate_id),)


def test_the_same_fix_contract_counts_containment_but_not_shared_context():
    """The system prompt counts a contained defect as same-fix, not a shared entrypoint, file, or sink."""
    system = issues_module._SYSTEM

    assert "One change at one place removes the defect that each finding describes." in system
    assert "One finding's defect is one of the places the other finding already requires changing" in system
    assert "distinct defects that each need their own change" in system
    assert "share an entrypoint, a file, a sink, or cited code" in system


def test_decisions_under_an_earlier_judge_contract_are_asked_again(tmp_path, monkeypatch):
    """A decision recorded under a patched system prompt is re-asked once, then reused on the third run."""
    findings = list(_linked_pair(tmp_path))
    store = ItemStore(tmp_path / "review", "link")
    provider = MockProvider(default=json.dumps({"same_fix": False, "rationale": "each needs its own change"}))
    judge = ModelIssueJudge(provider=provider, model="mock", seat_id="seat-test")

    with monkeypatch.context() as patch:
        patch.setattr(issues_module, "_SYSTEM", "an earlier same-fix contract")
        _link(findings, judge, tmp_path, store=store)
    _link(findings, judge, tmp_path, store=store)
    _link(findings, judge, tmp_path, store=store)

    assert len(provider.calls) == 2
    assert provider.calls[0]["system"] == "an earlier same-fix contract"
    assert provider.calls[1]["system"] == issues_module._SYSTEM


def test_link_decisions_are_reused_from_their_item_records(tmp_path):
    """A second run with a never-linking judge makes no calls and returns the recorded links."""
    findings = list(_linked_pair(tmp_path))
    store = ItemStore(tmp_path / "review", "link")
    first, resumed = StubIssueJudge(), StubIssueJudge(lambda pair: False)

    linked = _link(findings, first, tmp_path, store=store)
    reused = _link(findings, resumed, tmp_path, store=store)

    assert (len(first.pairs), len(resumed.pairs)) == (1, 0)
    assert reused.links == linked.links != ()


def test_a_failed_judgment_links_nothing_and_is_retried_on_resume(tmp_path):
    """A rate-limited judge yields no links and an error, and the resumed run asks again and links the pair."""
    findings = list(_linked_pair(tmp_path))
    store = ItemStore(tmp_path / "review", "link")

    failed = _link(findings, StubIssueJudge(error=RuntimeError("rate limited")), tmp_path, store=store)
    retried = StubIssueJudge()
    linked = _link(findings, retried, tmp_path, store=store)

    assert failed.links == ()
    assert "rate limited" in failed.errors[0]
    assert [len(issue.members) for issue in group_issues(findings, failed.links)] == [1, 1]
    assert len(retried.pairs) == 1
    assert len(linked.links) == 1


@pytest.mark.parametrize(
    "value", [{"same_fix": "yes", "rationale": "r"}, {"same_fix": True}, {"same_fix": True, "rationale": ""}]
)
def test_a_recorded_decision_must_keep_its_closed_shape(value):
    """A non-boolean same_fix, a missing rationale, or an empty rationale makes LinkDecision.from_dict raise."""
    with pytest.raises(ValueError, match="issue link decision"):
        LinkDecision.from_dict(value)


def test_grouping_never_drops_a_finding():
    """Seven findings over three lines plus one judged link group into sizes 5 and 2 with all members kept."""
    findings = [_finding(f"report {number}", line=number % 3 + 1) for number in range(7)]

    issues = group_issues(findings, [(findings[0].candidate_id, findings[1].candidate_id)])

    assert sorted(item.candidate_id for issue in issues for item in issue.members) == sorted(
        item.candidate_id for item in findings
    )
    assert [len(issue.members) for issue in issues] == [5, 2]
    assert issues[0].linked_by == ("judgment", "location")
