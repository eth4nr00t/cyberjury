"""Issue judgments require exact local source and independent complete votes."""

import json
from dataclasses import dataclass

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.adjudication import (
    IssueWitnessError,
    adjudicate_group_coverage,
    agreed_execution_witness,
)
from cyberjury.review.claims import ClaimRecord
from cyberjury.review.consolidation import ExecutionWitness
from cyberjury.review.engine import RoleResponseError
from cyberjury.review.navigation import SourceNavigationError, SourceNavigator
from cyberjury.review.relationships import DefinitionEvidence, RelationshipEvidenceBundle, SourceReference
from cyberjury.sources.snapshot import SourceSnapshot


@dataclass(frozen=True)
class _Candidate:
    id: str
    file: str
    line: int
    attack_path: str
    refs: tuple[str, ...] = ("seed",)

    @property
    def claims(self) -> tuple[ClaimRecord, ...]:
        return (
            ClaimRecord.create(
                self.id,
                {
                    "file": self.file,
                    "line": self.line,
                    "attack_path": self.attack_path,
                    "evidence_refs": list(self.refs),
                },
            ),
        )


def _source(tmp_path):
    source = "def handle(value):\n    unsafe_write(value)\n    later = value\n    return later\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    definition = DefinitionEvidence.create(
        source=SourceReference.create(path="app.py", start=0, end=len(source), content=source),
        kind="function",
        name="handle",
    )
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {"callgraph": {}},
        source_files=("app.py",),
        relationship_evidence=RelationshipEvidenceBundle.create(definitions=(definition,)),
    )
    assert navigator is not None
    evidence = navigator.session().read_source_scopes((("app.py", 2), ("app.py", 4)), target_chars=48_000)
    return navigator, SourceSnapshot.capture(tmp_path, ("app.py",)), evidence.source_evidence[0].id


def _judge(tmp_path, provider, *, root=None, child=None, navigator=None, snapshot=None):
    if navigator is None or snapshot is None:
        navigator, snapshot, _ = _source(tmp_path)
    root = root or _Candidate("root", "app.py", 2, "unsafe operation")
    child = child or _Candidate("child", "app.py", 4, "effect of the same operation")
    return adjudicate_group_coverage(
        root,
        (child,),
        navigator=navigator,
        provider=provider,
        model="mock",
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
        claims_of=lambda item: item.claims,
        source_snapshot=snapshot,
    )


def _full_reply(ref: str, *, operation_line: int = 2) -> str:
    return json.dumps(
        {
            "decisions": [
                {
                    "candidate_id": "child",
                    "coverage": "full",
                    "reason": "one repair prevents the complete child claim",
                    "evidence_refs": [ref],
                    "operation_file": "app.py",
                    "operation_line": operation_line,
                    "execution_witness": {
                        "kind": "same_local_control",
                        "callsite_id": "",
                        "definition_id": "",
                        "start_line": 2,
                        "end_line": 4,
                    },
                    "residual_operation": None,
                }
            ],
            "source_queries": [],
            "evidence_requests": [],
        }
    )


def _independent_reply() -> str:
    return json.dumps(
        {
            "decisions": [
                {
                    "candidate_id": "child",
                    "coverage": "independent",
                    "reason": "the child needs its own repair",
                    "evidence_refs": [],
                    "operation_file": "",
                    "operation_line": 0,
                    "execution_witness": None,
                    "residual_operation": None,
                }
            ],
            "source_queries": [],
            "evidence_requests": [],
        }
    )


def test_complete_local_coverage_needs_two_votes_with_one_cached_source_prefix(tmp_path):
    navigator, snapshot, ref = _source(tmp_path)
    provider = MockProvider(default=_full_reply(ref))

    result = _judge(tmp_path, provider, navigator=navigator, snapshot=snapshot)

    assert [(item.candidate_id, item.covered_by) for item in result.decisions] == [("child", ("root",))]
    assert len(result.votes) == 2
    assert len(provider.calls) == 2
    assert provider.calls[0]["cache_prefix"] == provider.calls[1]["cache_prefix"]
    assert provider.calls[0]["system"] == provider.calls[1]["system"]
    assert "Independent second judgment" in provider.calls[1]["messages"][0].content


def test_independent_repair_stays_separate_after_one_vote(tmp_path):
    provider = MockProvider(default=_independent_reply())

    result = _judge(tmp_path, provider)

    assert result.decisions == ()
    assert [(item.candidate_id, item.status) for item in result.relations] == [("child", "independent")]
    assert len(result.votes) == len(provider.calls) == 1


def test_another_line_in_the_root_function_cannot_be_the_repair(tmp_path):
    navigator, snapshot, ref = _source(tmp_path)
    provider = MockProvider(default=_full_reply(ref, operation_line=3))

    with pytest.raises(IssueWitnessError, match="outside the proposed root"):
        _judge(tmp_path, provider, navigator=navigator, snapshot=snapshot)

    assert len(provider.calls) == 2


def test_cross_function_reports_cannot_claim_a_local_witness(tmp_path):
    source = "def root(value):\n    unsafe_write(value)\n\ndef child(value):\n    return root(value)\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    cut = source.index("def child")
    definitions = (
        DefinitionEvidence.create(
            source=SourceReference.create(path="app.py", start=0, end=cut, content=source[:cut]),
            kind="function",
            name="root",
        ),
        DefinitionEvidence.create(
            source=SourceReference.create(path="app.py", start=cut, end=len(source), content=source[cut:]),
            kind="function",
            name="child",
        ),
    )
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {"callgraph": {}},
        source_files=("app.py",),
        relationship_evidence=RelationshipEvidenceBundle.create(definitions=definitions),
    )
    assert navigator is not None
    ref = navigator.session().read_source_scopes((("app.py", 2),), target_chars=48_000).source_evidence[0].id
    provider = MockProvider(default=_full_reply(ref))

    with pytest.raises(RoleResponseError, match="execution_witness"):
        _judge(
            tmp_path,
            provider,
            root=_Candidate("root", "app.py", 2, "unsafe operation"),
            child=_Candidate("child", "app.py", 5, "different function"),
            navigator=navigator,
            snapshot=SourceSnapshot.capture(tmp_path, ("app.py",)),
        )


def test_missing_child_citation_fails_before_a_model_call(tmp_path):
    navigator, snapshot, _ = _source(tmp_path)
    provider = MockProvider(default=_independent_reply())

    with pytest.raises(SourceNavigationError, match="source unavailable"):
        _judge(
            tmp_path,
            provider,
            child=_Candidate("child", "app.py", 4, "another report", refs=("src-unavailable",)),
            navigator=navigator,
            snapshot=snapshot,
        )

    assert provider.calls == []


def test_changed_source_snapshot_fails_before_a_model_call(tmp_path):
    navigator, snapshot, _ = _source(tmp_path)
    (tmp_path / "app.py").write_text("def handle(value):\n    return value\n", encoding="utf-8")
    provider = MockProvider(default=_independent_reply())

    with pytest.raises(ValueError, match="snapshot changed"):
        _judge(tmp_path, provider, navigator=navigator, snapshot=snapshot)

    assert provider.calls == []


def test_independent_votes_share_only_their_common_local_range():
    first = ExecutionWitness(kind="same_local_control", start_line=1, end_line=5)
    second = ExecutionWitness(kind="same_local_control", start_line=2, end_line=4)

    assert agreed_execution_witness(first, second) == second
    assert agreed_execution_witness(first, None) is None
