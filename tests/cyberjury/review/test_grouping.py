"""Source linked issue grouping retains candidates and resumes exact judgments."""

import json
from dataclasses import dataclass

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.claims import ClaimRecord
from cyberjury.review.consolidation import project_issues
from cyberjury.review.grouping import consolidate_candidate_issues, issue_policy_revision
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.relationships import DefinitionEvidence, RelationshipEvidenceBundle, SourceReference
from cyberjury.sources.snapshot import SourceSnapshot


@dataclass(frozen=True)
class _Candidate:
    id: str
    file: str
    line: int
    attack_path: str
    evidence_refs: tuple[str, ...]
    category: str = "other"
    attack_path_id: str = "path-local"

    @property
    def claims(self) -> tuple[ClaimRecord, ...]:
        return (
            ClaimRecord.create(
                self.id,
                {
                    "file": self.file,
                    "line": self.line,
                    "attack_path": self.attack_path,
                    "evidence_refs": list(self.evidence_refs),
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
    source_evidence = (
        navigator.session().read_source_scopes((("app.py", 2), ("app.py", 4)), target_chars=48_000).source_evidence
    )
    return navigator, SourceSnapshot.capture(tmp_path, ("app.py",)), source_evidence


def _candidates(ref: str) -> tuple[_Candidate, ...]:
    return (
        _Candidate("a", "app.py", 2, "unsafe write", (ref,)),
        _Candidate("b", "app.py", 4, "downstream effect", (ref,)),
    )


def _full_reply(ref: str) -> str:
    return json.dumps(
        {
            "decisions": [
                {
                    "candidate_id": "b",
                    "coverage": "full",
                    "reason": "one local repair prevents the full child claim",
                    "evidence_refs": [ref],
                    "operation_file": "app.py",
                    "operation_line": 2,
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
                    "candidate_id": "b",
                    "coverage": "independent",
                    "reason": "the child needs another repair",
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


def _run(
    candidates,
    navigator,
    snapshot,
    source_evidence,
    provider,
    *,
    checkpoint_path=None,
    revision=None,
):
    return consolidate_candidate_issues(
        candidates,
        navigator=navigator,
        provider=provider,
        model="mock",
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
        claims_of=lambda item: item.claims,
        source_refs_of=lambda item: item.evidence_refs,
        category_of=lambda item: item.category,
        attack_path_id_of=lambda item: item.attack_path_id,
        source_snapshot=snapshot,
        candidate_source_evidence=source_evidence,
        checkpoint_path=checkpoint_path,
        adjudicator_revision=revision or issue_policy_revision("a" * 64),
    )


def _issues(candidates, result):
    return project_issues(
        candidates,
        result.decisions,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
        source_evidence=result.source_evidence,
        unresolved_ids=result.unresolved_ids,
    )


def test_two_full_votes_group_one_local_issue_without_deleting_candidates(tmp_path):
    navigator, snapshot, evidence = _source(tmp_path)
    candidates = _candidates(evidence[0].id)
    provider = MockProvider(default=_full_reply(evidence[0].id))

    result = _run(candidates, navigator, snapshot, evidence, provider)

    assert result.failures == ()
    assert result.unresolved_ids == frozenset()
    assert [(item.candidate_id, item.covered_by) for item in result.decisions] == [("b", ("a",))]
    assert len(_issues(candidates, result)) == 1
    assert len(provider.calls) == 2


def test_solidity_reports_use_the_same_local_source_contract(tmp_path):
    source = (
        "contract Vault {\n"
        "    function withdraw(uint amount) external {\n"
        "        require(amount > 0);\n"
        "        sendValue(amount);\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "Vault.sol").write_text(source, encoding="utf-8")
    start = source.index("    function withdraw")
    end = source.index("    }", start) + len("    }")
    definition = DefinitionEvidence.create(
        source=SourceReference.create(path="Vault.sol", start=start, end=end, content=source[start:end]),
        kind="function",
        name="withdraw",
    )
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {"callgraph": {}},
        source_files=("Vault.sol",),
        relationship_evidence=RelationshipEvidenceBundle.create(definitions=(definition,)),
    )
    assert navigator is not None
    snapshot = SourceSnapshot.capture(tmp_path, ("Vault.sol",))
    evidence = navigator.session().read_source_scopes((("Vault.sol", 3), ("Vault.sol", 4)), target_chars=48_000)
    ref = evidence.source_evidence[0].id
    candidates = (
        _Candidate("a", "Vault.sol", 3, "missing local check", (ref,)),
        _Candidate("b", "Vault.sol", 4, "effect of the same check", (ref,)),
    )
    reply = json.loads(_full_reply(ref))
    reply["decisions"][0]["operation_file"] = "Vault.sol"
    reply["decisions"][0]["operation_line"] = 3
    reply["decisions"][0]["execution_witness"]["start_line"] = 3
    provider = MockProvider(default=json.dumps(reply))

    result = _run(candidates, navigator, snapshot, evidence.source_evidence, provider)

    assert result.failures == ()
    assert len(result.decisions) == 1
    assert len(_issues(candidates, result)) == 1


def test_independent_repair_retains_two_reports_after_one_vote(tmp_path):
    navigator, snapshot, evidence = _source(tmp_path)
    candidates = _candidates(evidence[0].id)
    provider = MockProvider(default=_independent_reply())

    result = _run(candidates, navigator, snapshot, evidence, provider)

    assert result.decisions == ()
    assert result.failures == ()
    assert [(item.candidate_id, item.status) for item in result.relations] == [("b", "independent")]
    assert len(_issues(candidates, result)) == 2
    assert len(provider.calls) == 1


def test_definition_declaration_cannot_be_a_local_repair_root(tmp_path):
    navigator, snapshot, evidence = _source(tmp_path)
    candidates = (
        _Candidate("a", "app.py", 1, "function declaration", (evidence[0].id,)),
        _Candidate("b", "app.py", 2, "unsafe write", (evidence[0].id,)),
    )
    provider = MockProvider(default=_full_reply(evidence[0].id))

    result = _run(candidates, navigator, snapshot, evidence, provider)

    assert result.search.neighborhoods == ()
    assert result.decisions == ()
    assert len(_issues(candidates, result)) == 2
    assert provider.calls == []


def test_malformed_judgment_keeps_both_candidates_incomplete(tmp_path):
    navigator, snapshot, evidence = _source(tmp_path)
    candidates = _candidates(evidence[0].id)
    provider = MockProvider(default="not JSON")

    result = _run(candidates, navigator, snapshot, evidence, provider)

    assert result.decisions == ()
    assert result.failures
    assert result.unresolved_ids == frozenset({"a", "b"})
    assert len(_issues(candidates, result)) == 2
    assert len(provider.calls) == 1


def test_exact_checkpoint_resumes_without_a_model_call(tmp_path):
    navigator, snapshot, evidence = _source(tmp_path)
    candidates = _candidates(evidence[0].id)
    path = tmp_path / "_issue_judgments.json"
    first = _run(
        candidates,
        navigator,
        snapshot,
        evidence,
        MockProvider(default=_full_reply(evidence[0].id)),
        checkpoint_path=path,
    )
    replay = MockProvider(default="not JSON")

    restored = _run(candidates, navigator, snapshot, evidence, replay, checkpoint_path=path)

    assert restored == first
    assert replay.calls == []


def test_checkpoint_rejects_tampering_before_a_model_call(tmp_path):
    navigator, snapshot, evidence = _source(tmp_path)
    candidates = _candidates(evidence[0].id)
    path = tmp_path / "_issue_judgments.json"
    _run(
        candidates,
        navigator,
        snapshot,
        evidence,
        MockProvider(default=_full_reply(evidence[0].id)),
        checkpoint_path=path,
    )
    saved = json.loads(path.read_text())
    saved["groups"][0]["judgment"]["relations"][0]["status"] = "independent"
    path.write_text(json.dumps(saved))
    replay = MockProvider(default="not JSON")

    with pytest.raises(ValueError, match="checkpoint is invalid"):
        _run(candidates, navigator, snapshot, evidence, replay, checkpoint_path=path)

    assert replay.calls == []


def test_changed_judgment_policy_cannot_reuse_a_checkpoint(tmp_path):
    navigator, snapshot, evidence = _source(tmp_path)
    candidates = _candidates(evidence[0].id)
    path = tmp_path / "_issue_judgments.json"
    _run(
        candidates,
        navigator,
        snapshot,
        evidence,
        MockProvider(default=_full_reply(evidence[0].id)),
        checkpoint_path=path,
    )
    replay = MockProvider(default="not JSON")

    with pytest.raises(ValueError, match="policy changed"):
        _run(
            candidates,
            navigator,
            snapshot,
            evidence,
            replay,
            checkpoint_path=path,
            revision=issue_policy_revision("b" * 64),
        )

    assert replay.calls == []
