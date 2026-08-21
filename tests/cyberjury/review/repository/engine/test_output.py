"""Repository finding serialization and reconciliation tests."""

import json

from cyberjury.review.repository.engine import (
    RepositoryFinalizeOptions,
    RepositoryVerificationOptions,
    finalize_repository_review,
)
from cyberjury.review.repository.union import Candidate
from tests.cyberjury.review.repository.engine.factories import mark_workspace as _mark_workspace


def test_write_findings_owns_findings_dir_and_never_touches_candidates(tmp_path):
    from cyberjury.review.repository.engine import _write_findings

    ws = tmp_path / "ws"
    (ws / "candidates").mkdir(parents=True)
    agent = ws / "candidates" / "agent-note.md"
    agent.write_text("# hand written\n- Risk: HIGH\n## Analysis\napp/x.py:1\n")

    two = [
        Candidate(title="A", endpoint="GET /a", file="a.py", line=1, severity="HIGH"),
        Candidate(title="B", endpoint="GET /b", file="b.py", line=2, severity="HIGH"),
    ]
    _write_findings(ws, two)
    assert len(list((ws / "findings").glob("*.md"))) == 2

    _write_findings(ws, two[:1])
    assert len(list((ws / "findings").glob("*.md"))) == 1
    assert agent.read_text().startswith("# hand written")
    assert len(json.loads((ws / "findings.json").read_text())["findings"]) == 1


def test_write_findings_keeps_two_findings_that_share_an_endpoint(tmp_path):
    from cyberjury.review.repository.engine import _write_findings

    ws = tmp_path / "ws"
    ws.mkdir()
    two = [
        Candidate(title="missing binding", category="idor", endpoint="POST /x", file="x.py", line=1),
        Candidate(title="token race", category="race-condition", endpoint="POST /x", file="x.py", line=2),
    ]
    _write_findings(ws, two)
    assert len(list((ws / "findings").glob("*.md"))) == 2
    assert len(json.loads((ws / "findings.json").read_text())["findings"]) == 2


def test_write_findings_dedupes_near_repeat_evidence_only_in_outputs(tmp_path):
    from cyberjury.review.repository.engine import _write_findings

    ws = tmp_path / "ws"
    evidence = (
        "## Analysis\n"
        "main.py uses allow_origins star with allow_credentials true, so any attacker origin can read "
        "credentialed browser responses from the API.\n\n"
        "main.py configures allow_origins star with allow_credentials true, so an attacker origin can read "
        "credentialed browser responses from the API.\n\n"
        "The exploit is a browser request from evil.example with the victim session attached."
    )
    finding = Candidate(
        title="cors",
        category="cors-misconfiguration",
        file="main.py",
        line=10,
        severity="HIGH",
        evidence=evidence,
    )

    _write_findings(ws, [finding])

    md = next((ws / "findings").glob("*.md")).read_text(encoding="utf-8")
    report = json.loads((ws / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    assert md.count("credentialed browser responses") == 1
    assert report["analysis"].count("credentialed browser responses") == 1
    assert "evil.example" in md
    assert finding.evidence == evidence


def test_finalize_finding_carries_agent_analysis_not_a_filename(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    proj = ws / "proj"
    (proj / "candidates").mkdir(parents=True)
    _mark_workspace(proj)
    (proj / "candidates" / "key-leak.md").write_text(
        "# Hardcoded key gates the webhook lane\n"
        "- Risk: HIGH\n- Type: hardcoded-secrets\n- Source: `@auth0()`\n- Status: confirmed\n\n"
        "## Analysis\n`settings/08.py:11` ships a literal AUTH0_AUTH_KEY, no prod override.\n\n"
        "## Attack Path\nRead the repository, replay the Basic header.\n\n"
        "## Fix\nLoad the key from the environment.\n"
    )

    finalize_repository_review(
        target,
        ws,
        options=RepositoryFinalizeOptions(
            verification=RepositoryVerificationOptions(enabled=False),
        ),
    )
    finding = (proj / "findings" / "key-leak.md").read_text()
    assert "ships a literal AUTH0_AUTH_KEY" in finding
    assert "## Attack Path" in finding
    assert "## Fix" in finding
    assert "key-leak.md" not in finding
    data = json.loads((proj / "findings.json").read_text())
    assert data["findings"][0]["candidate"] == "candidates/key-leak.md"


def test_candidate_key_respects_by_file_for_cross_file_findings():
    from cyberjury.review.repository.union import Candidate
    from cyberjury.review.repository.verify import candidate_key

    a = Candidate(title="t", category="reentrancy", endpoint="withdraw", file="A.sol")
    b = Candidate(title="t", category="reentrancy", endpoint="withdraw", file="B.sol")
    assert candidate_key(a, True) != candidate_key(b, True)
    assert candidate_key(a, False) == candidate_key(b, False)
