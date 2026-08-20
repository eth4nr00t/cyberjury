"""Repository finding provenance tests."""

import json

from cyberjury.review.repository.union import Candidate


def test_git_blame_owner_annotates_a_committed_line_and_is_fail_soft(tmp_path):
    import subprocess

    from cyberjury.review.repository.engine import _git_blame_owner

    repository = tmp_path / "r"
    repository.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(repository), *args], check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "dev@example.com")
    git("config", "user.name", "Dev One")
    git("config", "commit.gpgsign", "false")
    (repository / "a.py").write_text("line1\nline2\n", encoding="utf-8")
    git("add", "a.py")
    git("commit", "-q", "-m", "init")

    owner = _git_blame_owner(str(repository), "a.py", 1)
    assert "Dev One" in owner
    assert "dev@example.com" in owner
    assert _git_blame_owner(str(repository), "a.py", None) == ""
    assert _git_blame_owner("", "a.py", 1) == ""
    assert _git_blame_owner(str(repository), "../escape.py", 1) == ""
    assert _git_blame_owner(str(tmp_path / "not-a-repository"), "x.py", 1) == ""


def test_write_findings_skips_blame_for_promisor_clone(tmp_path, monkeypatch):
    import subprocess

    import cyberjury.review.repository.engine as engine

    repository = tmp_path / "r"
    repository.mkdir()
    subprocess.run(["git", "-C", str(repository), "init", "-q"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "remote.origin.promisor", "true"],
        check=True,
        capture_output=True,
    )
    ws = tmp_path / "ws"

    def fail_blame(*args):
        raise AssertionError("blame should not run for promisor clones")

    monkeypatch.setattr(engine, "_git_blame_owner", fail_blame)
    engine._write_findings(
        ws,
        [Candidate(title="idor", category="idor", file="a.py", line=1, evidence="no owner check")],
        str(repository),
    )

    data = json.loads((ws / "findings.json").read_text(encoding="utf-8"))
    assert data["findings"][0]["owner"] == ""
    finding_md = next((ws / "findings").glob("*.md"))
    assert "Owner:" not in finding_md.read_text(encoding="utf-8")
