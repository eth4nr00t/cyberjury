"""Repository proof of concept generation and execution tests."""

import json

import pytest

from cyberjury.profiles.base import PoCArtifact
from cyberjury.review.repository.engine import (
    RepositoryFinalizeOptions,
    RepositoryVerificationOptions,
    finalize_repository_review,
)
from cyberjury.review.repository.union import Candidate
from tests.cyberjury.review.repository.engine.factories import mark_workspace as _mark_workspace


def test_poc_for_matches_a_multi_suffix_extension(tmp_path):
    from cyberjury.review.repository.engine import _poc_for

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    (ws / "pocs" / "oracle-setter.t.sol").write_text("contract T {}")
    (ws / "pocs" / "idor.py").write_text("x = 1\n")
    assert _poc_for(ws, "oracle-setter") == "pocs/oracle-setter.t.sol"
    assert _poc_for(ws, "idor") == "pocs/idor.py"
    assert _poc_for(ws, "missing") == ""
    assert _poc_for(ws, "oracle") == ""


def test_finalize_links_pocs_and_reconciles(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    proj = ws / "proj"
    (proj / "candidates").mkdir(parents=True)
    (proj / "pocs").mkdir(parents=True)
    _mark_workspace(proj)
    (proj / "candidates" / "x.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (proj / "candidates" / "y.md").write_text(
        "# replay\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n## Analysis\napp/s.py:5\n"
    )
    (proj / "pocs" / "x.t.sol").write_text("contract T {}\n")
    (proj / "pocs" / "z.sh").write_text("#!/bin/sh\necho orphan\n")

    finalize_repository_review(
        target,
        ws,
        options=RepositoryFinalizeOptions(
            verification=RepositoryVerificationOptions(enabled=False),
        ),
    )
    data = json.loads((proj / "findings.json").read_text())
    findings_by_entry = {f["entry"]: f for f in data["findings"]}
    assert findings_by_entry["GET /x/<id>"]["poc"] == "pocs/x.t.sol"
    assert findings_by_entry["GET /x/<id>"]["candidate"] == "candidates/x.md"
    assert findings_by_entry["POST /t"]["poc"] == ""

    report = (proj / "_pocs.md").read_text()
    assert "POST /t" in report
    assert "pocs/z.sh" in report
    assert "GET /x" not in report


def test_run_pocs_writes_the_poc_annotates_and_never_drops(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _finding_name, _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [
        Candidate(
            title="oracle",
            category="access-control",
            file="O.sol",
            line=5,
            symbol="setX",
            evidence="unprotected setter",
        )
    ]

    class FakeBackend:
        executes = True
        ext = "t.sol"
        install_hint = ""

        def available(self):
            return True

        def reproduce(self, **kw):
            return SimpleNamespace(reproduced=True, test_source="contract T {}", detail="passed")

    out = _run_pocs(ws, findings, FakeBackend(), root=str(tmp_path))
    assert len(out) == 1
    assert (ws / "pocs" / f"{_finding_name(findings[0])}.t.sol").read_text() == "contract T {}"
    assert "PoC reproduced" in out[0].evidence


def test_run_pocs_keeps_finding_when_the_poc_fails_or_backend_errors(tmp_path):
    from cyberjury.review.repository.engine import _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [Candidate(title="x", category="idor", file="A.sol", line=1)]

    class Erroring:
        executes = True
        ext = "t.sol"
        install_hint = ""

        def available(self):
            return True

        def reproduce(self, **kw):
            raise RuntimeError("model down")

    out = _run_pocs(ws, findings, Erroring(), root=str(tmp_path))
    assert len(out) == 1
    assert "PoC failed to run" in out[0].evidence


def test_run_pocs_rejects_an_executing_backend_without_reproduction(tmp_path):
    from cyberjury.review.repository.engine import _run_pocs

    class InvalidBackend:
        executes = True
        ext = "t.sol"
        install_hint = ""

        def available(self):
            return True

    with pytest.raises(TypeError, match="must implement reproduce"):
        _run_pocs(tmp_path, [], InvalidBackend(), root=str(tmp_path))


def test_run_pocs_degrades_to_write_only_when_an_executing_toolchain_is_absent(tmp_path):
    from cyberjury.review.repository.engine import _finding_name, _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [Candidate(title="x", category="idor", file="A.sol", line=1, symbol="f", evidence="unchecked")]

    class Unavailable:
        executes = True
        ext = "t.sol"
        install_hint = "install the toolchain from https://example.test"

        def available(self):
            return False

        def reproduce(self, **kw):
            raise AssertionError("must not run when the toolchain is absent")

        def generate(self, **kw):
            return PoCArtifact(source="contract T {}", run_hint="forge test")

    out = _run_pocs(ws, findings, Unavailable(), root=str(tmp_path))
    assert len(out) == 1
    assert (ws / "pocs" / f"{_finding_name(findings[0])}.t.sol").read_text() == "contract T {}"
    assert "not run" in out[0].evidence
    assert "install the toolchain from https://example.test" in out[0].evidence


def test_run_pocs_writes_only_for_a_backend_that_does_not_execute(tmp_path):
    from cyberjury.review.repository.engine import _finding_name, _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [
        Candidate(title="idor", category="idor", file="views.py", line=3, symbol="get_order", evidence="no owner check")
    ]

    class WriteOnly:
        executes = False
        ext = "py"
        install_hint = ""

        def available(self):
            return False

        def generate(self, **kw):
            return PoCArtifact(source="import requests\n", run_hint="python it")

    out = _run_pocs(ws, findings, WriteOnly(), root=str(tmp_path))
    assert len(out) == 1
    assert (ws / "pocs" / f"{_finding_name(findings[0])}.py").read_text() == "import requests\n"
    assert "run it manually" in out[0].evidence


def test_run_pocs_folds_a_writer_side_note_into_the_evidence(tmp_path):
    from cyberjury.review.repository.engine import _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [Candidate(title="idor", category="idor", file="v.py", line=3, symbol="g", evidence="no owner check")]

    class WriteOnly:
        executes = False
        ext = "py"
        install_hint = ""

        def available(self):
            return False

        def generate(self, **kw):
            return PoCArtifact(
                source="def broken(:",
                run_hint="python it",
                note="PoC does not parse as Python: invalid syntax",
            )

    out = _run_pocs(ws, findings, WriteOnly(), root=str(tmp_path))
    assert "does not parse" in out[0].evidence
    assert len(out) == 1


def test_execute_present_pocs_runs_an_agent_written_poc(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _execute_present_pocs, _finding_name

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    c = Candidate(
        title="oracle", category="access-control", file="O.sol", line=5, symbol="setX", evidence="unprotected setter"
    )
    (ws / "pocs" / f"{_finding_name(c)}.t.sol").write_text("contract T {}")

    class Runner:
        executes = True
        ext = "t.sol"

        def execute(self, *, source, root):
            return SimpleNamespace(ran=True, ok=True, detail="passed")

    profile = SimpleNamespace(poc_backend=lambda: Runner())
    out = _execute_present_pocs(ws, [c], profile, root=str(tmp_path))
    assert "PoC reproduced" in out[0].evidence


def test_execute_present_pocs_leaves_a_web_profile_to_reconciliation(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _execute_present_pocs, _finding_name

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    c = Candidate(title="idor", category="idor", file="v.py", line=1, symbol="g", evidence="x")
    (ws / "pocs" / f"{_finding_name(c)}.py").write_text("import requests\n")

    class WebRunner:
        executes = False
        ext = "py"

    profile = SimpleNamespace(poc_backend=lambda: WebRunner())
    out = _execute_present_pocs(ws, [c], profile, root=str(tmp_path))
    assert out[0].evidence == "x"


def test_execute_present_pocs_does_not_run_a_finding_the_write_step_already_ran(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _execute_present_pocs, _finding_name

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    c = Candidate(
        title="oracle",
        category="access-control",
        file="O.sol",
        line=5,
        symbol="setX",
        evidence="setter\n\n[PoC reproduced: passed]",
    )
    (ws / "pocs" / f"{_finding_name(c)}.t.sol").write_text("contract T {}")

    ran: list[str] = []

    class Runner:
        executes = True
        ext = "t.sol"

        def execute(self, *, source, root):
            ran.append(source)
            return SimpleNamespace(ran=True, ok=True, detail="passed")

    profile = SimpleNamespace(poc_backend=lambda: Runner())
    out = _execute_present_pocs(ws, [c], profile, root=str(tmp_path))
    assert ran == []
    assert out[0].evidence.count("[PoC") == 1


def test_execute_present_pocs_records_runner_errors_and_keeps_the_finding(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _execute_present_pocs, _finding_name

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    c = Candidate(
        title="oracle", category="access-control", file="O.sol", line=5, symbol="setX", evidence="unprotected setter"
    )
    (ws / "pocs" / f"{_finding_name(c)}.t.sol").write_text("contract T {}")

    class Runner:
        executes = True

        def execute(self, *, source, root):
            raise RuntimeError("forge failed")

    profile = SimpleNamespace(poc_backend=lambda: Runner())
    out = _execute_present_pocs(ws, [c], profile, root=str(tmp_path))
    assert len(out) == 1
    assert "PoC failed to run: forge failed" in out[0].evidence
