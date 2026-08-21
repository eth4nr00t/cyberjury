"""Repository runs complete only after every review unit has valid work."""

import json

import pytest

from cyberjury.providers.mock import MockProvider
from tests.cyberjury.review.repository.engine.factories import run_review as _run_review

_REPLY = (
    '{"findings": [{"title": "wallet idor", "category": "insecure-direct-object-reference", '
    '"endpoint": "GET /wallets/<wallet_id>", "file": "app/services/wallet.py", "line": 11, '
    '"severity": "HIGH", "evidence": "wallet.py:11 no owner check", "status": "confirmed"}]}'
)


def test_standard_run_completes_writes_findings_and_marks_units(custody_repository, tmp_path):
    prov = MockProvider(default=_REPLY)
    res = _run_review(
        custody_repository,
        tmp_path / "ws",
        provider=prov,
        model="mock",
        converge_after=2,
        max_passes=12,
        verify=False,
    )
    ws = res.scaffold.workspace

    assert res.outcome.complete
    assert res.accumulator.converged is False
    assert len(res.accumulator.findings) == 1
    assert res.outcome is not None
    assert res.outcome.complete is True

    data = json.loads((ws / "findings.json").read_text())
    assert any(f["entry"] == "GET /wallets/<wallet_id>" for f in data["findings"])
    findings = list((ws / "findings").glob("*.md"))
    assert findings
    assert "Risk: HIGH" in findings[0].read_text()

    units = list((ws / "units").glob("*.md"))
    assert units
    assert all("Status: reviewed" in u.read_text() for u in units)
    assert not any("Status: open" in u.read_text() for u in units)

    assert not (ws / "_pocs.md").exists()

    status = json.loads((ws / "_run.json").read_text())
    assert status["converged"] is False
    assert status["complete"] is True
    assert status["errors"] == 0
    assert status["units_reviewed"] == status["units_total"] == len(units)
    assert status["failed_units"] == []


def test_run_writes_pocs_when_a_backend_is_bound(custody_repository, tmp_path):

    class WritePoC:
        executes = False
        ext = "py"

        def available(self):
            return False

        def generate(self, **kw):
            return type("Artifact", (), {"source": "import requests\n", "run_hint": "python poc.py", "note": ""})()

    res = _run_review(
        custody_repository,
        tmp_path / "ws",
        provider=MockProvider(default=_REPLY),
        model="mock",
        verify=False,
        converge_after=2,
        max_passes=12,
        poc_backend=WritePoC(),
    )
    pocs = sorted((res.scaffold.workspace / "pocs").glob("*.py"))
    assert len(pocs) == 1
    assert "import requests" in pocs[0].read_text()
    finding = next((res.scaffold.workspace / "findings").glob("*.md")).read_text()
    assert "PoC written, run it manually" in finding


def test_run_fails_loud_on_zero_units(tmp_path):
    repository = tmp_path / "empty"
    repository.mkdir()
    (repository / "README.md").write_text("nothing to review here\n")
    with pytest.raises(ValueError, match="no candidate entrypoints"):
        _run_review(repository, tmp_path / "ws")
