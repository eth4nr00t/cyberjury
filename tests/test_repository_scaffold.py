"""The repository review scaffold builds workspace structure without running the pipeline."""

import json
import stat
from dataclasses import replace

import pytest

from cyberjury.domains.base import Domain, Facts, FactsBackend
from cyberjury.domains.web import WEB
from cyberjury.review.repository.scaffold import scaffold

APP = """
from flask import Flask
app = Flask(__name__)

@app.route("/users", methods=["GET"])
def list_users():
    return "ok"

@app.route("/admin/users/<uid>", methods=["DELETE"])
def delete_user(uid):
    return "", 204
"""


def _target(tmp_path):
    d = tmp_path / "myservice"
    d.mkdir(exist_ok=True)
    (d / "app.py").write_text(APP)
    return d


GO_LIB = """
package matcher

func Match(a, b string) bool {
    return a == b
}
"""


def _go_lib(tmp_path):
    d = tmp_path / "matcher"
    d.mkdir(exist_ok=True)
    (d / "matcher.go").write_text(GO_LIB)
    return d


def test_scaffold_falls_back_to_public_api_for_a_library(tmp_path):
    """Scaffold falls back to public API for a library."""
    res = scaffold(_go_lib(tmp_path), tmp_path / "work")
    assert res.candidate_files == ("matcher.go",)
    assert "public API" in res.fallback_note
    assert (res.workspace / "units" / "matcher-go.md").exists()


def test_scaffold_no_fallback_when_entrypoints_seed(tmp_path):
    """Scaffold no fallback when entrypoints seed."""
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert res.fallback_note == ""


def test_scaffold_creates_workspace(tmp_path):
    """Scaffold creates workspace."""
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert res.project == "myservice"
    assert res.workspace == tmp_path / "work" / "myservice"
    for sub in ("inventory", "units", "candidates", "findings", "pocs"):
        assert (res.workspace / sub).is_dir()


def test_scaffold_seeds_the_inventory_templates(tmp_path):
    """Scaffold seeds the inventory templates."""
    res = scaffold(_target(tmp_path), tmp_path / "work")
    surface = res.workspace / "inventory" / "_surface.md"
    auth = res.workspace / "inventory" / "_auth_model.md"
    sev = res.workspace / "inventory" / "_severity.md"
    assert surface.is_file()
    assert "Attack Surface Inventory" in surface.read_text()
    assert auth.is_file()
    assert "Authorization Model" in auth.read_text()
    assert not (res.workspace / "inventory" / "_invariants.md").exists()
    rubric = sev.read_text()
    assert sev.is_file()
    assert "Severity Rubric" in rubric
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert level in rubric


def test_scaffold_flags_candidate_entrypoint_files(tmp_path):
    """Scaffold flags candidate entrypoint files."""
    d = tmp_path / "dj"
    d.mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app").mkdir()
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = scaffold(d, tmp_path / "work")
    assert "app/urls.py" in res.candidate_files
    seeded = (res.workspace / "inventory" / "_entrypoints.md").read_text()
    assert "app/urls.py" in seeded


def test_scaffold_surfaces_downstream_logic_layers(tmp_path):
    """Scaffold surfaces downstream logic layers."""
    d = tmp_path / "dj"
    (d / "app" / "managers").mkdir(parents=True)
    (d / "app" / "tests").mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "app" / "managers" / "auth_manager.py").write_text("class AuthManager:\n    pass\n")
    (d / "app" / "tests" / "test_managers.py").write_text("def test_x():\n    pass\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = scaffold(d, tmp_path / "work")
    assert "app/managers/auth_manager.py" in res.trace_targets
    assert "app/managers/auth_manager.py" not in res.candidate_files
    assert not any("test" in t for t in res.trace_targets)
    assert "app/managers/auth_manager.py" in (res.workspace / "inventory" / "_entrypoints.md").read_text()


def test_scaffold_seeds_a_unit_per_candidate(tmp_path):
    """Scaffold seeds a unit per candidate."""
    res = scaffold(_target(tmp_path), tmp_path / "work")
    units = list((res.workspace / "units").glob("*.md"))
    assert units
    body = (res.workspace / "units" / "app.md").read_text()
    assert "- Status: open" in body
    assert "app.py" in body
    assert "trace" in body.lower()
    assert "_severity.md" in body


def test_scaffold_splits_a_large_candidate_into_slice_units(tmp_path):
    """Scaffold splits a large candidate into slice units."""
    d = tmp_path / "big"
    d.mkdir()
    header = "from flask import Flask\napp = Flask(__name__)\n\n"
    block = '@app.route("/r%d")\ndef h%d():\n    x = "%s"\n    return x\n\n'
    body = "".join(block % (i, i, "p" * 200) for i in range(200))
    (d / "views.py").write_text(header + body)
    (d / "requirements.txt").write_text("Flask==3.0\n")
    res = scaffold(d, tmp_path / "work")
    slugs = sorted(p.stem for p in (res.workspace / "units").glob("*.md"))
    assert "views" not in slugs
    assert "views-py-1" in slugs
    assert "views-py-2" in slugs
    first = (res.workspace / "units" / "views-py-1.md").read_text()
    assert "views.py" in first
    assert "lines 1 to " in first


def test_methodology_is_a_fan_out(tmp_path):
    """Methodology is a fan out."""
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Agent Methodology" in res.methodology
    assert "Why Fan Out" in res.methodology
    for phase in ("Map the Attack Surface", "Fan Out", "Aggregate"):
        assert phase in res.methodology
    assert "Status: reviewed" in res.methodology


def test_methodology_accumulates_across_runs(tmp_path):
    """Methodology accumulates across runs."""
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Accumulate Across Runs" in res.methodology
    assert "Status: reviewed" in res.methodology


_VAULT_SOL = """\
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""


def _foundry_project(tmp_path):
    d = tmp_path / "vault"
    (d / "src").mkdir(parents=True)
    (d / "foundry.toml").write_text('[profile.default]\nsrc = "src"\nout = "out"\n')
    (d / "src" / "Vault.sol").write_text(_VAULT_SOL)
    return d


class _CountingBackend(FactsBackend):
    """A facts backend counts extractions without a real toolchain."""

    def __init__(self) -> None:
        self.calls = 0

    def available(self) -> bool:
        return True

    def extract(self, root):
        self.calls += 1
        block = "contract Fake\n  external f()  ext-call"
        return Facts(
            summary=block,
            data={
                "contracts": {},
                "by_file": {"app.py": block},
                "units": [
                    {"name": "app.py#Fake.f", "files": ["app.py"], "fragments": [["app.py", 0, 12]]},
                    {"name": "tests/t.py#T.f", "files": ["tests/t.py"], "fragments": [["tests/t.py", 0, 9]]},
                ],
                "graph": {"callgraph": {"app.py": {"f": [{"range": [0, 12], "calls": []}]}}, "imports": {}},
            },
        )


def _facts_domain(backend: FactsBackend) -> Domain:
    return replace(WEB, facts_backend=backend)


def test_scaffold_grounds_whenever_the_domain_binds_a_backend(tmp_path):
    """Scaffold grounds whenever the domain binds a backend."""
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    assert (res.workspace / "_facts.md").read_text().startswith("contract Fake")
    assert backend.calls == 1


def test_scaffold_leaves_a_domain_with_no_backend_ungrounded(tmp_path):
    """Scaffold leaves a domain with no backend ungrounded."""
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=replace(WEB, facts_backend=None))
    assert not (res.workspace / "_facts.md").exists()


class _UnavailableBackend(FactsBackend):
    """A facts backend whose toolchain is absent, so the scaffold must degrade, not fail."""

    def available(self) -> bool:
        return False

    def extract(self, root):
        raise AssertionError("extract must not run when the backend is unavailable")


def test_scaffold_fails_loud_when_the_facts_backend_cannot_run(tmp_path):
    """Scaffold fails loud when the facts backend cannot run."""
    from cyberjury.domains.base import BackendUnavailable

    with pytest.raises(BackendUnavailable, match="no grounding"):
        scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(_UnavailableBackend()))


def test_scaffold_persists_the_per_file_facts_map(tmp_path):
    """Scaffold persists the per file facts map."""
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    by_file = json.loads((res.workspace / "_facts_by_file.json").read_text())
    assert by_file["app.py"].startswith("contract Fake")


def test_scaffold_persists_the_call_path_units(tmp_path):
    """Scaffold persists the call path units."""
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    units = json.loads((res.workspace / "_facts_units.json").read_text())
    assert units[0]["name"] == "app.py#Fake.f"
    assert units[0]["fragments"] == [["app.py", 0, 12]]


def test_scaffold_persists_the_call_and_import_graph(tmp_path):
    """Scaffold persists the call and import graph."""
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    graph = json.loads((res.workspace / "_facts_graph.json").read_text())
    assert graph["callgraph"]["app.py"]["f"] == [{"range": [0, 12], "calls": []}]
    assert graph["imports"] == {}


def test_scaffold_drops_call_path_units_packed_from_test_code(tmp_path):
    """Scaffold drops call path units packed from test code."""
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    units = json.loads((res.workspace / "_facts_units.json").read_text())
    assert not any("tests/" in f[0] for u in units for f in u["fragments"])


def test_scaffold_reuses_the_cached_per_file_facts_map(tmp_path):
    """Scaffold reuses the cached per file facts map."""
    backend = _CountingBackend()
    dom = _facts_domain(backend)
    work = tmp_path / "work"
    scaffold(_target(tmp_path), work, domain=dom)
    res = scaffold(_target(tmp_path), work, domain=dom, fresh=True)
    assert backend.calls == 1
    assert json.loads((res.workspace / "_facts_by_file.json").read_text())["app.py"]
    assert json.loads((res.workspace / "_facts_units.json").read_text())[0]["name"] == "app.py#Fake.f"


def test_scaffold_reuses_cached_facts_across_a_fresh_run(tmp_path):
    """Scaffold reuses cached facts across a fresh run."""
    backend = _CountingBackend()
    dom = _facts_domain(backend)
    work = tmp_path / "work"
    scaffold(_target(tmp_path), work, domain=dom)
    assert backend.calls == 1
    res = scaffold(_target(tmp_path), work, domain=dom, fresh=True)
    assert (res.workspace / "_facts.md").read_text().startswith("contract Fake")
    assert backend.calls == 1
    for name in ("_facts_by_file.json", "_facts_units.json", "_facts_graph.json"):
        assert (res.workspace / name).is_file(), name


def test_scaffold_reextracts_when_source_changes(tmp_path):
    """Scaffold reextracts when source changes."""
    backend = _CountingBackend()
    dom = _facts_domain(backend)
    work = tmp_path / "work"
    target = _target(tmp_path)
    scaffold(target, work, domain=dom)
    (target / "app.py").write_text(APP + "\n# edit\n")
    scaffold(target, work, domain=dom, fresh=True)
    assert backend.calls == 2


def test_scaffold_persists_facts_for_the_evm_domain(tmp_path):
    """Scaffold persists facts for the EVM domain."""
    from shutil import which

    from cyberjury.domains.evm import EVM

    backend = EVM.facts_backend
    if backend is None or not backend.available() or which("forge") is None:
        pytest.skip("Slither or Foundry not installed, the facts path needs both")
    res = scaffold(_foundry_project(tmp_path), tmp_path / "work", domain=EVM)
    facts = res.workspace / "_facts.md"
    assert facts.is_file()
    text = facts.read_text()
    assert "contract Vault" in text
    assert "reenter" in text

    by_file = json.loads((res.workspace / "_facts_by_file.json").read_text())
    vault_key = next(k for k in by_file if k.endswith("Vault.sol"))
    assert "contract Vault" in by_file[vault_key]
    assert "reenter" in by_file[vault_key]


def test_scaffold_no_candidates_when_nothing_flagged(tmp_path):
    """Scaffold no candidates when nothing flagged."""
    d = tmp_path / "rb"
    d.mkdir()
    (d / "app.rb").write_text("puts 'hello'\n")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert "none flagged" in (res.workspace / "inventory" / "_entrypoints.md").read_text()


def test_scaffold_seeds_stack_guides(tmp_path):
    """Scaffold seeds stack guides."""
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "python" in res.guides
    assert "flask" in res.guides
    assert "app.py" in res.candidate_files
    stack = (res.workspace / "_stack.md").read_text().lower()
    assert "python" in stack
    assert "flask" in stack


def test_scaffold_seeds_vulnerability_classes(tmp_path):
    """Scaffold seeds vulnerability classes."""
    res = scaffold(_target(tmp_path), tmp_path / "work")
    vulns = res.workspace / "_vulnerabilities.md"
    assert vulns.is_file()
    text = vulns.read_text()
    assert "Vulnerability Classes" in text
    assert text.count("\n---\n") >= 5


def test_scaffold_flags_a_prior_run(tmp_path):
    """Scaffold flags a prior run."""
    ws_root = tmp_path / "work"
    first = scaffold(_target(tmp_path), ws_root)
    assert first.had_prior_run is False
    (first.workspace / "candidates" / "found.md").write_text("# a finding\n")
    second = scaffold(_target(tmp_path), ws_root)
    assert second.had_prior_run is True
    assert second.cleared == []
    assert (second.workspace / "candidates" / "found.md").is_file()


def test_scaffold_fresh_clears_prior_output(tmp_path):
    """Scaffold fresh clears prior output."""
    ws_root = tmp_path / "work"
    first = scaffold(_target(tmp_path), ws_root)
    (first.workspace / "candidates" / "found.md").write_text("# a finding\n")
    (first.workspace / "units" / "u1.md").write_text("# unit\n- Status: reviewed\n")
    fresh = scaffold(_target(tmp_path), ws_root, fresh=True)
    assert fresh.had_prior_run is True
    assert fresh.cleared
    assert not (fresh.workspace / "candidates" / "found.md").exists()
    assert not (fresh.workspace / "units" / "u1.md").exists()
    assert (fresh.workspace / "inventory" / "_surface.md").is_file()


def test_scaffold_creates_a_private_workspace(tmp_path):
    """Scaffold creates a private workspace."""
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert stat.S_IMODE(res.workspace.stat().st_mode) == 0o700


def test_fresh_refuses_to_clear_an_unmarked_directory(tmp_path):
    """Fresh refuses to clear an unmarked directory."""
    ws_root = tmp_path / "work"
    project_ws = ws_root / "myservice"
    project_ws.mkdir(parents=True)
    (project_ws / "important.txt").write_text("not cyberjury data")
    with pytest.raises(ValueError, match=r"no \.cyberjury-workspace marker"):
        scaffold(_target(tmp_path), ws_root, fresh=True)
    assert (project_ws / "important.txt").exists()


def test_scaffold_refuses_a_legacy_issues_layout(tmp_path):
    """Scaffold refuses a legacy issues layout."""
    ws_root = tmp_path / "work"
    project_ws = ws_root / "myservice"
    (project_ws / "issues").mkdir(parents=True)
    (project_ws / "issues" / "found.md").write_text("# a finding\n")
    with pytest.raises(ValueError, match="old issues/ layout"):
        scaffold(_target(tmp_path), ws_root)


def test_plain_repository_still_scaffolds(tmp_path):
    """Plain repository still scaffolds."""
    d = tmp_path / "plain"
    d.mkdir()
    (d / "notes.txt").write_text("hi")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert (res.workspace / "inventory" / "_surface.md").is_file()
