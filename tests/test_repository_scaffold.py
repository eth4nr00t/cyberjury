"""The repository-review scaffold sets up the fan-out workspace, inventory, units, candidates,
findings, and pocs directories plus seeded entrypoints, and returns the methodology. It
does not run an LLM pipeline."""

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
    # no application entrypoint, so the exported Go function is the entry surface
    res = scaffold(_go_lib(tmp_path), tmp_path / "work")
    assert res.candidate_files == ("matcher.go",)
    assert "public API" in res.fallback_note
    assert (res.workspace / "units" / "matcher-go.md").exists()


def test_scaffold_fallback_fails_loud_over_max_units(tmp_path):
    d = _go_lib(tmp_path)
    (d / "other.go").write_text("package matcher\nfunc Other() {}\n")
    with pytest.raises(ValueError, match="max-units"):
        scaffold(d, tmp_path / "work", max_units=1)


def test_scaffold_no_fallback_when_entrypoints_seed(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert res.fallback_note == ""


def test_scaffold_creates_workspace(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert res.project == "myservice"
    assert res.workspace == tmp_path / "work" / "myservice"
    for sub in ("inventory", "units", "candidates", "findings", "pocs"):
        assert (res.workspace / sub).is_dir()


def test_scaffold_seeds_the_inventory_templates(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    surface = res.workspace / "inventory" / "_surface.md"
    auth = res.workspace / "inventory" / "_auth_model.md"
    inv = res.workspace / "inventory" / "_invariants.md"
    sev = res.workspace / "inventory" / "_severity.md"
    assert surface.is_file()
    assert "Attack Surface Inventory" in surface.read_text()
    assert auth.is_file()
    assert "Authorization Model" in auth.read_text()
    assert inv.is_file()
    assert "Intent Invariants" in inv.read_text()
    rubric = sev.read_text()
    assert sev.is_file()
    assert "Severity Rubric" in rubric
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert level in rubric


def test_scaffold_keeps_an_edited_invariants_file_and_does_not_count_it_as_prior(tmp_path):
    target = _target(tmp_path)
    ws = tmp_path / "work"
    first = scaffold(target, ws)
    inv = first.workspace / "inventory" / "_invariants.md"
    inv.write_text("# Intent Invariants\n\nonly the owner moves the balance\n", encoding="utf-8")
    second = scaffold(target, ws)
    assert "only the owner moves the balance" in inv.read_text()
    # an operator-seeded invariants file is not engine output, so editing it alone is not a prior run
    assert second.had_prior_run is False


def test_scaffold_imports_invariants_from_a_file(tmp_path):
    src = tmp_path / "invariants.md"
    src.write_text("only the owner may withdraw their balance\n", encoding="utf-8")
    res = scaffold(_target(tmp_path), tmp_path / "work", invariants=src)
    inv = res.workspace / "inventory" / "_invariants.md"
    assert inv.read_text() == "only the owner may withdraw their balance\n"
    assert "seeded" in res.invariants_note


def test_scaffold_import_does_not_clobber_an_edited_invariants_file(tmp_path):
    target = _target(tmp_path)
    ws = tmp_path / "work"
    inv = scaffold(target, ws).workspace / "inventory" / "_invariants.md"
    inv.write_text("hand written rule\n", encoding="utf-8")
    src = tmp_path / "other.md"
    src.write_text("imported rule\n", encoding="utf-8")
    res = scaffold(target, ws, invariants=src)
    assert inv.read_text() == "hand written rule\n"
    assert "kept the edited" in res.invariants_note


def test_scaffold_fresh_replaces_invariants_from_the_import(tmp_path):
    target = _target(tmp_path)
    ws = tmp_path / "work"
    inv = scaffold(target, ws).workspace / "inventory" / "_invariants.md"
    inv.write_text("hand written rule\n", encoding="utf-8")
    src = tmp_path / "other.md"
    src.write_text("imported rule\n", encoding="utf-8")
    res = scaffold(target, ws, fresh=True, invariants=src)
    assert res.workspace.joinpath("inventory", "_invariants.md").read_text() == "imported rule\n"
    assert "seeded" in res.invariants_note


def test_scaffold_import_fails_loud_on_a_missing_file(tmp_path):
    with pytest.raises(ValueError, match="invariants file cannot be read"):
        scaffold(_target(tmp_path), tmp_path / "work", invariants=tmp_path / "nope.md")


def test_scaffold_flags_candidate_entrypoint_files(tmp_path):
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
    res = scaffold(_target(tmp_path), tmp_path / "work")
    units = list((res.workspace / "units").glob("*.md"))
    assert units
    body = (res.workspace / "units" / "app.md").read_text()
    assert "- Status: open" in body
    assert "app.py" in body
    assert "trace" in body.lower()
    assert "_severity.md" in body


def test_scaffold_splits_a_large_candidate_into_slice_units(tmp_path):
    # a large entrypoint file is seeded as several slice units at construct boundaries, so a
    # sub-review focuses on a few handlers instead of diluting across the whole file
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
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Agent Methodology" in res.methodology
    assert "Why Fan Out" in res.methodology
    for phase in ("Map the Attack Surface", "Fan Out", "Aggregate"):
        assert phase in res.methodology
    assert "Status: reviewed" in res.methodology


def test_methodology_accumulates_across_runs(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "Accumulate Across Runs" in res.methodology
    assert "Status: reviewed" in res.methodology


_VAULT_SOL = """\
// SPDX-License-Identifier: MIT
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
    """A stand-in facts backend that counts extractions, so a test can assert the cache
    spared a second extraction without needing a real toolchain."""

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
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    assert (res.workspace / "_facts.md").read_text().startswith("contract Fake")
    assert backend.calls == 1


def test_scaffold_leaves_a_domain_with_no_backend_ungrounded(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=replace(WEB, facts_backend=None))
    assert not (res.workspace / "_facts.md").exists()


class _UnavailableBackend(FactsBackend):
    """A facts backend whose toolchain is absent, so the scaffold must degrade, not fail."""

    def available(self) -> bool:
        return False

    def extract(self, root):
        raise AssertionError("extract must not run when the backend is unavailable")


def test_scaffold_fails_loud_when_the_facts_backend_cannot_run(tmp_path):
    from cyberjury.domains.base import BackendUnavailable

    with pytest.raises(BackendUnavailable, match="no grounding"):
        scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(_UnavailableBackend()))


def test_scaffold_persists_the_per_file_facts_map(tmp_path):
    # the engine grounds each unit per file, so the by_file map is persisted as JSON beside
    # the human-readable _facts.md

    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    by_file = json.loads((res.workspace / "_facts_by_file.json").read_text())
    assert by_file["app.py"].startswith("contract Fake")


def test_scaffold_persists_the_call_path_units(tmp_path):

    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    units = json.loads((res.workspace / "_facts_units.json").read_text())
    assert units[0]["name"] == "app.py#Fake.f"
    assert units[0]["fragments"] == [["app.py", 0, 12]]


def test_scaffold_persists_the_call_and_import_graph(tmp_path):
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    graph = json.loads((res.workspace / "_facts_graph.json").read_text())
    assert graph["callgraph"]["app.py"]["f"] == [{"range": [0, 12], "calls": []}]
    assert graph["imports"] == {}


def test_scaffold_drops_call_path_units_packed_from_test_code(tmp_path):
    # a backend may pack a unit from test code, the evm one compiles the whole project, so the
    # units are filtered against the same test paths the candidate selection excludes

    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", domain=_facts_domain(backend))
    units = json.loads((res.workspace / "_facts_units.json").read_text())
    assert not any("tests/" in f[0] for u in units for f in u["fragments"])


def test_scaffold_reuses_the_cached_per_file_facts_map(tmp_path):

    backend = _CountingBackend()
    dom = _facts_domain(backend)
    work = tmp_path / "work"
    scaffold(_target(tmp_path), work, domain=dom)
    res = scaffold(_target(tmp_path), work, domain=dom, fresh=True)
    assert backend.calls == 1
    assert json.loads((res.workspace / "_facts_by_file.json").read_text())["app.py"]
    assert json.loads((res.workspace / "_facts_units.json").read_text())[0]["name"] == "app.py#Fake.f"


def test_scaffold_reuses_cached_facts_across_a_fresh_run(tmp_path):
    # a fresh scaffold clears the workspace, but the content hash cache survives, so the extraction
    # runs once for a source tree, not on every re-run
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
    # editing the source changes the content hash, so a stale cache entry is not served
    backend = _CountingBackend()
    dom = _facts_domain(backend)
    work = tmp_path / "work"
    target = _target(tmp_path)
    scaffold(target, work, domain=dom)
    (target / "app.py").write_text(APP + "\n# edit\n")
    scaffold(target, work, domain=dom, fresh=True)
    assert backend.calls == 2


def test_scaffold_persists_facts_for_the_evm_domain(tmp_path):
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
    # the per-file map keys Vault's facts on its source path, so a unit owning that file is
    # grounded with its call graph no matter which slice it reviews

    by_file = json.loads((res.workspace / "_facts_by_file.json").read_text())
    vault_key = next(k for k in by_file if k.endswith("Vault.sol"))
    assert "contract Vault" in by_file[vault_key]
    assert "reenter" in by_file[vault_key]


def test_scaffold_no_candidates_when_nothing_flagged(tmp_path):
    d = tmp_path / "rb"
    d.mkdir()
    (d / "app.rb").write_text("puts 'hello'\n")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert "none flagged" in (res.workspace / "inventory" / "_entrypoints.md").read_text()


def test_scaffold_seeds_stack_guides(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "python" in res.guides
    assert "flask" in res.guides
    assert "app.py" in res.candidate_files
    stack = (res.workspace / "_stack.md").read_text().lower()
    assert "python" in stack
    assert "flask" in stack


def test_scaffold_seeds_vulnerability_classes(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    vulns = res.workspace / "_vulnerabilities.md"
    assert vulns.is_file()
    text = vulns.read_text()
    assert "Vulnerability Classes" in text
    assert text.count("\n---\n") >= 5


def test_scaffold_flags_a_prior_run(tmp_path):
    ws_root = tmp_path / "work"
    first = scaffold(_target(tmp_path), ws_root)
    assert first.had_prior_run is False
    (first.workspace / "candidates" / "found.md").write_text("# a finding\n")
    second = scaffold(_target(tmp_path), ws_root)
    assert second.had_prior_run is True
    assert second.cleared == []
    assert (second.workspace / "candidates" / "found.md").is_file()


def test_scaffold_fresh_clears_prior_output(tmp_path):
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
    # the workspace holds the auth model, exploit paths, and PoCs, so it must not be
    # world-readable on a shared host
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert stat.S_IMODE(res.workspace.stat().st_mode) == 0o700


def test_fresh_refuses_to_clear_an_unmarked_directory(tmp_path):
    ws_root = tmp_path / "work"
    project_ws = ws_root / "myservice"
    project_ws.mkdir(parents=True)
    (project_ws / "important.txt").write_text("not cyberjury data")
    with pytest.raises(ValueError, match=r"no \.cyberjury-workspace marker"):
        scaffold(_target(tmp_path), ws_root, fresh=True)
    assert (project_ws / "important.txt").exists()


def test_scaffold_refuses_a_legacy_issues_layout(tmp_path):
    ws_root = tmp_path / "work"
    project_ws = ws_root / "myservice"
    (project_ws / "issues").mkdir(parents=True)
    (project_ws / "issues" / "found.md").write_text("# a finding\n")
    with pytest.raises(ValueError, match="old issues/ layout"):
        scaffold(_target(tmp_path), ws_root)


def test_plain_repository_still_scaffolds(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "notes.txt").write_text("hi")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert (res.workspace / "inventory" / "_surface.md").is_file()
