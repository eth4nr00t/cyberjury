"""The coded repository run engine is exercised end to end with a mock provider."""

import json

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.repository.engine import (
    _parse_candidate,
    _spans,
    build_units,
    finalize_repository_review,
    run_repository_review,
)
from cyberjury.review.repository.gate import check_gate
from cyberjury.review.repository.paths import WORKSPACE_MARKER
from cyberjury.review.repository.reviewer import ModelReviewer, UnitReviewer
from cyberjury.review.repository.scaffold import unit_slug
from cyberjury.review.repository.shapes import Unit, UnitSourceError, gather
from cyberjury.review.repository.union import Candidate
from cyberjury.review.repository.verifier import RefutationChecker, Verdict, Verifier
from cyberjury.sources.metadata import SourceError

_REPLY = (
    '{"findings": [{"title": "wallet idor", "category": "insecure-direct-object-reference", '
    '"endpoint": "GET /wallets/<wallet_id>", "file": "app/services/wallet.py", "line": 11, '
    '"severity": "HIGH", "evidence": "wallet.py:11 no owner check", "status": "confirmed"}]}'
)


def _mark_workspace(project):
    (project / WORKSPACE_MARKER).write_text(f"{project.name}\n", encoding="utf-8")


def test_with_facts_folds_persisted_facts_and_marks_truncation(tmp_path):
    """With facts folds persisted facts and marks truncation."""
    from cyberjury.review.repository.engine import _FACTS_CONTEXT_CAP, _with_facts

    assert _with_facts("STACK", tmp_path) == "STACK"

    (tmp_path / "_facts.md").write_text("contract V\n  external withdraw()  ext-call", encoding="utf-8")
    folded = _with_facts("STACK", tmp_path)
    assert "STACK" in folded
    assert "Tool-extracted facts:" in folded
    assert "withdraw()" in folded

    (tmp_path / "_facts.md").write_text("x" * (_FACTS_CONTEXT_CAP + 500), encoding="utf-8")
    assert "facts truncated" in _with_facts("STACK", tmp_path)


def _prompt_of(prov):
    return prov.calls[0]["messages"][0].content


def test_reviewer_grounds_a_unit_with_only_its_own_files_facts(tmp_path):
    """Reviewer grounds a unit with only its own files facts."""
    (tmp_path / "V3Vault.sol").write_text("contract V3Vault { }")
    prov = MockProvider(default='{"findings": []}')
    by_file = {
        "V3Vault.sol": "contract V3Vault\n  internal _cleanupLoan()  calls[_updateAndCheckCollateral] ext-call reenter",
        "Swapper.sol": "contract Swapper\n  external swap()  ext-call",
    }
    rev = ModelReviewer(provider=prov, model="mock", facts_by_file=by_file)
    rev.review(Unit(name="V3Vault.sol", root=str(tmp_path), files=("V3Vault.sol",)))
    prompt = _prompt_of(prov)
    assert "_cleanupLoan" in prompt
    assert "reenter" in prompt
    assert "Swapper" not in prompt


def test_reviewer_adds_no_facts_block_without_a_map(tmp_path):
    """Reviewer adds no facts block without a map."""
    (tmp_path / "v.py").write_text("x = 1")
    prov = MockProvider(default='{"findings": []}')
    ModelReviewer(provider=prov, model="mock").review(Unit(name="v.py", root=str(tmp_path), files=("v.py",)))
    assert "Tool-extracted facts for this unit" not in _prompt_of(prov)


def test_reviewer_matches_facts_on_basename_when_the_directory_differs(tmp_path):
    """Reviewer matches facts on basename when the directory differs."""
    (tmp_path / "V3Vault.sol").write_text("contract V3Vault {}")
    prov = MockProvider(default='{"findings": []}')
    rev = ModelReviewer(
        provider=prov, model="mock", facts_by_file={"src/V3Vault.sol": "contract V3Vault\n  reenter-marker"}
    )
    rev.review(Unit(name="x", root=str(tmp_path), files=("V3Vault.sol",)))
    assert "reenter-marker" in _prompt_of(prov)


def test_load_facts_by_file_reads_the_map_drops_empty_and_fails_loud_on_corrupt(tmp_path):
    """Facts by file loading drops empty entries and fails loud on corrupt JSON."""
    from cyberjury.review.repository.engine import _load_facts_by_file

    assert _load_facts_by_file(tmp_path) == {}
    (tmp_path / "_facts_by_file.json").write_text('{"a.sol": "facts A", "b.sol": ""}')
    assert _load_facts_by_file(tmp_path) == {"a.sol": "facts A"}
    (tmp_path / "_facts_by_file.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        _load_facts_by_file(tmp_path)


def test_gather_assembles_call_path_fragments(tmp_path):
    """Gather assembles call path fragments."""
    text = "AAAA\n" + "B\n" * 100 + "CCCC_TWO\n" + "D\n" * 50
    (tmp_path / "V.sol").write_text(text)
    second = text.index("CCCC_TWO")
    u = Unit(
        name="cp", root=str(tmp_path), files=("V.sol",), fragments=(("V.sol", 0, 4), ("V.sol", second, second + 8))
    )
    g = gather(u)
    assert "AAAA" in g
    assert "CCCC_TWO" in g
    assert "B\nB" not in g
    assert "# file: V.sol lines 1-1" in g
    assert "# file: V.sol lines 102-102" in g
    assert "102 | CCCC_TWO" in g


def test_build_units_appends_call_path_units_from_facts(tmp_path):
    """Unit building appends call path units from facts."""
    (tmp_path / "V.sol").write_text("x" * 500)
    specs = [{"name": "V.sol#V.liquidate", "files": ["V.sol"], "fragments": [["V.sol", 10, 50], ["V.sol", 60, 120]]}]
    units = build_units(str(tmp_path), ["V.sol"], [], specs)
    assert "V.sol" in [u.name for u in units]
    cp = [u for u in units if u.fragments]
    assert len(cp) == 1
    assert cp[0].name == "V.sol#V.liquidate"
    assert cp[0].files == ("V.sol",)
    assert cp[0].fragments == (("V.sol", 10, 50), ("V.sol", 60, 120))


def test_build_units_without_facts_units_is_unchanged(tmp_path):
    """Unit building is unchanged when no facts units exist."""
    (tmp_path / "V.sol").write_text("x" * 500)
    units = build_units(str(tmp_path), ["V.sol"], [])
    assert not any(u.fragments for u in units)


def _graph():
    return {
        "callgraph": {
            "web.py": {"run_app": [{"range": [0, 100], "calls": []}]},
            "web_response.py": {
                "StreamResponse": [{"range": [200, 900], "calls": []}],
                "json_response": [{"range": [900, 1000], "calls": []}],
                "unexported": [{"range": [1000, 1100], "calls": []}],
            },
        },
        "imports": {"web.py": ["StreamResponse", "json_response", "run_app"]},
    }


def test_build_units_packs_the_definitions_a_candidate_imports(tmp_path):
    """Unit building packs the definitions a candidate imports."""
    (tmp_path / "web.py").write_text("x" * 100)
    units = build_units(str(tmp_path), ["web.py"], [], None, _graph())
    closure = [u for u in units if u.fragments]
    assert len(closure) == 1
    assert closure[0].name == "web.py->web_response.py"
    assert closure[0].files == ("web_response.py",)
    assert closure[0].fragments == (("web_response.py", 200, 900), ("web_response.py", 900, 1000))


def test_build_units_packs_two_import_hops_from_a_candidate(tmp_path):
    """Unit building packs two import hops from a candidate."""
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [0, 10], "calls": []}]},
            "service.py": {"load": [{"range": [20, 40], "calls": []}]},
            "models.py": {"read_owner": [{"range": [60, 90], "calls": []}]},
        },
        "imports": {"route.py": ["load"], "service.py": ["read_owner"]},
    }
    (tmp_path / "route.py").write_text("x" * 100)
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["route.py->service.py", "route.py->models.py"]
    assert units[0].fragments == (("service.py", 20, 40),)
    assert units[1].fragments == (("models.py", 60, 90),)


def test_build_units_packs_called_definitions_from_imported_target_files(tmp_path):
    """Unit building packs called definitions from imported target files."""
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [0, 10], "calls": ["read_owner"]}]},
            "store.py": {
                "StoreTable": [{"range": [20, 40], "calls": []}],
                "read_owner": [{"range": [60, 90], "calls": []}],
            },
            "other.py": {"read_owner": [{"range": [100, 130], "calls": []}]},
        },
        "imports": {"route.py": ["Store"]},
        "import_targets": {"route.py": ["store.py"]},
    }
    (tmp_path / "route.py").write_text("x" * 100)
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["route.py->store.py"]
    assert units[0].fragments == (("store.py", 60, 90),)


def test_build_units_adds_callsite_windows_for_imported_target_calls(tmp_path):
    """Import-target units include a small caller window for reachability context."""
    route = "\n".join(
        [
            "def helper():",
            "    pass",
            "",
            "def handle(user_id):",
            "    if not current_user:",
            "        raise Exception()",
            "    return read_owner(user_id)",
            "",
            "def unrelated():",
            "    pass",
        ]
    )
    store = "x" * 100
    (tmp_path / "route.py").write_text(route)
    (tmp_path / "store.py").write_text(store)
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [20, 140], "calls": ["read_owner"]}]},
            "store.py": {"read_owner": [{"range": [60, 90], "calls": []}]},
        },
        "imports": {"route.py": ["Store"]},
        "import_targets": {"route.py": ["store.py"]},
    }
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert units[0].files == ("route.py", "store.py")
    assert units[0].fragments[-1] == ("store.py", 60, 90)
    assert "read_owner(user_id)" in gather(units[0])


def test_build_units_stops_import_closure_after_two_hops(tmp_path):
    """Unit building stops import closure after two hops."""
    graph = {
        "callgraph": {
            "service.py": {"load": [{"range": [0, 10], "calls": []}]},
            "models.py": {"read_owner": [{"range": [20, 40], "calls": []}]},
            "driver.py": {"query": [{"range": [60, 90], "calls": []}]},
        },
        "imports": {"route.py": ["load"], "service.py": ["read_owner"], "models.py": ["query"]},
    }
    (tmp_path / "route.py").write_text("x" * 100)
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["route.py->service.py", "route.py->models.py"]


def test_build_units_does_not_repack_the_candidate_on_an_import_cycle(tmp_path):
    """Unit building does not repack the candidate on an import cycle."""
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [0, 10], "calls": []}]},
            "service.py": {"load": [{"range": [20, 40], "calls": []}]},
        },
        "imports": {"route.py": ["load"], "service.py": ["handle"]},
    }
    (tmp_path / "route.py").write_text("x" * 100)
    units = [u for u in build_units(str(tmp_path), ["route.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["route.py->service.py"]


def test_build_units_leaves_out_a_definition_the_candidate_does_not_import(tmp_path):
    """Unit building leaves out definitions the candidate does not import."""
    (tmp_path / "web.py").write_text("x" * 100)
    units = build_units(str(tmp_path), ["web.py"], [], None, _graph())
    packed = {f for u in units if u.fragments for f in u.fragments}
    assert ("web_response.py", 1000, 1100) not in packed


def test_build_units_leaves_out_a_definition_in_the_candidate_itself(tmp_path):
    """Unit building leaves out definitions in the candidate itself."""
    graph = _graph()
    assert "run_app" in graph["imports"]["web.py"]
    assert "run_app" in graph["callgraph"]["web.py"]
    (tmp_path / "web.py").write_text("x" * 100)
    units = build_units(str(tmp_path), ["web.py"], [], None, graph)
    assert all("web.py" not in u.files for u in units if u.fragments)


def test_build_units_cuts_an_import_closure_too_large_for_one_call(tmp_path):
    """Unit building splits an import closure too large for one call."""
    from cyberjury.review.repository.engine import _IMPORT_UNIT_CHARS

    big = _IMPORT_UNIT_CHARS
    graph = {
        "callgraph": {"m.py": {f"f{i}": [{"range": [i * big, (i + 1) * big], "calls": []}] for i in range(3)}},
        "imports": {"a.py": ["f0", "f1", "f2"]},
    }
    (tmp_path / "a.py").write_text("x" * 100)
    units = [u for u in build_units(str(tmp_path), ["a.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["a.py->m.py#1", "a.py->m.py#2", "a.py->m.py#3"]


def test_build_units_windows_one_definition_larger_than_the_cap(tmp_path):
    """Unit building windows one definition larger than the cap."""
    from cyberjury.review.repository.engine import _IMPORT_UNIT_CHARS

    body = "class Big {\n" + "  const x = 1;\n" * 6000 + "}\n"
    (tmp_path / "m.ts").write_text(body)
    (tmp_path / "a.ts").write_text("x" * 100)
    graph = {
        "callgraph": {"m.ts": {"Big": [{"range": [0, len(body)], "calls": []}]}},
        "imports": {"a.ts": ["Big"]},
    }
    units = [u for u in build_units(str(tmp_path), ["a.ts"], [], None, graph) if u.fragments]
    assert len(units) > 1
    for u in units:
        assert sum(e - s for _f, s, e in u.fragments) <= _IMPORT_UNIT_CHARS
    covered = sorted((s, e) for u in units for _f, s, e in u.fragments)
    assert covered[0][0] == 0
    assert covered[-1][1] == len(body)


def test_build_units_keeps_an_oversized_fragment_whose_file_cannot_be_read(tmp_path):
    """Unit building keeps an oversized fragment whose file cannot be read."""
    from cyberjury.review.repository.engine import _IMPORT_UNIT_CHARS

    over = _IMPORT_UNIT_CHARS + 1
    graph = {
        "callgraph": {"gone.py": {"big": [{"range": [0, over], "calls": []}]}},
        "imports": {"a.py": ["big"]},
    }
    (tmp_path / "a.py").write_text("x" * 100)
    units = [u for u in build_units(str(tmp_path), ["a.py"], [], None, graph) if u.fragments]
    assert [u.fragments for u in units] == [(("gone.py", 0, over),)]


def test_build_units_reviews_a_closure_two_candidates_share_only_once(tmp_path):
    """Unit building reviews a closure shared by two candidates only once."""
    graph = {
        "callgraph": {"m.py": {"shared": [{"range": [0, 10], "calls": []}]}},
        "imports": {"a.py": ["shared"], "b.py": ["shared"]},
    }
    (tmp_path / "a.py").write_text("x" * 100)
    (tmp_path / "b.py").write_text("x" * 100)
    units = [u for u in build_units(str(tmp_path), ["a.py", "b.py"], [], None, graph) if u.fragments]
    assert len(units) == 1


def test_build_units_keeps_shared_callee_units_when_callsite_context_differs(tmp_path):
    """Shared callees keep separate units when each entrypoint adds caller context."""
    graph = {
        "callgraph": {
            "a.py": {"a": [{"range": [0, 40], "calls": ["shared"]}]},
            "b.py": {"b": [{"range": [0, 40], "calls": ["shared"]}]},
            "m.py": {"shared": [{"range": [0, 10], "calls": []}]},
        },
        "imports": {"a.py": ["shared"], "b.py": ["shared"]},
        "import_targets": {"a.py": ["m.py"], "b.py": ["m.py"]},
    }
    (tmp_path / "a.py").write_text("def a():\n    return shared('a')\n")
    (tmp_path / "b.py").write_text("def b():\n    return shared('b')\n")
    (tmp_path / "m.py").write_text("x" * 100)
    units = [u for u in build_units(str(tmp_path), ["a.py", "b.py"], [], None, graph) if u.fragments]
    assert [u.name for u in units] == ["a.py->m.py", "b.py->m.py"]
    assert [u.files for u in units] == [("a.py", "m.py"), ("b.py", "m.py")]


def test_build_units_without_a_facts_graph_is_unchanged(tmp_path):
    """Unit building is unchanged without a facts graph."""
    (tmp_path / "web.py").write_text("x" * 100)
    assert not any(u.fragments for u in build_units(str(tmp_path), ["web.py"], []))


def test_load_facts_graph_reads_the_graph_empty_and_fails_loud_on_corrupt(tmp_path):
    """Facts graph loading accepts missing data and fails loud on corrupt JSON."""
    from cyberjury.review.repository.engine import _load_facts_graph

    assert _load_facts_graph(tmp_path) == {}
    (tmp_path / "_facts_graph.json").write_text('{"imports": {"a.py": ["f"]}}')
    assert _load_facts_graph(tmp_path)["imports"] == {"a.py": ["f"]}
    (tmp_path / "_facts_graph.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        _load_facts_graph(tmp_path)


def test_load_facts_units_reads_specs_empty_and_fails_loud_on_corrupt(tmp_path):
    """Load facts units reads specs empty and fails loud on corrupt JSON."""
    from cyberjury.review.repository.engine import _load_facts_units

    assert _load_facts_units(tmp_path) == []
    (tmp_path / "_facts_units.json").write_text('[{"name": "u", "files": ["a.sol"], "fragments": [["a.sol", 0, 10]]}]')
    assert _load_facts_units(tmp_path)[0]["name"] == "u"
    (tmp_path / "_facts_units.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        _load_facts_units(tmp_path)


def test_build_units_groups_trace_targets_by_package():
    """Unit building groups trace targets by package."""
    units = build_units(
        "/root",
        ["accounts/views/api.py", "authorization/views/web.py"],
        ["accounts/managers/m.py", "authorization/dao/d.py"],
    )
    units_by_name = {u.name: u for u in units}
    assert "accounts/managers/m.py" in units_by_name["accounts/views/api.py"].files
    assert "authorization/dao/d.py" not in units_by_name["accounts/views/api.py"].files


def test_build_units_splits_a_large_file_into_overlapping_windows(tmp_path):
    """Unit building splits a large file into overlapping windows."""
    (tmp_path / "views.py").write_text("x" * 60_000)
    units = build_units(str(tmp_path), ["views.py"], [])
    assert [u.name for u in units] == ["views.py#1", "views.py#2", "views.py#3"]
    assert units[0].span[0] == 0
    assert units[1].span[0] < units[0].span[1]
    assert units[-1].span[1] == 60_000


def test_spans_snaps_a_window_to_a_top_level_construct_boundary():
    """Spans snaps a window to a top level construct boundary."""
    a = "def f():\n" + "    x = 1\n" * 2000
    text = a + "def g():\n" + "    y = 2\n" * 2000
    spans = _spans(text)
    assert spans[0][0] == 0
    assert text[spans[0][1] :].startswith("def g")


def test_build_units_keeps_a_small_file_whole(tmp_path):
    """Unit building keeps a small file whole."""
    (tmp_path / "v.py").write_text("x" * 1_000)
    units = build_units(str(tmp_path), ["v.py"], [])
    assert [u.name for u in units] == ["v.py"]
    assert units[0].span is None


def test_gather_reads_only_the_span_window_of_a_chunked_unit(tmp_path):
    """Gather reads only the span window of a chunked unit."""
    (tmp_path / "big.py").write_text("AAAA" + "B" * 30_000 + "ZZZZ")
    tail = gather(Unit(name="big.py#2", root=str(tmp_path), files=("big.py",), span=(30_000, 30_008)))
    assert "ZZZZ" in tail
    assert "AAAA" not in tail


def test_gather_numbers_a_span_window_from_its_real_first_line(tmp_path):
    """Gather numbers a span window from its real first line."""
    text = "".join(f"line{i}\n" for i in range(1, 501))
    (tmp_path / "big.py").write_text(text)
    start = text.index("line300")
    g = gather(Unit(name="big.py#2", root=str(tmp_path), files=("big.py",), span=(start, start + 8)))
    assert "300 | line300" in g
    assert "# file: big.py lines 300-300" in g


def test_gather_budget_counts_source_not_the_line_number_prefixes(tmp_path):
    """Gather budget counts source not the line number prefixes."""
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text("x\n" * 20_000)
    g = gather(Unit(name="u", root=str(tmp_path), files=("a.py", "b.py", "c.py")))
    assert g.count("# file: ") == 3


def test_gather_fails_when_a_unit_source_file_is_missing(tmp_path):
    """Gather fails when a unit source file is missing."""
    with pytest.raises(UnitSourceError, match=r"missing\.py"):
        gather(Unit(name="u", root=str(tmp_path), files=("missing.py",)))


def test_run_converges_writes_findings_and_marks_units(custody_repository, tmp_path):
    """Run converges writes findings and marks units."""
    prov = MockProvider(default=_REPLY)
    res = run_repository_review(
        custody_repository, tmp_path / "ws", provider=prov, model="mock", converge_after=2, max_passes=12
    )
    ws = res.scaffold.workspace

    assert res.accumulator.converged
    assert len(res.accumulator.findings) == 1

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
    assert status["converged"] is True
    assert status["complete"] is True
    assert status["errors"] == 0
    assert status["units_reviewed"] == status["units_total"] == len(units)
    assert status["failed_units"] == []


def test_run_writes_pocs_when_a_backend_is_bound(custody_repository, tmp_path):
    """Run writes PoCs when a backend is bound."""

    class WritePoC:
        executes = False
        ext = "py"

        def available(self):
            return False

        def generate(self, **kw):
            return type("Artifact", (), {"source": "import requests\n", "run_hint": "python poc.py", "note": ""})()

    res = run_repository_review(
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


class _CountingReviewer(UnitReviewer):
    def __init__(self):
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        return [
            Candidate(
                title="wallet idor",
                category="idor",
                endpoint="GET /wallets/<id>",
                file="app/services/wallet.py",
                severity="HIGH",
            )
        ]


class _CountingVerifier(Verifier):
    def __init__(self):
        self.calls = 0

    def verify(self, candidate, root):
        self.calls += 1
        return Verdict(real=True)


def test_resume_skips_reviewed_units_and_verified_findings(custody_repository, tmp_path):
    """Resume skips reviewed units and verified findings."""
    ws = tmp_path / "ws"
    r1v = _CountingVerifier()
    run_repository_review(
        custody_repository, ws, reviewer=_CountingReviewer(), verifier=r1v, converge_after=1, max_passes=4
    )
    findings_after_1 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert findings_after_1
    assert r1v.calls >= 1

    r2 = _CountingReviewer()
    r2v = _CountingVerifier()
    run_repository_review(
        custody_repository, ws, reviewer=r2, verifier=r2v, converge_after=1, max_passes=4, fresh=False
    )
    assert r2.calls == 0
    assert r2v.calls == 0
    findings_after_2 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert {f["entry"] for f in findings_after_2} == {f["entry"] for f in findings_after_1}


def test_resume_with_reviewed_units_but_missing_union_fails_loud(custody_repository, tmp_path):
    """Resume with reviewed units but missing union fails loud."""
    ws = tmp_path / "ws"
    run_repository_review(
        custody_repository,
        ws,
        reviewer=_CountingReviewer(),
        verifier=_CountingVerifier(),
        converge_after=1,
        max_passes=4,
    )
    (ws / "custody" / "_union.json").unlink()
    with pytest.raises(ValueError, match=r"no _union\.json"):
        run_repository_review(
            custody_repository,
            ws,
            reviewer=_CountingReviewer(),
            verifier=_CountingVerifier(),
            converge_after=1,
            max_passes=4,
            fresh=False,
        )


def test_parse_candidate_captures_file_and_line_from_a_range(tmp_path):
    """Parse candidate captures file and line from a range."""
    p = tmp_path / "i.md"
    p.write_text(
        "# freshness gap\n- Risk: HIGH\n- Type: replay\n- Source: `POST /v1/check`\n"
        "## Analysis\n`authorizer/controllers/registrar.py:58-75` no nonce.\n"
    )
    c = _parse_candidate(p)
    assert c.file == "authorizer/controllers/registrar.py"
    assert c.line == 58
    assert c.severity == "HIGH"


def test_parse_candidate_strips_a_finding_title_prefix(tmp_path):
    """Parse candidate strips a finding title prefix."""
    p = tmp_path / "i.md"
    p.write_text(
        "# Finding: Signing Key Committed to Source\n- Risk: LOW\n- Type: secret\n"
        "- Source: `GET /v1/key`\n## Analysis\n`app/keys.py:3` hardcoded.\n"
    )
    c = _parse_candidate(p)
    assert c.title == "Signing Key Committed to Source"


def test_parse_candidate_drops_an_out_of_root_cited_path(tmp_path):
    """Parse candidate drops an out of root cited path."""
    traversing = tmp_path / "t.md"
    traversing.write_text("# leak\n- Risk: HIGH\n- Type: idor\n## Analysis\nsee `../../etc/secret.py:1` for the key.\n")
    assert _parse_candidate(traversing) is None
    absolute = tmp_path / "a.md"
    absolute.write_text("# leak\n- Risk: HIGH\n- Type: idor\n## Analysis\nsee `/home/user/secret.py:1` for the key.\n")
    assert _parse_candidate(absolute) is None


def test_parse_candidate_drops_a_cleared_or_refuted_record(tmp_path):
    """Parse candidate drops a cleared or refuted record."""
    refuted = tmp_path / "r.md"
    refuted.write_text(
        "# Attachment IDOR, refuted\n- Status: refuted (no finding)\n- Type: idor\n"
        "## Why\n`pkg/models/task_attachment.go:111` xorm scopes the fetch.\n"
    )
    assert _parse_candidate(refuted) is None
    cleared = tmp_path / "c.md"
    cleared.write_text(
        "# Permission methods cleared\n- Status: cleared\n- Type: idor\n"
        "## Scope\n`pkg/models/task_attachment_permissions.go:25` holds.\n"
    )
    assert _parse_candidate(cleared) is None
    titled = tmp_path / "t.md"
    titled.write_text(
        "# Cleared controls and paths checked\n- Type:\n"
        "## Blacklist gate\n`pkg/models/token.go:82` adminSanity enforces it.\n"
    )
    assert _parse_candidate(titled) is None
    confirmed = tmp_path / "k.md"
    confirmed.write_text(
        "# real leak\n- Status: confirmed\n- Type: idor\n## Analysis\n`pkg/models/link_sharing.go:272` leaks hashes.\n"
    )
    assert _parse_candidate(confirmed) is not None


def test_finalize_dedups_verifies_and_reports(tmp_path):
    """Finalize dedups verifies and reports."""
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (candidates / "a2.md").write_text(
        "# idor again\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/{id}`\n## Analysis\napp/v.py:10\n"
    )
    (candidates / "b.md").write_text(
        "# replay\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n## Analysis\napp/s.py:5\n"
    )
    (candidates / "fp.md").write_text(
        "# race fp\n- Risk: HIGH\n- Type: race\n- Source: `POST /r`\n## Analysis\napp/d.py:3\n"
    )

    class _V(Verifier):
        def verify(self, c, root):
            bad = "/r" in c.endpoint
            return Verdict(real=not bad, reason="lock holds on prod" if bad else "")

    class _C(RefutationChecker):
        def holds(self, c, reason, root):
            return "/r" in c.endpoint

    fr = finalize_repository_review(target, ws, verifier=_V(), confirmers=[("", _C())], concurrency=1)
    assert fr.parsed == 4
    assert fr.deduped == 3
    assert len(fr.verify.confirmed) == 2
    assert len(fr.verify.refuted) == 1
    data = json.loads((fr.workspace / "findings.json").read_text())
    entries = {f["entry"] for f in data["findings"]}
    assert any("/x/" in e for e in entries)
    assert any("/t" in e for e in entries)
    assert not any("/r" in e for e in entries)


def test_finalize_records_its_completeness_and_spend_so_a_later_gate_can_read_them(tmp_path):
    """Finalize records its completeness and spend so a later gate can read them."""
    from cyberjury.providers.metering import MeteringProvider, UsageMeter

    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (candidates / "b.md").write_text(
        "# race fp\n- Risk: HIGH\n- Type: race\n- Source: `POST /r`\n## Analysis\napp/d.py:3\n"
    )

    class _V(Verifier):
        def verify(self, c, root):
            bad = "/r" in c.endpoint
            return Verdict(real=not bad, reason="lock holds on prod" if bad else "")

    class _C(RefutationChecker):
        def holds(self, c, reason, root):
            return "/r" in c.endpoint

    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default='{"findings": []}'), meter)
    fr = finalize_repository_review(
        target, ws, verifier=_V(), confirmers=[("", _C())], concurrency=1, provider=provider, meter=meter
    )
    status = json.loads((fr.workspace / "_finalize.json").read_text())
    assert status["parsed"] == 2
    assert status["deduped"] == 2
    assert status["confirmed"] == 1
    assert status["refuted"] == 1
    assert status["verify_errors"] == 0
    assert status["incomplete"] == 0
    assert status["unlocatable"] == 0
    assert status["usage"] == meter.snapshot()


def test_finalize_without_a_meter_records_completeness_and_omits_usage(tmp_path):
    """Finalize without a meter records completeness and omits usage."""
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    fr = finalize_repository_review(target, ws, verify=False)
    status = json.loads((fr.workspace / "_finalize.json").read_text())
    assert status["deduped"] == 1
    assert "usage" not in status
    assert "confirmed" not in status


def test_finalize_requires_a_scaffolded_workspace(tmp_path):
    """Finalize requires a scaffolded workspace."""
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"

    with pytest.raises(ValueError, match="Run --scaffold or --run"):
        finalize_repository_review(target, ws, verify=False)


def test_finalize_falls_back_to_the_union_when_no_workspace_candidates(tmp_path):
    """Finalize falls back to the union when no workspace candidates."""
    from cyberjury.review.repository.engine import _save_union

    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    project = ws / "proj"
    (project / "candidates").mkdir(parents=True)
    _mark_workspace(project)
    _save_union(project, [Candidate(title="idor read", category="idor", file="app/v.py", line=10)])

    fr = finalize_repository_review(target, ws, verifier=_AllReal(), confirmers=[], concurrency=1)
    assert fr.parsed == 1
    assert len(fr.verify.confirmed) == 1
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert len(data["findings"]) == 1


class _AllReal(Verifier):
    def verify(self, c, root):
        return Verdict(real=True, reason="")


def _finalize_ws(tmp_path):
    target = tmp_path / "proj"
    (target / "app").mkdir(parents=True)
    for name in ("v.py", "s.py", "d.py"):
        (target / "app" / name).write_text("x = 1\n")
    ws = tmp_path / "work"
    candidates = ws / "proj" / "candidates"
    candidates.mkdir(parents=True)
    _mark_workspace(ws / "proj")
    return target, ws, candidates


def _seed_one_candidate(target, ws):
    candidates = ws / target.name / "candidates"
    candidates.mkdir(parents=True)
    _mark_workspace(ws / target.name)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )


def test_finalize_adds_target_metadata_without_changing_findings(tmp_path):
    """Finalize adds target metadata without changing findings."""
    meta = {
        "chain": "bsc",
        "chain_id": 56,
        "address": "0x" + "ab" * 20,
        "source_url": "https://bscscan.com/address/x#code",
        "contract_name": "Token",
    }

    plain_t = tmp_path / "plain"
    plain_t.mkdir()
    plain_ws = tmp_path / "plain_ws"
    _seed_one_candidate(plain_t, plain_ws)
    plain = finalize_repository_review(plain_t, plain_ws, verifier=_AllReal(), confirmers=[], concurrency=1)
    plain_report = json.loads((plain.workspace / "findings.json").read_text())

    meta_t = tmp_path / "meta"
    meta_t.mkdir()
    (meta_t / "cyberjury-source.json").write_text(json.dumps(meta))
    meta_ws = tmp_path / "meta_ws"
    _seed_one_candidate(meta_t, meta_ws)
    withmeta = finalize_repository_review(meta_t, meta_ws, verifier=_AllReal(), confirmers=[], concurrency=1)
    meta_report = json.loads((withmeta.workspace / "findings.json").read_text())

    assert meta_report["findings"] == plain_report["findings"]
    assert "target" not in plain_report
    assert meta_report["target"]["chain"] == "bsc"
    assert (withmeta.workspace / "_target.md").read_text().startswith("## Target")
    assert not (plain.workspace / "_target.md").exists()


def test_finalize_fails_loud_on_malformed_source_metadata(tmp_path):
    """Finalize fails loud on malformed source metadata."""
    target = tmp_path / "proj"
    target.mkdir()
    (target / "cyberjury-source.json").write_text("{not valid json")
    ws = tmp_path / "work"
    _seed_one_candidate(target, ws)
    with pytest.raises(SourceError, match="malformed"):
        finalize_repository_review(target, ws, verifier=_AllReal(), confirmers=[], concurrency=1)


class _RaisingReviewer(UnitReviewer):
    """Raises for marked units and reviews the rest cleanly."""

    def __init__(self, fail_substr):
        self.fail_substr = fail_substr

    def review(self, unit, *, shared_context=""):
        if self.fail_substr in unit.name:
            raise RuntimeError("provider rate limited")
        return [
            Candidate(
                title="ok", category="idor", endpoint=f"GET /{unit.name}", file=unit.name, line=1, severity="HIGH"
            )
        ]


def _two_entrypoint_repository(root):
    for pkg in ("alpha", "beta"):
        (root / pkg).mkdir(parents=True)
        (root / pkg / "routes.py").write_text(
            "from flask import Flask, request\napp = Flask(__name__)\n"
            f'@app.route("/{pkg}/<x>")\ndef h_{pkg}(x):\n    return request.args.get("y", "")\n'
        )
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def test_failed_unit_stays_open_and_fails_the_gate(tmp_path):
    """Failed unit stays open and fails the gate."""
    repository = _two_entrypoint_repository(tmp_path / "twop")
    ws = tmp_path / "ws"
    res = run_repository_review(
        repository, ws, reviewer=_RaisingReviewer("beta"), verify=False, converge_after=1, max_passes=4
    )
    proj = ws / "twop"

    assert "beta/routes.py" in res.accumulator.failed_units
    assert res.accumulator.errors > 0

    units = {u.stem: u.read_text() for u in (proj / "units").glob("*.md")}
    assert "Status: open" in units[unit_slug("beta/routes.py")]
    assert "Status: reviewed" in units[unit_slug("alpha/routes.py")]

    surface = (proj / "inventory" / "_surface.md").read_text()
    beta_row = next(line for line in surface.splitlines() if "beta/routes.py" in line)
    assert "open" in beta_row
    assert "reviewed" not in beta_row

    status = json.loads((proj / "_run.json").read_text())
    assert status["complete"] is False
    assert status["state"] == "incomplete"
    assert status["unit_failures"][0]["paths"] == ["beta/routes.py"]
    assert status["unit_failures"][0]["reason"] == "RuntimeError: provider rate limited"

    assert check_gate(proj).passed is False


def test_corrupt_union_on_resume_raises_loud_and_keeps_report(custody_repository, tmp_path):
    """Corrupt union on resume raises loud and keeps report."""
    ws = tmp_path / "ws"
    run_repository_review(
        custody_repository,
        ws,
        reviewer=_CountingReviewer(),
        verifier=_CountingVerifier(),
        converge_after=1,
        max_passes=4,
    )
    proj = ws / "custody"
    before = (proj / "findings.json").read_text()

    (proj / "_union.json").write_text("{ this is not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        run_repository_review(
            custody_repository,
            ws,
            reviewer=_CountingReviewer(),
            verifier=_CountingVerifier(),
            converge_after=1,
            max_passes=4,
            fresh=False,
        )
    assert (proj / "findings.json").read_text() == before


def test_corrupt_verified_on_finalize_raises_loud(tmp_path):
    """Corrupt verified on finalize raises loud."""
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "a.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (ws / "proj" / "_verified.json").write_text("{corrupt", encoding="utf-8")

    class _V(Verifier):
        def verify(self, c, root):
            return Verdict(real=True)

    with pytest.raises(ValueError, match="corrupt"):
        finalize_repository_review(target, ws, verifier=_V(), concurrency=1)


def test_failed_verification_is_kept_for_the_run_but_not_frozen_for_resume(tmp_path):
    """Failed verification is kept for the run but not frozen for resume."""
    from cyberjury.review.repository.engine import apply_verification

    class _Boom(Verifier):
        def verify(self, c, root):
            raise RuntimeError("rate limited")

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    findings = [Candidate(title="boom", endpoint="GET /a", file="a.py", line=1)]
    confirmed, vr = apply_verification(
        ws, findings, root=str(tmp_path), verifier=_Boom(), provider=None, model="m", votes=1, concurrency=1, fresh=True
    )
    assert [c.title for c in confirmed] == ["boom"]
    assert vr.errors >= 1
    assert json.loads((ws / "_verified.json").read_text()) == {}
    assert [c.title for c in vr.incomplete] == ["boom"]


def test_multi_source_finding_still_runs_verification(tmp_path):
    """Multi source finding still runs verification."""
    from cyberjury.review.repository.engine import apply_verification

    class _Refute(Verifier):
        def __init__(self):
            self.calls = 0

        def verify(self, c, root):
            self.calls += 1
            return Verdict(real=False, reason="guard at a.py:1")

    class _Confirm(RefutationChecker):
        def holds(self, candidate, reason, root):
            return True

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    verifier = _Refute()
    findings = [Candidate(title="fp", endpoint="GET /a", file="a.py", line=1, found_by=("claude", "gpt"))]
    confirmed, vr = apply_verification(
        ws,
        findings,
        root=str(tmp_path),
        verifier=verifier,
        confirmers=[("judge", _Confirm())],
        provider=None,
        model="m",
        votes=1,
        concurrency=1,
        fresh=True,
    )
    assert verifier.calls == 1
    assert confirmed == []
    assert [c.title for c, _reason in vr.refuted] == ["fp"]


def test_a_location_matching_no_file_is_kept_unverified_and_left_unfrozen(tmp_path):
    """Location matching no file is kept unverified and left unfrozen."""
    from cyberjury.review.repository.engine import apply_verification

    class _NeverCalled(Verifier):
        def verify(self, c, root):
            raise AssertionError("a location matching no file must never reach the skeptic")

    ws = tmp_path / "ws"
    ws.mkdir()
    findings = [Candidate(title="ghost", endpoint="GET /a", file="gone.py", line=1)]
    confirmed, vr = apply_verification(
        ws,
        findings,
        root=str(tmp_path),
        verifier=_NeverCalled(),
        provider=None,
        model="m",
        votes=1,
        concurrency=1,
        fresh=True,
    )
    assert [c.title for c in confirmed] == ["ghost"]
    assert [c.title for c in vr.unlocatable] == ["ghost"]
    assert not vr.refuted
    assert json.loads((ws / "_verified.json").read_text()) == {}


def test_finalize_drops_issue_with_no_file_location(tmp_path):
    """Finalize drops issue with no file location."""
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "noloc.md").write_text(
        "# missing location\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n"
        "## Analysis\nno concrete location was cited.\n"
    )
    fr = finalize_repository_review(target, ws, verify=False)
    assert fr.parsed == 0
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert data["findings"] == []


def test_finalize_preserves_blocked_status(tmp_path):
    """Finalize preserves blocked status."""
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "blocked.md").write_text(
        "# needs poc\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n- Status: blocked\n"
        "## Analysis\napp/s.py:5 no nonce, a PoC needs credentials.\n"
    )
    fr = finalize_repository_review(target, ws, verify=False)
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert len(data["findings"]) == 1
    assert data["findings"][0]["status"] == "blocked"


def test_parse_candidate_accepts_data_driven_extensions(tmp_path):
    """Parse candidate accepts data driven extensions."""
    go = tmp_path / "go.md"
    go.write_text(
        "# go handler idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x`\n"
        "- Status: confirmed\n## Analysis\nsrc/handler.go:42 no owner check\n"
    )
    c = _parse_candidate(go)
    assert c is not None
    assert c.file == "src/handler.go"
    assert c.line == 42

    tsx = tmp_path / "tsx.md"
    tsx.write_text(
        "# react xss\n- Risk: MEDIUM\n- Type: xss\n- Source: `x`\n"
        "- Status: confirmed\n## Analysis\nweb/App.tsx:10 dangerouslySetInnerHTML\n"
    )
    c2 = _parse_candidate(tsx)
    assert c2 is not None
    assert c2.file == "web/App.tsx"
    assert c2.line == 10


def test_run_fails_loud_on_zero_units(tmp_path):
    """Run fails loud on zero units."""
    repository = tmp_path / "empty"
    repository.mkdir()
    (repository / "README.md").write_text("nothing to review here\n")
    with pytest.raises(ValueError, match="no candidate entrypoints"):
        run_repository_review(repository, tmp_path / "ws")


def test_write_findings_owns_findings_dir_and_never_touches_candidates(tmp_path):
    """Write findings owns findings dir and never touches candidates."""
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
    """Write findings keeps two findings that share an endpoint."""
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
    """Write findings dedupes near repeat evidence only in outputs."""
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


def test_shared_context_feeds_the_finder_the_phase1_inventory(tmp_path):
    """Shared context feeds the finder the phase1 inventory."""
    from cyberjury.review.repository.engine import _shared_context
    from cyberjury.review.repository.scaffold import scaffold

    target = tmp_path / "app"
    target.mkdir()
    (target / "urls.py").write_text("urlpatterns = []\n", encoding="utf-8")
    res = scaffold(target, tmp_path / "work")
    ws = res.workspace
    ctx = _shared_context(ws)
    assert "## Stack" in ctx
    assert "## Vulnerability classes" in ctx
    assert "## False-positive traps" in ctx
    assert "## Authorization model" not in ctx


def test_git_blame_owner_annotates_a_committed_line_and_is_fail_soft(tmp_path):
    """Git blame owner annotates a committed line and is fail soft."""
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
    """Write findings skips blame for a promisor clone."""
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


def test_poc_for_matches_a_multi_suffix_extension(tmp_path):
    """PoC for matches a multi suffix extension."""
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
    """Finalize links PoCs and reconciles."""
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

    finalize_repository_review(target, ws, verify=False)
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
    """Run PoCs writes the PoC annotates and never drops."""
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
        def available(self):
            return True

        def reproduce(self, **kw):
            return SimpleNamespace(reproduced=True, test_source="contract T {}", detail="passed")

    out = _run_pocs(ws, findings, FakeBackend(), root=str(tmp_path))
    assert len(out) == 1
    assert (ws / "pocs" / f"{_finding_name(findings[0])}.t.sol").read_text() == "contract T {}"
    assert "PoC reproduced" in out[0].evidence


def test_run_pocs_keeps_finding_when_the_poc_fails_or_backend_errors(tmp_path):
    """Run PoCs keeps finding when the PoC fails or backend errors."""
    from cyberjury.review.repository.engine import _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [Candidate(title="x", category="idor", file="A.sol", line=1)]

    class Erroring:
        def available(self):
            return True

        def reproduce(self, **kw):
            raise RuntimeError("model down")

    out = _run_pocs(ws, findings, Erroring(), root=str(tmp_path))
    assert len(out) == 1
    assert "PoC failed to run" in out[0].evidence


def test_run_pocs_degrades_to_write_only_when_an_executing_toolchain_is_absent(tmp_path):
    """Run PoCs degrades to write only when an executing toolchain is absent."""
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _finding_name, _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [Candidate(title="x", category="idor", file="A.sol", line=1, symbol="f", evidence="unchecked")]

    class Unavailable:
        ext = "t.sol"
        install_hint = "install the toolchain from https://example.test"

        def available(self):
            return False

        def reproduce(self, **kw):
            raise AssertionError("must not run when the toolchain is absent")

        def generate(self, **kw):
            return SimpleNamespace(source="contract T {}", ext="t.sol", run_hint="forge test")

    out = _run_pocs(ws, findings, Unavailable(), root=str(tmp_path))
    assert len(out) == 1
    assert (ws / "pocs" / f"{_finding_name(findings[0])}.t.sol").read_text() == "contract T {}"
    assert "not run" in out[0].evidence
    assert "install the toolchain from https://example.test" in out[0].evidence


def test_run_pocs_writes_only_for_a_backend_that_does_not_execute(tmp_path):
    """Run PoCs writes only for a backend that does not execute."""
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _finding_name, _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [
        Candidate(title="idor", category="idor", file="views.py", line=3, symbol="get_order", evidence="no owner check")
    ]

    class WriteOnly:
        executes = False
        ext = "py"

        def available(self):
            return False

        def generate(self, **kw):
            return SimpleNamespace(source="import requests\n", ext="py", run_hint="python it")

    out = _run_pocs(ws, findings, WriteOnly(), root=str(tmp_path))
    assert len(out) == 1
    assert (ws / "pocs" / f"{_finding_name(findings[0])}.py").read_text() == "import requests\n"
    assert "run it manually" in out[0].evidence


def test_run_pocs_folds_a_writer_side_note_into_the_evidence(tmp_path):
    """Run PoCs folds a writer side note into the evidence."""
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [Candidate(title="idor", category="idor", file="v.py", line=3, symbol="g", evidence="no owner check")]

    class WriteOnly:
        executes = False
        ext = "py"

        def available(self):
            return False

        def generate(self, **kw):
            return SimpleNamespace(
                source="def broken(:",
                ext="py",
                run_hint="python it",
                note="PoC does not parse as Python: invalid syntax",
            )

    out = _run_pocs(ws, findings, WriteOnly(), root=str(tmp_path))
    assert "does not parse" in out[0].evidence
    assert len(out) == 1


def test_execute_present_pocs_runs_an_agent_written_poc(tmp_path):
    """Execute present PoCs runs an agent written PoC."""
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

    domain = SimpleNamespace(poc_backend=lambda: Runner())
    out = _execute_present_pocs(ws, [c], domain, root=str(tmp_path))
    assert "PoC reproduced" in out[0].evidence


def test_execute_present_pocs_leaves_a_web_domain_to_reconciliation(tmp_path):
    """Execute present PoCs leaves a web domain to reconciliation."""
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _execute_present_pocs, _finding_name

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    c = Candidate(title="idor", category="idor", file="v.py", line=1, symbol="g", evidence="x")
    (ws / "pocs" / f"{_finding_name(c)}.py").write_text("import requests\n")

    class WebRunner:
        executes = False
        ext = "py"

    domain = SimpleNamespace(poc_backend=lambda: WebRunner())
    out = _execute_present_pocs(ws, [c], domain, root=str(tmp_path))
    assert out[0].evidence == "x"


def test_execute_present_pocs_does_not_run_a_finding_the_write_step_already_ran(tmp_path):
    """Execute present PoCs does not run a finding the write step already ran."""
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

    domain = SimpleNamespace(poc_backend=lambda: Runner())
    out = _execute_present_pocs(ws, [c], domain, root=str(tmp_path))
    assert ran == []
    assert out[0].evidence.count("[PoC") == 1


def test_execute_present_pocs_records_runner_errors_and_keeps_the_finding(tmp_path):
    """Execute present PoCs records runner errors and keeps the finding."""
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

    domain = SimpleNamespace(poc_backend=lambda: Runner())
    out = _execute_present_pocs(ws, [c], domain, root=str(tmp_path))
    assert len(out) == 1
    assert "PoC failed to run: forge failed" in out[0].evidence


def test_finalize_finding_carries_agent_analysis_not_a_filename(tmp_path):
    """Finalize finding carries agent analysis not a filename."""
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

    finalize_repository_review(target, ws, verify=False)
    finding = (proj / "findings" / "key-leak.md").read_text()
    assert "ships a literal AUTH0_AUTH_KEY" in finding
    assert "## Attack Path" in finding
    assert "## Fix" in finding
    assert "key-leak.md" not in finding
    data = json.loads((proj / "findings.json").read_text())
    assert data["findings"][0]["candidate"] == "candidates/key-leak.md"


def test_keystr_respects_by_file_for_cross_file_findings():
    """Keystr respects by file for cross file findings."""
    from cyberjury.review.repository.engine import _keystr
    from cyberjury.review.repository.union import Candidate

    a = Candidate(title="t", category="reentrancy", endpoint="withdraw", file="A.sol")
    b = Candidate(title="t", category="reentrancy", endpoint="withdraw", file="B.sol")
    assert _keystr(a, True) != _keystr(b, True)
    assert _keystr(a, False) == _keystr(b, False)


def test_seed_run_units_seeds_split_units_and_prunes_orphan(tmp_path):
    """Seed run units seeds split units and prunes orphan."""
    from cyberjury.domains.registry import default_domain
    from cyberjury.review.repository.engine import _seed_run_units
    from cyberjury.review.repository.shapes import Unit

    (tmp_path / "units").mkdir()
    (tmp_path / "units" / "foo.md").write_text("# Unit: foo.py\n- Status: open\n", encoding="utf-8")
    units = [
        Unit(name="foo.py#1", root=str(tmp_path), files=("foo.py",)),
        Unit(name="foo.py#2", root=str(tmp_path), files=("foo.py",)),
    ]
    _seed_run_units(tmp_path, units, default_domain().paths)
    got = {p.name for p in (tmp_path / "units").glob("*.md")}
    assert got == {"foo-py-1.md", "foo-py-2.md"}


def test_run_writes_timing_and_state_to_run_json(tmp_path):
    """Run writes timing and state to run JSON."""
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    (repo / "b.py").write_text("def other():\n    return 1\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    run_repository_review(
        str(repo), str(ws), provider=MockProvider(default='{"findings": []}'), model="mock", verify=False
    )
    run = json.loads((ws / "svc" / "_run.json").read_text())
    assert run["state"] == "converged"
    timing = run["timing"]
    assert isinstance(timing["total_seconds"], (int, float))
    assert timing["per_pass"]
    assert all("seconds" in p for p in timing["per_pass"])
    names = [u["unit"] for u in timing["unit_seconds"]]
    assert names
    assert len(names) == len(set(names))
    assert set(names) <= {"a.py", "b.py"}


def test_standard_run_status_distinguishes_completion_from_convergence(tmp_path):
    """Standard run status distinguishes completion from convergence."""
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    run_repository_review(
        str(repo),
        str(ws),
        provider=MockProvider(default='{"findings": []}'),
        model="mock",
        verify=False,
        max_passes=1,
        min_rounds=1,
    )
    run = json.loads((ws / "svc" / "_run.json").read_text())
    assert run["complete"] is True
    assert run["converged"] is False
    assert run["state"] == "complete"


def _run_with_meter(tmp_path, *, verify=False):
    from cyberjury.providers.metering import MeteringProvider, UsageMeter
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default='{"findings": []}'), meter)
    run_repository_review(str(repo), str(ws), provider=provider, model="mock", verify=verify, meter=meter)
    return json.loads((ws / "svc" / "_run.json").read_text()), meter


def test_run_writes_its_spend_to_run_json_so_cost_survives_uncaptured_stderr(tmp_path):
    """Run writes its spend to run JSON so cost survives uncaptured stderr."""
    run, meter = _run_with_meter(tmp_path)
    usage = run["usage"]
    assert usage["model_requests"] == meter.model_requests
    components = usage["uncached_input_tokens"] + usage["cache_read_tokens"] + usage["cache_write_tokens"]
    assert usage["total_input_tokens"] == components
    assert usage["unit_review_calls"] >= run["units_reviewed"]


def test_each_pass_records_its_own_spend_so_an_expensive_pass_can_be_named(tmp_path):
    """Each pass records its own spend so an expensive pass can be named."""
    run, _ = _run_with_meter(tmp_path)
    per_pass = run["timing"]["per_pass"]
    assert all("usage" in p for p in per_pass)
    assert sum(p["usage"]["model_requests"] for p in per_pass) == run["usage"]["model_requests"]


def test_a_run_without_a_meter_writes_no_usage_rather_than_zeros(tmp_path):
    """Run without a meter writes no usage rather than zeros."""
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    run_repository_review(
        str(repo), str(ws), provider=MockProvider(default='{"findings": []}'), model="mock", verify=False
    )
    assert "usage" not in json.loads((ws / "svc" / "_run.json").read_text())
