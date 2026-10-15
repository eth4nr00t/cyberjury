"""The repository review scaffold builds workspace structure without running the pipeline."""

import json
import shutil
import stat
from dataclasses import replace

import pytest

from cyberjury.profiles.base import ReviewProfile
from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.review.facts import (
    BackendUnavailable,
    FactLimitation,
    Facts,
    FactsBackend,
    FactsResolutionReceipt,
    NativeAnalysisReceipt,
)
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.repository.scaffold import scaffold
from cyberjury.sources.snapshot import SourceSnapshotError

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


def test_scaffold_reviews_library_source_without_export_rules(tmp_path):
    res = scaffold(_go_lib(tmp_path), tmp_path / "work")
    assert res.candidate_files == ("matcher.go",)
    assert [unit.name for unit in res.units] == ["matcher.go"]


def test_scaffold_creates_workspace(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert res.project == "myservice"
    assert res.workspace == tmp_path / "work" / "myservice"
    assert (res.workspace / ".cyberjury" / "workspace.json").is_file()
    assert {path.name for path in res.workspace.iterdir()}.isdisjoint({"inventory", "units", "candidates", "findings"})


def test_scaffold_flags_candidate_entrypoint_files(tmp_path):
    d = tmp_path / "dj"
    d.mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app").mkdir()
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = scaffold(d, tmp_path / "work")
    assert "app/urls.py" in res.candidate_files


def test_scaffold_reviews_nested_source_without_framework_guides(tmp_path):
    target = tmp_path / "monorepo"
    (target / "packages" / "api").mkdir(parents=True)
    (target / "packages" / "api" / "package.json").write_text(
        '{"dependencies":{"@nestjs/core":"1.0.0","@nestjs/common":"1.0.0"}}'
    )
    (target / "packages" / "api" / "users.controller.ts").write_text("export class UsersController {}\n")

    result = scaffold(target, tmp_path / "work")

    assert "packages/api/users.controller.ts" in result.candidate_files


def test_scaffold_assigns_downstream_logic_to_review_units(tmp_path):
    d = tmp_path / "dj"
    (d / "app" / "managers").mkdir(parents=True)
    (d / "app" / "tests").mkdir()
    (d / "manage.py").write_text("import django\n")
    (d / "app" / "urls.py").write_text("from django.urls import path\nurlpatterns = []\n")
    (d / "app" / "managers" / "auth_manager.py").write_text("class AuthManager:\n    pass\n")
    (d / "app" / "tests" / "test_managers.py").write_text("def test_x():\n    pass\n")
    (d / "requirements.txt").write_text("Django==4.2\n")
    res = scaffold(d, tmp_path / "work")
    assert "app/managers/auth_manager.py" in res.candidate_files
    assert not any("test" in t for t in res.candidate_files)
    assert any(unit.files == ("app/managers/auth_manager.py",) for unit in res.units)


def test_scaffold_plans_a_unit_per_candidate(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert [unit.owned_paths for unit in res.units] == [("app.py",)]
    plan = json.loads((res.workspace / "_unit_plan.json").read_text())
    assert [unit["name"] for unit in plan["units"]] == ["app.py"]


def test_scaffold_splits_a_large_candidate_into_slice_units(tmp_path):
    d = tmp_path / "big"
    d.mkdir()
    header = "from flask import Flask\napp = Flask(__name__)\n\n"
    block = '@app.route("/r%d")\ndef h%d():\n    x = "%s"\n    return x\n\n'
    body = "".join(block % (i, i, "p" * 200) for i in range(200))
    (d / "views.py").write_text(header + body)
    (d / "requirements.txt").write_text("Flask==3.0\n")
    res = scaffold(d, tmp_path / "work")
    names = [unit.name for unit in res.units]
    assert "views.py" not in names
    assert {"views.py#1", "views.py#2"} <= set(names)
    first = next(unit for unit in res.units if unit.name == "views.py#1")
    assert first.files == ("views.py",)
    assert first.span is not None
    assert first.span[0] == 0


class _CountingBackend(FactsBackend):
    """A facts backend counts extractions without a real toolchain."""

    def __init__(self) -> None:
        self.calls = 0

    def extract(self, root):
        self.calls += 1
        block = "def f():\n    return 1"
        native_analysis = NativeAnalysisReceipt.create(
            producer="counting-test",
            producer_version="1",
            source_count=1,
            definition_count=1,
            callsite_count=0,
            limitation_count=0,
            evidence={"callgraph": {"app.py": ["f"]}},
        )
        relationship_evidence = RelationshipEvidenceBundle().to_data()
        facts = Facts(
            summary=block,
            native_analysis=native_analysis,
            data={
                "by_file": {"app.py": block},
                "relationship_evidence": relationship_evidence,
                "graph": {
                    "callgraph": {"app.py": {"f": [{"range": [0, 12], "calls": []}]}},
                },
            },
        )
        return replace(
            facts,
            facts_resolution=FactsResolutionReceipt.create(
                native_analysis=native_analysis,
                relationship_evidence=relationship_evidence,
                limitations=(),
            ),
        )


def _facts_profile(backend: FactsBackend) -> ReviewProfile:
    return replace(WEB_PROFILE, facts_backend=backend)


def test_scaffold_grounds_whenever_the_profile_binds_a_backend(tmp_path):
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", profile=_facts_profile(backend))
    assert (res.workspace / "_facts.md").read_text().startswith("def f():")
    assert backend.calls == 1


def test_scaffold_fails_loud_for_a_profile_with_no_facts_backend(tmp_path):
    with pytest.raises(ValueError, match="no facts backend"):
        scaffold(_target(tmp_path), tmp_path / "work", profile=replace(WEB_PROFILE, facts_backend=None))


class _UnavailableBackend(FactsBackend):
    """Exercise loud scaffold failure when the facts toolchain cannot run."""

    def extract(self, root):
        raise RuntimeError("facts toolchain is unavailable")


def test_scaffold_fails_loud_when_the_facts_backend_cannot_run(tmp_path):
    from cyberjury.review.facts import BackendUnavailable

    with pytest.raises(BackendUnavailable, match="no grounding"):
        scaffold(_target(tmp_path), tmp_path / "work", profile=_facts_profile(_UnavailableBackend()))


def test_scaffold_fails_loud_when_the_facts_backend_returns_no_receipts(tmp_path):
    class ReceiptlessBackend(FactsBackend):
        def extract(self, root):
            return Facts(summary="def f():\n    return 1")

    with pytest.raises(BackendUnavailable, match="no analysis receipts"):
        scaffold(_target(tmp_path), tmp_path / "work", profile=_facts_profile(ReceiptlessBackend()))
    assert (tmp_path / "work" / "myservice" / "_facts_error.txt").is_file()


def test_scaffold_rejects_source_changes_during_facts_extraction(tmp_path):
    class MutatingBackend(_CountingBackend):
        def extract(self, root):
            facts = super().extract(root)
            (root / "app.py").write_text(APP + "\nMUTATED = True\n")
            return facts

    target = _target(tmp_path)
    workspace = tmp_path / "work"

    with pytest.raises(BackendUnavailable, match="source changed during facts extraction"):
        scaffold(target, workspace, profile=_facts_profile(MutatingBackend()))

    project = workspace / target.name
    assert not (project / "_facts_manifest.json").exists()


def test_scaffold_records_an_unreadable_facts_source(monkeypatch, tmp_path):
    target = _target(tmp_path)
    source = target / "app.py"
    original_open = type(source).open

    def deny_source(path, *args, **kwargs):
        if path == source and args and args[0] == "rb":
            raise PermissionError("access denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(type(source), "open", deny_source)
    workspace = tmp_path / "work"

    with pytest.raises(SourceSnapshotError, match=r"app\.py.*access denied"):
        scaffold(target, workspace, profile=_facts_profile(_CountingBackend()))

    error = workspace / target.name / "_facts_error.txt"
    assert "app.py" in error.read_text(encoding="utf-8")


def test_scaffold_persists_the_per_file_facts_map(tmp_path):
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", profile=_facts_profile(backend))
    by_file = json.loads((res.workspace / "_facts_by_file.json").read_text())
    assert by_file["app.py"].startswith("def f():")


def test_scaffold_persists_the_exact_runtime_unit_plan(tmp_path):
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", profile=_facts_profile(backend))
    artifact = json.loads((res.workspace / "_unit_plan.json").read_text())

    assert res.unit_plan is not None
    assert artifact == res.unit_plan.to_dict()
    assert artifact["schema"] == "cyberjury.unit-plan/v2"
    assert artifact["unit_count"] == len(res.units)


def test_scaffold_persists_grounding_for_the_exact_runtime_units(tmp_path):
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", profile=_facts_profile(backend))
    artifact = json.loads((res.workspace / "_grounding.json").read_text())

    assert res.grounding_receipt is not None
    assert artifact == res.grounding_receipt.to_dict()
    assert GroundingReceipt.from_dict(artifact) == res.grounding_receipt
    assert artifact["unit_plan_receipt_sha256"] == res.unit_plan.receipt_sha256
    assert artifact["context_count"] == len(res.units)
    assert sum(context["facts_chars"] for context in artifact["contexts"]) > 0
    assert all(unit.grounding is not None for unit in res.units)


def test_scaffold_persists_the_call_graph(tmp_path):
    backend = _CountingBackend()
    res = scaffold(_target(tmp_path), tmp_path / "work", profile=_facts_profile(backend))
    graph = json.loads((res.workspace / "_facts_graph.json").read_text())
    assert graph["callgraph"]["app.py"]["f"] == [{"range": [0, 12], "calls": []}]


def test_scaffold_persists_but_does_not_cache_source_limitations(tmp_path):
    backend = _CountingBackend()
    limitation = FactLimitation(source="app.py", analyzer="python", reason="unparsable", line=2, column=1)
    original_extract = backend.extract

    def limited_extract(root):
        facts = original_extract(root)
        return replace(
            facts,
            limitations=(limitation,),
            facts_resolution=FactsResolutionReceipt.create(
                native_analysis=facts.native_analysis,
                relationship_evidence=facts.data["relationship_evidence"],
                limitations=(limitation,),
            ),
        )

    backend.extract = limited_extract
    profile = _facts_profile(backend)
    work = tmp_path / "work"
    first = scaffold(_target(tmp_path), work, profile=profile)
    second = scaffold(_target(tmp_path), work, profile=profile, fresh=True)

    assert backend.calls == 2
    assert json.loads((first.workspace / "_facts_limitations.json").read_text()) == [limitation.to_data()]
    assert json.loads((second.workspace / "_facts_limitations.json").read_text()) == [limitation.to_data()]


def test_scaffold_reuses_the_cached_per_file_facts_map(tmp_path):
    backend = _CountingBackend()
    profile = _facts_profile(backend)
    work = tmp_path / "work"
    scaffold(_target(tmp_path), work, profile=profile)
    res = scaffold(_target(tmp_path), work, profile=profile, fresh=True)
    assert backend.calls == 1
    assert json.loads((res.workspace / "_facts_by_file.json").read_text())["app.py"]
    assert json.loads((res.workspace / "_facts_graph.json").read_text())["callgraph"]["app.py"]


def test_scaffold_reuses_cached_facts_across_a_fresh_run(tmp_path):
    backend = _CountingBackend()
    profile = _facts_profile(backend)
    work = tmp_path / "work"
    scaffold(_target(tmp_path), work, profile=profile)
    assert backend.calls == 1
    res = scaffold(_target(tmp_path), work, profile=profile, fresh=True)
    assert (res.workspace / "_facts.md").read_text().startswith("def f():")
    assert backend.calls == 1
    for name in ("_facts_by_file.json", "_facts_graph.json"):
        assert (res.workspace / name).is_file(), name


def test_scaffold_restores_cached_facts_when_persisted_facts_are_incomplete(tmp_path):
    backend = _CountingBackend()
    profile = _facts_profile(backend)
    work = tmp_path / "work"
    res = scaffold(_target(tmp_path), work, profile=profile)
    (res.workspace / "_facts_graph.json").unlink()

    res = scaffold(_target(tmp_path), work, profile=profile)

    assert backend.calls == 1
    assert (res.workspace / "_facts_graph.json").is_file()


def test_scaffold_ignores_legacy_cached_facts_without_a_manifest(tmp_path):
    backend = _CountingBackend()
    profile = _facts_profile(backend)
    work = tmp_path / "work"
    scaffold(_target(tmp_path), work, profile=profile)
    cache_manifest = next((work / ".facts-cache").glob("*.manifest.json"))
    cache_manifest.unlink()

    res = scaffold(_target(tmp_path), work, profile=profile, fresh=True)

    assert backend.calls == 2
    assert (res.workspace / "_facts_graph.json").is_file()
    assert next((work / ".facts-cache").glob("*.manifest.json")).is_file()


def test_scaffold_reextracts_when_source_changes(tmp_path):
    backend = _CountingBackend()
    profile = _facts_profile(backend)
    work = tmp_path / "work"
    target = _target(tmp_path)
    scaffold(target, work, profile=profile)
    (target / "app.py").write_text(APP + "\n# edit\n")
    scaffold(target, work, profile=profile, fresh=True)
    assert backend.calls == 2


def test_scaffold_refreshes_changed_source_before_review_state_exists(tmp_path):
    backend = _CountingBackend()
    profile = _facts_profile(backend)
    work = tmp_path / "work"
    target = _target(tmp_path)
    scaffold(target, work, profile=profile)

    (target / "app.py").write_text(APP + "\nvalue = 1\n")
    refreshed = scaffold(target, work, profile=profile)

    assert backend.calls == 2
    assert refreshed.cleared


def test_scaffold_rejects_profile_change_after_review_state_exists(tmp_path):
    work = tmp_path / "work"
    target = _target(tmp_path)
    first = scaffold(target, work)
    (first.workspace / "_union.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match=r"source or profile changed.*--fresh"):
        scaffold(target, work, profile=replace(WEB_PROFILE, name="alternate-web"))


def test_scaffold_rejects_same_name_profile_content_change_after_review_state_exists(tmp_path):
    content = tmp_path / "profile"
    shutil.copytree(WEB_PROFILE.content_root, content)
    profile = replace(WEB_PROFILE, content_root=content)
    work = tmp_path / "work"
    target = _target(tmp_path)
    first = scaffold(target, work, profile=profile)
    (first.workspace / "_run.json").write_text('{"state":"complete"}', encoding="utf-8")
    detection = content / "detection.yaml"
    detection.write_text(detection.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"source or profile changed.*--fresh"):
        scaffold(target, work, profile=profile)


def test_scaffold_assigns_unlisted_language_to_a_review_unit(tmp_path):
    d = tmp_path / "rb"
    d.mkdir()
    (d / "app.rb").write_text("puts 'hello'\n")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ("app.rb",)
    assert [unit.files for unit in res.units] == [("app.rb",)]


def test_scaffold_does_not_seed_unknown_binary_assets_as_raw_work(tmp_path):
    target = _target(tmp_path)
    (target / "banner.png").write_bytes(b"\x89PNG\r\n\x1a\n\0binary")

    res = scaffold(target, tmp_path / "work")

    assert all("banner.png" not in unit.files for unit in res.units)


def test_scaffold_uses_no_stack_guides(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert "app.py" in res.candidate_files
    assert not (res.workspace / "_stack.md").exists()


def test_scaffold_does_not_copy_a_second_security_catalog(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert not (res.workspace / "_vulnerabilities.md").exists()


def test_scaffold_flags_a_prior_run(tmp_path):
    ws_root = tmp_path / "work"
    first = scaffold(_target(tmp_path), ws_root)
    assert first.had_prior_run is False
    (first.workspace / "findings.json").write_text("{}", encoding="utf-8")
    second = scaffold(_target(tmp_path), ws_root)
    assert second.had_prior_run is True
    assert second.cleared == []
    assert (second.workspace / "findings.json").is_file()


def test_scaffold_fresh_clears_prior_output(tmp_path):
    ws_root = tmp_path / "work"
    first = scaffold(_target(tmp_path), ws_root)
    (first.workspace / "findings.json").write_text("{}", encoding="utf-8")
    (first.workspace / "pocs").mkdir()
    (first.workspace / "pocs" / "candidate.py").write_text("assert True\n", encoding="utf-8")
    fresh = scaffold(_target(tmp_path), ws_root, fresh=True)
    assert fresh.had_prior_run is True
    assert fresh.cleared
    assert not (fresh.workspace / "findings.json").exists()
    assert not (fresh.workspace / "pocs").exists()
    assert (fresh.workspace / "_unit_plan.json").is_file()


def test_scaffold_fresh_refuses_a_workspace_owned_by_another_target(tmp_path):
    first_target = tmp_path / "first" / "service"
    second_target = tmp_path / "second" / "service"
    first_target.mkdir(parents=True)
    second_target.mkdir(parents=True)
    (first_target / "app.py").write_text("first = True\n")
    (second_target / "app.py").write_text("second = True\n")
    workspace_root = tmp_path / "work"
    first = scaffold(first_target, workspace_root)

    with pytest.raises(ValueError, match="belongs to a different target"):
        scaffold(second_target, workspace_root, fresh=True)

    assert (first.workspace / ".cyberjury" / "workspace.json").is_file()


def test_scaffold_creates_a_private_workspace(tmp_path):
    res = scaffold(_target(tmp_path), tmp_path / "work")
    assert stat.S_IMODE(res.workspace.stat().st_mode) == 0o700


def test_fresh_refuses_to_clear_an_unmarked_directory(tmp_path):
    ws_root = tmp_path / "work"
    project_ws = ws_root / "myservice"
    project_ws.mkdir(parents=True)
    (project_ws / "important.txt").write_text("not cyberjury data")
    with pytest.raises(ValueError, match=r"no \.cyberjury/workspace\.json marker"):
        scaffold(_target(tmp_path), ws_root, fresh=True)
    assert (project_ws / "important.txt").exists()


def test_plain_repository_still_scaffolds(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "notes.txt").write_text("hi")
    res = scaffold(d, tmp_path / "work")
    assert res.candidate_files == ()
    assert res.units == ()
