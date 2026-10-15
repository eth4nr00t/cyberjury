"""Diff context renders bounded repository evidence and reports incomplete coverage."""

from dataclasses import replace
from pathlib import Path

import pytest

from cyberjury.detection import load_detection
from cyberjury.profiles.registry import default_profile
from cyberjury.review.context import GroundingContext, SourceEvidence
from cyberjury.review.definitions import DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.diff.context import (
    DiffContextCollector,
    _importing_files_for_seeds,
    _initial_candidate_sources,
    build_diff_context_collector,
)
from cyberjury.review.diff.model import DiffUnit
from cyberjury.review.diff.prompts import related_file_context
from cyberjury.review.facts import BackendUnavailable, FactLimitation, Facts, FactsBackend
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.sources.snapshot import SourceSnapshot


class _FactsBackend(FactsBackend):
    def __init__(self, facts: Facts | None = None) -> None:
        self._facts = facts or Facts()
        self.extracts = 0

    def extract(self, root: str | Path) -> Facts:
        self.extracts += 1
        return self._facts


def _profile(backend: FactsBackend):
    return replace(default_profile(), facts_backend=backend)


def _detection():
    return load_detection(default_profile().paths.detection_file)


def _prepare(collector: DiffContextCollector, diff: str) -> list[DiffUnit]:
    return collector.ground(collector.plan(diff))


def _collect(collector: DiffContextCollector, diff: str, plan: DefinitionUnitPlan) -> GroundingContext:
    unit = DiffUnit(index=1, total=1, diff=diff, paths=(), definition_plan=plan)
    return collector.ground([unit])[0].grounding


def _ground(root: Path, diff: str, profile) -> GroundingContext:
    units = _prepare(build_diff_context_collector(root, profile, review_diff=diff), diff)
    assert len(units) == 1
    return units[0].grounding


def test_changed_definition_is_requestable_without_an_initial_prefix(tmp_path):
    source = "class Handler(Base):\n    owner = request.user\n    control = check(owner)\n    return_value = 1\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    file_seed = DefinitionFragment("app.py", "<file>", 0, len(source))
    class_seed = DefinitionFragment("app.py", "Handler", 0, len(source))
    plan = DefinitionUnitPlan(seeds=(file_seed, class_seed))
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1 +1 @@\n"
        "-class Handler:\n"
        "+class Handler(Base):\n"
    )
    collector = DiffContextCollector(root=tmp_path, detection=_detection(), by_file={}, graph={})

    context = _collect(collector, diff, plan)

    assert context.source_evidence == ()
    assert "control = check(owner)" not in context.prompt.source
    assert any(item.label.startswith("app.py:Handler") for item in context.evidence)
    handler = next(item for item in context.evidence if item.label.startswith("app.py:Handler"))
    assert f"`{handler.id}`" in context.prompt.controls
    assert "complete changed definition" in handler.label
    assert "control = check(owner)" in handler.text


def test_changed_definition_reaches_its_importing_control(tmp_path):
    changed = "def apply(value):\n    return value\n"
    related = "from service import apply\n\nclass Route:\n    permission = require_user\n    handler = apply\n"
    (tmp_path / "service.py").write_text(changed, encoding="utf-8")
    (tmp_path / "views.py").write_text(related, encoding="utf-8")
    graph = {
        "callgraph": {
            "service.py": {"apply": [{"range": [0, len(changed)], "calls": []}]},
            "views.py": {"Route": [{"range": [related.index("class Route"), len(related)], "calls": []}]},
        },
        "syntax_imports": {
            "views.py": [{"module": "service", "imported": "apply", "local": "apply", "range": [0, 25]}],
        },
    }
    collector = DiffContextCollector(
        root=tmp_path,
        detection=_detection(),
        by_file={},
        graph=graph,
    )
    plan = DefinitionUnitPlan(seeds=(DefinitionFragment("service.py", "apply", 0, len(changed)),))
    diff = "diff --git a/service.py b/service.py\n+++ b/service.py\n@@ -1,1 +1,1 @@\n+def apply(value):\n"

    context = _collect(collector, diff, plan)

    assert "File: views.py" in context.text
    assert "permission = require_user" in context.text


def test_importing_source_candidates_skip_noise_and_remain_bounded():
    seed = DefinitionFragment("service.py", "apply", 0, 10)
    imports = {
        file: [{"imported": "apply", "local": "apply"}]
        for file in ("views.py", "consumer.py", "worker.py", "tests/test_views.py")
    }

    selected, names = _importing_files_for_seeds(
        {"syntax_imports": imports},
        (seed,),
        _detection(),
        ("views.py",),
        ("service.py",),
    )

    assert selected == ("views.py",)
    assert names == {"views.py": ("apply",)}


def test_importing_source_candidates_prefer_matching_source_module():
    seed = DefinitionFragment("src/documents/file_handling.py", "generate_unique_filename", 0, 10)
    imports = {
        "src-ui/editor.ts": [
            {"module": "app/data/file_handling", "imported": "generate_unique_filename"},
        ],
        "src/documents/signals/handlers.py": [
            {"module": "documents.file_handling", "imported": "generate_unique_filename"},
        ],
    }

    selected, _names = _importing_files_for_seeds(
        {"syntax_imports": imports},
        (seed,),
        _detection(),
        ("src-ui/editor.ts",),
        ("src/documents/file_handling.py",),
    )

    assert selected == ("src/documents/signals/handlers.py",)


def test_importing_source_candidates_follow_local_alias():
    seed = DefinitionFragment("src/service.py", "apply", 0, 10)

    selected, names = _importing_files_for_seeds(
        {"syntax_imports": {"src/views.py": [{"module": "service", "imported": "apply", "local": "run"}]}},
        (seed,),
        _detection(),
        (),
        ("src/service.py",),
    )

    assert selected == ("src/views.py",)
    assert names == {"src/views.py": ("run",)}


def test_large_unit_prioritizes_specific_imports_across_callers():
    seeds = (
        DefinitionFragment("src/documents/models.py", "StoragePath", 0, 10),
        DefinitionFragment("src/documents/file_handling.py", "generate_unique_filename", 0, 10),
    )
    imports = {
        file: [
            {"module": "documents.models", "imported": "StoragePath"},
            {"module": "documents.file_handling", "imported": "generate_unique_filename"},
        ]
        for file in ("src/documents/consumer.py", "src/documents/tasks.py")
    }
    imports["src/documents/signals/handlers.py"] = [
        {"module": "documents.file_handling", "imported": "generate_unique_filename"},
    ]
    imports["src/documents/views.py"] = [{"module": "documents.models", "imported": "StoragePath"}]

    selected, _names = _importing_files_for_seeds(
        {"syntax_imports": imports},
        seeds,
        _detection(),
        (),
        ("src/documents/models.py", "src/documents/file_handling.py", "src/documents/templating/utils.py", "app.ts"),
    )

    assert selected == (
        "src/documents/consumer.py",
        "src/documents/tasks.py",
        "src/documents/signals/handlers.py",
    )


def test_related_source_budget_carries_distinct_importing_controls(tmp_path):
    source = (
        "class GlobalSearchView:\n"
        "    serializers = (FirstSerializer, SecondSerializer)\n"
        f"    filler = '{'g' * 4000}'\n"
        "\nclass FirstView:\n"
        "    permission = require_owner\n"
        "    serializer = FirstSerializer\n"
        f"    filler = '{'a' * 4000}'\n"
        "\nclass SecondView:\n"
        "    permission = require_owner\n"
        "    serializer = SecondSerializer\n"
        f"    filler = '{'b' * 4000}'\n"
    )
    (tmp_path / "views.py").write_text(source)
    first = source.index("class FirstView")
    second = source.index("class SecondView")
    definitions = {
        "GlobalSearchView": [{"range": [0, first], "calls": []}],
        "FirstView": [{"range": [first, second], "calls": []}],
        "SecondView": [{"range": [second, len(source)], "calls": []}],
    }

    text, _included = related_file_context(
        tmp_path,
        "views.py",
        "",
        definitions,
        set(),
        "FirstSerializer SecondSerializer",
        linked_names=("FirstSerializer", "SecondSerializer"),
        max_chars=3000,
    )

    assert "Definition FirstView:" in text
    assert "Definition SecondView:" in text
    assert "Definition GlobalSearchView:" not in text
    assert text.count("permission = require_owner") == 2
    assert len(text) <= 3000


def test_related_source_preserves_later_effect_after_imported_call(tmp_path):
    source = (
        "def update_target():\n"
        "    generated = generate_name()\n"
        f"    payload = '{'x' * 2650}'\n"
        "    move_file(generated)\n"
    )
    (tmp_path / "handler.py").write_text(source)

    text, _included = related_file_context(
        tmp_path,
        "handler.py",
        "",
        {
            "<file>": [{"range": [0, len(source)], "calls": []}],
            "update_target": [{"range": [0, len(source)], "calls": ["generate_name", "move_file"]}],
        },
        set(),
        "generate_name",
        linked_names=("generate_name",),
        max_chars=3500,
    )

    assert "move_file(generated)" in text
    assert len(text) <= 3500


def test_diff_context_collects_a_changed_source_path_with_spaces(tmp_path):
    source = "def route():\n    return sink()\n"
    (tmp_path / "app route.py").write_text(source)
    diff = (
        "diff --git a/app route.py b/app route.py\n"
        "--- a/app route.py\n"
        "+++ b/app route.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+def route():\n"
        "+    return sink()\n"
    )

    context = _ground(tmp_path, diff, _profile(_FactsBackend(Facts())))

    assert context.files == ("app route.py",)
    assert "def route():" in context.text
    assert context.coverage.complete is True


def test_diff_context_discloses_only_source_limitations_in_the_unit_scope(tmp_path):
    source = "def route():\n    return 1\n"
    for name in ("app.py", "related.py", "unrelated.py"):
        (tmp_path / name).write_text(source)
    route = DefinitionFragment("app.py", "route", 0, len(source))
    related = DefinitionFragment("related.py", "route", 0, len(source))
    collector = DiffContextCollector(
        root=tmp_path,
        detection=_detection(),
        by_file={},
        graph={},
        facts_limitations=(
            FactLimitation(source="related.py", analyzer="python", reason="unparsable", line=1, column=1),
            FactLimitation(source="unrelated.py", analyzer="python", reason="unparsable", line=1, column=1),
        ),
    )
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+def route(): return 2\n"

    context = _collect(collector, diff, DefinitionUnitPlan(seeds=(route,), evidence=(route, related)))

    assert context.coverage.limitations == ("facts:related.py:1:1",)
    assert "related.py at 1:1" in context.text
    assert "unrelated.py at 1:1" not in context.text


def test_diff_context_keeps_a_limitation_for_a_published_evidence_source(tmp_path, monkeypatch):
    from cyberjury.review.diff import context as context_module

    app_source = "def route():\n    return load()\n"
    service_source = "def load():\n    return 1\n"
    (tmp_path / "app.py").write_text(app_source, encoding="utf-8")
    (tmp_path / "service.py").write_text(service_source, encoding="utf-8")
    source = DefinitionFragment("app.py", "route", 0, len(app_source))
    target = DefinitionFragment("service.py", "load", 0, len(service_source))
    plan = DefinitionUnitPlan(seeds=(source,), evidence=(source, target))
    collector = DiffContextCollector(
        root=tmp_path,
        detection=_detection(),
        by_file={},
        graph={},
        facts_limitations=(
            FactLimitation(source="service.py", analyzer="python", reason="unparsable", line=1, column=1),
        ),
    )
    original = context_module.related_file_context

    def omit_related(root, rel, *args, **kwargs):
        return ("", ()) if rel == "service.py" else original(root, rel, *args, **kwargs)

    monkeypatch.setattr(context_module, "related_file_context", omit_related)
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+def route(): return load()\n"

    context = _collect(collector, diff, plan)

    assert context.files == ()
    assert context.coverage.limitations == ("facts:service.py:1:1",)


def test_fallback_diff_context_renders_facts_and_current_source(tmp_path):
    (tmp_path / "app.py").write_text(
        "def get_client():\n    return current_user_client()\n\ndef tool():\n    return get_client()\n",
        encoding="utf-8",
    )
    facts = Facts(
        summary="Call graph",
        data={"by_file": {"app.py": "app.py\n  tool()  calls get_client\n  get_client()"}},
    )
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -3,0 +4,2 @@\n+def tool():\n+    return get_client()\n"

    ctx = _ground(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert ctx.source == "diff"
    assert ctx.files == ("app.py",)
    assert "Syntax hints (unverified; cite only delivered source):" in ctx.text
    assert "tool()  calls get_client" in ctx.text
    assert "current_user_client" in ctx.text
    assert "   1: def get_client():" in ctx.text


def test_collect_diff_context_prefixes_scoped_facts_to_repository_paths(tmp_path):
    scope = tmp_path / "backend"
    scope.mkdir()
    (scope / "service.py").write_text("def execute():\n    return 1\n", encoding="utf-8")
    (scope / "views.py").write_text(
        "from service import execute\n\ndef route():\n    return execute()\n", encoding="utf-8"
    )
    facts = Facts(
        data={
            "by_file": {"service.py": "service.py\n  execute()"},
            "graph": {
                "callgraph": {
                    "service.py": {"execute": [{"range": [0, 27], "calls": []}]},
                    "views.py": {"route": [{"range": [29, 64], "calls": ["execute"]}]},
                },
                "syntax_imports": {
                    "views.py": [{"module": "service", "imported": "execute", "local": "execute", "range": [0, 27]}]
                },
            },
        },
    )
    diff = (
        "diff --git a/backend/service.py b/backend/service.py\n"
        "+++ b/backend/service.py\n"
        "@@ -2,0 +2,1 @@\n"
        "+    return 1\n"
    )

    collector = build_diff_context_collector(tmp_path, _profile(_FactsBackend(facts)), facts_root=scope)
    [unit] = _prepare(collector, diff)
    ctx = unit.grounding

    assert unit.paths == ("backend/service.py",)
    assert [seed.identity for seed in unit.definition_plan.seeds] == ["backend/service.py:execute:0:27"]
    assert collector.by_file == {"backend/service.py": "service.py\n  execute()"}
    assert set(collector.graph["callgraph"]) == {"backend/service.py", "backend/views.py"}
    assert collector.source_snapshot is not None
    assert collector.source_snapshot.root == tmp_path.resolve()
    assert collector.source_snapshot.matches_files(("backend/service.py",))
    ctx.validate_snapshot()


def test_scoped_diff_context_reaches_importing_control_through_rebased_imports(tmp_path):
    scope = tmp_path / "backend"
    scope.mkdir()
    changed = "def apply(value):\n    return value\n"
    related = "from service import apply\n\nclass Route:\n    permission = require_user\n    handler = apply\n"
    (scope / "service.py").write_text(changed, encoding="utf-8")
    (scope / "views.py").write_text(related, encoding="utf-8")
    facts = Facts(
        data={
            "graph": {
                "callgraph": {
                    "service.py": {"apply": [{"range": [0, len(changed)], "calls": []}]},
                    "views.py": {"Route": [{"range": [related.index("class Route"), len(related)], "calls": []}]},
                },
                "syntax_imports": {
                    "views.py": [{"module": "service", "imported": "apply", "local": "apply", "range": [0, 25]}],
                },
            },
        },
    )
    diff = (
        "diff --git a/backend/service.py b/backend/service.py\n"
        "+++ b/backend/service.py\n"
        "@@ -1,1 +1,1 @@\n"
        "+def apply(value):\n"
    )

    collector = build_diff_context_collector(tmp_path, _profile(_FactsBackend(facts)), facts_root=scope)
    [unit] = _prepare(collector, diff)

    assert set(collector.graph["syntax_imports"]) == {"backend/views.py"}
    assert "File: backend/views.py" in unit.grounding.text
    assert "permission = require_user" in unit.grounding.text


def test_collect_diff_context_rejects_facts_root_outside_repository(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()

    with pytest.raises(BackendUnavailable, match="outside repository root"):
        build_diff_context_collector(tmp_path, _profile(_FactsBackend()), facts_root=outside)


def test_diff_navigation_exposes_go_package_callers_as_candidates(tmp_path):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts

    helper = 'package app\n\nfunc CheckPolicy(value string) bool {\n    return value != ""\n}\n'
    caller = "package app\n\nfunc ApplyPolicy(value string) bool {\n    return CheckPolicy(value)\n}\n"
    (tmp_path / "policy.go").write_text(helper)
    (tmp_path / "service.go").write_text(caller)
    diff = (
        "diff --git a/policy.go b/policy.go\n"
        "--- a/policy.go\n"
        "+++ b/policy.go\n"
        "@@ -4 +4 @@ func CheckPolicy(value string) bool {\n"
        "-    return true\n"
        '+    return value != ""\n'
    )
    collector = build_diff_context_collector(
        tmp_path,
        _profile(TreeSitterFacts()),
        review_diff=diff,
    )
    evidence = collector.relationship_evidence
    target = next(item for item in evidence.definitions if item.name == "CheckPolicy")
    assert collector.navigator is not None
    session = collector.navigator.session()
    session.execute(
        [{"kind": "search_symbols", "query": "CheckPolicy", "page": 0}],
        target_chars=10_000,
    )
    candidates = session.execute(
        [
            {
                "kind": "search_call_candidates",
                "definition_id": target.id,
                "direction": "callers",
                "page": 0,
            }
        ],
        target_chars=10_000,
    )

    assert "ApplyPolicy" in candidates.text
    assert "CheckPolicy(value)" in candidates.text
    assert "page 0" in candidates.text


def test_diff_grounding_exposes_candidate_callee_clues_for_changed_callers(tmp_path, monkeypatch):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts

    (tmp_path / "route.py").write_text(
        "from service import load\n\ndef route(value):\n    return load(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "service.py").write_text(
        "def load(value):\n    return value\n",
        encoding="utf-8",
    )
    diff = (
        "diff --git a/route.py b/route.py\n"
        "--- a/route.py\n"
        "+++ b/route.py\n"
        "@@ -3,2 +3,2 @@\n"
        " def route(value):\n"
        "-    return value\n"
        "+    return load(value)\n"
    )
    collector = build_diff_context_collector(
        tmp_path,
        _profile(TreeSitterFacts()),
        review_diff=diff,
    )

    unit = _prepare(collector, diff)[0]

    assert unit.grounding is not None
    assert "Unverified direct call candidates from this unit" in unit.grounding.text
    assert "service.py:load" in unit.grounding.text
    candidate_source = unit.grounding.source_evidence[0]
    assert "def load(value)" in candidate_source.text
    assert candidate_source.id in unit.grounding.prompt.source
    assert candidate_source.text in unit.grounding.prompt.source
    assert "service.py" in unit.grounding.snapshot_files

    from cyberjury.review.diff import context as context_module

    monkeypatch.setattr(context_module, "_MAX_INITIAL_CANDIDATE_SOURCE_CHARS", 1)
    requestable = _prepare(collector, diff)[0].grounding
    assert requestable is not None
    assert requestable.source_evidence == ()
    assert any(item.source_span and item.source_span.file == "service.py" for item in requestable.evidence)
    assert "service.py" in requestable.snapshot_files
    (tmp_path / "service.py").write_text("def load(value):\n    return None\n", encoding="utf-8")
    with pytest.raises(BackendUnavailable, match="source changed"):
        requestable.validate_snapshot()


def test_initial_candidate_source_budget_keeps_large_callees_requestable():
    short = SourceEvidence(id="src-short", identity="short", text="source" * 100)
    large = SourceEvidence(id="src-large", identity="large", text="source" * 700)

    delivered = _initial_candidate_sources((large, short), context_chars=20_000)

    assert delivered == (short,)


def test_diff_surface_packing_does_not_charge_lazy_seed_definitions_to_context_budget():
    from cyberjury.review.diff.model import _pack_surface_plans

    first = DefinitionFragment("first.py", "first", 0, 100_000)
    second = DefinitionFragment("second.py", "second", 0, 100_000)
    settings = replace(
        DEFAULT_REVIEW_SETTINGS.diff,
        target_patch_chars_per_unit=1_000,
    )

    packed = _pack_surface_plans(
        [
            DefinitionUnitPlan(seeds=(first,), evidence=(first,)),
            DefinitionUnitPlan(seeds=(second,), evidence=(second,)),
        ],
        {"first.py": "small patch", "second.py": "small patch"},
        settings,
    )

    assert len(packed) == 1
    assert packed[0].seeds == (first, second)


def test_diff_surface_packing_bounds_the_lazy_definition_catalog():
    from cyberjury.review.diff.model import _pack_surface_plans

    first = DefinitionFragment("first.py", "first", 0, 100)
    second = DefinitionFragment("second.py", "second", 0, 100)
    settings = replace(
        DEFAULT_REVIEW_SETTINGS.diff,
        max_definition_evidence_items_per_unit=1,
    )

    packed = _pack_surface_plans(
        [
            DefinitionUnitPlan(seeds=(first,), evidence=(first,)),
            DefinitionUnitPlan(seeds=(second,), evidence=(second,)),
        ],
        {"first.py": "small patch", "second.py": "small patch"},
        settings,
    )

    assert [plan.seeds for plan in packed] == [(first,), (second,)]


def test_diff_keeps_alias_calls_and_navigation_sources_before_model_analysis(tmp_path):
    from cyberjury.profiles.web.facts.backend import TreeSitterFacts

    (tmp_path / "service.ts").write_text("export default function actual(value: number) { return value; }\n")
    (tmp_path / "route.ts").write_text(
        "import client from './service';\nexport function route(value: number) { return client(value); }\n"
    )
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"paths":{"@app/*":["./*"]}}}\n')
    diff = (
        "diff --git a/service.ts b/service.ts\n"
        "--- a/service.ts\n"
        "+++ b/service.ts\n"
        "@@ -1 +1 @@\n"
        "-export default function actual(value: number) { return 0; }\n"
        "+export default function actual(value: number) { return value; }\n"
    )

    collector = build_diff_context_collector(
        tmp_path,
        _profile(TreeSitterFacts()),
        review_diff=diff,
    )

    evidence = collector.relationship_evidence
    assert any(callsite.expression == "client(value)" for callsite in evidence.callsites)
    assert any(
        relationship.kind == "import" and relationship.source_file == "route.ts"
        for relationship in evidence.structural_relationships
    )
    assert "tsconfig.json" in {source.path for source in evidence.sources}


def test_collect_diff_context_respects_total_budget(tmp_path):
    diff_parts: list[str] = []
    for i in range(40):
        path = tmp_path / f"app_{i}.py"
        path.write_text("\n".join(f"value_{j} = {j}" for j in range(200)), encoding="utf-8")
        diff_parts.append(f"diff --git a/app_{i}.py b/app_{i}.py\n+++ b/app_{i}.py\n@@ -1,0 +1,1 @@\n+value = {i}\n")

    diff = "".join(diff_parts)
    units = _prepare(build_diff_context_collector(tmp_path, _profile(_FactsBackend()), review_diff=diff), diff)

    assert units
    assert all(
        len(unit.grounding.text) <= DEFAULT_REVIEW_SETTINGS.diff.target_repository_context_chars_per_unit
        for unit in units
    )


def test_diff_planning_and_grounding_are_distinct_deterministic_steps(tmp_path):
    source = "def route():\n    return sink()\n"
    (tmp_path / "route.py").write_text(source)
    diff = "diff --git a/route.py b/route.py\n+++ b/route.py\n@@ -1,2 +1,2 @@\n+def route():\n+    return sink()\n"
    collector = build_diff_context_collector(tmp_path, _profile(_FactsBackend()))

    planned = collector.plan(diff)
    grounded = collector.ground(planned)

    assert all(unit.grounding is None for unit in planned)
    assert all(unit.grounding is not None for unit in grounded)
    assert [unit.diff for unit in planned] == [unit.diff for unit in grounded]
    assert grounded[0].grounding.source_snapshot == collector.source_snapshot
    assert _prepare(collector, diff) == grounded


def test_collect_diff_context_reports_only_rendered_files(tmp_path):
    diff = "diff --git a/missing.py b/missing.py\n+++ b/missing.py\n@@ -1,0 +1,1 @@\n+print(1)\n"

    ctx = _ground(tmp_path, diff, _profile(_FactsBackend()))

    assert ctx.files == ()
    assert ctx.text == ""


def test_deleted_diff_source_is_bound_by_the_patch_not_the_post_change_snapshot(tmp_path):
    diff = (
        "diff --git a/deleted.py b/deleted.py\n"
        "--- a/deleted.py\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-dangerous_default = True\n"
    )
    collector = build_diff_context_collector(tmp_path, _profile(_FactsBackend()), review_diff=diff)

    unit = _prepare(collector, diff)[0]

    assert unit.grounding is not None
    assert unit.grounding.snapshot_files == ()
    unit.grounding.validate_snapshot()


def test_collect_diff_context_handles_hunk_lines_beyond_current_source(tmp_path):
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -100,1 +100,1 @@\n-print(0)\n+print(1)\n"

    ctx = _ground(tmp_path, diff, _profile(_FactsBackend()))

    assert "outside current source length 1" in ctx.text


def test_diff_context_collector_reuses_facts_for_batch_context(tmp_path):
    (tmp_path / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def b():\n    return 2\n", encoding="utf-8")
    backend = _FactsBackend()
    collector = build_diff_context_collector(tmp_path, _profile(backend))

    [unit_a] = _prepare(collector, "diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -1,0 +1,1 @@\n+print(a())\n")
    [unit_b] = _prepare(collector, "diff --git a/b.py b/b.py\n+++ b/b.py\n@@ -1,0 +1,1 @@\n+print(b())\n")
    ctx_a, ctx_b = unit_a.grounding, unit_b.grounding

    assert backend.extracts == 1
    assert "File: a.py" in ctx_a.text
    assert "File: b.py" not in ctx_a.text
    assert "File: b.py" in ctx_b.text


def test_diff_context_rejects_source_changes_during_facts_extraction(tmp_path):
    class MutatingBackend(_FactsBackend):
        def extract(self, root):
            (Path(root) / "app.py").write_text("def changed():\n    return 2\n")
            return Facts()

    (tmp_path / "app.py").write_text("def original():\n    return 1\n")

    with pytest.raises(BackendUnavailable, match="source changed during diff facts extraction"):
        build_diff_context_collector(tmp_path, _profile(MutatingBackend()))


def test_diff_context_reuses_a_bound_snapshot_and_rejects_drift(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def original():\n    return 1\n")
    snapshot = SourceSnapshot.capture(tmp_path, ("app.py",), scope_provider=lambda: ("app.py",))
    profile = _profile(_FactsBackend())

    collector = build_diff_context_collector(tmp_path, profile, source_snapshot=snapshot)

    assert collector.source_snapshot is snapshot
    source.write_text("def changed():\n    return 2\n")
    with pytest.raises(BackendUnavailable, match="source changed before diff facts extraction"):
        build_diff_context_collector(tmp_path, profile, source_snapshot=snapshot)


@pytest.mark.parametrize(
    ("path", "source"),
    [
        ("app.py", "def route():\n    allowed = policy()\n    return sensitive() if allowed else None\n"),
        ("policy.yaml", "require_approval: true\nrole: admin\n"),
    ],
)
def test_prepared_fallback_units_keep_current_repository_context(tmp_path, path, source):
    (tmp_path / path).write_text(source)
    collector = DiffContextCollector(
        root=tmp_path,
        detection=_detection(),
        by_file={},
        graph={},
    )
    diff = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"

    unit = _prepare(collector, diff)[0]

    assert unit.grounding is not None
    assert "Current source" in unit.grounding.text
    assert "admin" in unit.grounding.text or "sensitive" in unit.grounding.text


def test_diff_grounding_requires_a_definition_plan(tmp_path):
    collector = DiffContextCollector(root=tmp_path, detection=_detection(), by_file={}, graph={})
    unit = DiffUnit(index=1, total=1, diff="diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+x = 1\n", paths=("app.py",))

    with pytest.raises(ValueError, match="requires a definition plan"):
        collector.ground([unit])
