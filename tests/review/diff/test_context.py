"""Diff context renders bounded repository evidence and reports incomplete coverage."""

from dataclasses import replace
from pathlib import Path

import pytest

from cyberjury.review.context import GroundingContext
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.diff.context import ground_diff_unit, plan_diff_units
from cyberjury.review.diff.model import DiffUnit
from cyberjury.review.diff.prepare import prepare_diff_review
from cyberjury.review.facts import FactLimitation, Facts
from cyberjury.review.prepare import SharedGrounding
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.sources.snapshot import capture_source_snapshot
from tests.review.support import definition, shared_grounding


def _prepare(shared: SharedGrounding, diff: str) -> list[DiffUnit]:
    return [replace(unit, grounding=ground_diff_unit(unit, shared)) for unit in plan_diff_units(diff, shared, ()).units]


def _collect(shared: SharedGrounding, diff: str, plan: DefinitionUnitPlan) -> GroundingContext:
    return ground_diff_unit(DiffUnit(index=1, total=1, diff=diff, paths=(), definition_plan=plan), shared)


def _ground(root: Path, diff: str, facts: Facts | None = None) -> GroundingContext:
    units = _prepare(shared_grounding(root, facts=facts), diff)
    assert len(units) == 1
    return units[0].grounding


def _extracted(root: Path, diff: str):
    return prepare_diff_review(diff, capture_source_snapshot(root))


def test_changed_definition_is_requestable_without_an_initial_prefix(tmp_path):
    source = "class Handler(Base):\n    owner = request.user\n    control = check(owner)\n    return_value = 1\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    file_seed = definition("app.py", "<file>", 0, len(source))
    class_seed = definition("app.py", "Handler", 0, len(source))
    plan = DefinitionUnitPlan(seeds=(file_seed, class_seed))
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1 +1 @@\n"
        "-class Handler:\n"
        "+class Handler(Base):\n"
    )
    collector = shared_grounding(tmp_path)

    context = _collect(collector, diff, plan)

    assert context.source_evidence == ()
    assert "control = check(owner)" not in context.prompt.source
    assert any(item.label.startswith("app.py:Handler") for item in context.evidence)
    handler = next(item for item in context.evidence if item.label.startswith("app.py:Handler"))
    assert f"`{handler.id}`" in context.prompt.controls
    assert "complete changed definition" in handler.label
    assert "control = check(owner)" in handler.text


def test_importing_source_stays_behind_navigation_instead_of_being_preselected(tmp_path):
    changed = "def apply(value):\n    return value\n"
    related = "from service import apply\n\nclass Route:\n    permission = require_user\n    handler = apply\n"
    (tmp_path / "service.py").write_text(changed, encoding="utf-8")
    (tmp_path / "views.py").write_text(related, encoding="utf-8")
    collector = shared_grounding(tmp_path)
    plan = DefinitionUnitPlan(seeds=(definition("service.py", "apply", 0, len(changed)),))
    diff = "diff --git a/service.py b/service.py\n+++ b/service.py\n@@ -1,1 +1,1 @@\n+def apply(value):\n"

    context = _collect(collector, diff, plan)

    assert "views.py" not in context.prompt.source
    assert "permission = require_user" not in context.prompt.source


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

    context = _ground(tmp_path, diff)

    assert context.files == ("app route.py",)
    assert "def route():" in context.source_evidence[0].text
    assert context.coverage.complete is True


def test_diff_context_discloses_only_source_limitations_in_the_unit_scope(tmp_path):
    source = "def route():\n    return 1\n"
    for name in ("app.py", "related.py", "unrelated.py"):
        (tmp_path / name).write_text(source)
    route = definition("app.py", "route", 0, len(source))
    related = definition("related.py", "route", 0, len(source))
    collector = shared_grounding(
        tmp_path,
        facts=Facts(
            limitations=(
                FactLimitation(source="related.py", analyzer="python", reason="unparsable", line=1, column=1),
                FactLimitation(source="unrelated.py", analyzer="python", reason="unparsable", line=1, column=1),
            )
        ),
    )
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+def route(): return 2\n"

    context = _collect(collector, diff, DefinitionUnitPlan(seeds=(route, related)))

    assert context.coverage.limitations == ("facts:related.py:1:1",)
    assert "related.py at 1:1" in context.text
    assert "unrelated.py at 1:1" not in context.text


def test_fallback_diff_context_renders_facts_and_current_source(tmp_path):
    (tmp_path / "app.py").write_text(
        "def get_client():\n    return current_user_client()\n\ndef tool():\n    return get_client()\n",
        encoding="utf-8",
    )
    facts = Facts(by_file={"app.py": "app.py\n  tool()  calls get_client\n  get_client()"})
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -3,0 +4,2 @@\n+def tool():\n+    return get_client()\n"

    ctx = _ground(tmp_path, diff, facts)

    assert ctx.files == ("app.py",)
    assert ctx.syntax_hints.startswith("app.py: syntax hints (unverified; cite only delivered source):\n```\n")
    assert "tool()  calls get_client" in ctx.syntax_hints
    [window] = ctx.source_evidence
    assert window.text.startswith("# file: app.py lines 1-5\n1 | def get_client():")
    assert (window.source_span.start_line, window.source_span.end_line) == (1, 5)
    assert f"Initial source `{window.id}`, delivered by the review agent:" in ctx.prompt.source


def test_diff_navigation_exposes_go_package_callers_as_candidates(tmp_path):

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
    shared = _extracted(tmp_path, diff).shared
    target = next(item for item in shared.facts.relationships.definitions if item.name == "CheckPolicy")
    assert shared.navigator is not None
    session = shared.navigator.session()
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


def test_diff_grounding_exposes_candidate_callee_clues_for_changed_callers(tmp_path):

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
    prepared = _extracted(tmp_path, diff)

    unit = prepared.units[0]

    assert unit.grounding is not None
    assert "Unverified direct call candidates from this unit" in unit.grounding.text
    assert "service.py:load" in unit.grounding.text
    candidate_source = unit.grounding.source_evidence[0]
    assert "def load(value)" in candidate_source.text
    assert candidate_source.id in unit.grounding.prompt.source
    assert (
        f"Initial source `{candidate_source.id}`, delivered by the review agent:\n```\n{candidate_source.text}\n```"
        in unit.grounding.prompt.source
    )
    assert f"source `{candidate_source.id}` delivered below" in unit.grounding.text
    assert "service.py" in unit.grounding.snapshot_files

    execution = replace(DEFAULT_REVIEW_SETTINGS.execution, max_initial_candidate_source_chars=1)
    requestable = ground_diff_unit(replace(unit, grounding=None), prepared.shared, execution=execution)
    assert requestable is not None
    assert requestable.source_evidence == ()
    assert any(item.source_span and item.source_span.file == "service.py" for item in requestable.evidence)
    assert "service.py" in requestable.snapshot_files


def test_diff_keeps_alias_calls_and_navigation_sources_before_model_analysis(tmp_path):

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

    evidence = _extracted(tmp_path, diff).shared.facts.relationships
    assert any(callsite.expression == "client(value)" for callsite in evidence.callsites)
    assert any(
        relationship.kind == "import" and relationship.source.path == "route.ts"
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
    units = _prepare(shared_grounding(tmp_path), diff)

    assert units
    assert all(
        len(unit.grounding.prompt.source.removeprefix(f"{unit.grounding.seed}\n\n"))
        <= DEFAULT_REVIEW_SETTINGS.diff.target_repository_context_chars_per_unit
        for unit in units
    )


def test_diff_planning_and_grounding_are_distinct_deterministic_steps(tmp_path):
    source = "def route():\n    return sink()\n"
    (tmp_path / "route.py").write_text(source)
    diff = "diff --git a/route.py b/route.py\n+++ b/route.py\n@@ -1,2 +1,2 @@\n+def route():\n+    return sink()\n"
    shared = shared_grounding(tmp_path)

    planned = plan_diff_units(diff, shared, ()).units
    grounded = _prepare(shared, diff)

    assert all(unit.grounding is None for unit in planned)
    assert all(unit.grounding is not None for unit in grounded)
    assert [unit.diff for unit in planned] == [unit.diff for unit in grounded]
    assert grounded[0].grounding.source_snapshot == shared.snapshot
    assert _prepare(shared, diff) == grounded


def test_collect_diff_context_reports_only_rendered_files(tmp_path):
    diff = "diff --git a/missing.py b/missing.py\n+++ b/missing.py\n@@ -1,0 +1,1 @@\n+print(1)\n"

    ctx = _ground(tmp_path, diff)

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
    unit = _prepare(shared_grounding(tmp_path), diff)[0]

    assert unit.grounding is not None
    assert unit.grounding.snapshot_files == ()


def test_collect_diff_context_handles_hunk_lines_beyond_current_source(tmp_path):
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -100,1 +100,1 @@\n-print(0)\n+print(1)\n"

    ctx = _ground(tmp_path, diff)

    assert "outside current source length 1" in ctx.text


def test_diff_units_share_one_facts_context_for_batch_context(tmp_path):
    (tmp_path / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def b():\n    return 2\n", encoding="utf-8")
    diff_a = "diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -1,0 +1,1 @@\n+print(a())\n"
    diff_b = "diff --git a/b.py b/b.py\n+++ b/b.py\n@@ -1,0 +1,1 @@\n+print(b())\n"
    shared = shared_grounding(tmp_path)

    [unit_a] = _prepare(shared, diff_a)
    [unit_b] = _prepare(shared, diff_b)
    ctx_a, ctx_b = unit_a.grounding, unit_b.grounding

    assert [item.source_span.file for item in ctx_a.source_evidence] == ["a.py"]
    assert [item.source_span.file for item in ctx_b.source_evidence] == ["b.py"]


@pytest.mark.parametrize(
    ("path", "source"),
    [
        ("app.py", "def route():\n    allowed = policy()\n    return sensitive() if allowed else None\n"),
        ("policy.yaml", "require_approval: true\nrole: admin\n"),
    ],
)
def test_prepared_fallback_units_keep_current_repository_context(tmp_path, path, source):
    (tmp_path / path).write_text(source)
    collector = shared_grounding(tmp_path)
    diff = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"

    unit = _prepare(collector, diff)[0]

    assert unit.grounding is not None
    [window] = unit.grounding.source_evidence
    assert window.text.startswith(f"# file: {path} lines 1-")
    assert "admin" in window.text or "sensitive" in window.text


def test_changed_file_windows_center_on_every_changed_region_of_any_text_file(tmp_path):
    lines = [f"<p>line {number}</p>" for number in range(1, 2001)]
    (tmp_path / "page.html").write_text("\n".join(lines) + "\n", encoding="utf-8")
    diff = (
        "diff --git a/page.html b/page.html\n--- a/page.html\n+++ b/page.html\n"
        "@@ -900 +900 @@\n-<p>old</p>\n+<p>line 900</p>\n"
    )

    ctx = _ground(tmp_path, diff)

    spans = [(item.source_span.start_line, item.source_span.end_line) for item in ctx.source_evidence]
    assert spans[0] == (895, 905)
    assert spans[1][0] == 1
    assert "<p>line 900</p>" in ctx.source_evidence[0].text


def test_changed_file_windows_stay_inside_the_context_budget_as_exact_line_ranges(tmp_path):
    from cyberjury.review.context import delivered_source_block
    from cyberjury.review.diff.context import changed_file_sources

    (tmp_path / "app.py").write_text("".join(f"value_{index} = {index}\n" for index in range(1, 4000)))

    _text, delivered = changed_file_sources(tmp_path, ("app.py",), {})

    [window] = delivered
    limit = DEFAULT_REVIEW_SETTINGS.diff.target_repository_context_chars_per_unit
    assert len(delivered_source_block(window)) + 2 <= limit
    assert window.source_span.start_line == 1
    assert window.text.endswith(f"value_{window.source_span.end_line} = {window.source_span.end_line}")


def test_a_changed_file_without_a_seed_definition_gets_windows_and_hints_beside_seeded_files(tmp_path):
    (tmp_path / "views.py").write_text("def show(request):\n    return render(request)\n", encoding="utf-8")
    (tmp_path / "settings.py").write_text(
        "import os\n\nSECRET_KEY = os.environ.get('KEY')\nDEBUG = True\n", encoding="utf-8"
    )
    diff = (
        "diff --git a/views.py b/views.py\n--- a/views.py\n+++ b/views.py\n@@ -2 +2 @@\n"
        "-    return render(request, safe=True)\n+    return render(request)\n"
        "diff --git a/settings.py b/settings.py\n--- a/settings.py\n+++ b/settings.py\n@@ -4 +4 @@\n"
        "-DEBUG = False\n+DEBUG = True\n"
    )
    prepared = _extracted(tmp_path, diff)

    [unit] = prepared.units
    grounding = unit.grounding

    assert {seed.kind for seed in unit.definition_plan.seeds if seed.source.path == "settings.py"} == {"file"}
    assert [item.source_span.file for item in grounding.source_evidence] == ["settings.py"]
    assert grounding.files == ("settings.py",)
    assert grounding.syntax_hints.startswith("settings.py: syntax hints")
    assert "views.py: syntax hints" not in grounding.syntax_hints
    assert any(item.label.startswith("views.py:show") for item in grounding.evidence)
