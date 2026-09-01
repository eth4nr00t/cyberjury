"""Diff context renders bounded repository evidence and reports incomplete coverage."""

from dataclasses import replace
from pathlib import Path

import pytest

from cyberjury.detection import load_detection
from cyberjury.profiles.registry import default_profile, get_profile
from cyberjury.review.definitions import DefinitionDependency, DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.diff.context import (
    DiffContextCollector,
    build_diff_context_collector,
    collect_diff_context,
)
from cyberjury.review.facts import BackendUnavailable, FactLimitation, Facts, FactsBackend, definition_dependencies
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS


class _FactsBackend(FactsBackend):
    def __init__(self, facts: Facts | None = None, available: bool = True) -> None:
        self._facts = facts or Facts()
        self._available = available
        self.install_hint = "install test facts"
        self.extracts = 0

    def available(self) -> bool:
        return self._available

    def extract(self, root: str | Path) -> Facts:
        self.extracts += 1
        return self._facts


def _profile(backend: FactsBackend):
    return replace(default_profile(), facts_backend=backend)


def _evm_profile(backend: FactsBackend):
    return replace(get_profile("evm"), facts_backend=backend)


def _dependency(
    source_file: str,
    target: tuple[str, str, int, int],
    source: tuple[str, str, int, int] | None = None,
) -> dict[str, object]:
    def record(fragment: tuple[str, str, int, int]) -> dict[str, object]:
        file, name, start, end = fragment
        return {"file": file, "name": name, "range": [start, end]}

    return {
        "source_file": source_file,
        "source": record(source) if source is not None else None,
        "target": record(target),
    }


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

    context = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(Facts())))

    assert context.files == ("app route.py",)
    assert "def route():" in context.text
    assert context.coverage.complete is True


def test_diff_context_discloses_only_source_limitations_in_the_unit_scope(tmp_path):
    for name in ("app.py", "related.py", "unrelated.py"):
        (tmp_path / name).write_text("def route():\n    return 1\n")
    facts = Facts(
        data={"graph": {"callgraph": {}, "import_targets": {"app.py": ["related.py"]}}},
        limitations=(
            FactLimitation(source="related.py", analyzer="python", reason="unparsable", line=1, column=1),
            FactLimitation(source="unrelated.py", analyzer="python", reason="unparsable", line=1, column=1),
        ),
    )
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+def route(): return 2\n"

    context = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

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
    plan = DefinitionUnitPlan(
        seeds=(source,),
        dependencies=(DefinitionDependency("app.py", target, source, "call"),),
        evidence=(source,),
    )
    collector = DiffContextCollector(
        root=tmp_path,
        detection=load_detection(default_profile().paths.detection_file),
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

    context = collector.collect(diff, plan)

    assert context.files == ()
    assert context.coverage.limitations == ("facts:service.py:1:1",)
    assert any(item.identity == target.identity for item in context.evidence)


def test_collect_diff_context_renders_facts_and_current_source(tmp_path):
    (tmp_path / "app.py").write_text(
        "def get_client():\n    return current_user_client()\n\ndef tool():\n    return get_client()\n",
        encoding="utf-8",
    )
    facts = Facts(
        summary="Call graph",
        data={
            "by_file": {"app.py": "app.py\n  tool()  calls get_client\n  get_client()"},
            "graph": {
                "callgraph": {
                    "app.py": {
                        "tool": [{"range": [57, 92], "calls": ["get_client"]}],
                        "get_client": [{"range": [0, 56], "calls": ["current_user_client"]}],
                    }
                },
                "imports": {},
                "dependencies": [
                    _dependency(
                        "app.py",
                        ("app.py", "get_client", 0, 56),
                        ("app.py", "tool", 57, 92),
                    )
                ],
            },
        },
    )
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -3,0 +4,2 @@\n+def tool():\n+    return get_client()\n"

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert ctx.source == "diff"
    assert ctx.files == ("app.py",)
    assert "Facts:" in ctx.text
    assert "tool()  calls get_client" in ctx.text
    assert "current_user_client" in ctx.text
    assert "   1: def get_client():" in ctx.text


def test_collect_diff_context_prefixes_scoped_facts_to_repository_paths(tmp_path):
    scope = tmp_path / "contracts"
    scope.mkdir()
    (scope / "Token.sol").write_text("contract Token {\n    function mint() public {}\n}\n", encoding="utf-8")
    (scope / "Use.sol").write_text(
        "import './Token.sol';\ncontract Use {\n    function callMint() public {}\n}\n", encoding="utf-8"
    )
    facts = Facts(
        data={
            "by_file": {"Token.sol": "Token.sol\n  mint()"},
            "graph": {
                "callgraph": {
                    "Token.sol": {"mint": [{"range": [17, 41], "calls": []}]},
                    "Use.sol": {"callMint": [{"range": [36, 66], "calls": ["mint"]}]},
                },
                "imports": {"Use.sol": ["mint"]},
                "import_targets": {"Use.sol": ["Token.sol"]},
                "dependencies": [
                    _dependency(
                        "Use.sol",
                        ("Token.sol", "mint", 17, 41),
                        ("Use.sol", "callMint", 36, 66),
                    )
                ],
            },
        },
    )
    diff = (
        "diff --git a/contracts/Token.sol b/contracts/Token.sol\n"
        "+++ b/contracts/Token.sol\n"
        "@@ -2,0 +2,1 @@\n"
        "+    function mint() public {}\n"
    )

    collector = build_diff_context_collector(tmp_path, _evm_profile(_FactsBackend(facts)), facts_root=scope)
    ctx = collector.collect(diff)

    assert ctx.files == ("contracts/Token.sol",)
    assert "Facts:" in ctx.text
    assert "Token.sol\n  mint()" in ctx.text
    assert "File: contracts/Use.sol" in ctx.text
    dependency = definition_dependencies(collector.graph)[0]
    assert dependency.source.file == "contracts/Use.sol"
    assert dependency.target.file == "contracts/Token.sol"
    assert collector.source_snapshot is not None
    assert collector.source_snapshot.root == tmp_path.resolve()
    assert collector.source_snapshot.matches_files(("contracts/Token.sol",))
    ctx.validate_snapshot()


def test_collect_diff_context_rejects_facts_root_outside_repository(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()

    with pytest.raises(BackendUnavailable, match="outside repository root"):
        build_diff_context_collector(tmp_path, _profile(_FactsBackend()), facts_root=outside)


def test_collect_diff_context_renders_same_file_helper_definitions(tmp_path):
    source = (
        "def route(server_id, tool, allowed):\n"
        "    denied = _denied_if_not_declared(server_id, tool, allowed)\n"
        "    if denied is not None:\n"
        "        return denied\n"
        "    return call_tool(server_id, tool)\n"
        "\n"
        "\n"
        "def _denied_if_not_declared(server_id, tool, allowed):\n"
        "    if _tool_declared(server_id, tool, allowed):\n"
        "        return None\n"
        '    return {"reason": "tool_not_declared"}\n'
        "\n"
        "\n"
        "def _tool_declared(server_id, tool, allowed):\n"
        "    return server_id in allowed and tool in allowed[server_id]\n"
    )
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    facts = Facts(
        data={
            "by_file": {"app.py": "app.py\n  route()  calls _denied_if_not_declared"},
            "graph": {
                "callgraph": {
                    "app.py": {
                        "route": [
                            {
                                "range": [source.index("def route"), source.index("\n\n\ndef _denied")],
                                "calls": ["_denied_if_not_declared", "call_tool"],
                            }
                        ],
                        "_denied_if_not_declared": [
                            {
                                "range": [source.index("def _denied"), source.index("\n\n\ndef _tool")],
                                "calls": ["_tool_declared"],
                            }
                        ],
                        "_tool_declared": [
                            {
                                "range": [source.index("def _tool"), len(source)],
                                "calls": [],
                            }
                        ],
                    }
                },
                "imports": {},
                "dependencies": [
                    _dependency(
                        "app.py",
                        (
                            "app.py",
                            "_denied_if_not_declared",
                            source.index("def _denied"),
                            source.index("\n\n\ndef _tool"),
                        ),
                        ("app.py", "route", source.index("def route"), source.index("\n\n\ndef _denied")),
                    ),
                    _dependency(
                        "app.py",
                        ("app.py", "_tool_declared", source.index("def _tool"), len(source)),
                        (
                            "app.py",
                            "_denied_if_not_declared",
                            source.index("def _denied"),
                            source.index("\n\n\ndef _tool"),
                        ),
                    ),
                ],
            },
        },
    )
    diff = (
        "diff --git a/app.py b/app.py\n"
        "+++ b/app.py\n"
        "@@ -3,1 +5,1 @@\n"
        "-    return call_tool(server_id, tool)\n"
        "+    return call_tool(server_id, tool)\n"
    )

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert "Definition _denied_if_not_declared:" in ctx.text
    assert "Definition _tool_declared:" in ctx.text
    assert "tool_not_declared" in ctx.text


def test_collect_diff_context_includes_reverse_import_callers_for_changed_helpers(tmp_path):
    """A barrel export must not hide the entrypoint that consumes a changed helper."""
    (tmp_path / "utils").mkdir()
    (tmp_path / "controllers").mkdir()
    (tmp_path / "utils" / "dataStore.ts").write_text(
        "export const blendData = (target, source) => {\n"
        "  Object.keys(source).forEach((key) => {\n"
        "    target[key] = source[key];\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )
    (tmp_path / "utils" / "index.ts").write_text("export * from './dataStore';\n", encoding="utf-8")
    (tmp_path / "controllers" / "request.controller.ts").write_text(
        "import { blendData } from '../utils';\n"
        "export function testConnection(body) {\n"
        "  const config = {};\n"
        "  blendData(config, body);\n"
        "  return config;\n"
        "}\n",
        encoding="utf-8",
    )
    facts = Facts(
        data={
            "by_file": {
                "utils/dataStore.ts": "utils/dataStore.ts\n  blendData()  calls keys, forEach",
                "utils/index.ts": "utils/index.ts\n  imports blendData",
                "controllers/request.controller.ts": "controllers/request.controller.ts\n  imports blendData\n"
                "  testConnection()  calls blendData",
            },
            "graph": {
                "callgraph": {
                    "utils/dataStore.ts": {"blendData": [{"range": [0, 126], "calls": ["keys", "forEach"]}]},
                    "utils/index.ts": {},
                    "controllers/request.controller.ts": {
                        "testConnection": [{"range": [37, 138], "calls": ["blendData"]}]
                    },
                },
                "imports": {
                    "utils/index.ts": ["blendData"],
                    "controllers/request.controller.ts": ["blendData"],
                },
                "import_targets": {
                    "utils/index.ts": ["utils/dataStore.ts"],
                    "controllers/request.controller.ts": ["utils/index.ts"],
                },
                "dependencies": [
                    _dependency(
                        "controllers/request.controller.ts",
                        ("utils/dataStore.ts", "blendData", 0, 126),
                        ("controllers/request.controller.ts", "testConnection", 37, 138),
                    )
                ],
            },
        },
    )
    diff = (
        "diff --git a/utils/dataStore.ts b/utils/dataStore.ts\n"
        "+++ b/utils/dataStore.ts\n"
        "@@ -1,0 +1,4 @@\n"
        "+export const blendData = (target, source) => {\n"
        "+  Object.keys(source).forEach((key) => {\n"
        "+    target[key] = source[key];\n"
        "+  });\n"
    )

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert ctx.files == ("utils/dataStore.ts",)
    assert "File: controllers/request.controller.ts" in ctx.text
    assert "blendData(config, body)" in ctx.text


def test_collect_diff_context_follows_renamed_wrappers_to_repository_entrypoints(tmp_path):
    """Reverse traversal follows each imported name instead of assuming one symbol survives every layer."""
    (tmp_path / "leaf.py").write_text("def leaf():\n    return 1\n", encoding="utf-8")
    (tmp_path / "middle.py").write_text(
        "from leaf import leaf\n\ndef wrapper():\n    return leaf()\n",
        encoding="utf-8",
    )
    (tmp_path / "entry.py").write_text(
        "from middle import wrapper\n\ndef endpoint():\n    return wrapper()\n",
        encoding="utf-8",
    )
    facts = Facts(
        data={
            "by_file": {},
            "graph": {
                "callgraph": {
                    "leaf.py": {"leaf": [{"range": [0, 25], "calls": []}]},
                    "middle.py": {"wrapper": [{"range": [23, 57], "calls": ["leaf"]}]},
                    "entry.py": {"endpoint": [{"range": [28, 65], "calls": ["wrapper"]}]},
                },
                "imports": {
                    "middle.py": ["leaf"],
                    "entry.py": ["wrapper"],
                },
                "import_targets": {
                    "middle.py": ["leaf.py"],
                    "entry.py": ["middle.py"],
                },
                "dependencies": [
                    _dependency(
                        "middle.py",
                        ("leaf.py", "leaf", 0, 25),
                        ("middle.py", "wrapper", 23, 57),
                    ),
                    _dependency(
                        "entry.py",
                        ("middle.py", "wrapper", 23, 57),
                        ("entry.py", "endpoint", 28, 65),
                    ),
                ],
            },
        }
    )
    diff = "diff --git a/leaf.py b/leaf.py\n+++ b/leaf.py\n@@ -1,0 +1,2 @@\n+def leaf():\n+    return 1\n"

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert "File: entry.py" in ctx.text
    assert "return wrapper()" in ctx.text


def test_collect_diff_context_includes_reverse_callers_for_same_package_helpers(tmp_path):
    """Same package calls need a reverse edge even when no import connects the files."""
    policy = "package app\n\nfunc CheckPolicy(value string) bool {\n    return true\n}\n"
    service = "package app\n\nfunc ApplyPolicy(value string) bool {\n    return CheckPolicy(value)\n}\n"
    (tmp_path / "policy.go").write_text(policy, encoding="utf-8")
    (tmp_path / "service.go").write_text(service, encoding="utf-8")
    policy_start = policy.index("func")
    service_start = service.index("func")
    facts = Facts(
        data={
            "by_file": {
                "policy.go": "policy.go\n  CheckPolicy()",
                "service.go": "service.go\n  ApplyPolicy()  calls CheckPolicy",
            },
            "graph": {
                "callgraph": {
                    "policy.go": {"CheckPolicy": [{"range": [policy_start, len(policy)], "calls": []}]},
                    "service.go": {"ApplyPolicy": [{"range": [service_start, len(service)], "calls": ["CheckPolicy"]}]},
                },
                "imports": {},
                "import_targets": {},
                "dependencies": [
                    _dependency(
                        "service.go",
                        ("policy.go", "CheckPolicy", policy_start, len(policy)),
                        ("service.go", "ApplyPolicy", service_start, len(service)),
                    )
                ],
            },
        },
    )
    diff = "diff --git a/policy.go b/policy.go\n+++ b/policy.go\n@@ -3,1 +3,1 @@\n+    return value != ''\n"

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert ctx.files == ("policy.go",)
    assert "File: service.go" in ctx.text
    assert "CheckPolicy(value)" in ctx.text


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
    assert "not established call relationships" in candidates.text


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
        subject.kind == "import" and subject.source_file == "route.ts" for subject in evidence.structural_subjects
    )
    assert "tsconfig.json" in {source.path for source in evidence.sources}


def test_collect_diff_context_includes_related_definitions_for_small_multi_file_diffs(tmp_path):
    """A small multi file patch still needs the unchanged helper behind its changed wrapper."""
    (tmp_path / "utils").mkdir()
    (tmp_path / "apps").mkdir()
    (tmp_path / "utils" / "__init__.py").write_text(
        "from secure import secure_random\n\ndef make_nonce():\n    return secure_random()\n",
        encoding="utf-8",
    )
    (tmp_path / "utils" / "api_utils.py").write_text(
        "from utils import make_nonce\n\ndef build_temporary_credential(tenant_id):\n    return make_nonce()\n",
        encoding="utf-8",
    )
    (tmp_path / "apps" / "api_app.py").write_text(
        "from utils.api_utils import build_temporary_credential\n\n"
        "def issue_credential(tenant_id):\n"
        "    return build_temporary_credential(tenant_id)\n",
        encoding="utf-8",
    )
    facts = Facts(
        data={
            "by_file": {
                "utils/__init__.py": "utils/__init__.py\n  imports uuid\n  make_nonce()  calls uuid1",
                "utils/api_utils.py": "utils/api_utils.py\n  imports make_nonce\n"
                "  build_temporary_credential()  calls make_nonce",
                "apps/api_app.py": "apps/api_app.py\n  imports build_temporary_credential\n"
                "  issue_credential()  calls build_temporary_credential",
            },
            "graph": {
                "callgraph": {
                    "utils/__init__.py": {"make_nonce": [{"range": [13, 58], "calls": ["secure_random"]}]},
                    "utils/api_utils.py": {
                        "build_temporary_credential": [{"range": [28, 95], "calls": ["make_nonce"]}]
                    },
                    "apps/api_app.py": {
                        "issue_credential": [{"range": [58, 130], "calls": ["build_temporary_credential"]}]
                    },
                },
                "imports": {
                    "utils/api_utils.py": ["make_nonce"],
                    "apps/api_app.py": ["build_temporary_credential"],
                },
                "import_targets": {
                    "utils/api_utils.py": ["utils/__init__.py"],
                    "apps/api_app.py": ["utils/api_utils.py"],
                },
                "dependencies": [
                    _dependency(
                        "apps/api_app.py",
                        ("utils/api_utils.py", "build_temporary_credential", 28, 95),
                        ("apps/api_app.py", "issue_credential", 58, 130),
                    ),
                    _dependency(
                        "utils/api_utils.py",
                        ("utils/__init__.py", "make_nonce", 13, 58),
                        ("utils/api_utils.py", "build_temporary_credential", 28, 95),
                    ),
                ],
            },
        },
    )
    diff = (
        "diff --git a/apps/api_app.py b/apps/api_app.py\n"
        "+++ b/apps/api_app.py\n"
        "@@ -1,0 +1,1 @@\n"
        "+from utils.api_utils import build_temporary_credential\n"
        "diff --git a/utils/api_utils.py b/utils/api_utils.py\n"
        "+++ b/utils/api_utils.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+from utils import make_nonce\n"
        "+def build_temporary_credential(tenant_id): return make_nonce()\n"
    )

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert ctx.files == ("apps/api_app.py", "utils/api_utils.py")
    assert "File: utils/__init__.py" in ctx.text
    assert "secure_random()" in ctx.text


def test_collect_diff_context_keeps_direct_import_definitions_for_large_diffs(tmp_path):
    """Changed file volume must not evict a directly imported definition."""
    (tmp_path / "utils").mkdir()
    (tmp_path / "apps").mkdir()
    (tmp_path / "utils" / "__init__.py").write_text(
        "from secure import secure_random\n\ndef make_nonce():\n    return secure_random()\n",
        encoding="utf-8",
    )
    (tmp_path / "apps" / "api_app.py").write_text(
        "from utils import make_nonce\n\ndef issue_credential(tenant_id):\n    return make_nonce()\n",
        encoding="utf-8",
    )
    by_file = {
        "utils/__init__.py": "utils/__init__.py\n  imports uuid\n  make_nonce()  calls uuid1",
        "apps/api_app.py": "apps/api_app.py\n  imports make_nonce\n  issue_credential()  calls make_nonce",
    }
    callgraph = {
        "utils/__init__.py": {"make_nonce": [{"range": [13, 58], "calls": ["secure_random"]}]},
        "apps/api_app.py": {"issue_credential": [{"range": [28, 85], "calls": ["make_nonce"]}]},
    }
    imports = {"apps/api_app.py": ["make_nonce"]}
    import_targets = {"apps/api_app.py": ["utils/__init__.py"]}
    diff = (
        "diff --git a/apps/api_app.py b/apps/api_app.py\n"
        "+++ b/apps/api_app.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+from utils import make_nonce\n"
        "+def issue_credential(tenant_id): return make_nonce()\n"
    )
    for i in range(5):
        path = tmp_path / f"changed_{i}.py"
        path.write_text(f"value_{i} = {i}\n", encoding="utf-8")
        rel = f"changed_{i}.py"
        by_file[rel] = f"{rel}\n  value_{i}"
        callgraph[rel] = {}
        diff += f"diff --git a/{rel} b/{rel}\n+++ b/{rel}\n@@ -1,0 +1,1 @@\n+value_{i} = {i}\n"
    facts = Facts(
        data={
            "by_file": by_file,
            "graph": {
                "callgraph": callgraph,
                "imports": imports,
                "import_targets": import_targets,
                "dependencies": [
                    _dependency(
                        "apps/api_app.py",
                        ("utils/__init__.py", "make_nonce", 13, 58),
                        ("apps/api_app.py", "issue_credential", 28, 85),
                    )
                ],
            },
        },
    )

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert "File: utils/__init__.py" in ctx.text
    assert "secure_random()" in ctx.text
    assert ctx.text.index("File: utils/__init__.py") < ctx.text.index("File: apps/api_app.py")


def test_collect_diff_context_prioritizes_imported_definitions_over_unrelated_symbol_matches(tmp_path):
    """Symbol collisions must not displace the implementation called by changed code."""
    (tmp_path / "apps").mkdir()
    (tmp_path / "utils").mkdir()
    (tmp_path / "apps" / "api_app.py").write_text(
        "from utils import current_timestamp, get_uuid\n\n"
        "def issue_token():\n"
        "    return get_uuid(), current_timestamp()\n",
        encoding="utf-8",
    )
    definition = (
        "import uuid\n\ndef get_uuid():\n    return uuid.uuid1().hex\n\ndef current_timestamp():\n    return 1\n"
    )
    (tmp_path / "utils" / "__init__.py").write_text(definition, encoding="utf-8")
    by_file = {
        "apps/api_app.py": "apps/api_app.py\n  imports current_timestamp, get_uuid\n"
        "  issue_token()  calls get_uuid, current_timestamp",
        "utils/__init__.py": "utils/__init__.py\n  imports uuid\n  get_uuid()  calls uuid1\n  current_timestamp()",
    }
    callgraph = {
        "apps/api_app.py": {"issue_token": [{"range": [47, 111], "calls": ["get_uuid", "current_timestamp"]}]},
        "utils/__init__.py": {
            "get_uuid": [{"range": [13, 56], "calls": ["uuid1"]}],
            "current_timestamp": [{"range": [58, len(definition)], "calls": []}],
        },
    }
    imports = {"apps/api_app.py": ["current_timestamp", "get_uuid"]}
    import_targets = {"apps/api_app.py": ["utils/__init__.py"]}
    for index in range(5):
        rel = f"consumer_{index}.py"
        source = "def current_timestamp():\n    return '" + ("x" * 7_000) + "'\n"
        (tmp_path / rel).write_text(source, encoding="utf-8")
        by_file[rel] = f"{rel}\n  current_timestamp()"
        callgraph[rel] = {"current_timestamp": [{"range": [0, len(source)], "calls": []}]}
    facts = Facts(
        data={
            "by_file": by_file,
            "graph": {
                "callgraph": callgraph,
                "imports": imports,
                "import_targets": import_targets,
                "dependencies": [
                    _dependency(
                        "apps/api_app.py",
                        ("utils/__init__.py", "current_timestamp", 58, len(definition)),
                        ("apps/api_app.py", "issue_token", 47, 111),
                    ),
                    _dependency(
                        "apps/api_app.py",
                        ("utils/__init__.py", "get_uuid", 13, 56),
                        ("apps/api_app.py", "issue_token", 47, 111),
                    ),
                ],
            },
        }
    )
    diff = (
        "diff --git a/apps/api_app.py b/apps/api_app.py\n"
        "+++ b/apps/api_app.py\n"
        "@@ -1,0 +1,4 @@\n"
        "+from utils import current_timestamp, get_uuid\n"
        "+\n"
        "+def issue_token():\n"
        "+    return get_uuid(), current_timestamp()\n"
    )

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert "File: utils/__init__.py" in ctx.text
    assert ctx.coverage.required == (
        f"utils/__init__.py:current_timestamp:58:{len(definition)}",
        "utils/__init__.py:get_uuid:13:56",
    )
    assert "return uuid.uuid1().hex" in ctx.text
    assert "File: consumer_0.py" in ctx.text
    assert ctx.text.index("File: utils/__init__.py") < ctx.text.index("File: consumer_0.py")


def test_batch_context_prioritizes_related_changes_from_the_full_diff(tmp_path):
    """A related changed helper wins the limited context slots for one batch."""
    (tmp_path / "controller.ts").write_text(
        "export function handle(body) {\n  alpha();\n  beta();\n  mergeOptions(config, body);\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "index.ts").write_text("export * from './helper';\n", encoding="utf-8")
    (tmp_path / "helper.ts").write_text(
        "export const mergeOptions = (target, source) => {\n  target.value = source.value;\n};\n",
        encoding="utf-8",
    )
    distractor_sources = {}
    for name in ("alpha.ts", "beta.ts"):
        symbol = name.removesuffix(".ts")
        source = f"export const {symbol} = () => '" + ("x" * 7_000) + "';\n"
        distractor_sources[name] = source
        (tmp_path / name).write_text(source, encoding="utf-8")

    by_file = {}
    callgraph = {
        "controller.ts": {"handle": [{"range": [0, 85], "calls": ["mergeOptions"]}]},
        "index.ts": {},
        "helper.ts": {"mergeOptions": [{"range": [0, 84], "calls": []}]},
        "alpha.ts": {"alpha": [{"range": [0, len(distractor_sources["alpha.ts"])], "calls": []}]},
        "beta.ts": {"beta": [{"range": [0, len(distractor_sources["beta.ts"])], "calls": []}]},
    }
    imports = {"controller.ts": ["alpha", "beta", "mergeOptions"], "index.ts": ["mergeOptions"]}
    import_targets = {
        "controller.ts": ["alpha.ts", "beta.ts", "index.ts"],
        "index.ts": ["helper.ts"],
    }
    batch_parts = [
        "diff --git a/controller.ts b/controller.ts\n"
        "+++ b/controller.ts\n"
        "@@ -1,0 +1,5 @@\n"
        "+export function handle(body) {\n"
        "+  alpha();\n"
        "+  beta();\n"
        "+  mergeOptions({}, body);\n"
        "+}\n"
    ]
    for index in range(5):
        rel = f"noise_{index}.ts"
        (tmp_path / rel).write_text(f"export const value{index} = {index};\n", encoding="utf-8")
        callgraph[rel] = {}
        batch_parts.append(
            f"diff --git a/{rel} b/{rel}\n+++ b/{rel}\n@@ -1,0 +1,1 @@\n+export const value{index} = {index};\n"
        )
    batch_diff = "".join(batch_parts)
    helper_diff = (
        "diff --git a/helper.ts b/helper.ts\n"
        "+++ b/helper.ts\n"
        "@@ -1,3 +1,3 @@\n"
        " export const mergeOptions = (target, source) => {\n"
        "-  target.value = target.value;\n"
        "+  target.value = source.value;\n"
        " };\n"
    )
    distractor_diffs = "".join(
        f"diff --git a/{name} b/{name}\n+++ b/{name}\n@@ -1,0 +1,1 @@\n+export const version = 2;\n"
        for name in ("alpha.ts", "beta.ts")
    )
    facts = Facts(
        data={
            "by_file": by_file,
            "graph": {
                "callgraph": callgraph,
                "imports": imports,
                "import_targets": import_targets,
                "dependencies": [
                    _dependency(
                        "controller.ts",
                        ("helper.ts", "mergeOptions", 0, 84),
                        ("controller.ts", "handle", 0, 85),
                    )
                ],
            },
        }
    )
    collector = build_diff_context_collector(
        tmp_path,
        _profile(_FactsBackend(facts)),
        review_diff=batch_diff + distractor_diffs + helper_diff,
    )

    ctx = collector.collect(batch_diff)

    assert "File: helper.ts" in ctx.text
    assert "Definition mergeOptions:" in ctx.text
    assert "target.value = source.value" in ctx.text
    assert ctx.text.index("File: helper.ts") < ctx.text.index("File: controller.ts")


def test_collect_diff_context_respects_total_budget(tmp_path):
    diff_parts: list[str] = []
    for i in range(40):
        path = tmp_path / f"app_{i}.py"
        path.write_text("\n".join(f"value_{j} = {j}" for j in range(200)), encoding="utf-8")
        diff_parts.append(f"diff --git a/app_{i}.py b/app_{i}.py\n+++ b/app_{i}.py\n@@ -1,0 +1,1 @@\n+value = {i}\n")

    ctx = collect_diff_context(tmp_path, "".join(diff_parts), _profile(_FactsBackend()))

    assert len(ctx.text) <= DEFAULT_REVIEW_SETTINGS.diff.target_repository_context_chars_per_unit


def test_collect_diff_context_requires_receiver_import_definitions(tmp_path):
    route = (
        "from domain.models import AccessRule\n\ndef handle(user):\n    return AccessRule.objects.filter(user=user)\n"
    )
    model = "class AccessRule:\n    owner = 'user'\n"
    (tmp_path / "routes.py").write_text(route, encoding="utf-8")
    (tmp_path / "domain").mkdir()
    (tmp_path / "domain" / "models.py").write_text(model, encoding="utf-8")
    facts = Facts(
        data={
            "graph": {
                "callgraph": {
                    "routes.py": {"handle": [{"range": [38, len(route)], "calls": ["filter"]}]},
                    "domain/models.py": {"AccessRule": [{"range": [0, len(model)], "calls": []}]},
                },
                "imports": {"routes.py": ["AccessRule"]},
                "import_targets": {"routes.py": ["domain/models.py"]},
                "dependencies": [_dependency("routes.py", ("domain/models.py", "AccessRule", 0, len(model)))],
            }
        }
    )
    diff = (
        "diff --git a/routes.py b/routes.py\n"
        "+++ b/routes.py\n"
        "@@ -4,1 +4,1 @@\n"
        "+    return AccessRule.objects.filter(user=user)\n"
    )

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert ctx.coverage.required == (f"domain/models.py:AccessRule:0:{len(model)}",)
    assert ctx.coverage.included == ctx.coverage.required
    assert ctx.coverage.complete is True
    assert "Definition AccessRule:" in ctx.text


def test_changed_definition_requires_a_callee_from_an_unchanged_call_line(tmp_path):
    route = (
        "from service import load_account\n\n"
        "def handle(user):\n"
        "    allowed = user.is_admin\n"
        "    account = load_account(user.account_id)\n"
        "    return account if allowed else None\n"
    )
    service = "def load_account(account_id):\n    return Account.objects.get(id=account_id)\n"
    (tmp_path / "route.py").write_text(route, encoding="utf-8")
    (tmp_path / "service.py").write_text(service, encoding="utf-8")
    handle_start = route.index("def handle")
    facts = Facts(
        data={
            "graph": {
                "callgraph": {
                    "route.py": {"handle": [{"range": [handle_start, len(route)], "calls": ["load_account"]}]},
                    "service.py": {"load_account": [{"range": [0, len(service)], "calls": ["get"]}]},
                },
                "dependencies": [
                    _dependency(
                        "route.py",
                        ("service.py", "load_account", 0, len(service)),
                        ("route.py", "handle", handle_start, len(route)),
                    )
                ],
            }
        }
    )
    diff = (
        "diff --git a/route.py b/route.py\n"
        "+++ b/route.py\n"
        "@@ -4 +4 @@\n"
        "-    allowed = user.is_admin\n"
        "+    allowed = user.is_staff\n"
    )

    context = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert context.coverage.required == (f"service.py:load_account:0:{len(service)}",)
    assert context.coverage.complete is True
    assert "Account.objects.get" in context.text


def test_collect_diff_context_bounds_required_evidence_at_direct_dependencies(tmp_path):
    route = "from domain.rules import AccessRule\n\ndef handle():\n    return AccessRule.objects.all()\n"
    rule = "from domain.base import OwnedRecord\n\nclass AccessRule(OwnedRecord):\n    pass\n"
    base = "class OwnedRecord:\n    owner = 'user'\n"
    (tmp_path / "route.py").write_text(route, encoding="utf-8")
    (tmp_path / "domain").mkdir()
    (tmp_path / "domain" / "rules.py").write_text(rule, encoding="utf-8")
    (tmp_path / "domain" / "base.py").write_text(base, encoding="utf-8")
    facts = Facts(
        data={
            "graph": {
                "callgraph": {
                    "route.py": {"handle": [{"range": [37, len(route)], "calls": ["all"]}]},
                    "domain/rules.py": {"AccessRule": [{"range": [37, len(rule)], "calls": []}]},
                    "domain/base.py": {"OwnedRecord": [{"range": [0, len(base)], "calls": []}]},
                },
                "imports": {"route.py": ["AccessRule"], "domain/rules.py": ["OwnedRecord"]},
                "import_targets": {
                    "route.py": ["domain/rules.py"],
                    "domain/rules.py": ["domain/base.py"],
                },
                "dependencies": [
                    _dependency("route.py", ("domain/rules.py", "AccessRule", 37, len(rule))),
                    _dependency("domain/rules.py", ("domain/base.py", "OwnedRecord", 0, len(base))),
                ],
            }
        }
    )
    diff = "diff --git a/route.py b/route.py\n+++ b/route.py\n@@ -4,1 +4,1 @@\n+    return AccessRule.objects.all()\n"

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert ctx.coverage.required == (f"domain/rules.py:AccessRule:37:{len(rule)}",)
    assert ctx.coverage.complete is True


def test_diff_preparation_keeps_connected_changed_surfaces_in_one_unit(tmp_path, monkeypatch):
    from cyberjury.review.diff import context as context_module

    monkeypatch.setattr(
        context_module,
        "_SETTINGS",
        replace(context_module._SETTINGS, target_patch_chars_per_unit=1),
    )
    cases = [
        (
            _profile,
            ("unrelated.py", "serializers.py", "views.py"),
            {
                "callgraph": {
                    "serializers.py": {"Input": [{"range": [0, 20], "calls": []}]},
                    "views.py": {"handle": [{"range": [0, 20], "calls": []}]},
                },
                "imports": {"views.py": ["Input"]},
                "import_targets": {"views.py": ["serializers.py"]},
                "dependencies": [_dependency("views.py", ("serializers.py", "Input", 0, 20))],
            },
        ),
        (
            _evm_profile,
            ("Unrelated.sol", "Vault.sol", "Token.sol"),
            {
                "callgraph": {
                    "Vault.sol": {"withdraw": [{"range": [0, 20], "calls": ["transfer"]}]},
                    "Token.sol": {"transfer": [{"range": [0, 20], "calls": []}]},
                },
                "imports": {},
                "import_targets": {},
                "dependencies": [
                    _dependency(
                        "Vault.sol",
                        ("Token.sol", "transfer", 0, 20),
                        ("Vault.sol", "withdraw", 0, 20),
                    )
                ],
            },
        ),
    ]
    for profile_factory, paths, graph in cases:
        for path in paths:
            referenced = "Input()" if path == "views.py" else "transfer()" if path == "Vault.sol" else "source"
            (tmp_path / path).write_text(f"{referenced}".ljust(19) + "\n", encoding="utf-8")
        diff = "".join(
            f"diff --git a/{path} b/{path}\n+++ b/{path}\n@@ -1 +1 @@\n+{(tmp_path / path).read_text()}"
            for path in paths
        )
        collector = build_diff_context_collector(
            tmp_path,
            profile_factory(_FactsBackend(Facts(data={"graph": graph}))),
        )

        units = collector.prepare(diff)

        assert len(units) == 2
        assert all([path for unit in units for path in unit.paths].count(path) == 1 for path in paths)
        source_path = graph["dependencies"][0]["source_file"]
        target_path = graph["dependencies"][0]["target"]["file"]
        grounded = next(unit for unit in units if source_path in unit.paths)
        assert set(grounded.paths) == {source_path, target_path}
        assert grounded.grounding is not None
        assert "Additional repository evidence available by id" in grounded.grounding.prompt_text


def test_diff_preparation_keeps_each_oversized_changed_surface_once(tmp_path, monkeypatch):
    from cyberjury.review.diff import context as context_module

    monkeypatch.setattr(context_module, "_SETTINGS", replace(context_module._SETTINGS, target_patch_chars_per_unit=1))
    for path in ("a.py", "b.py", "shared.py"):
        (tmp_path / path).write_text("def f():\n    return 1\n", encoding="utf-8")
    graph = {
        "callgraph": {
            "a.py": {"a": [{"range": [0, 22], "calls": ["shared"]}]},
            "b.py": {"b": [{"range": [0, 22], "calls": ["shared"]}]},
            "shared.py": {"shared": [{"range": [0, 22], "calls": []}]},
        },
        "dependencies": [
            _dependency("a.py", ("shared.py", "shared", 0, 22), ("a.py", "a", 0, 22)),
            _dependency("b.py", ("shared.py", "shared", 0, 22), ("b.py", "b", 0, 22)),
        ],
    }
    diff = "".join(
        f"diff --git a/{path} b/{path}\n+++ b/{path}\n@@ -1 +1 @@\n+def f():\n"
        for path in ("a.py", "b.py", "shared.py")
    )
    collector = build_diff_context_collector(tmp_path, _profile(_FactsBackend(Facts(data={"graph": graph}))))

    units = collector.prepare(diff)

    assert len(units) == 1
    assert [path for unit in units for path in unit.paths].count("shared.py") == 1
    assert set(units[0].paths) == {"a.py", "b.py", "shared.py"}

    monkeypatch.setattr(
        context_module,
        "_SETTINGS",
        replace(context_module._SETTINGS, target_patch_chars_per_unit=100_000),
    )
    merged = collector.prepare(diff)
    assert len(merged) == 1
    assert merged[0].diff.count("diff --git a/shared.py b/shared.py") == 1


def test_required_definition_is_incomplete_when_its_full_body_does_not_fit(tmp_path, monkeypatch):
    from cyberjury.review.diff import context as context_module

    route = "from model import Policy\n\ndef handle():\n    return Policy()\n"
    policy = "class Policy:\n" + "    value = 1\n" * 100
    (tmp_path / "route.py").write_text(route, encoding="utf-8")
    (tmp_path / "model.py").write_text(policy, encoding="utf-8")
    monkeypatch.setattr(
        context_module,
        "_SETTINGS",
        replace(
            context_module._SETTINGS,
            target_repository_context_chars_per_unit=300,
            max_changed_source_prefix_chars=100,
            target_definition_context_chars_per_file=200,
            max_caller_definition_chars=200,
        ),
    )
    facts = Facts(
        data={
            "graph": {
                "callgraph": {
                    "route.py": {"handle": [{"range": [26, len(route)], "calls": ["Policy"]}]},
                    "model.py": {"Policy": [{"range": [0, len(policy)], "calls": []}]},
                },
                "imports": {"route.py": ["Policy"]},
                "import_targets": {"route.py": ["model.py"]},
                "dependencies": [_dependency("route.py", ("model.py", "Policy", 0, len(policy)))],
            }
        }
    )
    diff = "diff --git a/route.py b/route.py\n+++ b/route.py\n@@ -4 +4 @@\n+    return Policy()\n"

    context = collect_diff_context(tmp_path, diff, _profile(_FactsBackend(facts)))

    assert context.coverage.required == (f"model.py:Policy:0:{len(policy)}",)
    assert context.coverage.included == ()
    assert context.coverage.complete is False


def test_prepared_diff_publishes_oversized_callee_as_requestable_evidence(tmp_path, monkeypatch):
    from cyberjury.review.diff import context as context_module

    route = "from model import Policy\n\ndef handle():\n    return Policy()\n"
    policy = "class Policy:\n" + "    value = 1\n" * 100
    (tmp_path / "route.py").write_text(route)
    (tmp_path / "model.py").write_text(policy)
    monkeypatch.setattr(
        context_module,
        "_SETTINGS",
        replace(
            context_module._SETTINGS,
            target_repository_context_chars_per_unit=300,
            max_changed_source_prefix_chars=100,
        ),
    )
    graph = {
        "callgraph": {
            "route.py": {"handle": [{"range": [26, len(route)], "calls": ["Policy"]}]},
            "model.py": {"Policy": [{"range": [0, len(policy)], "calls": []}]},
        },
        "dependencies": [_dependency("route.py", ("model.py", "Policy", 0, len(policy)))],
    }
    diff = "diff --git a/route.py b/route.py\n+++ b/route.py\n@@ -4 +4 @@\n+    return Policy()\n"
    collector = build_diff_context_collector(tmp_path, _profile(_FactsBackend(Facts(data={"graph": graph}))))

    unit = collector.prepare(diff)[0]

    assert unit.grounding is not None
    assert unit.grounding.coverage.complete is True
    assert unit.definition_plan is not None
    relationship = unit.definition_plan.dependencies[0]
    assert relationship.identity in unit.grounding.coverage.required
    assert relationship.identity in unit.grounding.coverage.included
    assert "Resolved definition relationships:" in unit.grounding.text
    assert "model.py:Policy" in unit.grounding.prompt_text
    assert "call Policy from route.py [supported]" in unit.grounding.prompt_text
    assert "declaration: `class Policy:`" in unit.grounding.prompt_text
    assert "route.py:handle, complete changed definition" in unit.grounding.prompt_text
    assert policy.rstrip().splitlines()[-1] not in unit.grounding.text


def test_collect_diff_context_reports_only_rendered_files(tmp_path):
    diff = "diff --git a/missing.py b/missing.py\n+++ b/missing.py\n@@ -1,0 +1,1 @@\n+print(1)\n"

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend()))

    assert ctx.files == ()
    assert ctx.text == ""


def test_collect_diff_context_handles_hunk_lines_beyond_current_source(tmp_path):
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -100,1 +100,1 @@\n-print(0)\n+print(1)\n"

    ctx = collect_diff_context(tmp_path, diff, _profile(_FactsBackend()))

    assert "outside current source length 1" in ctx.text


def test_diff_context_collector_reuses_facts_for_batch_context(tmp_path):
    (tmp_path / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def b():\n    return 2\n", encoding="utf-8")
    backend = _FactsBackend()
    collector = build_diff_context_collector(tmp_path, _profile(backend))

    ctx_a = collector.collect("diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -1,0 +1,1 @@\n+print(a())\n")
    ctx_b = collector.collect("diff --git a/b.py b/b.py\n+++ b/b.py\n@@ -1,0 +1,1 @@\n+print(b())\n")

    assert backend.extracts == 1
    assert "File: a.py" in ctx_a.text
    assert "File: b.py" not in ctx_a.text
    assert "File: b.py" in ctx_b.text


def test_collect_diff_context_fails_loud_when_backend_is_unavailable(tmp_path):
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n+print(1)\n"
    with pytest.raises(BackendUnavailable, match="cannot run"):
        collect_diff_context(tmp_path, diff, _profile(_FactsBackend(available=False)))


def test_diff_context_rejects_source_changes_during_facts_extraction(tmp_path):
    class MutatingBackend(_FactsBackend):
        def extract(self, root):
            (Path(root) / "app.py").write_text("def changed():\n    return 2\n")
            return Facts()

    (tmp_path / "app.py").write_text("def original():\n    return 1\n")

    with pytest.raises(BackendUnavailable, match="source changed during diff facts extraction"):
        build_diff_context_collector(tmp_path, _profile(MutatingBackend()))


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
        detection=load_detection(default_profile().paths.detection_file),
        by_file={},
        graph={},
    )
    diff = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"

    unit = collector.prepare(diff)[0]

    assert unit.grounding is not None
    assert "Current source" in unit.grounding.text
    assert "admin" in unit.grounding.text or "sensitive" in unit.grounding.text
