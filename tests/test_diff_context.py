"""Provide package exports and import side effects."""

from dataclasses import replace
from pathlib import Path

import pytest

from cyberjury.domains.base import BackendUnavailable, Facts, FactsBackend
from cyberjury.domains.registry import default_domain, get_domain
from cyberjury.review.diff.context import build_diff_context_collector, changed_paths, collect_diff_context


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


def _domain(backend: FactsBackend):
    return replace(default_domain(), facts_backend=backend)


def _evm_domain(backend: FactsBackend):
    return replace(get_domain("evm"), facts_backend=backend)


def test_changed_paths_filters_noise_files():
    """Changed paths filters noise files."""
    diff = (
        "diff --git a/app.py b/app.py\n+++ b/app.py\n+print(1)\n"
        "diff --git a/catalog.json b/catalog.json\n+++ b/catalog.json\n+{}\n"
        "diff --git a/README.md b/README.md\n+++ b/README.md\n+hi\n"
        "diff --git a/tests/test_app.py b/tests/test_app.py\n+++ b/tests/test_app.py\n+def test_x(): pass\n"
    )
    assert changed_paths(diff) == ("app.py",)


def test_collect_diff_context_renders_facts_and_current_source(tmp_path):
    """Collect diff context renders facts and current source."""
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
            },
        },
    )
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -3,0 +4,2 @@\n+def tool():\n+    return get_client()\n"

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend(facts)))

    assert ctx.files == ("app.py",)
    assert "Facts:" in ctx.text
    assert "tool()  calls get_client" in ctx.text
    assert "current_user_client" in ctx.text
    assert "   1: def get_client():" in ctx.text


def test_collect_diff_context_prefixes_scoped_facts_to_repository_paths(tmp_path):
    """Scoped facts are joined back to repository relative diff paths."""
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
            },
        },
    )
    diff = (
        "diff --git a/contracts/Token.sol b/contracts/Token.sol\n"
        "+++ b/contracts/Token.sol\n"
        "@@ -2,0 +2,1 @@\n"
        "+    function mint() public {}\n"
    )

    collector = build_diff_context_collector(tmp_path, _evm_domain(_FactsBackend(facts)), facts_root=scope)
    ctx = collector.collect(diff)

    assert ctx.files == ("contracts/Token.sol",)
    assert "Facts:" in ctx.text
    assert "Token.sol\n  mint()" in ctx.text
    assert "File: contracts/Use.sol" in ctx.text


def test_collect_diff_context_rejects_facts_root_outside_repository(tmp_path):
    """A facts root outside the repository fails with a review context error."""
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()

    with pytest.raises(BackendUnavailable, match="outside repository root"):
        build_diff_context_collector(tmp_path, _domain(_FactsBackend()), facts_root=outside)


def test_collect_diff_context_renders_same_file_helper_definitions(tmp_path):
    """Collect diff context renders same file helper definitions."""
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

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend(facts)))

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

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend(facts)))

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
            },
        }
    )
    diff = "diff --git a/leaf.py b/leaf.py\n+++ b/leaf.py\n@@ -1,0 +1,2 @@\n+def leaf():\n+    return 1\n"

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend(facts)))

    assert "File: entry.py" in ctx.text
    assert "return wrapper()" in ctx.text


def test_collect_diff_context_includes_reverse_callers_for_same_package_helpers(tmp_path):
    """Same package calls need a reverse edge even when no import connects the files."""
    (tmp_path / "helper.go").write_text(
        "package app\n\nfunc ValueInConfig(needle string, haystack []string) bool {\n    return true\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "authorize_helper.go").write_text(
        "package app\n\n"
        "func AllowedConfigurationMatches(rawurl string, allowed []string) bool {\n"
        "    return ValueInConfig(rawurl, allowed)\n"
        "}\n",
        encoding="utf-8",
    )
    facts = Facts(
        data={
            "by_file": {
                "helper.go": "helper.go\n  ValueInConfig()",
                "authorize_helper.go": "authorize_helper.go\n  AllowedConfigurationMatches()  calls ValueInConfig",
            },
            "graph": {
                "callgraph": {
                    "helper.go": {"ValueInConfig": [{"range": [13, 86], "calls": []}]},
                    "authorize_helper.go": {
                        "AllowedConfigurationMatches": [{"range": [13, 132], "calls": ["ValueInConfig"]}]
                    },
                },
                "imports": {},
                "import_targets": {},
            },
        },
    )
    diff = (
        "diff --git a/helper.go b/helper.go\n"
        "+++ b/helper.go\n"
        "@@ -3,1 +3,1 @@\n"
        "+    return strings.ToLower(a) == strings.ToLower(b)\n"
    )

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend(facts)))

    assert ctx.files == ("helper.go",)
    assert "File: authorize_helper.go" in ctx.text
    assert "ValueInConfig(rawurl, allowed)" in ctx.text


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

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend(facts)))

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
            },
        },
    )

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend(facts)))

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

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend(facts)))

    assert "File: utils/__init__.py" in ctx.text
    assert "Imported definitions called by changed code: current_timestamp, get_uuid" in ctx.text
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
            },
        }
    )
    collector = build_diff_context_collector(
        tmp_path,
        _domain(_FactsBackend(facts)),
        review_diff=batch_diff + distractor_diffs + helper_diff,
    )

    ctx = collector.collect(batch_diff)

    assert "File: helper.ts" in ctx.text
    assert "Definition mergeOptions:" in ctx.text
    assert "target.value = source.value" in ctx.text
    assert ctx.text.index("File: helper.ts") < ctx.text.index("File: controller.ts")


def test_collect_diff_context_respects_total_budget(tmp_path):
    """Collect diff context respects total budget."""
    diff_parts: list[str] = []
    for i in range(40):
        path = tmp_path / f"app_{i}.py"
        path.write_text("\n".join(f"value_{j} = {j}" for j in range(200)), encoding="utf-8")
        diff_parts.append(f"diff --git a/app_{i}.py b/app_{i}.py\n+++ b/app_{i}.py\n@@ -1,0 +1,1 @@\n+value = {i}\n")

    ctx = collect_diff_context(tmp_path, "".join(diff_parts), _domain(_FactsBackend()))

    assert len(ctx.text) <= 24_000


def test_collect_diff_context_reports_only_rendered_files(tmp_path):
    """Collect diff context reports only rendered files."""
    diff = "diff --git a/missing.py b/missing.py\n+++ b/missing.py\n@@ -1,0 +1,1 @@\n+print(1)\n"

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend()))

    assert ctx.files == ()
    assert ctx.text == ""


def test_collect_diff_context_handles_hunk_lines_beyond_current_source(tmp_path):
    """Collect diff context handles hunk lines beyond current source."""
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -100,1 +100,1 @@\n-print(0)\n+print(1)\n"

    ctx = collect_diff_context(tmp_path, diff, _domain(_FactsBackend()))

    assert "outside current source length 1" in ctx.text


def test_diff_context_collector_reuses_facts_for_batch_context(tmp_path):
    """Diff context collector reuses facts for batch context."""
    (tmp_path / "a.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def b():\n    return 2\n", encoding="utf-8")
    backend = _FactsBackend()
    collector = build_diff_context_collector(tmp_path, _domain(backend))

    ctx_a = collector.collect("diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -1,0 +1,1 @@\n+print(a())\n")
    ctx_b = collector.collect("diff --git a/b.py b/b.py\n+++ b/b.py\n@@ -1,0 +1,1 @@\n+print(b())\n")

    assert backend.extracts == 1
    assert "File: a.py" in ctx_a.text
    assert "File: b.py" not in ctx_a.text
    assert "File: b.py" in ctx_b.text


def test_collect_diff_context_fails_loud_when_backend_is_unavailable(tmp_path):
    """Collect diff context fails loud when backend is unavailable."""
    diff = "diff --git a/app.py b/app.py\n+++ b/app.py\n+print(1)\n"
    with pytest.raises(BackendUnavailable, match="cannot run"):
        collect_diff_context(tmp_path, diff, _domain(_FactsBackend(available=False)))
