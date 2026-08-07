"""Provide package exports and import side effects."""

from dataclasses import replace
from pathlib import Path

import pytest

from cyberjury.domains.base import BackendUnavailable, Facts, FactsBackend
from cyberjury.domains.registry import default_domain
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
