"""Source symbol location and score integration tests."""

import pytest

from evals.benchmarks.contract import load_answer_key
from evals.score.engine import score
from evals.score.location import SymbolLocationError
from evals.score.report import Report, ReportLocation


def test_symbol_anchor_credits_a_report_that_pins_the_line_without_naming_the_symbol(tmp_path, answer_key_file):
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.ts").write_text(
        "export function createGen(a, b) {\n"
        "    const x = 1;\n"
        "    const service = new ItemsService(c);\n"
        "    return x;\n"
        "}\n"
        "function other() {\n"
        "    return 2;\n"
        "}\n",
        encoding="utf-8",
    )
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: gen\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "  - file: src/mod.ts\n"
                "    symbol: createGen\n"
            ),
        )
    )
    inside = Report(name="r-in", locations=(ReportLocation("src/mod.ts", 3),))
    sibling = Report(name="r-sib", locations=(ReportLocation("src/mod.ts", 7),))
    assert score(key, [inside], source_root=str(tmp_path)).found == ["gen"]
    with pytest.raises(SymbolLocationError, match="without benchmark source"):
        score(key, [inside])
    assert score(key, [sibling], source_root=str(tmp_path)).found == []


def test_python_symbol_anchor_uses_the_definition_after_an_earlier_call(tmp_path, answer_key_file):
    src = tmp_path / "src"
    src.mkdir()
    (src / "policies.py").write_text(
        "def route(value):\n"
        "    return apply_policy(value)\n"
        "\n"
        "def apply_policy(value):\n"
        "    if value:\n"
        "        return evaluate_pattern(value)\n"
        "    return False\n",
        encoding="utf-8",
    )
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: expensive-pattern\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "  - file: src/policies.py\n"
                "    symbol: apply_policy\n"
            ),
        )
    )
    inside = Report(name="r-in", locations=(ReportLocation("src/policies.py", 6),))
    earlier_call = Report(name="r-call", locations=(ReportLocation("src/policies.py", 2),))
    assert score(key, [inside], source_root=str(tmp_path)).found == ["expensive-pattern"]
    assert score(key, [earlier_call], source_root=str(tmp_path)).found == []


def test_python_assignment_anchor_stops_before_a_sibling_and_later_dictionary(tmp_path, answer_key_file):
    src = tmp_path / "src"
    src.mkdir()
    (src / "pipelines.py").write_text(
        "def build_pipeline():\n"
        "    selected_steps = (\n"
        "        load_selected_steps()\n"
        "    )\n"
        "    fallback_steps = (\n"
        "        load_fallback_steps()\n"
        "    )\n"
        "    metadata = {\n"
        "        'source': None,\n"
        "    }\n"
        "    return metadata\n",
        encoding="utf-8",
    )
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: selected-steps\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "  - file: src/pipelines.py\n"
                "    symbol: selected_steps\n"
            ),
        )
    )
    inside = Report(name="r-in", locations=(ReportLocation("src/pipelines.py", 3),))
    sibling = Report(name="r-sib", locations=(ReportLocation("src/pipelines.py", 6),))
    assert score(key, [inside], source_root=str(tmp_path)).found == ["selected-steps"]
    assert score(key, [sibling], source_root=str(tmp_path)).found == []


@pytest.mark.parametrize(
    ("filename", "source", "inside_line", "call_line"),
    [
        (
            "handlers.js",
            "function route(value) {\n  return processPayload(value);\n}\n"
            "function processPayload(value) {\n  return consumePayload(value);\n}\n",
            5,
            2,
        ),
        (
            "handlers.ts",
            "function route(value: string) {\n  return processPayload(value);\n}\n"
            "function processPayload(value: string) {\n  return consumePayload(value);\n}\n",
            5,
            2,
        ),
        (
            "handlers.tsx",
            "function route(value: string) {\n  return processPayload(value);\n}\n"
            "function processPayload(value: string) {\n  return <span>{consumePayload(value)}</span>;\n}\n",
            5,
            2,
        ),
        (
            "handlers.go",
            "package handlers\n\nfunc route(value string) bool {\n  return processPayload(value)\n}\n"
            "func processPayload(value string) bool {\n  return consumePayload(value)\n}\n",
            7,
            4,
        ),
    ],
)
def test_symbol_anchor_uses_definitions_across_benchmark_languages(
    tmp_path,
    filename,
    source,
    inside_line,
    call_line,
    answer_key_file,
):
    src = tmp_path / "src"
    src.mkdir()
    source_file = src / filename
    source_file.write_text(source, encoding="utf-8")
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            "schema_version: 1\n"
            "benchmark_id: t\n"
            "checks:\n"
            "  - id: sink\n"
            "    applies_to: [repository-vulnerable]\n"
            "    expectation: findings\n"
            f"    locations:\n      - file: src/{filename}\n        symbol: processPayload\n",
        )
    )
    inside = Report(name="r-in", locations=(ReportLocation(f"src/{filename}", inside_line),))
    earlier_call = Report(name="r-call", locations=(ReportLocation(f"src/{filename}", call_line),))
    assert score(key, [inside], source_root=str(tmp_path)).found == ["sink"]
    assert score(key, [earlier_call], source_root=str(tmp_path)).found == []


@pytest.mark.parametrize(
    ("filename", "source", "symbol", "expected"),
    [
        ("settings.py", "selected_steps = (\n    load_steps()\n)\n", "selected_steps", ((1, 3),)),
        ("settings.js", "const selectedSteps = {\n  enabled: true,\n};\n", "selectedSteps", ((1, 3),)),
        ("settings.ts", 'const selectedSteps: string[] = [\n  "one",\n];\n', "selectedSteps", ((1, 3),)),
        ("settings.tsx", 'const selectedSteps = [\n  <span key="one" />,\n];\n', "selectedSteps", ((1, 3),)),
        ("settings.go", 'package settings\nvar selectedSteps = []string{\n  "one",\n}\n', "selectedSteps", ((2, 4),)),
    ],
)
def test_symbol_locator_supports_named_values_across_benchmark_languages(tmp_path, filename, source, symbol, expected):
    from evals.score.location import symbol_line_spans

    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    assert symbol_line_spans(str(tmp_path), filename, symbol) == expected


def test_python_symbol_locator_reports_lines_in_large_files(tmp_path):
    from evals.score.location import symbol_line_spans

    path = tmp_path / "handlers.py"
    path.write_text("\n" * 700 + "def process():\n    return True\n", encoding="utf-8")

    assert symbol_line_spans(str(tmp_path), "handlers.py", "process") == ((701, 702),)


def test_symbol_anchor_checks_every_same_name_definition(tmp_path, answer_key_file):
    src = tmp_path / "src"
    src.mkdir()
    (src / "handlers.py").write_text(
        "class PublicHandler:\n"
        "    def process(self, value):\n"
        "        return value\n"
        "\n"
        "class AdminHandler:\n"
        "    def process(self, value):\n"
        "        return authorize(value)\n",
        encoding="utf-8",
    )
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: handler-check\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "  - file: src/handlers.py\n"
                "    symbol: process\n"
            ),
        )
    )
    second_definition = Report(name="r-second", locations=(ReportLocation("src/handlers.py", 7),))

    assert score(key, [second_definition], source_root=str(tmp_path)).found == ["handler-check"]


def test_configured_symbol_parser_failure_is_not_scored_as_a_miss(tmp_path, monkeypatch, answer_key_file):
    from evals.score import location

    source = tmp_path / "handler.py"
    source.write_text("def process(value):\n    return value\n", encoding="utf-8")
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: handler-check\n"
                "  applies_to:\n"
                "  - repository-vulnerable\n"
                "  expectation: findings\n"
                "  locations:\n"
                "  - file: handler.py\n"
                "    symbol: process\n"
            ),
        )
    )
    report = Report(name="r", locations=(ReportLocation("handler.py", 2),))
    location._tree_sitter_runtime.cache_clear()
    location.symbol_line_spans.cache_clear()

    def unavailable_module(name):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(location.importlib, "import_module", unavailable_module)

    with pytest.raises(location.SymbolLocationError, match="cannot initialize python symbol parser"):
        score(key, [report], source_root=str(tmp_path))


def test_invalid_symbol_query_fails_loudly(tmp_path, monkeypatch):
    from evals.score import location

    source = tmp_path / "handler.py"
    source.write_text("def process(value):\n    return value\n", encoding="utf-8")
    invalid = location.LanguageSpec(
        "python",
        (".py",),
        "tree_sitter_python",
        "language",
        "(missing_node name: (identifier) @name) @def",
    )
    monkeypatch.setattr(location, "_LANGUAGE_SPECS", (invalid,))
    location._tree_sitter_runtime.cache_clear()
    location.symbol_line_spans.cache_clear()

    with pytest.raises(location.SymbolLocationError, match="cannot initialize python symbol parser"):
        location.symbol_line_spans(str(tmp_path), "handler.py", "process")


def test_unknown_source_type_has_no_heuristic_symbol_fallback(tmp_path):
    from evals.score.location import symbol_line_spans

    source = tmp_path / "handler.txt"
    source.write_text("function process(value) { return value; }\n", encoding="utf-8")

    assert symbol_line_spans(str(tmp_path), "handler.txt", "process") == ()


def test_symbol_location_uses_the_line_cited_for_the_matching_file(tmp_path, answer_key_file):
    (tmp_path / "a.py").write_text("\n" * 5 + "danger = True\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("\n" * 5 + "def guarded():\n    return True\n", encoding="utf-8")
    key = load_answer_key(
        answer_key_file(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: guarded-check\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "  - file: b.py\n"
                "    symbol: guarded\n"
            ),
        )
    )
    report = Report(name="state-flaw", locations=(ReportLocation("a.py", 6), ReportLocation("b.py")))

    result = score(key, [report], source_root=str(tmp_path))

    assert report.lines_for("a.py") == (6,)
    assert report.lines_for("b.py") == ()
    assert result.missed == ["guarded-check"]
