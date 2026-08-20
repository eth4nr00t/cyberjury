"""Source symbol location and score integration tests."""

from types import SimpleNamespace

import pytest

from evals.benchmarks.contract import load_answer_key
from evals.score.engine import score
from evals.score.report import Report, parse_finding_md

from .support import _key


def _use_solidity_spans(monkeypatch, path, declarations):
    from evals.score import location

    filename = SimpleNamespace(absolute=str(path.resolve()), relative=path.name)

    def declaration(name, lines):
        mapping = SimpleNamespace(filename=filename, lines=list(lines))
        return SimpleNamespace(name=name, source_mapping=mapping)

    contract = SimpleNamespace(
        name="Fixture",
        source_mapping=SimpleNamespace(filename=filename, lines=[1]),
        functions_declared=[declaration(name, lines) for name, lines in declarations],
        modifiers_declared=[],
        state_variables_declared=[],
        structures_declared=[],
        enums_declared=[],
    )
    analysis = SimpleNamespace(contracts=[contract], compilation_units=[])
    monkeypatch.setattr(location, "_slither_runtime", lambda _source_root: analysis)
    location.symbol_line_spans.cache_clear()


def test_symbol_anchor_credits_a_report_that_pins_the_line_without_naming_the_symbol(tmp_path):
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
        _key(
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
                "    files:\n"
                "    - src/mod.ts\n"
                "    symbols:\n"
                "    - createGen\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - missing-authorization\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    inside = Report.make(
        "r-in",
        "",
        "missing authorization",
        ["src/mod.ts"],
        text="new ItemsService built with no accountability",
        lines=[3],
    )
    sibling = Report.make(
        "r-sib", "", "missing authorization", ["src/mod.ts"], text="something in the other function", lines=[7]
    )
    assert score(key, [inside], source_root=str(tmp_path)).found == ["gen"]
    assert score(key, [inside]).found == []
    assert score(key, [sibling], source_root=str(tmp_path)).found == []


def test_python_symbol_anchor_uses_the_definition_after_an_earlier_call(tmp_path):
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
        _key(
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
                "    files:\n"
                "    - src/policies.py\n"
                "    symbols:\n"
                "    - apply_policy\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - resource-exhaustion\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    inside = Report.make("r-in", "", "resource exhaustion", ["src/policies.py"], lines=[6])
    earlier_call = Report.make("r-call", "", "resource exhaustion", ["src/policies.py"], lines=[2])
    assert score(key, [inside], source_root=str(tmp_path)).found == ["expensive-pattern"]
    assert score(key, [earlier_call], source_root=str(tmp_path)).found == []


def test_python_assignment_anchor_stops_before_a_sibling_and_later_dictionary(tmp_path):
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
        _key(
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
                "    files:\n"
                "    - src/pipelines.py\n"
                "    symbols:\n"
                "    - selected_steps\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - missing-authorization\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    inside = Report.make("r-in", "", "missing authorization", ["src/pipelines.py"], lines=[3])
    sibling = Report.make("r-sib", "", "missing authorization", ["src/pipelines.py"], lines=[6])
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
        (
            "Handlers.sol",
            "contract Handlers {\n  function route(bytes memory value) public {\n    processPayload(value);\n  }\n"
            "  function processPayload(bytes memory value) public {\n    consumePayload(value);\n  }\n}\n",
            6,
            3,
        ),
    ],
)
def test_symbol_anchor_uses_definitions_across_benchmark_languages(
    tmp_path,
    monkeypatch,
    filename,
    source,
    inside_line,
    call_line,
):
    src = tmp_path / "src"
    src.mkdir()
    source_file = src / filename
    source_file.write_text(source, encoding="utf-8")
    if source_file.suffix == ".sol":
        _use_solidity_spans(monkeypatch, source_file, [("processPayload", range(5, 8))])
    key = load_answer_key(
        _key(
            tmp_path,
            "schema_version: 1\n"
            "benchmark_id: t\n"
            "checks:\n"
            "  - id: sink\n"
            "    applies_to: [repository-vulnerable]\n"
            "    expectation: findings\n"
            "    severity: HIGH\n"
            f"    locations:\n      files: [src/{filename}]\n      symbols: [processPayload]\n"
            "    knowledge:\n      vulnerabilities: [resource-exhaustion]\n      guides: []\n",
        )
    )
    inside = Report.make("r-in", "", "resource exhaustion", [f"src/{filename}"], lines=[inside_line])
    earlier_call = Report.make("r-call", "", "resource exhaustion", [f"src/{filename}"], lines=[call_line])
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
        ("Settings.sol", "contract Settings {\n uint256 public selectedSteps = 1;\n}\n", "selectedSteps", ((2, 2),)),
    ],
)
def test_symbol_locator_supports_named_values_across_benchmark_languages(
    tmp_path, monkeypatch, filename, source, symbol, expected
):
    from evals.score.location import symbol_line_spans

    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    if path.suffix == ".sol":
        _use_solidity_spans(monkeypatch, path, [(symbol, range(expected[0][0], expected[0][1] + 1))])

    assert symbol_line_spans(str(tmp_path), filename, symbol) == expected


def test_symbol_anchor_checks_every_same_name_definition(tmp_path):
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
        _key(
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
                "    files:\n"
                "    - src/handlers.py\n"
                "    symbols:\n"
                "    - process\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - missing-authorization\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    second_definition = Report.make(
        "r-second",
        "",
        "missing authorization",
        ["src/handlers.py"],
        lines=[7],
    )

    assert score(key, [second_definition], source_root=str(tmp_path)).found == ["handler-check"]


def test_solidity_parser_checks_every_same_name_definition(tmp_path, monkeypatch):
    source = tmp_path / "Handlers.sol"
    source.write_text(
        "contract PublicHandler {\n"
        "    function process(bytes memory value) public {\n"
        "        emit Processed(value);\n"
        "    }\n"
        "}\n"
        "contract AdminHandler {\n"
        "    function process(bytes memory value) public {\n"
        "        authorize(value);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    _use_solidity_spans(monkeypatch, source, [("process", range(2, 5)), ("process", range(7, 10))])
    key = load_answer_key(
        _key(
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
                "    files:\n"
                "    - Handlers.sol\n"
                "    symbols:\n"
                "    - process\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - missing-authorization\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    second_definition = Report.make(
        "r-second",
        "",
        "missing authorization",
        ["Handlers.sol"],
        lines=[8],
    )

    assert score(key, [second_definition], source_root=str(tmp_path)).found == ["handler-check"]


def test_solidity_parser_span_is_not_truncated_by_a_brace_in_a_string(tmp_path, monkeypatch):
    from evals.score.location import symbol_line_spans

    source = tmp_path / "Handler.sol"
    source.write_text(
        "contract Handler {\n"
        "    function process(uint256 value) public {\n"
        '        string memory marker = "}";\n'
        "        authorize(value);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    _use_solidity_spans(monkeypatch, source, [("process", range(2, 6))])

    assert symbol_line_spans(str(tmp_path), "Handler.sol", "process") == ((2, 5),)


def test_solidity_parser_failure_is_not_scored_as_a_miss(tmp_path, monkeypatch):
    from evals.score import location

    source = tmp_path / "Handler.sol"
    source.write_text("contract Handler { function process() public {} }\n", encoding="utf-8")
    key = load_answer_key(
        _key(
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
                "    files:\n"
                "    - Handler.sol\n"
                "    symbols:\n"
                "    - process\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - missing-authorization\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    report = Report.make("r", "", "missing authorization", ["Handler.sol"], lines=[1])
    location.symbol_line_spans.cache_clear()

    def unavailable(_source_root):
        raise location.SymbolLocationError("cannot initialize Solidity symbol parser")

    monkeypatch.setattr(location, "_slither_runtime", unavailable)

    with pytest.raises(location.SymbolLocationError, match="cannot initialize Solidity symbol parser"):
        score(key, [report], source_root=str(tmp_path))


def test_configured_symbol_parser_failure_is_not_scored_as_a_miss(tmp_path, monkeypatch):
    from evals.score import location

    source = tmp_path / "handler.py"
    source.write_text("def process(value):\n    return value\n", encoding="utf-8")
    key = load_answer_key(
        _key(
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
                "    files:\n"
                "    - handler.py\n"
                "    symbols:\n"
                "    - process\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - missing-authorization\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    report = Report.make("r", "", "missing authorization", ["handler.py"], lines=[2])
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


def test_clean_symbol_anchor_without_endpoint_requires_the_class_it_certifies(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "body.py").write_text(
        "class LengthReader:\n"
        "    def read(self, n):\n"
        "        return n\n"
        "class Body:\n"
        "    def readline(self):\n"
        "        return 1\n",
        encoding="utf-8",
    )
    key = load_answer_key(
        _key(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: real\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files:\n"
                "    - src/other.py\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - idor\n"
                "    guides: []\n"
                "  severity: HIGH\n"
                "- id: bounded-reader\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: clean\n"
                "  locations:\n"
                "    files:\n"
                "    - src/body.py\n"
                "    symbols:\n"
                "    - LengthReader\n"
                "  knowledge:\n"
                "    vulnerabilities:\n"
                "    - http-request-smuggling\n"
                "    guides: []\n"
            ),
        )
    )
    off_class = Report.make(
        "r-oc", "", "uncontrolled resource consumption", ["src/body.py"], text="reads too much", lines=[3]
    )
    same_class = Report.make("r-sc", "", "http request smuggling", ["src/body.py"], text="framing desync", lines=[3])
    assert score(key, [off_class], source_root=str(tmp_path)).false_positives == []
    assert score(key, [same_class], source_root=str(tmp_path)).false_positives == ["bounded-reader"]


def test_symbol_location_uses_the_line_cited_for_the_matching_file(tmp_path):
    (tmp_path / "a.py").write_text("\n" * 5 + "danger = True\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("\n" * 5 + "def guarded():\n    return True\n", encoding="utf-8")
    key = load_answer_key(
        _key(
            tmp_path,
            (
                "schema_version: 1\n"
                "benchmark_id: t\n"
                "checks:\n"
                "- id: guarded-check\n"
                "  applies_to: [repository-vulnerable]\n"
                "  expectation: findings\n"
                "  locations:\n"
                "    files: [b.py]\n"
                "    symbols: [guarded]\n"
                "  knowledge:\n"
                "    vulnerabilities: [business-logic]\n"
                "    guides: []\n"
                "  severity: HIGH\n"
            ),
        )
    )
    report = parse_finding_md(
        "# state flaw\n"
        "- Type: business-logic\n"
        "The unsafe state is at a.py:6. The related implementation is in `b.py`.\n",
        "state-flaw",
    )

    result = score(key, [report], source_root=str(tmp_path))

    assert report.files == ("a.py", "b.py")
    assert report.lines_for("a.py", exact=True) == (6,)
    assert report.lines_for("b.py", exact=True) == ()
    assert result.missed == ["guarded-check"]
