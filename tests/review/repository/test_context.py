"""Repository context keeps source and facts scoped to each review unit."""

from dataclasses import replace
from pathlib import Path

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.facts import FactLimitation, Facts
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.relationships import (
    DefinitionEvidence,
    SourceReference,
)
from cyberjury.review.repository.context import (
    UnitSourceError,
    gather_context,
    ground_repository_unit,
)
from cyberjury.review.repository.model import RepositoryUnit
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot
from tests.review.repository.support import EMPTY_REPLY, finder, review, source_unit
from tests.review.support import route_call, shared_grounding


def _ground(unit, *, facts_by_file, limitations, navigator, snapshot):
    facts = Facts(by_file=facts_by_file, limitations=limitations)
    shared = shared_grounding(Path(unit.root), facts=facts, navigator=navigator, snapshot=snapshot)
    return replace(unit, grounding=ground_repository_unit(unit, shared))


def _route_load_navigator(tmp_path):
    graph = route_call(
        tmp_path,
        "def route(value):\n    return load(value)\n",
        {"service.py": "def load(value):\n    return value\n"},
    )
    navigator = SourceNavigator.from_facts(
        tmp_path,
        source_files=("route.py", "service.py"),
        relationship_evidence=graph.relationships,
    )
    snapshot = SourceSnapshot.capture(
        tmp_path,
        ("route.py", "service.py"),
        scope_provider=lambda: ("route.py", "service.py"),
    )
    return graph.caller, navigator, snapshot


def test_repository_grounding_exposes_the_same_candidate_call_clues(tmp_path):
    """A route.py seed calling load lists service.py:load as a candidate and delivers its source."""
    caller, navigator, snapshot = _route_load_navigator(tmp_path)
    unit = source_unit(
        tmp_path,
        "route.py",
        definition_plan=DefinitionUnitPlan(seeds=(caller,)),
    )

    grounded = _ground(
        unit,
        facts_by_file={},
        limitations=(),
        navigator=navigator,
        snapshot=snapshot,
    )

    assert grounded.grounding is not None
    assert "Unverified direct call candidates from this unit" in grounded.grounding.text
    assert "service.py:load" in grounded.grounding.text
    [candidate_source] = grounded.grounding.source_evidence
    assert candidate_source.source_span.file == "service.py"
    assert "def load(value)" in candidate_source.text
    assert grounded.grounding.evidence == ()
    assert f"source `{candidate_source.id}` delivered below" in grounded.grounding.text
    assert (
        f"Initial source `{candidate_source.id}`, delivered by the review agent:\n```\n{candidate_source.text}\n```"
        in grounded.grounding.prompt.source
    )
    assert grounded.grounding.syntax_hints == ""
    assert "service.py" in grounded.grounding.snapshot_files


def test_repository_candidate_file_limitations_follow_the_published_source(tmp_path):
    """An incomplete parse of candidate service.py is recorded as an advisory limitation and appears in the prompt."""
    caller, navigator, snapshot = _route_load_navigator(tmp_path)
    unit = source_unit(
        tmp_path,
        "route.py",
        definition_plan=DefinitionUnitPlan(seeds=(caller,)),
    )
    limitation = FactLimitation(source="service.py", analyzer="tree-sitter", reason="incomplete parse")

    grounded = _ground(
        unit,
        facts_by_file={},
        limitations=(limitation,),
        navigator=navigator,
        snapshot=snapshot,
    ).grounding

    assert grounded is not None
    assert "service.py" in grounded.snapshot_files
    assert limitation.identity in grounded.coverage.limitations
    assert grounded.coverage.complete is True
    assert "incomplete parse" in grounded.prompt.source


def test_a_unit_limitation_is_attached_to_its_rendered_source(tmp_path):
    """A partially parsed broken.py limitation at 1:11 appears in the rendered source and leaves coverage complete."""
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    limitation = FactLimitation(source="broken.py", analyzer="python", reason="partially parsed", line=1, column=11)

    grounded = _ground(
        source_unit(tmp_path, "broken.py"),
        facts_by_file={},
        limitations=(limitation,),
        navigator=None,
        snapshot=capture_source_snapshot(tmp_path),
    ).grounding

    assert "broken.py at 1:11" in grounded.prompt.source
    assert grounded.coverage.limitations == ("facts:broken.py:1:11",)
    assert grounded.coverage.complete is True


def test_repository_reviewer_keeps_embedded_markdown_fence_in_source(tmp_path):
    """A source line containing ``` is fenced with ~~~ so the triple backtick reaches the prompt intact."""
    (tmp_path / "app.py").write_text('marker = "```"\n', encoding="utf-8")
    provider = MockProvider(default=EMPTY_REPLY)

    review(finder(provider), source_unit(tmp_path, "app.py", name="app.py"))

    prompt = provider.calls[0]["messages"][0].content
    assert "Code under review, cited as `seed`:\n~~~\n# file: app.py" in prompt
    assert 'marker = "```"' in prompt


def test_repository_prompt_never_carries_the_unit_name(tmp_path):
    """A unit named with a backtick and newline leaks neither fragment into the prompt."""
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    provider = MockProvider(default=EMPTY_REPLY)

    review(finder(provider), source_unit(tmp_path, "app.py", name="app`unit\nnext heading"))

    prompt = provider.calls[0]["messages"][0].content
    assert "app`unit" not in prompt
    assert "next heading" not in prompt


def _prompt_of(prov):
    return prov.calls[0]["messages"][0].content


def _grounded(tmp_path, name, facts_by_file):
    return _ground(
        source_unit(tmp_path, name),
        facts_by_file=facts_by_file,
        limitations=(),
        navigator=None,
        snapshot=capture_source_snapshot(tmp_path),
    )


def test_reviewer_grounds_a_unit_with_only_its_own_files_facts(tmp_path):
    """The views.py prompt carries its calls[load_owner] hints while admin.py delete_all hints stay out."""
    (tmp_path / "views.py").write_text("def list_items():\n    return load_owner()\n")
    prov = MockProvider(default=EMPTY_REPLY)
    by_file = {
        "views.py": "def list_items()  calls[load_owner]",
        "admin.py": "def delete_all()  calls[purge]",
    }
    review(finder(prov), _grounded(tmp_path, "views.py", by_file))
    prompt = _prompt_of(prov)
    assert "views.py: syntax hints (unverified, cite only delivered source):\n```\n" in prompt
    assert "calls[load_owner]" in prompt
    assert "delete_all" not in prompt


def test_repository_syntax_hints_are_bounded_per_file_with_a_visible_marker(tmp_path):
    """Hints over the per-file character limit are truncated and labelled with 'first N characters'."""
    (tmp_path / "large.py").write_text("value = 1\n")
    limit = DEFAULT_REVIEW_SETTINGS.execution.max_syntax_hint_chars_per_file
    facts = "fact\n" * (limit // 5 + 1)
    provider = MockProvider(default=EMPTY_REPLY)

    review(
        finder(provider),
        _grounded(tmp_path, "large.py", {"large.py": facts}),
    )

    prompt = _prompt_of(provider)
    assert f"large.py: syntax hints (unverified, cite only delivered source), first {limit} characters:" in prompt
    assert facts[:limit] in prompt
    assert facts not in prompt


def test_repository_units_with_seed_definitions_get_no_syntax_hints(tmp_path):
    """A views.py unit seeded with its show definition drops the facts marker and has empty syntax hints."""
    source = "def show():\n    return 1\n"
    (tmp_path / "views.py").write_text(source)
    plan = DefinitionUnitPlan(
        seeds=(
            DefinitionEvidence.create(
                source=SourceReference.create(path="views.py", start=0, end=len(source), content=source),
                kind="function",
                name="show",
            ),
        )
    )

    grounded = _ground(
        source_unit(tmp_path, "views.py", definition_plan=plan),
        facts_by_file={"views.py": "def show()  marker"},
        limitations=(),
        navigator=None,
        snapshot=capture_source_snapshot(tmp_path),
    )

    assert grounded.grounding.syntax_hints == ""


def test_reviewer_adds_no_facts_block_without_a_map(tmp_path):
    """An empty facts map leaves the finder prompt without any 'syntax hints' block."""
    (tmp_path / "v.py").write_text("x = 1")
    prov = MockProvider(default=EMPTY_REPLY)
    review(finder(prov), _grounded(tmp_path, "v.py", {}))
    assert "syntax hints" not in _prompt_of(prov)


def test_grounding_does_not_guess_facts_from_a_matching_basename(tmp_path):
    """Facts keyed by src/views.py are not applied to a root-level views.py unit."""
    (tmp_path / "views.py").write_text("def show():\n    return 1\n")

    grounded = _grounded(tmp_path, "views.py", {"src/views.py": "def show()  marker"})

    assert grounded.grounding.syntax_hints == ""


def test_grounding_uses_only_the_exact_facts_path_when_basenames_repeat(tmp_path):
    """Root handlers.py receives FACTS_ROOT and not facts for src/a/handlers.py or src/b/handlers.py."""
    (tmp_path / "handlers.py").write_text("def handle():\n    return 1\n")

    grounded = _grounded(
        tmp_path,
        "handlers.py",
        {"src/a/handlers.py": "FACTS_A", "src/b/handlers.py": "FACTS_B", "handlers.py": "FACTS_ROOT"},
    )

    assert "FACTS_ROOT" in grounded.grounding.syntax_hints
    assert "FACTS_A" not in grounded.grounding.syntax_hints


def test_gather_reads_only_the_span_window_of_a_chunked_unit(tmp_path):
    """A unit spanning the last 8 characters of a 30 KB file sees the ZZZZ tail but not the AAAA head."""
    (tmp_path / "big.py").write_text("AAAA" + "B" * 30_000 + "ZZZZ")
    tail = gather_context(
        RepositoryUnit(name="big.py#2", root=str(tmp_path), file="big.py", span=(30_000, 30_008))
    ).seed
    assert "ZZZZ" in tail
    assert "AAAA" not in tail


def test_gather_numbers_a_span_window_from_its_real_first_line(tmp_path):
    """A span starting at line300 renders as '300 | line300' under a 'lines 300-300' header."""
    text = "".join(f"line{i}\n" for i in range(1, 501))
    (tmp_path / "big.py").write_text(text)
    start = text.index("line300")
    content = gather_context(
        RepositoryUnit(name="big.py#2", root=str(tmp_path), file="big.py", span=(start, start + 8))
    ).seed
    assert "300 | line300" in content
    assert "# file: big.py lines 300-300" in content


def test_gather_fails_when_a_unit_source_file_is_missing(tmp_path):
    """A unit pointing at a nonexistent missing.py raises UnitSourceError naming that file."""
    with pytest.raises(UnitSourceError, match=r"missing\.py"):
        gather_context(RepositoryUnit(name="u", root=str(tmp_path), file="missing.py", span=(0, 1)))
