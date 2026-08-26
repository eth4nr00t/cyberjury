"""Repository context keeps source and facts scoped to each review unit."""

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import RelationshipEvidence
from cyberjury.review.repository.context import Unit, UnitSourceError, gather, gather_context, repository_context
from cyberjury.review.repository.engine import RepositoryRoleOptions, RepositoryRunOptions, run_repository_review
from cyberjury.review.repository.reviewer import ModelReviewer, RepositoryReviewError
from cyberjury.review.repository.scaffold import scaffold
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS


def test_repository_review_rejects_unknown_modes_before_touching_the_target(tmp_path):
    with pytest.raises(ValueError, match="unknown review mode"):
        run_repository_review(
            tmp_path / "missing",
            tmp_path / "ws",
            options=RepositoryRunOptions(roles=RepositoryRoleOptions(mode="deep")),
        )


def test_with_facts_summary_folds_persisted_facts_and_marks_truncation(tmp_path):
    from cyberjury.review.repository.context import with_facts_summary

    assert with_facts_summary("STACK", tmp_path) == "STACK"

    (tmp_path / "_facts.md").write_text("contract V\n  external withdraw()  ext-call", encoding="utf-8")
    folded = with_facts_summary("STACK", tmp_path)
    assert "STACK" in folded
    assert "Tool-extracted facts:" in folded
    assert "withdraw()" in folded

    limit = DEFAULT_REVIEW_SETTINGS.repository.max_facts_chars_per_unit
    (tmp_path / "_facts.md").write_text("x" * (limit + 500), encoding="utf-8")
    assert "facts truncated" in with_facts_summary("STACK", tmp_path)


def test_repository_context_excludes_knowledge_selected_per_unit(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "urls.py").write_text("urlpatterns = []\n", encoding="utf-8")
    result = scaffold(target, tmp_path / "work")

    context = repository_context(result.workspace)

    assert context.source == "repository"
    assert "## Stack" in context.text
    assert "## Vulnerability classes" not in context.text
    assert "## False-positive traps" in context.text
    assert "## Authorization model" not in context.text
    assert "# Vulnerability Classes" in (result.workspace / "_vulnerabilities.md").read_text()


def _prompt_of(prov):
    return prov.calls[0]["messages"][0].content


def test_reviewer_grounds_a_unit_with_only_its_own_files_facts(tmp_path):
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
    (tmp_path / "v.py").write_text("x = 1")
    prov = MockProvider(default='{"findings": []}')
    ModelReviewer(provider=prov, model="mock").review(Unit(name="v.py", root=str(tmp_path), files=("v.py",)))
    assert "Tool-extracted facts for this unit" not in _prompt_of(prov)


def test_reviewer_matches_facts_on_basename_when_the_directory_differs(tmp_path):
    (tmp_path / "V3Vault.sol").write_text("contract V3Vault {}")
    prov = MockProvider(default='{"findings": []}')
    rev = ModelReviewer(
        provider=prov, model="mock", facts_by_file={"src/V3Vault.sol": "contract V3Vault\n  reenter-marker"}
    )
    rev.review(Unit(name="x", root=str(tmp_path), files=("V3Vault.sol",)))
    assert "reenter-marker" in _prompt_of(prov)


def test_reviewer_rejects_an_ambiguous_facts_basename(tmp_path):
    (tmp_path / "Foo.sol").write_text("contract Foo {}")
    reviewer = ModelReviewer(
        provider=MockProvider(default='{"findings": []}'),
        model="mock",
        facts_by_file={"src/a/Foo.sol": "FACTS_A", "src/b/Foo.sol": "FACTS_B"},
    )

    with pytest.raises(RepositoryReviewError, match=r"facts path.*ambiguous"):
        reviewer.review(Unit(name="foo", root=str(tmp_path), files=("Foo.sol",)))


def test_load_facts_by_file_reads_the_map_drops_empty_and_fails_loud_on_corrupt(tmp_path):
    from cyberjury.review.repository.context import load_facts_by_file

    assert load_facts_by_file(tmp_path) == {}
    (tmp_path / "_facts_by_file.json").write_text('{"a.sol": "facts A", "b.sol": ""}')
    assert load_facts_by_file(tmp_path) == {"a.sol": "facts A"}
    (tmp_path / "_facts_by_file.json").write_text("not json at all")
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_by_file(tmp_path)
    (tmp_path / "_facts_by_file.json").write_text('{"a.sol": {"nested": true}}')
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_by_file(tmp_path)


def test_load_facts_limitations_reads_validated_records(tmp_path):
    from cyberjury.review.repository.context import load_facts_limitations

    assert load_facts_limitations(tmp_path) == ()
    (tmp_path / "_facts_limitations.json").write_text(
        '[{"source":"app.py","analyzer":"python","reason":"unparsable","line":2,"column":4}]'
    )

    limitation = load_facts_limitations(tmp_path)[0]

    assert limitation.identity == "facts:app.py:2:4"
    (tmp_path / "_facts_limitations.json").write_text('[{"source":"app.py"}]')
    with pytest.raises(ValueError, match="corrupt"):
        load_facts_limitations(tmp_path)


def test_gather_assembles_fact_unit_fragments(tmp_path):
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


def test_gather_receipts_and_renders_definition_relationships(tmp_path):
    source = "def route():\n    return load()\n\ndef load():\n    return 1\n"
    (tmp_path / "app.py").write_text(source)
    relationship = RelationshipEvidence(
        identity="app.py:route:0:31:call:load:exact:app.py:load:33:58",
        summary="app.py:route:0:31 --call load [exact]--> app.py:load:33:58",
    )
    context = gather_context(
        Unit(
            name="route",
            root=str(tmp_path),
            files=("app.py",),
            fragments=(("app.py", 0, len(source)),),
            relationships=(relationship,),
        )
    )

    assert relationship.summary in context.text
    assert relationship.identity in context.coverage.required
    assert relationship.identity in context.coverage.included
    assert context.coverage.complete is True


def test_gather_reads_only_the_span_window_of_a_chunked_unit(tmp_path):
    (tmp_path / "big.py").write_text("AAAA" + "B" * 30_000 + "ZZZZ")
    tail = gather(Unit(name="big.py#2", root=str(tmp_path), files=("big.py",), span=(30_000, 30_008)))
    assert "ZZZZ" in tail
    assert "AAAA" not in tail


def test_gather_numbers_a_span_window_from_its_real_first_line(tmp_path):
    text = "".join(f"line{i}\n" for i in range(1, 501))
    (tmp_path / "big.py").write_text(text)
    start = text.index("line300")
    content = gather(Unit(name="big.py#2", root=str(tmp_path), files=("big.py",), span=(start, start + 8)))
    assert "300 | line300" in content
    assert "# file: big.py lines 300-300" in content


def test_gather_budget_counts_source_not_the_line_number_prefixes(tmp_path):
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text("x\n" * 20_000)
    content = gather(Unit(name="u", root=str(tmp_path), files=("a.py", "b.py", "c.py")))
    assert content.count("# file: ") == 3


def test_gather_fails_when_a_unit_source_file_is_missing(tmp_path):
    with pytest.raises(UnitSourceError, match=r"missing\.py"):
        gather(Unit(name="u", root=str(tmp_path), files=("missing.py",)))
