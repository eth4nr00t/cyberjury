"""Shared markdown-doc plumbing: frontmatter split and directory loading."""

from cyberjury.markdown_docs import iter_md_docs, parse_frontmatter


def test_parse_frontmatter_well_formed():
    """Exercise the parse frontmatter well formed case."""
    meta, body = parse_frontmatter("---\nid: x\ntitle: X\n---\nthe body\n")
    assert meta == {"id": "x", "title": "X"}
    assert body == "the body"


def test_parse_frontmatter_absent():
    """Exercise the parse frontmatter absent case."""
    meta, body = parse_frontmatter("no frontmatter here\n")
    assert meta == {}
    assert body == "no frontmatter here\n"


def test_parse_frontmatter_empty_block():
    """Exercise the parse frontmatter empty block case."""
    meta, body = parse_frontmatter("---\n---\nbody")
    assert meta == {}
    assert body == "body"


def test_iter_md_docs_skips_index_and_missing(tmp_path):
    """Exercise the iter md docs skips index and missing case."""
    (tmp_path / "a.md").write_text("---\nid: a\n---\nA")
    (tmp_path / "index.md").write_text("index")
    (tmp_path / "note.txt").write_text("ignored")
    docs = list(iter_md_docs(tmp_path))
    assert [p.name for p, _, _ in docs] == ["a.md"]
    assert docs[0][1] == {"id": "a"}
    assert docs[0][2] == "A"
    assert list(iter_md_docs(tmp_path / "nope")) == []
