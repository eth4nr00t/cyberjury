"""Review guides load from data and are selected by file and dependency signals."""

import pytest

from cyberjury.domains.evm import EVM
from cyberjury.domains.web import WEB
from cyberjury.guides import Guide, load_guides, select_guides
from cyberjury.markdown_docs import iter_md_docs

_GUIDE_REQUIRED_FIELDS = {"id", "title", "kind", "detect"}
_GUIDE_ROUTING_FIELDS = {"entrypoint_files", "entrypoint_markers", "logic_layers", "api_patterns"}


def _guide_docs():
    for domain in (WEB, EVM):
        for directory in (domain.paths.languages_dir, domain.paths.frameworks_dir, domain.paths.protocols_dir):
            for path, meta, _body in iter_md_docs(directory):
                yield domain.name, path, meta


def test_shipped_guides_load():
    """Shipped guides load."""
    by_id = {g.id: g for g in load_guides()}
    assert {"python", "django", "oauth"} <= set(by_id)
    assert by_id["python"].kind == "language"
    assert by_id["django"].kind == "framework"
    assert by_id["django"].language == "python"
    assert by_id["oauth"].kind == "protocol"
    assert "IDOR" in by_id["django"].body or "idor" in by_id["django"].body.lower()


def test_every_guide_declares_a_kind_in_frontmatter():
    """Every guide declares a kind in frontmatter."""
    for g in load_guides():
        assert g.kind in {"language", "framework", "protocol"}, f"{g.id} has kind {g.kind!r}"


def test_guide_frontmatter_uses_the_shared_schema():
    """Stack detection depends on a stable guide metadata shape."""
    allowed = _GUIDE_REQUIRED_FIELDS | _GUIDE_ROUTING_FIELDS | {"language"}
    for domain, path, meta in _guide_docs():
        fields = set(meta)
        assert fields >= _GUIDE_REQUIRED_FIELDS, f"{domain}/{path.name}: missing schema fields"
        assert fields <= allowed, f"{domain}/{path.name}: unknown schema fields {fields - allowed}"
        assert meta["id"] == path.stem, f"{domain}/{path.name}: id must match the file stem"
        assert meta["kind"] in {"language", "framework", "protocol"}, f"{domain}/{path.name}: bad kind"
        assert isinstance(meta["detect"], dict), f"{domain}/{path.name}: detect must be a map"
        assert meta["detect"], f"{domain}/{path.name}: detect must be non-empty"


def test_guide_routing_fields_follow_the_guide_kind_contract():
    """Each guide kind owns the routing fields the scaffold consumes."""
    for domain, path, meta in _guide_docs():
        kind = meta["kind"]
        if kind == "framework":
            assert meta.get("language"), f"{domain}/{path.name}: framework guide needs a language"
            for field in ("entrypoint_files", "entrypoint_markers", "logic_layers"):
                assert meta.get(field), f"{domain}/{path.name}: framework guide needs {field}"
        elif kind == "language":
            for field in ("entrypoint_files", "entrypoint_markers", "logic_layers"):
                assert field in meta, f"{domain}/{path.name}: language guide needs {field}"
            for field in ("entrypoint_markers", "logic_layers"):
                assert meta[field], f"{domain}/{path.name}: language guide needs {field}"
            assert "language" not in meta, f"{domain}/{path.name}: language guide id is the language"
        else:
            assert "language" not in meta, f"{domain}/{path.name}: protocol guide is language-neutral"
        for field in _GUIDE_ROUTING_FIELDS:
            values = meta.get(field, [])
            assert isinstance(values, list), f"{domain}/{path.name}: {field} must be a list when present"
            assert all(isinstance(v, str) and v for v in values), f"{domain}/{path.name}: bad {field}"


@pytest.mark.parametrize("field", sorted(_GUIDE_ROUTING_FIELDS))
def test_guide_routing_fields_do_not_repeat_values_within_one_guide(field):
    """Duplicate routing signals can hide stale guide metadata."""
    for domain, path, meta in _guide_docs():
        values = meta.get(field, [])
        assert len(values) == len(set(values)), f"{domain}/{path.name}: duplicate {field}"


def test_protocol_guide_selected_by_protocol_token():
    """Protocol guide selected by protocol token."""
    matched = {g.id for g in select_guides(["main.py"], source_text="grant_type=authorization_code\nredirect_uri\n")}
    assert "oauth" in matched


def test_mcp_guide_selected_by_protocol_token():
    """Mcp guide selected by protocol token."""
    src = "from mcp.server import Server\n@mcp.tool\ndef call_tool(): ...\n"
    matched = {g.id for g in select_guides(["server.py"], source_text=src)}
    assert "mcp" in matched


def test_evm_token_launch_guide_selected_by_content_token():
    """EVM token launch guide selected by content token."""
    from cyberjury.domains.registry import get_domain

    paths = get_domain("evm").paths
    pool = load_guides(paths.languages_dir, paths.frameworks_dir, paths.protocols_dir)
    src = "function enableTrading() external onlyOwner { tradingEnabled = true; }\n"
    matched = {g.id for g in select_guides(["Token.sol"], source_text=src, guides=pool)}
    assert "token-launches" in matched


def test_manifest_name_does_not_match_a_word_in_source():
    """Manifest name does not match a word in source."""
    assert "flask" not in {g.id for g in select_guides(["app.py"], source_text="x = some_expression_flask_like\n")}
    assert "flask" in {g.id for g in select_guides(["app.py"], manifest_text="Flask==3.0\n")}


def test_select_by_file_glob():
    """Select by file glob."""
    matched = {g.id for g in select_guides(["app/urls.py", "app/views.py", "manage.py"])}
    assert "python" in matched
    assert "django" in matched


def test_select_by_manifest_substring():
    """Select by manifest substring."""
    matched = {g.id for g in select_guides(["main.py"], manifest_text="Django==4.2\nrequests\n")}
    assert "django" in matched
    assert "python" in matched


def test_no_signal_no_match():
    """No signal no match."""
    assert select_guides(["index.html", "style.css"]) == []


def test_select_respects_injected_pool():
    """Select respects injected pool."""
    only = [
        Guide(
            id="x",
            kind="framework",
            language="",
            title="X",
            detect_files=("*.xyz",),
            detect_manifest=(),
            detect_imports=(),
            detect_content=(),
            entrypoint_files=(),
            entrypoint_markers=(),
            logic_layers=(),
            api_patterns=(),
            body="b",
        )
    ]
    assert [g.id for g in select_guides(["a.xyz"], guides=only)] == ["x"]
    assert select_guides(["a.py"], guides=only) == []
