"""Language/framework review guides load and are selected by detection signals such as.

file globs and dependency-manifest substrings, so adding one is a drop-in file.
"""

from cyberjury.guides import Guide, load_guides, select_guides


def test_shipped_guides_load():
    """Exercise the shipped guides load case."""
    by_id = {g.id: g for g in load_guides()}
    assert {"python", "django", "oauth"} <= set(by_id)
    assert by_id["python"].kind == "language"
    assert by_id["django"].kind == "framework"
    assert by_id["django"].language == "python"
    assert by_id["oauth"].kind == "protocol"
    assert "IDOR" in by_id["django"].body or "idor" in by_id["django"].body.lower()


def test_every_guide_declares_a_kind_in_frontmatter():
    """Exercise the every guide declares a kind in frontmatter case."""
    for g in load_guides():
        assert g.kind in {"language", "framework", "protocol"}, f"{g.id} has kind {g.kind!r}"


def test_protocol_guide_selected_by_protocol_token():
    """Exercise the protocol guide selected by protocol token case."""
    matched = {g.id for g in select_guides(["main.py"], source_text="grant_type=authorization_code\nredirect_uri\n")}
    assert "oauth" in matched


def test_mcp_guide_selected_by_protocol_token():
    """Exercise the mcp guide selected by protocol token case."""
    src = "from mcp.server import Server\n@mcp.tool\ndef call_tool(): ...\n"
    matched = {g.id for g in select_guides(["server.py"], source_text=src)}
    assert "mcp" in matched


def test_evm_token_launch_guide_selected_by_content_token():
    """Exercise the evm token launch guide selected by content token case."""
    from cyberjury.domains.registry import get_domain

    paths = get_domain("evm").paths
    pool = load_guides(paths.languages_dir, paths.frameworks_dir, paths.protocols_dir)
    src = "function enableTrading() external onlyOwner { tradingEnabled = true; }\n"
    matched = {g.id for g in select_guides(["Token.sol"], source_text=src, guides=pool)}
    assert "token-launches" in matched


def test_manifest_name_does_not_match_a_word_in_source():
    """Exercise the manifest name does not match a word in source case."""
    assert "flask" not in {g.id for g in select_guides(["app.py"], source_text="x = some_expression_flask_like\n")}
    assert "flask" in {g.id for g in select_guides(["app.py"], manifest_text="Flask==3.0\n")}


def test_select_by_file_glob():
    """Exercise the select by file glob case."""
    matched = {g.id for g in select_guides(["app/urls.py", "app/views.py", "manage.py"])}
    assert "python" in matched
    assert "django" in matched


def test_select_by_manifest_substring():
    """Exercise the select by manifest substring case."""
    matched = {g.id for g in select_guides(["main.py"], manifest_text="Django==4.2\nrequests\n")}
    assert "django" in matched
    assert "python" in matched


def test_no_signal_no_match():
    """Exercise the no signal no match case."""
    assert select_guides(["index.html", "style.css"]) == []


def test_select_respects_injected_pool():
    """Exercise the select respects injected pool case."""
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
