"""Review guides load from data and are selected by file and dependency signals."""

import re

import pytest

from cyberjury.guides import (
    Guide,
    entrypoint_globs,
    entrypoint_markers,
    load_guides,
    logic_layer_globs,
    public_api_patterns,
    select_guides,
)
from cyberjury.markdown_docs import iter_md_docs
from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.profiles.web import WEB_PROFILE

_GUIDE_REQUIRED_FIELDS = {"id", "title", "kind", "detect"}
_GUIDE_ROUTING_FIELDS = {
    "entrypoint_files",
    "entrypoint_markers",
    "logic_layer_files",
    "public_api_patterns",
}
_GUIDE_DETECT_FIELDS = {"files", "manifest_hints", "imports", "content"}
_GUIDE_FIELD_ORDER = ("id", "title", "kind", "language", "detect")
_GUIDE_DETECT_FIELD_ORDER = ("files", "manifest_hints", "imports", "content")
_GUIDE_ROUTING_FIELD_ORDER = (
    "entrypoint_files",
    "entrypoint_markers",
    "logic_layer_files",
    "public_api_patterns",
)


def _guide_docs():
    for profile in (WEB_PROFILE, EVM_PROFILE):
        for directory in (profile.paths.languages_dir, profile.paths.frameworks_dir, profile.paths.protocols_dir):
            for path, meta, _body in iter_md_docs(directory):
                yield profile.name, path, meta


def _guide_bodies():
    for profile in (WEB_PROFILE, EVM_PROFILE):
        for directory in (profile.paths.languages_dir, profile.paths.frameworks_dir, profile.paths.protocols_dir):
            for path, meta, body in iter_md_docs(directory):
                yield profile.name, path, meta, body


def test_shipped_guides_load():
    by_id = {g.id: g for g in load_guides()}
    assert {"python", "django", "oauth"} <= set(by_id)
    assert by_id["python"].kind == "language"
    assert by_id["django"].kind == "framework"
    assert by_id["django"].language == "python"
    assert by_id["oauth"].kind == "protocol"
    assert "IDOR" in by_id["django"].body or "idor" in by_id["django"].body.lower()


def test_guide_bodies_follow_the_document_contract():
    expected_h2s = ["Attack Surface", "Trust Boundaries", "Review Guidance", "Safe Boundaries"]
    for profile, path, meta, body in _guide_bodies():
        headings = re.findall(r"^# (.+)$", body, re.MULTILINE)
        assert headings == [f"{meta['title']} Review Notes"], f"{profile}/{path.name}: H1 must match title"
        h2s = re.findall(r"^## (.+)$", body, re.MULTILINE)
        assert h2s == expected_h2s, f"{profile}/{path.name}: H2 order must be {expected_h2s}"
        before_first_h2 = body.split("## Attack Surface", 1)[0]
        unnamed_prose = [line for line in before_first_h2.splitlines()[1:] if line.strip()]
        assert not unnamed_prose, f"{profile}/{path.name}: prose must start under Attack Surface"
        for index, heading in enumerate(expected_h2s):
            end = expected_h2s[index + 1] if index + 1 < len(expected_h2s) else None
            section = body.split(f"## {heading}", 1)[1]
            if end:
                section = section.split(f"## {end}", 1)[0]
            assert section.strip(), f"{profile}/{path.name}: {heading} must not be empty"


def test_every_guide_declares_a_kind_in_frontmatter():
    for g in load_guides():
        assert g.kind in {"language", "framework", "protocol"}, f"{g.id} has kind {g.kind!r}"


def test_guide_frontmatter_uses_the_shared_schema():
    """Stack detection depends on a stable guide metadata shape."""
    allowed = _GUIDE_REQUIRED_FIELDS | _GUIDE_ROUTING_FIELDS | {"language"}
    for profile, path, meta in _guide_docs():
        fields = set(meta)
        assert fields >= _GUIDE_REQUIRED_FIELDS, f"{profile}/{path.name}: missing schema fields"
        assert fields <= allowed, f"{profile}/{path.name}: unknown schema fields {fields - allowed}"
        assert meta["id"] == path.stem, f"{profile}/{path.name}: id must match the file stem"
        assert meta["kind"] in {"language", "framework", "protocol"}, f"{profile}/{path.name}: bad kind"
        assert isinstance(meta["detect"], dict), f"{profile}/{path.name}: detect must be a map"
        assert meta["detect"], f"{profile}/{path.name}: detect must be non-empty"
        assert set(meta["detect"]) <= _GUIDE_DETECT_FIELDS, f"{profile}/{path.name}: unknown detect fields"


def test_guide_frontmatter_field_order_is_stable():
    """Stable guide field order keeps routing metadata comparable."""
    for profile, path, meta in _guide_docs():
        expected = tuple(k for k in (*_GUIDE_FIELD_ORDER, *_GUIDE_ROUTING_FIELD_ORDER) if k in meta)
        assert tuple(meta) == expected, f"{profile}/{path.name}: field order should be {expected}"


def test_guide_detect_field_order_is_stable():
    """Detection signals should flow from file shape to source content."""
    for profile, path, meta in _guide_docs():
        expected = tuple(k for k in _GUIDE_DETECT_FIELD_ORDER if k in meta["detect"])
        assert tuple(meta["detect"]) == expected, f"{profile}/{path.name}: detect order should be {expected}"


def test_guide_routing_fields_follow_the_guide_kind_contract():
    """Each guide kind owns the routing fields the scaffold consumes."""
    for profile, path, meta in _guide_docs():
        fields = set(meta)
        kind = meta["kind"]
        if kind == "framework":
            assert meta.get("language"), f"{profile}/{path.name}: framework guide needs a language"
            for field in ("entrypoint_files", "entrypoint_markers"):
                assert meta.get(field), f"{profile}/{path.name}: framework guide needs {field}"
            assert "logic_layer_files" in meta, f"{profile}/{path.name}: framework guide needs logic_layer_files"
        elif kind == "language":
            for field in ("entrypoint_files", "entrypoint_markers", "logic_layer_files"):
                assert field in meta, f"{profile}/{path.name}: language guide needs {field}"
            for field in ("entrypoint_markers", "logic_layer_files"):
                assert meta[field], f"{profile}/{path.name}: language guide needs {field}"
            assert "language" not in meta, f"{profile}/{path.name}: language guide id is the language"
        else:
            assert "language" not in meta, f"{profile}/{path.name}: protocol guide is language neutral"
        assert fields >= _GUIDE_ROUTING_FIELDS, f"{profile}/{path.name}: missing routing fields"
        for field in _GUIDE_ROUTING_FIELDS:
            values = meta.get(field, [])
            assert isinstance(values, list), f"{profile}/{path.name}: {field} must be a list when present"
            assert all(isinstance(v, str) and v for v in values), f"{profile}/{path.name}: bad {field}"


@pytest.mark.parametrize("field", sorted(_GUIDE_ROUTING_FIELDS))
def test_guide_routing_fields_do_not_repeat_values_within_one_guide(field):
    """Duplicate routing signals can hide stale guide metadata."""
    for profile, path, meta in _guide_docs():
        values = meta.get(field, [])
        assert len(values) == len(set(values)), f"{profile}/{path.name}: duplicate {field}"


@pytest.mark.parametrize("field", ["entrypoint_files", "logic_layer_files", "public_api_patterns"])
def test_framework_guides_do_not_repeat_declared_language_routing(field):
    """Language guides own generic routing signals for their frameworks."""
    by_profile: dict[str, dict[str, dict]] = {}
    for profile, path, meta in _guide_docs():
        if meta["kind"] == "language":
            by_profile.setdefault(profile, {})[path.stem] = meta
    for profile, path, meta in _guide_docs():
        if meta["kind"] != "framework":
            continue
        language = by_profile[profile][meta["language"]]
        repeated = set(meta.get(field, [])) & set(language.get(field, []))
        assert not repeated, f"{profile}/{path.name}: repeats {field} from {meta['language']}: {sorted(repeated)}"


def test_framework_guides_inherit_declared_language_routing_at_load():
    """A framework selected by manifest still carries its language routing signals."""
    by_id = {g.id: g for g in load_guides()}
    for framework in (g for g in by_id.values() if g.kind == "framework" and g.language in by_id):
        language = by_id[framework.language]
        assert entrypoint_globs([language, framework]) == framework.entrypoint_files
        assert entrypoint_markers([language, framework]) == framework.entrypoint_markers
        assert logic_layer_globs([language, framework]) == framework.logic_layer_files
        assert public_api_patterns([language, framework]) == framework.public_api_patterns


def test_framework_entrypoint_markers_name_entrypoint_definitions():
    """Framework entrypoint markers avoid helper calls and producer call sites."""
    by_id = {g.id: g for g in load_guides()}
    assert "Depends(" not in by_id["fastapi"].entrypoint_markers
    assert ".delay(" not in by_id["celery"].entrypoint_markers
    assert ".apply_async(" not in by_id["celery"].entrypoint_markers


@pytest.mark.parametrize("path", ["service.ts", "service.tsx", "service.mts", "service.cts"])
def test_typescript_guide_detects_each_supported_module_extension(path):
    selected = {guide.id for guide in select_guides([path])}

    assert "typescript" in selected


def test_python_public_api_patterns_cover_sync_async_and_class_symbols():
    python = {guide.id: guide for guide in load_guides()}["python"]

    for source in ("def load():\n    pass\n", "async def load():\n    pass\n", "class Loader:\n    pass\n"):
        assert any(re.search(pattern, source, re.MULTILINE) for pattern in python.public_api_patterns)


def test_protocol_guide_selected_by_protocol_token():
    matched = {g.id for g in select_guides(["main.py"], source_text="grant_type=authorization_code\nredirect_uri\n")}
    assert "oauth" in matched


def test_mcp_guide_selected_by_protocol_token():
    src = "from mcp.server import Server\n@mcp.tool\ndef call_tool(): ...\n"
    matched = {g.id for g in select_guides(["server.py"], source_text=src)}
    assert "mcp" in matched


def test_evm_token_launch_guide_selected_by_content_token():
    from cyberjury.profiles.registry import get_profile

    paths = get_profile("evm").paths
    pool = load_guides(paths.languages_dir, paths.frameworks_dir, paths.protocols_dir)
    src = "function enableTrading() external onlyOwner { tradingEnabled = true; }\n"
    matched = {g.id for g in select_guides(["Token.sol"], source_text=src, guides=pool)}
    assert "token-launches" in matched


def test_manifest_name_does_not_match_a_word_in_source():
    assert "flask" not in {g.id for g in select_guides(["app.py"], source_text="x = some_expression_flask_like\n")}
    assert "flask" in {g.id for g in select_guides(["app.py"], manifest_text="Flask==3.0\n")}


def test_select_by_file_glob():
    matched = {g.id for g in select_guides(["app/urls.py", "app/views.py", "manage.py"])}
    assert "python" in matched
    assert "django" in matched


def test_select_by_manifest_substring():
    matched = {g.id for g in select_guides(["main.py"], manifest_text="Django==4.2\nrequests\n")}
    assert "django" in matched
    assert "python" in matched


def test_no_signal_no_match():
    assert select_guides(["index.html", "style.css"]) == []


def test_select_respects_injected_pool():
    only = [
        Guide(
            id="x",
            kind="framework",
            language="",
            title="X",
            detect_files=("*.xyz",),
            detect_manifest_hints=(),
            detect_imports=(),
            detect_content=(),
            entrypoint_files=(),
            entrypoint_markers=(),
            logic_layer_files=(),
            public_api_patterns=(),
            body="b",
        )
    ]
    assert [g.id for g in select_guides(["a.xyz"], guides=only)] == ["x"]
    assert select_guides(["a.py"], guides=only) == []
