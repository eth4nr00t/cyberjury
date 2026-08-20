"""The profile layer resolves content, detects profiles, and fails loud on unavailable profiles."""

import re

import pytest

from cyberjury.markdown_docs import iter_md_docs
from cyberjury.profiles.base import content_paths
from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.profiles.registry import detect_profile, get_profile, resolve_profile
from cyberjury.profiles.web import WEB_PROFILE

_VULNERABILITY_REQUIRED_FIELDS = {"id", "title", "impact", "tags", "selection_hints"}
_VULNERABILITY_OPTIONAL_FIELDS = {"aliases"}
_VULNERABILITY_FIELD_ORDER = ("id", "title", "impact", "tags", "selection_hints", "aliases")
_LOW_SIGNAL_SELECTION_HINTS = {
    "/ ",
    ".length",
    "@app.route",
    "@router",
    "amount",
    "auth",
    "check",
    "constructor",
    "cursor",
    "external",
    "find(",
    "form",
    "location",
    "merge",
    "open(",
    "origin",
    "price",
    "public",
    "request.args",
    "resource",
    "session",
    "status",
    "transfer(",
    "while",
}


def test_web_profile_resolves_shipped_content():
    paths = WEB_PROFILE.paths
    assert paths.vulnerabilities_dir.is_dir()
    assert paths.detection_file.is_file()
    assert paths.methodology_file.is_file()
    assert paths.severity_rubric_file.is_file()
    assert paths.knowledge_index.parent == paths.vulnerabilities_dir.parent


def test_content_paths_layout_follows_the_root():
    paths = content_paths("/srv/x")
    assert str(paths.vulnerabilities_dir) == "/srv/x/knowledge/vulnerabilities"
    assert str(paths.detection_file) == "/srv/x/detection.yaml"
    assert str(paths.unit_review_file) == "/srv/x/playbook/unit-review.md"


def test_get_profile_returns_registered_and_fails_loud_on_unknown():
    assert get_profile("web") is WEB_PROFILE
    assert get_profile("evm") is EVM_PROFILE
    with pytest.raises(ValueError, match="unknown or unavailable review profile"):
        get_profile("nonsense")


def test_detect_profile_names_evm_for_any_solidity_source():
    assert detect_profile(["app.py", "views.py", "go.mod"]) == "web"
    assert detect_profile(["Vault.sol", "Token.sol"]) == "evm"
    assert detect_profile(["Vault.sol", "deploy.py"]) == "evm"
    assert detect_profile(["Vault.sol", "README.md", "foundry.toml", "explorer-raw.json"]) == "evm"
    assert detect_profile([]) == "web"


def test_resolve_profile_auto_detects_then_looks_up():
    assert resolve_profile("auto", ["a.py"]) is WEB_PROFILE
    assert resolve_profile("web", []) is WEB_PROFILE
    assert resolve_profile("auto", ["Vault.sol", "Token.sol"]) is EVM_PROFILE
    assert resolve_profile("evm", []) is EVM_PROFILE


def test_evm_profile_resolves_shipped_content_and_strategy():
    paths = EVM_PROFILE.paths
    assert (paths.languages_dir / "solidity.md").is_file()
    assert (paths.vulnerabilities_dir / "reentrancy.md").is_file()
    assert paths.detection_file.is_file()
    assert paths.methodology_file.is_file()
    assert "reentrancy" in EVM_PROFILE.diff_focus.lower()
    assert EVM_PROFILE.dedup_by_file is True
    assert WEB_PROFILE.dedup_by_file is False


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_frontmatter_uses_the_shared_schema(profile):
    allowed = _VULNERABILITY_REQUIRED_FIELDS | _VULNERABILITY_OPTIONAL_FIELDS
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        fields = set(meta)
        assert fields >= _VULNERABILITY_REQUIRED_FIELDS, f"{profile.name}/{path.name}: missing schema fields"
        assert fields <= allowed, f"{profile.name}/{path.name}: unknown schema fields {fields - allowed}"
        assert meta["id"] == path.stem, f"{profile.name}/{path.name}: id must match the file stem"
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", meta["id"]), (
            f"{profile.name}/{path.name}: id must use lowercase kebab-case"
        )
        assert meta["impact"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}, f"{profile.name}/{path.name}: bad impact"
        for key in ("tags", "selection_hints", "aliases"):
            values = meta.get(key, [])
            assert isinstance(values, list), f"{profile.name}/{path.name}: {key} must be a list"
            assert all(isinstance(v, str) and v for v in values), f"{profile.name}/{path.name}: bad {key}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_frontmatter_field_order_is_stable(profile):
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        expected = tuple(k for k in _VULNERABILITY_FIELD_ORDER if k in meta)
        assert tuple(meta) == expected, f"{profile.name}/{path.name}: field order should be {expected}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_selection_hints_are_unique(profile):
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        hints = [str(t).lower() for t in meta["selection_hints"]]
        assert len(hints) == len(set(hints)), f"{profile.name}/{path.name}: duplicate selection hints"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_selection_hints_avoid_known_low_signal_literals(profile):
    deny = {h.lower() for h in _LOW_SIGNAL_SELECTION_HINTS}
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        hints = {str(t).lower() for t in meta["selection_hints"]}
        assert not (hints & deny), f"{profile.name}/{path.name}: low signal hints {sorted(hints & deny)}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_aliases_are_optional_and_canonical(profile):
    docs = list(iter_md_docs(profile.paths.vulnerabilities_dir))
    canonical_ids = {meta["id"] for _path, meta, _body in docs}
    seen: dict[str, str] = {}
    for path, meta, _body in docs:
        cid = meta["id"]
        for alias in meta.get("aliases", []):
            norm = alias.strip().lower().replace("_", "-").replace(" ", "-")
            assert norm != cid, f"{profile.name}/{path.name}: alias repeats the canonical id"
            assert norm not in canonical_ids, f"{profile.name}/{path.name}: alias collides with class id {norm}"
            assert norm not in seen, f"{profile.name}/{path.name}: alias also owned by {seen[norm]}"
            seen[norm] = cid


_EVM_NO_SWC = {"accounting-precision", "oracle-price-manipulation", "weird-erc20"}


def _class_tags(profile):
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        yield path.name[:-3], [str(t) for t in (meta.get("tags") or [])]


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_tags_lead_with_registry_codes(profile):
    rows = list(_class_tags(profile))
    assert rows, f"{profile.name} has no vulnerability classes"
    for cid, tags in rows:
        assert tags, f"{profile.name}/{cid} has no tags"
        seen_keyword = False
        for t in tags:
            if not t.startswith(("swc-", "cwe-", "owasp-")):
                seen_keyword = True
            elif seen_keyword:
                pytest.fail(f"{profile.name}/{cid}: code {t!r} after a keyword, tags={tags}")


def test_every_web_class_tags_a_cwe_and_an_owasp():
    for cid, tags in _class_tags(WEB_PROFILE):
        assert any(t.startswith("cwe-") for t in tags), f"web/{cid} has no cwe tag: {tags}"
        assert any(t.startswith("owasp-") for t in tags), f"web/{cid} has no owasp tag: {tags}"


def test_every_evm_class_tags_swc_unless_post_swc_defi():
    for cid, tags in _class_tags(EVM_PROFILE):
        has_swc = any(t.startswith("swc-") for t in tags)
        if cid in _EVM_NO_SWC:
            assert not has_swc, f"evm/{cid} now has an swc id, drop it from the no-swc allowlist"
            assert tags, f"evm/{cid} has no tags at all"
        else:
            assert has_swc, f"evm/{cid} has no swc tag and is not an allowed exception: {tags}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_every_class_carries_a_code_example(profile):
    for path, _meta, body in iter_md_docs(profile.paths.vulnerabilities_dir):
        assert "```" in body, f"{profile.name}/{path.name[:-3]} has no fenced code example"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_bodies_follow_the_document_contract(profile):
    supported_languages = {
        "web": {"go", "javascript", "python", "typescript"},
        "evm": {"solidity"},
    }
    for path, meta, body in iter_md_docs(profile.paths.vulnerabilities_dir):
        headings = re.findall(r"^# (.+)$", body, re.MULTILINE)
        assert headings == [meta["title"]], f"{profile.name}/{path.name}: H1 must match title"
        safe_boundaries = re.findall(r"^## Not a Finding$", body, re.MULTILINE)
        assert len(safe_boundaries) == 1, f"{profile.name}/{path.name}: safe boundary required"
        fence_lines = re.findall(r"^```(.*)$", body, re.MULTILINE)
        opening_fences = fence_lines[::2]
        closing_fences = fence_lines[1::2]
        assert len(fence_lines) % 2 == 0, f"{profile.name}/{path.name}: unbalanced code fences"
        assert all(language.strip() for language in opening_fences), f"{profile.name}/{path.name}: untagged fence"
        assert not any(language.strip() for language in closing_fences), f"{profile.name}/{path.name}: bad close fence"
        unsupported = set(opening_fences) - supported_languages[profile.name]
        assert not unsupported, f"{profile.name}/{path.name}: unsupported fence languages {sorted(unsupported)}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_knowledge_index_matches_each_profile_catalog(profile):
    expected = {path.stem for path, _meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir)}
    text = profile.paths.knowledge_index.read_text(encoding="utf-8")
    listed = re.findall(r"^- `([a-z0-9-]+)`", text, re.MULTILINE)
    assert len(listed) == len(set(listed)), f"{profile.name}: duplicate class in index"
    assert set(listed) == expected, f"{profile.name}: index differs from class files"
    assert not text.startswith("---\n"), f"{profile.name}: documentation index must not be loadable"


def test_both_profiles_bind_a_facts_backend():
    from cyberjury.review.facts import FactsBackend

    assert isinstance(EVM_PROFILE.facts_backend, FactsBackend)
    assert isinstance(WEB_PROFILE.facts_backend, FactsBackend)


def test_each_backend_names_its_own_toolchain_in_its_install_hint():
    assert "solc" in EVM_PROFILE.facts_backend.install_hint
    assert "tree-sitter" in WEB_PROFILE.facts_backend.install_hint
    assert "solc" not in WEB_PROFILE.facts_backend.install_hint
