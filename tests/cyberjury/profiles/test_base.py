"""Profile base contracts resolve content and expose typed proof backends."""

from dataclasses import replace
from shutil import copytree

import pytest

from cyberjury.profiles.base import (
    PoCBackend,
    ProfileBinding,
    ReproducingPoCBackend,
    content_paths,
    profile_binding,
)
from cyberjury.profiles.evm.poc import ForgePoC
from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.profiles.web.poc import WebPoC


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


def test_profile_poc_backends_implement_the_shared_contracts():
    web = WebPoC()
    evm = ForgePoC()

    assert isinstance(web, PoCBackend)
    assert isinstance(evm, PoCBackend)
    assert not isinstance(web, ReproducingPoCBackend)
    assert isinstance(evm, ReproducingPoCBackend)


def test_profile_binding_is_stable_strict_and_covers_prompt_policy():
    bindings = [profile_binding(WEB_PROFILE) for _ in range(3)]
    restored = ProfileBinding.from_dict(bindings[0].to_dict())
    changed = profile_binding(replace(WEB_PROFILE, diff_focus=WEB_PROFILE.diff_focus + "\nAdditional focus."))

    assert len({binding.profile_sha256 for binding in bindings}) == 1
    assert restored == bindings[0]
    assert changed.content_snapshot_id == bindings[0].content_snapshot_id
    assert changed.diff_policy_sha256 != bindings[0].diff_policy_sha256
    assert changed.profile_sha256 != bindings[0].profile_sha256


def test_profile_binding_changes_when_profile_content_changes(tmp_path):
    root = copytree(WEB_PROFILE.content_root, tmp_path / "web")
    profile = replace(WEB_PROFILE, content_root=root)
    before = profile_binding(profile)
    detection = root / "detection.yaml"
    detection.write_text(detection.read_text() + "\n")
    after = profile_binding(profile)

    assert after.content_snapshot_id != before.content_snapshot_id
    assert after.profile_sha256 != before.profile_sha256


def test_profile_binding_fails_loud_on_missing_content_or_facts_backend(tmp_path):
    root = copytree(WEB_PROFILE.content_root, tmp_path / "web")
    profile = replace(WEB_PROFILE, content_root=root)
    (root / "playbook" / "unit-review.md").unlink()

    with pytest.raises(ValueError, match=r"unit-review\.md"):
        profile_binding(profile)
    with pytest.raises(ValueError, match="facts backend"):
        profile_binding(replace(WEB_PROFILE, facts_backend=None))


def test_profile_binding_fails_loud_on_missing_backend_owned_content(tmp_path):
    root = copytree(WEB_PROFILE.content_root, tmp_path / "web")
    (root / "facts" / "queries.yaml").unlink()

    with pytest.raises(ValueError, match="facts backend content is invalid"):
        profile_binding(replace(WEB_PROFILE, content_root=root))
