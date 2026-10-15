"""Profile base contracts resolve content and expose typed proof backends."""

from dataclasses import replace
from shutil import copytree

import pytest

from cyberjury.profiles.base import PoCBackend, ProfileBinding, content_paths, profile_binding
from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.profiles.web.poc import WebPoC
from cyberjury.providers.mock import MockProvider


def test_web_profile_resolves_shipped_content():
    paths = WEB_PROFILE.paths
    assert paths.detection_file.is_file()
    assert paths.severity_rubric_file.is_file()
    assert paths.security_kernel_file.is_file()


def test_content_paths_layout_follows_the_root():
    paths = content_paths("/srv/x")
    assert str(paths.detection_file) == "/srv/x/detection.yaml"
    assert str(paths.severity_rubric_file) == "/srv/x/playbook/severity-rubric.md"
    assert str(paths.security_kernel_file) == "/srv/x/knowledge/security-kernel.md"


def test_web_profile_poc_backend_implements_the_shared_contract():
    web = WebPoC(provider=MockProvider(), model="m")

    assert isinstance(web, PoCBackend)


def test_profile_binding_is_stable_strict_and_covers_behavior_policy():
    bindings = [profile_binding(WEB_PROFILE) for _ in range(3)]
    restored = ProfileBinding.from_dict(bindings[0].to_dict())
    changed = profile_binding(replace(WEB_PROFILE, poc_backend=None))

    assert len({binding.profile_sha256 for binding in bindings}) == 1
    assert restored == bindings[0]
    assert "diff_policy_sha256" not in bindings[0].to_dict()
    assert bindings[0].to_dict()["schema"] == "cyberjury.profile-binding/v4"
    assert changed.content_snapshot_id == bindings[0].content_snapshot_id
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
    (root / "playbook" / "severity-rubric.md").unlink()

    with pytest.raises(ValueError, match=r"severity-rubric\.md"):
        profile_binding(profile)
    with pytest.raises(ValueError, match="facts backend"):
        profile_binding(replace(WEB_PROFILE, facts_backend=None))


def test_profile_binding_fails_loud_on_missing_backend_owned_content(tmp_path):
    root = copytree(WEB_PROFILE.content_root, tmp_path / "web")
    (root / "facts" / "queries.yaml").unlink()

    with pytest.raises(ValueError, match="facts backend content is invalid"):
        profile_binding(replace(WEB_PROFILE, content_root=root))


def test_profile_binding_requires_detection_parser_inputs_to_equal_query_languages(tmp_path):
    root = copytree(WEB_PROFILE.content_root, tmp_path / "web")
    detection = root / "detection.yaml"
    detection.write_text(detection.read_text().replace('  - ".go"\n', "", 1))

    with pytest.raises(ValueError, match="source_extensions must equal"):
        profile_binding(replace(WEB_PROFILE, content_root=root))


def test_profile_binding_fails_loud_on_missing_security_kernel(tmp_path):
    root = copytree(WEB_PROFILE.content_root, tmp_path / "web")
    profile = replace(WEB_PROFILE, content_root=root)
    kernel = root / "knowledge" / "security-kernel.md"
    kernel.unlink()

    with pytest.raises(ValueError, match=r"knowledge|security-kernel\.md"):
        profile_binding(profile)
