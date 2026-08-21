"""Profile base contracts resolve content and expose typed proof backends."""

from cyberjury.profiles.base import PoCBackend, ReproducingPoCBackend, content_paths
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
