"""Repository benchmark targets preserve source and scope identity."""

from types import SimpleNamespace

from cyberjury.profiles.registry import get_profile
from evals.benchmarks.contract import RepositoryCase
from evals.review.repository import targets


def test_materialize_uses_the_declared_repository_scope(tmp_path):
    root = tmp_path / "repo"
    scope = root / "backend"
    scope.mkdir(parents=True)
    case = RepositoryCase(
        id="demo",
        kind="repository",
        answer_key=tmp_path / "answer-key.yaml",
        provenance="public",
        target={"type": "git", "root": str(root), "path": "backend"},
        profile="web",
    )

    with targets.materialize(case, get_profile("web")) as target:
        assert target.root == root
        assert target.scope == scope


def test_materialize_prepares_explorer_source(tmp_path, monkeypatch):
    case = RepositoryCase(
        id="explorer-demo",
        kind="repository",
        answer_key=tmp_path / "answer-key.yaml",
        provenance="public",
        target={"type": "explorer", "chain": "test", "address": "0x1", "path": "."},
        profile="evm",
    )

    def fake_prepare(name, target, root):
        (root / name).mkdir()
        (root / name / "Token.sol").write_text("contract Token {}\n", encoding="utf-8")
        return SimpleNamespace(ok=True, detail="prepared")

    monkeypatch.setattr(targets, "prepare_target", fake_prepare)

    with targets.materialize(case, get_profile("evm")) as target:
        assert target.scope == target.root
        assert (target.scope / "Token.sol").is_file()


def test_materialize_prepares_evm_git_scope(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    scope = root / "contracts"
    scope.mkdir(parents=True)
    seen = {}
    case = RepositoryCase(
        id="evm-demo",
        kind="repository",
        answer_key=tmp_path / "answer-key.yaml",
        provenance="public",
        target={"type": "git", "root": str(root), "path": "contracts"},
        profile="evm",
    )

    def fake_prepare(name, target, repository, review_scope, *, verify):
        seen.update(name=name, repository=repository, scope=review_scope, verify=verify)
        return SimpleNamespace(ok=True, detail="prepared")

    monkeypatch.setattr(targets, "prepare_git_scope", fake_prepare)

    with targets.materialize(case, get_profile("evm")):
        pass

    assert seen == {"name": "evm-demo", "repository": root, "scope": scope, "verify": False}
