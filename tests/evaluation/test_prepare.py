"""Target preparation replaces subprocess execution so tests do no external setup."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.benchmarks import prepare as prep

_SOURCE_META = (
    '{"source":"bscscan","chain":"bsc","address":"0x0000000000000000000000000000000000000001",'
    '"compiler_version":"v0.8.2+commit.661d1103","optimization_used":false,"runs":200}'
)
_GIT_URL = "https://example.invalid/x"


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _successful_output(cmd: list[str]) -> str:
    if cmd == ["git", "remote", "get-url", "origin"]:
        return f"{_GIT_URL}\n"
    return ""


@pytest.fixture
def calls(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(cmd, cwd, timeout=1800):
        seen.append(cmd)
        return 0, _successful_output(cmd)

    monkeypatch.setattr(prep, "_run", fake_run)
    return seen


def test_a_missing_binary_reports_the_step_instead_of_raising(tmp_path):
    code, log = prep._run(["definitely-not-installed-xyz", "--version"], tmp_path)
    assert code == 127
    assert "cannot run definitely-not-installed-xyz" in log


def test_solidity_targets_selects_only_the_targets_that_need_a_build():
    targets = prep.solidity_targets()
    assert "next-generation-eurf" in targets
    assert "aiohttp" not in targets
    assert all(t.get("type") in ("git", "explorer") for t in targets.values())


def test_default_root_fails_loud_without_the_backtest_dir(monkeypatch):
    monkeypatch.delenv("CYBERJURY_BACKTEST_DIR", raising=False)
    with pytest.raises(ValueError, match="CYBERJURY_BACKTEST_DIR"):
        prep.default_root()


def test_default_root_reads_the_backtest_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERJURY_BACKTEST_DIR", str(tmp_path))
    assert prep.default_root() == tmp_path / "repositories"


def test_a_yarn_lockfile_selects_yarn_and_a_npm_lockfile_selects_npm_ci(calls, tmp_path):
    yarn_project = tmp_path / "y"
    yarn_project.mkdir()
    (yarn_project / "package.json").write_text("{}")
    (yarn_project / "yarn.lock").write_text("yarn lockfile v1\n")
    ok, _steps = prep._install(yarn_project, {})
    assert ok
    assert calls[0][:2] == ["yarn", "install"]

    calls.clear()
    npm_project = tmp_path / "n"
    npm_project.mkdir()
    (npm_project / "package.json").write_text("{}")
    (npm_project / "package-lock.json").write_text("{}")
    ok, _steps = prep._install(npm_project, {})
    assert ok
    assert calls[0][:2] == ["npm", "ci"]


def test_no_package_json_installs_nothing(calls, tmp_path):
    ok, steps = prep._install(tmp_path, {})
    assert ok
    assert calls == []
    assert "no package.json" in steps[0]


def test_a_failed_install_retries_with_legacy_peer_deps_then_gives_up(monkeypatch, tmp_path):
    attempts: list[list[str]] = []

    def always_fail(cmd, cwd, timeout=1800):
        attempts.append(cmd)
        return 1, "ERESOLVE could not resolve"

    monkeypatch.setattr(prep, "_run", always_fail)
    project = tmp_path / "p"
    project.mkdir()
    (project / "package.json").write_text("{}")
    (project / "package-lock.json").write_text("{}")
    ok, steps = prep._install(project, {})
    assert ok is False
    assert attempts[0] == ["npm", "ci", "--no-audit", "--no-fund"]
    assert "--legacy-peer-deps" in attempts[-1]
    assert any("ERESOLVE" in s for s in steps)


def test_pinning_writes_only_into_node_modules(calls, tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "package.json").write_text("{}")
    (project / "yarn.lock").write_text("yarn lockfile v1\n")
    ok, _steps = prep._install(project, {"typescript": "^5"})
    assert ok
    pin = calls[-1]
    assert "typescript@^5" in pin
    assert "--no-save" in pin
    assert "--no-package-lock" in pin


def test_npm_pins_come_from_target_prepare_data():
    backed = prep.solidity_targets()["backed-nft-lending"]
    telcoin = prep.solidity_targets()["telcoin-stablecoin"]
    assert prep._npm_pins(backed)["@rari-capital/solmate"] == "6.2.0"
    assert prep._npm_pins(telcoin)["typescript"] == "^5"
    assert prep._npm_pins(telcoin)["@openzeppelin/contracts"] == "5.0.1"


def test_a_yarn_project_falls_back_to_ignoring_an_unusable_lockfile(monkeypatch, tmp_path):
    attempts: list[list[str]] = []

    def fail_until_no_lockfile(cmd, cwd, timeout=1800):
        attempts.append(cmd)
        return (0, "") if "--no-lockfile" in cmd else (1, "error SyntaxError: Invalid value type")

    monkeypatch.setattr(prep, "_run", fail_until_no_lockfile)
    project = tmp_path / "p"
    project.mkdir()
    (project / "package.json").write_text("{}")
    (project / "yarn.lock").write_text("yarn lockfile v1\n")
    ok, _steps = prep._install(project, {})
    assert ok
    assert attempts[-1] == ["yarn", "install", "--no-lockfile"]


def test_a_foundry_project_builds_with_forge(calls, tmp_path):
    project = tmp_path / "f"
    project.mkdir()
    (project / "foundry.toml").write_text("[profile.default]\n")
    prep._compile(project)
    assert calls[-1] == ["forge", "build"]


def test_a_hardhat_config_compiles_with_hardhat_not_forge(calls, tmp_path):
    project = tmp_path / "h"
    project.mkdir()
    (project / "hardhat.config.ts").write_text("export default {}")
    (project / "foundry.toml").write_text("[profile.default]\n")
    prep._compile(project)
    assert calls[-1] == ["npx", "hardhat", "compile"]


def test_clone_only_checks_out_the_pinned_ref(calls, tmp_path):
    dest = tmp_path / "repository"
    (dest / ".git").mkdir(parents=True)
    prep._clone(_GIT_URL, "abc123", dest)
    assert calls == [["git", "remote", "get-url", "origin"], ["git", "checkout", "abc123"]]
    (dest / ".gitmodules").write_text('[submodule "lib/forge-std"]\n')
    prep._clone(_GIT_URL, "abc123", dest)
    assert calls[-1] == ["git", "checkout", "abc123"]


def test_an_existing_clone_still_checks_out_the_pinned_ref(calls, tmp_path):
    dest = tmp_path / "repository"
    (dest / ".git").mkdir(parents=True)
    ok, note = prep._clone(_GIT_URL, "def456", dest)
    assert ok
    assert note == "checked out"
    assert calls == [["git", "remote", "get-url", "origin"], ["git", "checkout", "def456"]]


def test_cached_clone_clears_generated_foundry_files_before_a_ref_transition(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    _git(source, "config", "user.email", "test@example.com")
    _git(source, "config", "user.name", "Test User")
    (source / "Token.sol").write_text("pragma solidity ^0.8.20; contract Token {}\n")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "base")
    base = _git(source, "rev-parse", "HEAD")
    (source / "foundry.toml").write_text("committed config\n")
    (source / "remappings.txt").write_text("committed/=lib/committed/\n")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "config")
    configured = _git(source, "rev-parse", "HEAD")
    cache = tmp_path / "cache"
    assert prep._clone(str(source), base, cache)[0]
    prep._write_foundry_config(cache, repository=cache)
    (cache / "remappings.txt").write_text("generated/=lib/generated/\n")
    prep._record_generated(cache, cache / "remappings.txt")

    ok, note = prep._clone(str(source), configured, cache)

    assert ok, note
    assert (cache / "foundry.toml").read_text() == "committed config\n"
    assert (cache / "remappings.txt").read_text() == "committed/=lib/committed/\n"
    assert not (cache / prep._GENERATED_MARKER).exists()


def test_cached_clone_refuses_to_delete_a_modified_generated_file(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    _git(source, "config", "user.email", "test@example.com")
    _git(source, "config", "user.name", "Test User")
    (source / "Token.sol").write_text("pragma solidity ^0.8.20; contract Token {}\n")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "base")
    ref = _git(source, "rev-parse", "HEAD")
    cache = tmp_path / "cache"
    assert prep._clone(str(source), ref, cache)[0]
    prep._write_foundry_config(cache, repository=cache)
    (cache / "foundry.toml").write_text("operator change\n")

    ok, note = prep._clone(str(source), ref, cache)

    assert ok is False
    assert "changed after preparation" in note
    assert (cache / "foundry.toml").read_text() == "operator change\n"


def test_an_existing_clone_with_a_different_origin_fails_before_checkout(monkeypatch, tmp_path):
    attempts: list[list[str]] = []

    def run(cmd, cwd, timeout=1800):
        attempts.append(cmd)
        return 0, "https://example.invalid/other\n"

    monkeypatch.setattr(prep, "_run", run)
    dest = tmp_path / "repository"
    (dest / ".git").mkdir(parents=True)
    ok, note = prep._clone(_GIT_URL, "def456", dest)
    assert ok is False
    assert "does not match target" in note
    assert attempts == [["git", "remote", "get-url", "origin"]]


def test_a_local_repository_target_is_cloned_at_its_pinned_ref(monkeypatch, tmp_path):
    source = tmp_path / "source"
    (source / ".git").mkdir(parents=True)
    cache = tmp_path / "cache"
    attempts: list[list[str]] = []

    def run(cmd, cwd, timeout=1800):
        attempts.append(cmd)
        if cmd[:2] == ["git", "clone"]:
            dest = Path(cmd[-1])
            (dest / ".git").mkdir(parents=True)
            (dest / "Token.sol").write_text("pragma solidity ^0.8.0; contract Token {}\n")
        return 0, ""

    monkeypatch.setattr(prep, "_run", run)
    monkeypatch.setattr(prep, "_verify", lambda scope: (True, "1 files, 1 focused unit specs"))
    target = {"type": "git", "root": str(source), "ref": "abc123", "path": "."}
    result = prep.prepare_target("local", target, cache)
    assert result.ok
    assert attempts[0] == [
        "git",
        "clone",
        "--filter=blob:none",
        "--no-checkout",
        str(source.resolve()),
        str(cache / "local"),
    ]
    assert attempts[1] == ["git", "checkout", "abc123"]


def test_a_missing_ref_is_fetched_before_checkout_is_retried(monkeypatch, tmp_path):
    attempts: list[list[str]] = []

    def run(cmd, cwd, timeout=1800):
        attempts.append(cmd)
        if cmd == ["git", "remote", "get-url", "origin"]:
            return 0, f"{_GIT_URL}\n"
        if cmd[:2] == ["git", "checkout"] and len(attempts) == 2:
            return 1, "pathspec did not match"
        return 0, ""

    monkeypatch.setattr(prep, "_run", run)
    dest = tmp_path / "repository"
    (dest / ".git").mkdir(parents=True)
    ok, note = prep._clone(_GIT_URL, "def456", dest)
    assert ok
    assert note == "checked out"
    assert attempts == [
        ["git", "remote", "get-url", "origin"],
        ["git", "checkout", "def456"],
        ["git", "fetch", "--filter=blob:none", "origin", "def456"],
        ["git", "checkout", "FETCH_HEAD"],
    ]


def test_a_missing_ref_reports_fetch_failure(monkeypatch, tmp_path):
    attempts: list[list[str]] = []

    def run(cmd, cwd, timeout=1800):
        attempts.append(cmd)
        if cmd == ["git", "remote", "get-url", "origin"]:
            return 0, f"{_GIT_URL}\n"
        if cmd[:2] == ["git", "checkout"]:
            return 1, "pathspec did not match"
        return 1, "could not fetch"

    monkeypatch.setattr(prep, "_run", run)
    dest = tmp_path / "repository"
    (dest / ".git").mkdir(parents=True)
    ok, note = prep._clone(_GIT_URL, "def456", dest)
    assert ok is False
    assert "fetch def456 failed" in note
    assert attempts == [
        ["git", "remote", "get-url", "origin"],
        ["git", "checkout", "def456"],
        ["git", "fetch", "--filter=blob:none", "origin", "def456"],
    ]


def test_an_explorer_target_without_an_api_key_fails_loud(monkeypatch, tmp_path):
    monkeypatch.delenv("CYBERJURY_ETHERSCAN_API_KEY", raising=False)
    target = {"type": "explorer", "chain": "bsc", "address": "0x0000000000000000000000000000000000000001"}
    res = prep.prepare_target("feta", target, tmp_path)
    assert not res.skipped
    assert res.ok is False
    assert "Etherscan API key" in res.detail


def test_an_explorer_target_without_source_coordinates_fails_loud(tmp_path):
    res = prep.prepare_target("feta", {"type": "explorer", "chain": "bsc"}, tmp_path)
    assert res.ok is False
    assert "missing chain or address" in res.detail


def test_an_explorer_target_fetches_source_compiles_and_verifies_the_source_tree(monkeypatch, tmp_path):
    seen = {}
    builds = []

    def fake_fetch_source(**kw):
        seen.update(kw)
        out = tmp_path / "feta"
        out.mkdir()
        (out / "Token.sol").write_text("contract Token {}\n")
        (out / "cyberjury-source.json").write_text(_SOURCE_META)
        return SimpleNamespace(file_count=1, meta=prep.read_source_meta_file(out / "cyberjury-source.json"))

    scopes = []
    monkeypatch.setenv("CYBERJURY_ETHERSCAN_API_KEY", "KEY")
    monkeypatch.setattr(prep, "fetch_source", fake_fetch_source)
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: builds.append((cmd, cwd)) or (0, ""))
    monkeypatch.setattr(prep, "_verify", lambda scope: scopes.append(scope) or (True, "1 files, 1 focused unit specs"))
    target = {"type": "explorer", "chain": "bsc", "address": "0x0000000000000000000000000000000000000001"}
    res = prep.prepare_target("feta", target, tmp_path)
    assert res.ok
    assert seen["chain_key"] == "bsc"
    assert seen["api_key"] == "KEY"
    assert seen["out"] == str(tmp_path / "feta")
    assert scopes == [tmp_path / "feta"]
    assert builds == [(["forge", "build"], tmp_path / "feta")]
    assert "fetched 1 source files" in res.steps
    config = (tmp_path / "feta" / "foundry.toml").read_text()
    assert 'solc_version = "0.8.2"' in config
    assert "optimizer = false" in config
    assert "optimizer_runs = 200" in config


def test_an_existing_explorer_source_is_reused_compiled_and_verified_as_a_tree(monkeypatch, tmp_path):
    dest = tmp_path / "feta"
    dest.mkdir()
    (dest / "cyberjury-source.json").write_text(_SOURCE_META)
    (dest / "Token.sol").write_text("contract Token {}\n")
    (dest / "Ownable.sol").write_text("contract Ownable {}\n")
    monkeypatch.setattr(prep, "fetch_source", lambda **kw: pytest.fail("source should be reused"))
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: (0, ""))
    monkeypatch.setattr(prep, "_verify", lambda scope: (scope == dest, "2 files, 1 focused unit specs"))
    target = {"type": "explorer", "chain": "bsc", "address": "0x0000000000000000000000000000000000000001"}
    res = prep.prepare_target("feta", target, tmp_path)
    assert res.ok
    assert res.steps[:4] == [
        "source already fetched",
        "generated foundry.toml from explorer metadata",
        "forge build ok",
        "review scope .",
    ]


def test_an_existing_explorer_source_with_a_different_identity_fails_before_build(monkeypatch, tmp_path):
    dest = tmp_path / "feta"
    dest.mkdir()
    (dest / "cyberjury-source.json").write_text(_SOURCE_META)
    (dest / "Token.sol").write_text("contract Token {}\n")
    monkeypatch.setattr(prep, "fetch_source", lambda **kw: pytest.fail("source should not be replaced"))
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: pytest.fail("build should not run"))
    target = {"type": "explorer", "chain": "bsc", "address": "0x0000000000000000000000000000000000000002"}
    res = prep.prepare_target("feta", target, tmp_path)
    assert res.ok is False
    assert "does not match target" in res.detail


def test_an_existing_explorer_address_is_compared_case_insensitively(monkeypatch, tmp_path):
    dest = tmp_path / "feta"
    dest.mkdir()
    metadata = _SOURCE_META.replace(
        "0000000000000000000000000000000000000001", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    (dest / "cyberjury-source.json").write_text(metadata)
    (dest / "Token.sol").write_text("contract Token {}\n")
    monkeypatch.setattr(prep, "fetch_source", lambda **kw: pytest.fail("source should be reused"))
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: (0, ""))
    monkeypatch.setattr(prep, "_verify", lambda scope: (True, "1 files, 1 focused unit specs"))
    target = {"type": "explorer", "chain": "BSC", "address": "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
    assert prep.prepare_target("feta", target, tmp_path).ok


def test_an_existing_explorer_foundry_config_is_not_rewritten(monkeypatch, tmp_path):
    dest = tmp_path / "feta"
    dest.mkdir()
    (dest / "cyberjury-source.json").write_text(_SOURCE_META)
    (dest / "foundry.toml").write_text("[profile.default]\nsrc = 'contracts'\n")
    (dest / "Token.sol").write_text("contract Token {}\n")
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: (0, ""))
    monkeypatch.setattr(prep, "_verify", lambda scope: (True, "1 files, 1 focused unit specs"))
    target = {"type": "explorer", "chain": "bsc", "address": "0x0000000000000000000000000000000000000001"}
    res = prep.prepare_target("feta", target, tmp_path)
    assert res.ok
    assert "foundry.toml already present" in res.steps
    assert (dest / "foundry.toml").read_text() == "[profile.default]\nsrc = 'contracts'\n"


def test_empty_existing_explorer_metadata_fails_loud(monkeypatch, tmp_path):
    dest = tmp_path / "feta"
    dest.mkdir()
    (dest / "cyberjury-source.json").write_text("{}")
    (dest / "Token.sol").write_text("contract Token {}\n")
    monkeypatch.setattr(prep, "_verify", lambda scope: pytest.fail("metadata failure should stop before verify"))
    target = {"type": "explorer", "chain": "bsc", "address": "0x0000000000000000000000000000000000000001"}
    res = prep.prepare_target("feta", target, tmp_path)
    assert res.ok is False
    assert "no source metadata" in res.detail


def test_malformed_existing_explorer_metadata_fails_loud(monkeypatch, tmp_path):
    dest = tmp_path / "feta"
    dest.mkdir()
    (dest / "cyberjury-source.json").write_text("{")
    (dest / "Token.sol").write_text("contract Token {}\n")
    monkeypatch.setattr(prep, "_verify", lambda scope: pytest.fail("metadata failure should stop before verify"))
    target = {"type": "explorer", "chain": "bsc", "address": "0x0000000000000000000000000000000000000001"}
    res = prep.prepare_target("feta", target, tmp_path)
    assert res.ok is False
    assert "cyberjury-source.json is malformed" in res.detail


def test_an_existing_explorer_source_without_solidity_fails_loud(tmp_path):
    dest = tmp_path / "feta"
    dest.mkdir()
    (dest / "cyberjury-source.json").write_text(_SOURCE_META)
    (dest / "README.md").write_text("not source\n")
    target = {"type": "explorer", "chain": "bsc", "address": "0x0000000000000000000000000000000000000001"}
    res = prep.prepare_target("feta", target, tmp_path)
    assert res.ok is False
    assert "no Solidity files" in res.detail


def test_a_missing_review_scope_is_a_loud_failure(calls, tmp_path):
    dest = tmp_path / "gone"
    (dest / ".git").mkdir(parents=True)
    res = prep.prepare_target("gone", {"type": "git", "url": _GIT_URL, "ref": "r", "path": "nope"}, tmp_path)
    assert res.ok is False
    assert "missing" in res.detail


def test_a_bare_git_solidity_tree_generates_foundry_config_at_the_import_root(monkeypatch, tmp_path):
    calls: list[tuple[list[str], object]] = []
    scopes = []

    def run(cmd, cwd, timeout=1800):
        calls.append((cmd, cwd))
        return 0, _successful_output(cmd)

    dest = tmp_path / "goodentry"
    (dest / ".git").mkdir(parents=True)
    helper = dest / "contracts" / "helper"
    interfaces = dest / "contracts" / "interfaces"
    helper.mkdir(parents=True)
    interfaces.mkdir(parents=True)
    (helper / "Proxy.sol").write_text('pragma solidity ^0.8.0;\nimport "../interfaces/I.sol";\ncontract Proxy {}\n')
    (interfaces / "I.sol").write_text("pragma solidity ^0.8.0;\ninterface I {}\n")
    monkeypatch.setattr(prep, "_run", run)
    monkeypatch.setattr(prep, "_verify", lambda scope: scopes.append(scope) or (True, "2 files, 1 focused unit specs"))
    res = prep.prepare_target(
        "goodentry", {"type": "git", "url": _GIT_URL, "ref": "r", "path": "contracts/helper"}, tmp_path
    )
    assert res.ok
    assert (dest / "contracts" / "foundry.toml").is_file()
    assert "compile root contracts" in res.steps
    assert (["forge", "build"], dest / "contracts") in calls
    assert scopes == [helper.resolve()]


def test_a_bare_git_solidity_tree_without_imports_generates_foundry_config_at_the_scope(monkeypatch, tmp_path):
    calls: list[tuple[list[str], object]] = []
    dest = tmp_path / "meebits"
    (dest / ".git").mkdir(parents=True)
    (dest / "Token.sol").write_text("pragma solidity 0.7.6;\ncontract Token {}\n")
    monkeypatch.setattr(
        prep,
        "_run",
        lambda cmd, cwd, timeout=1800: calls.append((cmd, cwd)) or (0, _successful_output(cmd)),
    )
    monkeypatch.setattr(prep, "_verify", lambda scope: (True, "1 files, 1 focused unit specs"))
    res = prep.prepare_target("meebits", {"type": "git", "url": _GIT_URL, "ref": "r", "path": "."}, tmp_path)
    assert res.ok
    assert (dest / "foundry.toml").is_file()
    assert (["forge", "build"], dest.resolve()) in calls


def test_a_bare_git_solidity_tree_with_unresolved_imports_stays_unconfigured(monkeypatch, tmp_path):
    dest = tmp_path / "evm-demo"
    (dest / ".git").mkdir(parents=True)
    scope = dest / "oracle" / "src"
    scope.mkdir(parents=True)
    (scope / "Oracle.sol").write_text('pragma solidity ^0.8.0;\nimport "solmate/utils/FixedPointMathLib.sol";\n')
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: (0, _successful_output(cmd)))
    monkeypatch.setattr(prep, "_verify", lambda scope: (False, "no grounding"))
    res = prep.prepare_target("evm-demo", {"type": "git", "url": _GIT_URL, "ref": "r", "path": "oracle/src"}, tmp_path)
    assert res.ok is False
    assert not (scope / "foundry.toml").exists()
    assert any("unresolved imports" in step for step in res.steps)


def test_unresolved_bare_tree_fails_even_without_verification(monkeypatch, tmp_path):
    dest = tmp_path / "evm-demo"
    (dest / ".git").mkdir(parents=True)
    scope = dest / "oracle" / "src"
    scope.mkdir(parents=True)
    (scope / "Oracle.sol").write_text('pragma solidity ^0.8.0;\nimport "solmate/utils/FixedPointMathLib.sol";\n')
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: (0, _successful_output(cmd)))
    res = prep.prepare_git_scope("evm-demo", {"type": "git", "path": "oracle/src"}, dest, scope, verify=False)
    assert res.ok is False
    assert "unresolved imports" in res.detail


def test_a_truffle_project_is_not_treated_as_a_bare_solidity_tree(monkeypatch, tmp_path):
    dest = tmp_path / "truffle"
    (dest / ".git").mkdir(parents=True)
    (dest / "contracts").mkdir()
    (dest / "contracts" / "Token.sol").write_text("pragma solidity ^0.8.0;\ncontract Token {}\n")
    (dest / "contracts" / "truffle-config.js").write_text("module.exports = {}\n")
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: (0, _successful_output(cmd)))
    monkeypatch.setattr(prep, "_verify", lambda scope: (True, "1 files, 1 focused unit specs"))
    res = prep.prepare_target("truffle", {"type": "git", "url": _GIT_URL, "ref": "r", "path": "contracts"}, tmp_path)
    assert res.ok
    assert not (dest / "contracts" / "foundry.toml").exists()
    assert "generated foundry.toml" not in res.steps


def test_the_report_records_every_target_and_its_steps(tmp_path):
    results = [
        prep.PrepareResult(name="a", steps=["cloned", "forge build ok"], ok=True, detail="2 files"),
        prep.PrepareResult(name="b", steps=["cloned"], ok=False, detail="compile failed"),
    ]
    out = tmp_path / "prepare.json"
    prep.write_report(results, out)
    payload = json.loads(out.read_text())
    assert [r["name"] for r in payload] == ["a", "b"]
    assert payload[1]["ok"] is False
    assert payload[0]["steps"] == ["cloned", "forge build ok"]
    assert all("skipped" in r for r in payload)


def test_a_green_compile_that_cannot_ground_is_still_a_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: (0, _successful_output(cmd)))
    monkeypatch.setattr(prep, "_verify", lambda scope: (False, "no grounding: the facts backend cannot run"))
    dest = tmp_path / "t"
    (dest / ".git").mkdir(parents=True)
    (dest / "src").mkdir()
    (dest / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
    res = prep.prepare_target("t", {"type": "git", "url": _GIT_URL, "ref": "r", "path": "src"}, tmp_path)
    assert res.ok is False
    assert "no grounding" in res.detail


def test_solmate_stays_below_the_version_that_turned_ownerOf_into_a_function():
    assert prep._npm_pins(prep.solidity_targets()["backed-nft-lending"])["@rari-capital/solmate"] == "6.2.0"


def test_typescript_stays_below_the_major_that_removed_the_api_ts_node_reads():
    assert prep._npm_pins(prep.solidity_targets()["telcoin-stablecoin"])["typescript"] == "^5"


def test_openzeppelin_stays_below_the_minor_that_reached_for_a_cancun_opcode():
    pins = prep._npm_pins(prep.solidity_targets()["telcoin-stablecoin"])
    assert pins["@openzeppelin/contracts"] == "5.0.1"
    assert pins["@openzeppelin/contracts-upgradeable"] == "5.0.1"
