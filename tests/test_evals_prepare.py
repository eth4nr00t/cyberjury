"""Target preparation. The subprocess runner is replaced, so no test clones, installs, or compiles."""

import json

import pytest

from evals import prepare as prep


@pytest.fixture
def calls(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(cmd, cwd, timeout=1800):
        seen.append(cmd)
        return 0, ""

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
    (yarn_project / "yarn.lock").write_text("# yarn lockfile v1\n")
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
    (project / "yarn.lock").write_text("# yarn lockfile v1\n")
    ok, _steps = prep._install(project, {"typescript": "^5"})
    assert ok
    pin = calls[-1]
    assert "typescript@^5" in pin
    assert "--no-save" in pin
    assert "--no-package-lock" in pin


def test_a_yarn_project_falls_back_to_ignoring_an_unusable_lockfile(monkeypatch, tmp_path):
    attempts: list[list[str]] = []

    def fail_until_no_lockfile(cmd, cwd, timeout=1800):
        attempts.append(cmd)
        return (0, "") if "--no-lockfile" in cmd else (1, "error SyntaxError: Invalid value type")

    monkeypatch.setattr(prep, "_run", fail_until_no_lockfile)
    project = tmp_path / "p"
    project.mkdir()
    (project / "package.json").write_text("{}")
    (project / "yarn.lock").write_text("# yarn lockfile v1\n")
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


def test_submodules_are_initialized_only_when_the_target_declares_them(calls, tmp_path):
    dest = tmp_path / "repository"
    (dest / ".git").mkdir(parents=True)
    prep._clone("https://example.invalid/x", "abc123", dest)
    assert calls == []
    (dest / ".gitmodules").write_text('[submodule "lib/forge-std"]\n')
    prep._clone("https://example.invalid/x", "abc123", dest)
    assert calls[-1] == ["git", "submodule", "update", "--init", "--recursive", "--depth", "1"]


def test_an_explorer_target_is_skipped_and_never_counted_as_prepared(tmp_path):
    res = prep.prepare_target("feta", {"type": "explorer", "chain": "bsc", "address": "0x0"}, tmp_path)
    assert res.skipped
    assert res.ok is False
    assert "fetch" in res.detail


def test_a_missing_review_scope_is_a_loud_failure(calls, tmp_path):
    dest = tmp_path / "gone"
    (dest / ".git").mkdir(parents=True)
    res = prep.prepare_target("gone", {"type": "git", "url": "u", "ref": "r", "path": "nope"}, tmp_path)
    assert res.ok is False
    assert "missing" in res.detail


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
    monkeypatch.setattr(prep, "_run", lambda cmd, cwd, timeout=1800: (0, ""))
    monkeypatch.setattr(prep, "_verify", lambda scope: (False, "no grounding: the facts backend cannot run"))
    dest = tmp_path / "t"
    (dest / ".git").mkdir(parents=True)
    (dest / "src").mkdir()
    res = prep.prepare_target("t", {"type": "git", "url": "u", "ref": "r", "path": "src"}, tmp_path)
    assert res.ok is False
    assert "no grounding" in res.detail


def test_solmate_stays_below_the_version_that_turned_ownerOf_into_a_function():
    assert prep._NPM_PINS["backed-nft-lending"]["@rari-capital/solmate"] == "6.2.0"


def test_typescript_stays_below_the_major_that_removed_the_api_ts_node_reads():
    assert prep._NPM_PINS["telcoin-stablecoin"]["typescript"] == "^5"


def test_openzeppelin_stays_below_the_minor_that_reached_for_a_cancun_opcode():
    pins = prep._NPM_PINS["telcoin-stablecoin"]
    assert pins["@openzeppelin/contracts"] == "5.0.1"
    assert pins["@openzeppelin/contracts-upgradeable"] == "5.0.1"
