"""Bring a benchmark target to the state a review can measure, on any machine.

A target's `ref` pins its source but not its build, and Slither cannot ground a review
until the project compiles. Only Solidity targets need this, since a Python, JavaScript,
or Go target is parsed from source as cloned.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cyberjury.domains.evm.facts.slither import _compile_root

_DUMMY_KEY = "0x" + "0" * 63 + "1"

_NPM_PINS: dict[str, dict[str, str]] = {
    "backed-nft-lending": {
        "@rari-capital/solmate": "6.2.0",
    },
    "telcoin-stablecoin": {
        "typescript": "^5",
        "@openzeppelin/contracts": "5.0.1",
        "@openzeppelin/contracts-upgradeable": "5.0.1",
    },
}


@dataclass(frozen=True, kw_only=True)
class PrepareResult:
    """A target this module has nothing to do for is `skipped`, never `ok`.

    since nothing to do is not the same as ready to ground.
    """

    name: str
    steps: list[str]
    ok: bool
    detail: str = ""
    skipped: bool = False


def _run(cmd: list[str], cwd: Path, timeout: int = 1800) -> tuple[int, str]:
    env = {**os.environ, "PRIVATE_KEY": _DUMMY_KEY}
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 127, f"cannot run {cmd[0]}: {exc}"
    return r.returncode, (r.stdout + r.stderr)


def _clone(url: str, ref: str, dest: Path) -> tuple[bool, str]:
    """A Foundry project keeps its dependencies in submodules.

    and neither a filtered clone nor a checkout initializes them. Their commits are pinned
    by the parent tree, so fetching them is the only step here, not choosing a version.
    """
    if not (dest / ".git").is_dir():
        dest.parent.mkdir(parents=True, exist_ok=True)
        code, log = _run(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(dest)], dest.parent)
        if code != 0:
            return False, f"clone failed: {log.strip()[-200:]}"
        code, log = _run(["git", "checkout", ref], dest)
        if code != 0:
            return False, f"checkout {ref} failed: {log.strip()[-200:]}"
    if (dest / ".gitmodules").is_file():
        code, log = _run(["git", "submodule", "update", "--init", "--recursive", "--depth", "1"], dest)
        if code != 0:
            return False, f"submodule update failed: {log.strip()[-200:]}"
    return True, "cloned"


def _install(at: Path, pins: dict[str, str]) -> tuple[bool, list[str]]:
    """A yarn lockfile can name dependency protocols npm does not understand.

    so npm in a yarn project fails outright rather than resolving differently. The peer
    graph of an audit-era project is often unsatisfiable under current npm, which is what
    the peer dependency fallback is for.
    """
    steps: list[str] = []
    if not (at / "package.json").is_file():
        return True, ["no package.json at the compile root"]
    if (at / "yarn.lock").is_file():
        attempts = [["yarn", "install", "--frozen-lockfile"], ["yarn", "install"], ["yarn", "install", "--no-lockfile"]]
    elif (at / "package-lock.json").is_file():
        attempts = [["npm", "ci", "--no-audit", "--no-fund"]]
    else:
        attempts = [["npm", "install", "--no-audit", "--no-fund"]]
    attempts.append(["npm", "install", "--no-audit", "--no-fund", "--legacy-peer-deps"])
    for cmd in attempts:
        code, log = _run(cmd, at, timeout=1200)
        steps.append(f"{' '.join(cmd)} {'ok' if code == 0 else 'FAILED'}")
        if code == 0:
            break
    else:
        return False, [*steps, log.strip()[-200:]]
    if pins:
        spec = [f"{name}@{version}" for name, version in sorted(pins.items())]
        cmd = ["npm", "install", "--no-audit", "--no-fund", "--no-save", "--no-package-lock", *spec]
        code, log = _run(cmd, at, timeout=1200)
        steps.append(f"pin {' '.join(spec)} {'ok' if code == 0 else 'FAILED'}")
        if code != 0:
            return False, [*steps, log.strip()[-200:]]
    return True, steps


def _compile(at: Path) -> tuple[bool, list[str]]:
    if any((at / f).is_file() for f in ("hardhat.config.js", "hardhat.config.ts")):
        code, log = _run(["npx", "hardhat", "compile"], at)
        return code == 0, [f"hardhat compile {'ok' if code == 0 else 'FAILED ' + log.strip()[-200:]}"]
    if (at / "foundry.toml").is_file():
        code, log = _run(["forge", "build"], at)
        return code == 0, [f"forge build {'ok' if code == 0 else 'FAILED ' + log.strip()[-200:]}"]
    return True, ["no framework config at the compile root"]


def _verify(scope: Path) -> tuple[bool, str]:
    """Ground the review scope once, so preparation is judged by the thing the review needs.

    A green install and a green compile still leave the review ungrounded when the compile
    covered a different directory, which is the failure this whole module exists to make
    visible.
    """
    from cyberjury.domains.base import BackendUnavailable
    from cyberjury.domains.registry import get_domain

    backend = get_domain("evm").facts_backend
    try:
        facts = backend.extract(scope)
    except BackendUnavailable as exc:
        return False, f"no grounding: {exc}"
    data = facts.data
    return True, f"{len(data['by_file'])} files, {len(data['units'])} call-path units"


def prepare_target(name: str, target: dict, root: Path) -> PrepareResult:
    """Prepare one benchmark target for grounded review."""
    steps: list[str] = []
    if target.get("type") != "git":
        return PrepareResult(
            name=name, steps=[], ok=False, skipped=True, detail="explorer target, fetch its source first"
        )
    dest = root / name
    ok, note = _clone(target["url"], target["ref"], dest)
    steps.append(note)
    if not ok:
        return PrepareResult(name=name, steps=steps, ok=False, detail=note)
    scope = (dest / (target.get("path") or ".")).resolve()
    if not scope.is_dir():
        return PrepareResult(name=name, steps=steps, ok=False, detail=f"review scope {target.get('path')} is missing")
    at = _compile_root(scope)
    steps.append(f"compile root {at.relative_to(dest) if at != dest else '.'}")
    ok, install_steps = _install(at, _NPM_PINS.get(name, {}))
    steps += install_steps
    if not ok:
        return PrepareResult(name=name, steps=steps, ok=False, detail="dependency install failed")
    ok, compile_steps = _compile(at)
    steps += compile_steps
    if not ok:
        return PrepareResult(name=name, steps=steps, ok=False, detail="compile failed")
    ok, detail = _verify(scope)
    steps.append(detail)
    return PrepareResult(name=name, steps=steps, ok=ok, detail=detail)


def solidity_targets() -> dict[str, dict]:
    """Return repository benchmarks that need Solidity preparation."""
    from evals.registry import all_benchmarks

    return {
        name: b.target
        for name, b in sorted(all_benchmarks().items())
        if "solidity" in (b.stack.get("languages") or []) and b.target
    }


def default_root() -> Path:
    """Return the default cache root for prepared benchmark targets."""
    base = os.environ.get("CYBERJURY_BACKTEST_DIR")
    if not base:
        raise ValueError("set CYBERJURY_BACKTEST_DIR to a persistent directory outside the repository first")
    return Path(base).expanduser() / "repositories"


def write_report(results: list[PrepareResult], path: Path) -> None:
    """Write report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {"name": r.name, "ok": r.ok, "skipped": r.skipped, "detail": r.detail, "steps": r.steps} for r in results
    ]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
