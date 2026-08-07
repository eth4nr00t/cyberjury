"""Bring a benchmark target to the state a review can measure, on any machine.

A target's `ref` pins its source but not its build, and Slither cannot ground a review
until the project compiles. Only Solidity targets need this, since a Python, JavaScript,
or Go target is parsed from source as cloned.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cyberjury.domains.evm.facts.slither import _compile_root
from cyberjury.sources import SourceError
from cyberjury.sources.fetch import fetch_source
from cyberjury.sources.metadata import SourceMeta, read_source_meta_file

_DUMMY_KEY = "0x" + "0" * 63 + "1"
_SOURCE_META = "cyberjury-source.json"
_COMPILER_VERSION = re.compile(r"v?(\d+\.\d+\.\d+)")
_SOLIDITY_IMPORT = re.compile(r"^\s*import\s+(?:[^\"']+\s+from\s+)?[\"']([^\"']+)[\"']", re.MULTILINE)


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
    ok, note = _checkout_ref(dest, ref)
    if not ok:
        return False, note
    if (dest / ".gitmodules").is_file():
        code, log = _run(["git", "submodule", "update", "--init", "--recursive", "--depth", "1"], dest)
        if code != 0:
            return False, f"submodule update failed: {log.strip()[-200:]}"
    return True, "cloned"


def _checkout_ref(dest: Path, ref: str) -> tuple[bool, str]:
    code, log = _run(["git", "checkout", ref], dest)
    if code == 0:
        return True, "checked out"
    checkout_log = log
    code, log = _run(["git", "fetch", "--filter=blob:none", "origin", ref], dest)
    if code != 0:
        return False, f"fetch {ref} failed after checkout failed: {log.strip()[-200:]}"
    code, log = _run(["git", "checkout", "FETCH_HEAD"], dest)
    if code != 0:
        return False, f"checkout {ref} failed after fetch: {(log or checkout_log).strip()[-200:]}"
    return True, "checked out"


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


def _npm_pins(target: dict) -> dict[str, str]:
    prepare = target.get("prepare")
    if not isinstance(prepare, dict):
        return {}
    pins = prepare.get("npm_pins")
    if not isinstance(pins, dict):
        return {}
    return {str(name): str(version) for name, version in pins.items()}


def _compile(at: Path) -> tuple[bool, list[str]]:
    if any((at / f).is_file() for f in ("hardhat.config.js", "hardhat.config.ts")):
        code, log = _run(["npx", "hardhat", "compile"], at)
        return code == 0, [f"hardhat compile {'ok' if code == 0 else 'FAILED ' + log.strip()[-200:]}"]
    if (at / "foundry.toml").is_file():
        code, log = _run(["forge", "build"], at)
        return code == 0, [f"forge build {'ok' if code == 0 else 'FAILED ' + log.strip()[-200:]}"]
    return True, ["no framework config at the compile root"]


def _solc_version(version: str) -> str:
    match = _COMPILER_VERSION.search(version)
    return match.group(1) if match else ""


def _write_foundry_config(root: Path, meta: SourceMeta | None = None) -> str:
    if (root / "foundry.toml").is_file():
        return "foundry.toml already present"
    lines = [
        "[profile.default]",
        'src = "."',
        'out = "out"',
        "build_info = true",
        "auto_detect_solc = true",
    ]
    if meta is not None:
        version = _solc_version(meta.compiler_version)
        if version:
            lines.append(f'solc_version = "{version}"')
        if meta.optimization_used is not None:
            lines.append(f"optimizer = {str(meta.optimization_used).lower()}")
        if meta.runs is not None:
            lines.append(f"optimizer_runs = {meta.runs}")
        evm = meta.evm_version.strip()
        if evm and evm.lower() != "default":
            lines.append(f'evm_version = "{evm}"')
    (root / "foundry.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return "generated foundry.toml from explorer metadata" if meta is not None else "generated foundry.toml"


def _framework_config_present(root: Path) -> bool:
    return any(
        (root / name).is_file()
        for name in ("foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js")
    )


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _bare_compile_root(scope: Path, repository: Path) -> Path | None:
    files = {p.resolve() for p in scope.rglob("*.sol") if p.is_file()}
    pending = list(files)
    while pending:
        source = pending.pop()
        for spec in _SOLIDITY_IMPORT.findall(_read(source)):
            if not spec.startswith("."):
                return None
            target = (source.parent / spec).resolve()
            if not target.is_file() or not target.is_relative_to(repository):
                return None
            if target not in files:
                files.add(target)
                pending.append(target)
    if not files:
        return None
    common = Path(os.path.commonpath([str(scope.resolve()), *(str(p.parent) for p in files)]))
    return common if common.is_relative_to(repository) else None


def _prepare_bare_solidity_tree(scope: Path, repository: Path) -> tuple[Path | None, str]:
    root = _bare_compile_root(scope, repository.resolve())
    if root is None:
        return None, "bare Solidity tree has unresolved imports, no generated config"
    return root, _write_foundry_config(root)


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


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _has_solidity(dest: Path) -> bool:
    return any(p.is_file() for p in dest.rglob("*.sol"))


def _prepare_explorer(name: str, target: dict, root: Path) -> PrepareResult:
    steps: list[str] = []
    dest = root / name
    meta: SourceMeta
    if (dest / _SOURCE_META).is_file():
        try:
            meta = read_source_meta_file(dest / _SOURCE_META)
        except SourceError as exc:
            return PrepareResult(name=name, steps=steps, ok=False, detail=str(exc))
        if meta is None:
            return PrepareResult(
                name=name, steps=steps, ok=False, detail="cyberjury-source.json has no source metadata"
            )
        steps.append("source already fetched")
    else:
        chain = target.get("chain")
        address = target.get("address")
        if not chain or not address:
            return PrepareResult(name=name, steps=steps, ok=False, detail="explorer target is missing chain or address")
        api_key = os.environ.get("CYBERJURY_ETHERSCAN_API_KEY", "")
        try:
            result = fetch_source(
                chain_key=chain,
                address=address,
                api_key=api_key,
                out=str(dest),
                fetched_at=_utc_now(),
            )
        except SourceError as exc:
            return PrepareResult(name=name, steps=steps, ok=False, detail=str(exc))
        steps.append(f"fetched {result.file_count} source files")
        meta = result.meta
    if not _has_solidity(dest):
        return PrepareResult(name=name, steps=steps, ok=False, detail="fetched source has no Solidity files")
    steps.append(_write_foundry_config(dest, meta))
    ok, compile_steps = _compile(dest)
    steps += compile_steps
    if not ok:
        return PrepareResult(name=name, steps=steps, ok=False, detail="compile failed")
    steps.append("review scope .")
    ok, detail = _verify(dest)
    steps.append(detail)
    return PrepareResult(name=name, steps=steps, ok=ok, detail=detail)


def prepare_target(name: str, target: dict, root: Path) -> PrepareResult:
    """Prepare one benchmark target for grounded review."""
    steps: list[str] = []
    target_type = target.get("type")
    if target_type == "explorer":
        return _prepare_explorer(name, target, root)
    if target_type != "git":
        detail = f"target type {target_type!r} is not prepared by this command"
        return PrepareResult(name=name, steps=[], ok=False, skipped=True, detail=detail)
    dest = root / name
    ok, note = _clone(target["url"], target["ref"], dest)
    steps.append(note)
    if not ok:
        return PrepareResult(name=name, steps=steps, ok=False, detail=note)
    scope = (dest / (target.get("path") or ".")).resolve()
    if not scope.is_dir():
        return PrepareResult(name=name, steps=steps, ok=False, detail=f"review scope {target.get('path')} is missing")
    at = _compile_root(scope)
    if at == scope and not _framework_config_present(at):
        generated_at, note = _prepare_bare_solidity_tree(scope, dest.resolve())
        steps.append(note)
        if generated_at is not None:
            at = generated_at
    steps.append(f"compile root {at.relative_to(dest) if at != dest else '.'}")
    ok, install_steps = _install(at, _npm_pins(target))
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
