"""Prepare benchmark targets for grounded review on any machine.

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
from hashlib import sha256
from pathlib import Path
from typing import Literal, Required, TypedDict, cast

from cyberjury.profiles.evm.facts.backend import resolve_compile_root
from cyberjury.sources import SourceError
from cyberjury.sources.explorer import chain_for
from cyberjury.sources.fetch import fetch_source
from cyberjury.sources.metadata import SourceMeta, read_source_meta_file

_DUMMY_KEY = "0x" + "0" * 63 + "1"
_SOURCE_META = "cyberjury-source.json"
_GENERATED_MARKER = ".cyberjury-eval-generated.json"
_COMPILER_VERSION = re.compile(r"v?(\d+\.\d+\.\d+)")
_SOLIDITY_IMPORT = re.compile(r"^\s*import\s+(?:[^\"']+\s+from\s+)?[\"']([^\"']+)[\"']", re.MULTILINE)


class TargetPrepareData(TypedDict, total=False):
    """Optional setup inputs for a prepared target."""

    npm_pins: dict[str, str]


class GitTargetData(TypedDict, total=False):
    """Shared fields for a pinned repository target."""

    type: Required[Literal["git"]]
    ref: Required[str]
    base: str
    path: str
    prepare: TargetPrepareData


class RemoteGitTarget(GitTargetData):
    """A pinned remote repository target."""

    url: Required[str]


class LocalGitTarget(GitTargetData):
    """A pinned local repository target."""

    root: Required[str]


GitTarget = RemoteGitTarget | LocalGitTarget


class ExplorerTarget(TypedDict, total=False):
    """A verified contract target that preparation can fetch."""

    type: Required[Literal["explorer"]]
    chain: Required[str]
    address: Required[str]
    path: str
    prepare: TargetPrepareData


class GitScopeTarget(TypedDict, total=False):
    """Inputs needed after a repository has already been checked out."""

    type: Required[Literal["git"]]
    path: str
    prepare: TargetPrepareData


PrepareTarget = GitTarget | ExplorerTarget


@dataclass(frozen=True, kw_only=True)
class PrepareResult:
    """A target with nothing to prepare is `skipped`, not `ok`."""

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


def _canonical_git_source(source: str) -> str:
    if source.startswith("https://"):
        return source.rstrip("/")
    return str(Path(source).expanduser().resolve())


def _file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _generated_files(repository: Path) -> dict[str, str]:
    marker = repository / _GENERATED_MARKER
    if not marker.is_file():
        return {}
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"generated file marker at {marker} is malformed") from exc
    files = data.get("files") if isinstance(data, dict) and data.get("version") == 1 else None
    if not isinstance(files, dict) or any(
        not isinstance(path, str) or not isinstance(digest, str) for path, digest in files.items()
    ):
        raise ValueError(f"generated file marker at {marker} is malformed")
    return files


def _record_generated(repository: Path, path: Path) -> None:
    repository = repository.resolve()
    path = path.resolve()
    if not path.is_relative_to(repository):
        raise ValueError(f"generated file {path} is outside repository {repository}")
    files = _generated_files(repository)
    files[path.relative_to(repository).as_posix()] = _file_digest(path)
    (repository / _GENERATED_MARKER).write_text(
        json.dumps({"version": 1, "files": dict(sorted(files.items()))}, indent=2) + "\n",
        encoding="utf-8",
    )


def _clear_generated(repository: Path) -> tuple[bool, str]:
    marker = repository / _GENERATED_MARKER
    try:
        files = _generated_files(repository)
    except ValueError as exc:
        return False, str(exc)
    for rel, digest in files.items():
        path = (repository / rel).resolve()
        if not path.is_relative_to(repository):
            return False, f"generated file marker contains unsafe path {rel!r}"
        if not path.exists():
            continue
        if not path.is_file() or _file_digest(path) != digest:
            return False, f"generated file {rel} changed after preparation"
        path.unlink()
    marker.unlink(missing_ok=True)
    return True, "cleared generated preparation files" if files else ""


def _clone(source: str, ref: str, dest: Path) -> tuple[bool, str]:
    """A cached clone is reusable only for the same source and ref."""
    source = _canonical_git_source(source)
    existing = (dest / ".git").is_dir()
    if not existing:
        dest.parent.mkdir(parents=True, exist_ok=True)
        code, log = _run(["git", "clone", "--filter=blob:none", "--no-checkout", source, str(dest)], dest.parent)
        if code != 0:
            return False, f"clone failed: {log.strip()[-200:]}"
    else:
        code, log = _run(["git", "remote", "get-url", "origin"], dest)
        if code != 0:
            return False, f"cannot identify cached clone origin: {log.strip()[-200:]}"
        origin = _canonical_git_source(log.strip())
        if origin != source:
            return False, f"cached clone origin {origin!r} does not match target {source!r}"
        cleared, note = _clear_generated(dest)
        if not cleared:
            return False, note
    ok, note = _checkout_ref(dest, ref)
    if not ok:
        return False, note
    return True, "checked out" if existing else "cloned"


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

    npm in a yarn project fails outright rather than resolving differently. Audit era
    projects can also have peer dependency graphs that current npm rejects, which is why
    the fallback uses legacy peer dependency resolution.
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


def _npm_pins(target: PrepareTarget | GitScopeTarget) -> dict[str, str]:
    prepare = target.get("prepare")
    if not isinstance(prepare, dict):
        return {}
    pins = prepare.get("npm_pins")
    if not isinstance(pins, dict):
        return {}
    return {str(name): str(version) for name, version in pins.items()}


def _ensure_foundry_remappings(at: Path, repository: Path) -> str:
    if (at / "remappings.txt").is_file() or not (at / "foundry.toml").is_file():
        return ""
    code, log = _run(["forge", "remappings"], at, timeout=120)
    if code != 0:
        return "forge remappings FAILED"
    lines = [line.strip() for line in log.splitlines() if line.strip() and "=" in line]
    if not lines:
        return ""
    (at / "remappings.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    _record_generated(repository, at / "remappings.txt")
    return "generated remappings.txt"


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


def _write_foundry_config(
    root: Path,
    meta: SourceMeta | None = None,
    *,
    src: str = ".",
    repository: Path | None = None,
) -> str:
    if (root / "foundry.toml").is_file():
        return "foundry.toml already present"
    lines = [
        "[profile.default]",
        f'src = "{src}"',
        'out = "out"',
        'libs = ["lib"]',
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
    if repository is not None:
        _record_generated(repository, root / "foundry.toml")
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
    return root, _write_foundry_config(root, repository=repository)


def _verify(scope: Path) -> tuple[bool, str]:
    """Ground the review scope once, so preparation is judged by the thing the review needs.

    A green install and a green compile still leave the review ungrounded when the compile
    covered a different directory, which is the failure this module exists to make
    visible.
    """
    from cyberjury.profiles.registry import get_profile
    from cyberjury.review.facts import BackendUnavailable, extract_facts

    backend = get_profile("evm").facts_backend
    try:
        facts = extract_facts(backend, scope, purpose="EVM source preparation")
    except BackendUnavailable as exc:
        return False, f"no grounding: {exc}"
    data = facts.data
    return True, f"{len(data['by_file'])} files, {len(data['unit_specs'])} focused unit specs"


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _has_solidity(dest: Path) -> bool:
    return any(p.is_file() for p in dest.rglob("*.sol"))


def _prepare_explorer(name: str, target: ExplorerTarget, root: Path) -> PrepareResult:
    steps: list[str] = []
    dest = root / name
    chain = target.get("chain")
    address = target.get("address")
    if not chain or not address:
        return PrepareResult(name=name, steps=steps, ok=False, detail="explorer target is missing chain or address")
    address = address.strip()
    try:
        chain_key = chain_for(chain).key
    except SourceError as exc:
        return PrepareResult(name=name, steps=steps, ok=False, detail=str(exc))
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
        if meta.chain.strip().lower() != chain_key or meta.address.strip().casefold() != address.casefold():
            cached = f"{meta.chain}:{meta.address}"
            expected = f"{chain_key}:{address}"
            return PrepareResult(
                name=name,
                steps=steps,
                ok=False,
                detail=f"cached explorer source {cached!r} does not match target {expected!r}",
            )
        steps.append("source already fetched")
    else:
        api_key = os.environ.get("CYBERJURY_ETHERSCAN_API_KEY", "")
        try:
            result = fetch_source(
                chain_key=chain_key,
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


def prepare_target(name: str, target: PrepareTarget, root: Path) -> PrepareResult:
    """Prepare one benchmark target for grounded review."""
    steps: list[str] = []
    target_type = target.get("type")
    if target_type == "explorer":
        return _prepare_explorer(name, cast(ExplorerTarget, target), root)
    if target_type != "git":
        detail = f"target type {target_type!r} is not prepared by this command"
        return PrepareResult(name=name, steps=[], ok=False, skipped=True, detail=detail)
    dest = root / name
    git_target = cast(GitTarget, target)
    has_url = "url" in git_target
    has_root = "root" in git_target
    if has_url == has_root:
        detail = "git target must define exactly one of url or root"
        return PrepareResult(name=name, steps=steps, ok=False, detail=detail)
    ref = git_target.get("ref")
    if not ref:
        return PrepareResult(name=name, steps=steps, ok=False, detail="git target is missing ref")
    source = git_target["url"] if has_url else git_target["root"]
    if not source.strip():
        return PrepareResult(name=name, steps=steps, ok=False, detail="git target source is empty")
    ok, note = _clone(source, ref, dest)
    steps.append(note)
    if not ok:
        return PrepareResult(name=name, steps=steps, ok=False, detail=note)
    scope = (dest / (git_target.get("path") or ".")).resolve()
    res = prepare_git_scope(name, git_target, dest.resolve(), scope, verify=True)
    return PrepareResult(name=name, steps=[*steps, *res.steps], ok=res.ok, detail=res.detail, skipped=res.skipped)


def _update_submodules(repository: Path) -> tuple[bool, list[str]]:
    if not (repository / ".gitmodules").is_file():
        return True, []
    code, log = _run(["git", "submodule", "update", "--init", "--recursive", "--depth", "1"], repository)
    status = f"git submodule update {'ok' if code == 0 else 'FAILED'}"
    return code == 0, [status] if code == 0 else [status, log.strip()[-200:]]


def _prepared_compile_root(scope: Path, repository: Path) -> tuple[Path | None, list[str], str]:
    at = resolve_compile_root(scope)
    if not at.is_dir():
        return None, [], f"compile root {at} is missing"
    if at != scope or _framework_config_present(at):
        return at, [], ""
    generated_at, note = _prepare_bare_solidity_tree(scope, repository)
    return generated_at, [note], "" if generated_at is not None else note


def prepare_git_scope(
    name: str,
    target: GitTarget | GitScopeTarget,
    repository: Path,
    scope: Path,
    *,
    verify: bool = True,
) -> PrepareResult:
    """Prepare a checked out git review scope for grounded Solidity analysis."""
    steps: list[str] = []
    repository = repository.resolve()
    scope = scope.resolve()
    if not scope.is_dir():
        return PrepareResult(name=name, steps=steps, ok=False, detail=f"review scope {target.get('path')} is missing")
    if not scope.is_relative_to(repository):
        return PrepareResult(name=name, steps=steps, ok=False, detail=f"review scope {scope} escapes the repository")
    ok, submodule_steps = _update_submodules(repository)
    steps += submodule_steps
    if not ok:
        return PrepareResult(name=name, steps=steps, ok=False, detail="submodule update failed")
    at, root_steps, detail = _prepared_compile_root(scope, repository)
    steps += root_steps
    if at is None:
        return PrepareResult(name=name, steps=steps, ok=False, detail=detail)
    steps.append(f"compile root {at.relative_to(repository) if at != repository else '.'}")
    note = _ensure_foundry_remappings(at, repository)
    if note:
        steps.append(note)
    ok, install_steps = _install(at, _npm_pins(target))
    steps += install_steps
    if not ok:
        return PrepareResult(name=name, steps=steps, ok=False, detail="dependency install failed")
    ok, compile_steps = _compile(at)
    steps += compile_steps
    if not ok:
        return PrepareResult(name=name, steps=steps, ok=False, detail="compile failed")
    if not verify:
        return PrepareResult(name=name, steps=steps, ok=True, detail="prepared")
    ok, detail = _verify(scope)
    steps.append(detail)
    return PrepareResult(name=name, steps=steps, ok=ok, detail=detail)


def solidity_targets() -> dict[str, PrepareTarget]:
    """Return repository benchmarks that need Solidity preparation."""
    from evals.benchmarks.cases import repository_cases

    return {
        name: cast(PrepareTarget, b.target)
        for name, b in sorted(repository_cases().items())
        if "solidity" in (b.stack.get("languages") or []) and b.target
    }


def default_root() -> Path:
    """Return the default cache root for prepared benchmark targets."""
    base = os.environ.get("CYBERJURY_BACKTEST_DIR")
    if not base:
        raise ValueError("set CYBERJURY_BACKTEST_DIR to a persistent directory outside the repository first")
    return Path(base).expanduser() / "repositories"


def write_report(results: list[PrepareResult], path: Path) -> None:
    """Persist preparation evidence for a later backtest audit."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {"name": r.name, "ok": r.ok, "skipped": r.skipped, "detail": r.detail, "steps": r.steps} for r in results
    ]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
