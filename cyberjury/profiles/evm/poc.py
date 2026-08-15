"""Generate and run local Foundry proofs that add evidence without refuting findings."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from shutil import which

from cyberjury.profiles.base import PoCArtifact, PoCExecResult
from cyberjury.providers.base import Message, Provider
from cyberjury.review.facts import BackendUnavailable

_FOUNDRY_URL = "https://getfoundry.sh"

_INSTALL_HINT = (
    "Foundry is not installed. The evm PoC backend needs forge on PATH: install Foundry "
    f"from {_FOUNDRY_URL}, then re-run."
)

_SYSTEM = (
    "You write a single Foundry test in Solidity that reproduces one smart contract "
    "vulnerability. The test runs locally with no fork, no rpc, and no broadcast. Declare the "
    "cheatcode interface inline and use the cheatcode address "
    "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D for vm, do not import forge-std. Import the "
    "contract under test with the exact import line given to you. A public function whose name "
    "starts with test is a test case, and it must pass only when the exploit succeeds, so use a "
    "revert or a failing assertion for the safe case. Respond with only the Solidity source of "
    "the test file, no prose and no fences."
)


@dataclass(frozen=True)
class PoCResult:
    """Record whether a generated test compiled and reproduced the candidate locally."""

    reproduced: bool
    test_source: str
    detail: str


def _extract_solidity(text: str) -> str:
    """The Solidity body from a model reply, tolerating a fenced block or bare source."""
    fence = re.search(r"```(?:solidity)?\s*(.*?)```", text, re.DOTALL)
    return (fence.group(1) if fence else text).strip()


class ForgePoC:
    """Write and run local Foundry tests that can add evidence but never refute."""

    ext = "t.sol"
    install_hint = f"install Foundry from {_FOUNDRY_URL}"

    def __init__(
        self,
        *,
        provider: Provider | None = None,
        model: str | None = None,
        timeout: int = 180,
        max_tokens: int = 4096,
        attempts: int = 2,
    ) -> None:
        """Bind the model and Foundry execution settings for generated PoCs."""
        self._provider = provider
        self._model = model
        self._timeout = timeout
        self._max_tokens = max_tokens
        self._attempts = max(1, attempts)

    def available(self) -> bool:
        """Report whether forge is available to execute an already written PoC."""
        return which("forge") is not None

    def generate(
        self, *, title: str, analysis: str, symbol: str, file: str, line: int | None, root: str, endpoint: str = ""
    ) -> PoCArtifact:
        """Write a Foundry test without running it, ignoring the web specific endpoint."""
        import_line, note = self._import_note(Path(root), file)
        target = _read(Path(root) / file) if file else ""
        prompt = _prompt(
            title=title,
            analysis=analysis,
            symbol=symbol,
            file=file,
            line=line,
            target_source=target,
            import_line=import_line,
            note=note,
        )
        return PoCArtifact(
            source=self._complete(prompt),
            ext=self.ext,
            run_hint="forge test, deploys the contract locally, no fork or rpc",
        )

    def execute(self, *, source: str, root: str) -> PoCExecResult:
        """Run locally without a fork or broadcast and preserve findings when execution fails."""
        if not self.available():
            return PoCExecResult(ran=False, ok=False, detail="forge not installed, PoC not executed")
        if not source:
            return PoCExecResult(ran=False, ok=False, detail="no PoC source to run")
        root_p = Path(root)
        sources = sorted(root_p.rglob("*.sol"))
        foundry = (root_p / "foundry.toml").is_file()
        with self._project(root_p, sources, foundry) as (proj, test_path):
            ok, detail = self._run_test(proj, source, test_path)
        return PoCExecResult(ran=True, ok=ok, detail=detail)

    def reproduce(self, *, title: str, analysis: str, symbol: str, file: str, line: int | None, root: str) -> PoCResult:
        """Generate, repair, and run a Foundry test across the configured attempts."""
        if not self.available():
            raise BackendUnavailable(_INSTALL_HINT)
        root_p = Path(root)
        sources = sorted(root_p.rglob("*.sol"))
        if not sources:
            return PoCResult(reproduced=False, test_source="", detail="no Solidity sources under the target")
        foundry = (root_p / "foundry.toml").is_file()
        target = _read(root_p / file) if file else ""
        import_line, note = self._import_note(root_p, file)
        test_source = ""
        detail = "no attempt ran"
        with self._project(root_p, sources, foundry) as (proj, test_path):
            for attempt in range(self._attempts):
                if attempt == 0:
                    prompt = _prompt(
                        title=title,
                        analysis=analysis,
                        symbol=symbol,
                        file=file,
                        line=line,
                        target_source=target,
                        import_line=import_line,
                        note=note,
                    )
                else:
                    prompt = _fix_prompt(previous=test_source, error=detail, import_line=import_line, note=note)
                test_source = self._complete(prompt)
                if not test_source:
                    detail = "model returned no test source"
                    continue
                ok, detail = self._run_test(proj, test_source, test_path)
                if ok:
                    return PoCResult(reproduced=True, test_source=test_source, detail=detail)
        return PoCResult(reproduced=False, test_source=test_source, detail=detail)

    def _import_note(self, root: Path, file: str) -> tuple[str, str]:
        if (root / "foundry.toml").is_file():
            import_line = os.path.relpath(root / file, root / "test") if file else ""
            note = (
                "This is a Foundry project. Import other libraries such as OpenZeppelin through "
                'the project\'s own remappings, for example "openzeppelin/...".'
            )
        else:
            import_line = f"../src/{file}" if file else ""
            note = "The contracts are copied under src, import any dependency by its src-relative path."
        return import_line, note

    def _complete(self, prompt: str) -> str:
        if self._provider is None:
            raise ValueError("generating a PoC needs a provider, this backend was built to run only")
        reply = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=False,
        )
        return _extract_solidity(reply.text)

    @contextmanager
    def _project(self, root: Path, sources: list[Path], foundry: bool):
        """Create an isolated project that retains remappings and never enables a fork."""
        with tempfile.TemporaryDirectory(prefix="cyberjury-poc-") as tmp:
            if foundry:
                proj = Path(tmp) / "repository"
                shutil.copytree(root, proj, ignore=shutil.ignore_patterns("out", "cache", "node_modules"))
                lib = proj / "lib"
                if (proj / ".gitmodules").is_file() and not (lib.is_dir() and any(lib.iterdir())):
                    self._forge(["install"], proj)
                (proj / "test").mkdir(exist_ok=True)
                yield proj, "test/CyberjuryPoC.t.sol"
            else:
                proj = Path(tmp)
                (proj / "foundry.toml").write_text(
                    "[profile.default]\nsrc = 'src'\ntest = 'test'\nauto_detect_solc = true\n", encoding="utf-8"
                )
                for s in sources:
                    dest = proj / "src" / s.relative_to(root)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(s, dest)
                (proj / "test").mkdir()
                yield proj, "test/PoC.t.sol"

    def _run_test(self, proj: Path, test_source: str, test_path: str) -> tuple[bool, str]:
        (proj / test_path).write_text(test_source, encoding="utf-8")
        build = self._forge(["build"], proj)
        if build.returncode != 0:
            return False, f"compile failed: {_tail(build.stdout + build.stderr)}"
        run = self._forge(["test", "--match-path", test_path], proj)
        if run.returncode == 0:
            return True, "PoC compiled and passed, exploit reproduced"
        return False, f"PoC ran but did not pass: {_tail(run.stdout + run.stderr)}"

    def _forge(self, args: list[str], cwd: Path) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                ["forge", *args], cwd=cwd, capture_output=True, text=True, timeout=self._timeout, check=False
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr="forge timed out")


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _tail(text: str, limit: int = 800) -> str:
    text = text.strip()
    return text[-limit:] if len(text) > limit else text


def _prompt(
    *,
    title: str,
    analysis: str,
    symbol: str,
    file: str,
    line: int | None,
    target_source: str,
    import_line: str,
    note: str,
) -> str:
    loc = f"{file}:{line}" if line else file
    return (
        f"Vulnerability: {title}\n"
        f"Location: {loc}\n"
        f"Function or symbol: {symbol}\n"
        f"Analysis: {analysis}\n\n"
        f'Import the contract under test with exactly:\nimport "{import_line}";\n'
        f"{note}\n\n"
        f"Source of the file under test ({file}):\n{target_source}\n\n"
        "Write the test that deploys the relevant contract and proves this vulnerability. "
        "The test passes only when the exploit succeeds."
    )


def _fix_prompt(*, previous: str, error: str, import_line: str, note: str) -> str:
    return (
        "Your previous test failed. Return the full corrected test that fixes the reported "
        "problem.\n\n"
        f'Import the contract under test with exactly:\nimport "{import_line}";\n{note}\n\n'
        f"Failure:\n{error}\n\n"
        f"Previous test:\n{previous}"
    )
