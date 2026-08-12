"""Apply one recall-safe verification contract to every review target."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from time import perf_counter
from typing import Protocol

from cyberjury.domains.base import ContentPaths
from cyberjury.json_parse import optional_json_object
from cyberjury.providers.base import Message, Provider
from cyberjury.resources import FALSE_POSITIVE_TRAPS_FILE
from cyberjury.review.paths import resolve_source_path

_READ_MAX = 40_000


class VerificationFinding(Protocol):
    """The evidence fields required by the shared verification route."""

    title: str
    category: str
    endpoint: str
    file: str
    line: int | None
    severity: str
    evidence: str
    found_by: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class VerificationCandidate:
    """A target-neutral finding shape for verification adapters."""

    title: str
    category: str = ""
    endpoint: str = ""
    file: str = ""
    line: int | None = None
    severity: str = "HIGH"
    evidence: str = ""
    source: str = ""
    found_by: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class Verdict:
    """Verifier decision for one candidate and the reason behind it."""

    real: bool
    reason: str = ""


class VerifyError(RuntimeError):
    """A verifier produced no usable verdict for a completed review step."""


class Verifier(ABC):
    """Interface for candidate refutation checks."""

    @abstractmethod
    def verify(self, candidate: VerificationFinding, root: str) -> Verdict:
        """Try to refute one candidate. Return real or refuted, with the reason."""


@dataclass(frozen=True, kw_only=True)
class VerifyResult[T]:
    """Verified candidates, refutations, and incomplete verification state."""

    confirmed: list[T] = field(default_factory=list)
    refuted: list[tuple[T, str]] = field(default_factory=list)
    errors: int = 0
    error_details: list[str] = field(default_factory=list)
    incomplete: list[T] = field(default_factory=list)
    unlocatable: list[T] = field(default_factory=list)


def verification_failure_reason(details: list[str]) -> str:
    """Keep repeated verifier failures concise without hiding their common cause."""
    if not details:
        return ""
    unique = list(dict.fromkeys(details))
    rendered = ". ".join(unique[:3])
    remaining = len(unique) - 3
    if remaining > 0:
        rendered += f". {remaining} more distinct verification errors"
    return f"verification failed: {rendered}"


_SYSTEM = (
    "You are a skeptical security reviewer. Your job is to REFUTE a proposed finding "
    "by reading the code: find the controlling fact that makes it safe, judging against "
    "production semantics, not a shallow read. You are shown only the code at the finding's "
    "own file, so you may refute only on a fact visible in that code or a genuine framework "
    "guarantee. When the finding would be safe only because of a control in another file you "
    "were not shown, an upstream service or controller you assume enforces it for example, you "
    "have not refuted it: report it real and name that other file in control_file. Only if you "
    "genuinely cannot refute it is it real. Respond with a single JSON object and nothing else."
)

_JSON_SHAPE = (
    '{"real": true, "reason": "the controlling fact at file:line", '
    '"control_file": "the file holding that fact, empty if none"}'
)


def _control_ref(ref: str) -> str:
    """Return the cited control file without a trailing line number."""
    return ref.strip().strip("`").split(":", 1)[0].strip()


def _control_is_on_file(control: str, candidate_file: str) -> bool:
    """Accept a control only when it identifies the file shown to the skeptic."""
    if "/" in control:
        return control == candidate_file
    return control == candidate_file.rsplit("/", 1)[-1]


def _read_file(root: str, rel: str) -> str:
    path = resolve_source_path(root, rel)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")[:_READ_MAX]
    except (OSError, UnicodeDecodeError):
        return ""


class ModelVerifier(Verifier):
    """Default skeptic: one grounded model call that tries to refute the candidate."""

    def __init__(
        self, *, provider: Provider, model: str, max_tokens: int = 2048, content: ContentPaths | None = None
    ) -> None:
        """Bind the skeptic model and false positive traps for one candidate check."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        traps_file = content.false_positive_traps_file if content else FALSE_POSITIVE_TRAPS_FILE
        self._traps = traps_file.read_text(encoding="utf-8")

    def close(self) -> None:
        """Release the bound provider when it owns a persistent transport."""
        close = getattr(self._provider, "close", None)
        if callable(close):
            close()

    def verify(self, candidate: VerificationFinding, root: str) -> Verdict:
        """Try to refute one candidate against the source tree."""
        code = _read_file(root, candidate.file)
        cache_head = (
            "Try to REFUTE this proposed finding. Read the code and decide whether a "
            "controlling fact makes it genuinely safe, judging against PRODUCTION "
            "semantics, not a shallow read.\n\n"
            f"Traps to check against, in both directions, refuting a real finding as "
            f"wrongly as confirming a safe one:\n{self._traps}\n\n"
        )
        prompt = (
            cache_head + f"Proposed finding:\n- {candidate.title}\n- category: {candidate.category}\n"
            f"- endpoint: {candidate.endpoint}\n- location: {candidate.file}:{candidate.line}\n"
            f"- claimed evidence: {candidate.evidence}\n\n"
            f"Code at {candidate.file}:\n```\n{code}\n```\n\n"
            f"Respond with a single JSON object exactly like:\n{_JSON_SHAPE}"
        )
        result = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
            cache_prefix=cache_head,
        )
        obj, ok = optional_json_object(result.text, required_key="real")
        if not ok:
            raise VerifyError("unparseable verification reply")
        real = obj.get("real")
        if not isinstance(real, bool):
            raise VerifyError("verification reply real field was not boolean")
        if real:
            return Verdict(real=True, reason=str(obj.get("reason", "")))
        control = _control_ref(str(obj.get("control_file", "")))
        if control and not _control_is_on_file(control, candidate.file):
            return Verdict(real=True, reason=f"refuted on unshown {control}, kept for cross-file check")
        return Verdict(real=False, reason=str(obj.get("reason", "")))


class RefutationChecker(ABC):
    """Independent checker for a proposed refutation."""

    @abstractmethod
    def holds(self, candidate: VerificationFinding, reason: str, root: str) -> bool:
        """Uphold a refutation only when its controlling fact neutralizes the real path."""


_CHECK_SYSTEM = (
    "You audit a proposed refutation, not the finding. A reviewer claims a security finding is "
    "safe because of one controlling fact. Assume the finding is REAL and try to show the fact "
    "does not actually neutralize it: the fact may be true yet guard a different path, a "
    "different precondition, or a different function than the one the finding exploits, the "
    "rate==0 branch when the bug bites at rate>0. Read the code at the finding's file. Conclude "
    "the refutation holds only when the controlling fact clearly and completely makes the "
    "finding unexploitable on its real path. Any doubt, any gap, the refutation does not hold "
    "and the finding stays. Respond with a single JSON object and nothing else."
)

_CHECK_SHAPE = '{"holds": true, "reason": "why the controlling fact does or does not neutralize the finding"}'


class ModelRefutationChecker(RefutationChecker):
    """Require an independent grounded call before accepting a refutation."""

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 1024) -> None:
        """Bind the confirmer model that tests whether a refutation holds."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def close(self) -> None:
        """Release the bound provider when it owns a persistent transport."""
        close = getattr(self._provider, "close", None)
        if callable(close):
            close()

    def holds(self, candidate: VerificationFinding, reason: str, root: str) -> bool:
        """Report whether an independent read upholds the refutation."""
        code = _read_file(root, candidate.file)
        if not code.strip():
            return False
        prompt = (
            "Audit this refutation. Does the controlling fact genuinely make the finding "
            "unexploitable on its real path, or does it guard a different path or precondition?\n\n"
            f"Finding:\n- {candidate.title}\n- category: {candidate.category}\n"
            f"- location: {candidate.file}:{candidate.line}\n- claimed evidence: {candidate.evidence}\n\n"
            f"Refutation's controlling fact, the reason it is called safe:\n{reason}\n\n"
            f"Code at {candidate.file}:\n```\n{code}\n```\n\n"
            f"Respond with a single JSON object exactly like:\n{_CHECK_SHAPE}"
        )
        result = self._provider.complete(
            system=_CHECK_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
        )
        obj, ok = optional_json_object(result.text, required_key="holds")
        if not ok:
            raise VerifyError("unparseable refutation check reply")
        holds = obj.get("holds")
        if not isinstance(holds, bool):
            raise VerifyError("refutation check holds field was not boolean")
        return holds


Confirmer = tuple[str, RefutationChecker]


def _applicable(confirmers: list[Confirmer], found_by: tuple[str, ...]) -> list[RefutationChecker]:
    """Exclude confirmers whose model already surfaced the finding."""
    seen = set(found_by)
    return [chk for label, chk in confirmers if not label or label not in seen]


def verify_findings[T: VerificationFinding](
    candidates: list[T],
    verifier: Verifier,
    root: str,
    *,
    confirmers: list[Confirmer] | None = None,
    votes: int = 1,
    concurrency: int = 8,
    on_verify: Callable[[int, int, float], None] | None = None,
) -> VerifyResult[T]:
    """Drop a candidate only when every independent completed check supports refutation."""
    confirmers = confirmers or []

    def verify_one(candidate: T):
        verdicts: list[Verdict] = []
        error_details: list[str] = []
        for _ in range(max(1, votes)):
            try:
                verdicts.append(verifier.verify(candidate, root))
            except Exception as exc:
                error_details.append(f"{type(exc).__name__}: {exc}")
        if not verdicts:
            return candidate, True, "", error_details, True
        if any(v.real for v in verdicts):
            return candidate, True, "", error_details, False
        reason = next((v.reason for v in verdicts if not v.real), "")
        applicable = _applicable(confirmers, candidate.found_by)
        if not applicable:
            return candidate, True, "", error_details, False
        try:
            upheld = all(chk.holds(candidate, reason, root) for chk in applicable)
        except Exception as exc:
            error_details.append(f"{type(exc).__name__}: {exc}")
            return candidate, True, "", error_details, True
        if upheld:
            return candidate, False, reason, error_details, False
        return candidate, True, "", error_details, False

    fn = verify_one
    if on_verify is not None:
        total = len(candidates)
        lock = threading.Lock()
        done = 0

        def timed(candidate):
            nonlocal done
            started = perf_counter()
            result = verify_one(candidate)
            with lock:
                done += 1
                on_verify(done, total, round(perf_counter() - started, 1))
            return result

        fn = timed
    if concurrency > 1 and len(candidates) > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(fn, candidates))
    else:
        results = [fn(c) for c in candidates]

    confirmed = [c for c, real, _r, _e, _i in results if real]
    refuted = [(c, reason) for c, real, reason, _e, _i in results if not real]
    error_details = [detail for _c, _real, _r, details, _i in results for detail in details]
    incomplete = [c for c, real, _r, _e, inc in results if real and inc]
    return VerifyResult(
        confirmed=confirmed,
        refuted=refuted,
        errors=len(error_details),
        error_details=error_details,
        incomplete=incomplete,
    )
