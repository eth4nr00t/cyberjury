"""Apply one recall-safe verification contract to every review target."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from time import perf_counter
from typing import Protocol

from cyberjury.detection import Detection, load_detection
from cyberjury.json_parse import optional_json_object
from cyberjury.profiles.base import ContentPaths
from cyberjury.providers.base import Message, Provider
from cyberjury.resources import FALSE_POSITIVE_TRAPS_FILE
from cyberjury.review.paths import resolve_source_path
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace, emit_trace

_SETTINGS = DEFAULT_REVIEW_SETTINGS.verification


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
    finding_id: str = ""
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


def _read_file(root: str, rel: str, detection: Detection | None = None) -> str:
    path = resolve_source_path(root, rel, detection=detection)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")[: _SETTINGS.max_source_chars_per_finding]
    except (OSError, UnicodeDecodeError):
        return ""


class ModelVerifier(Verifier):
    """Default skeptic: one grounded model call that tries to refute the candidate."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = DEFAULT_REVIEW_SETTINGS.verification.skeptic_max_output_tokens,
        content: ContentPaths | None = None,
    ) -> None:
        """Bind the skeptic model and false positive traps for one candidate check."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._detection = load_detection(content.detection_file) if content else None
        traps_file = content.false_positive_traps_file if content else FALSE_POSITIVE_TRAPS_FILE
        self._traps = traps_file.read_text(encoding="utf-8")

    def close(self) -> None:
        """Release the bound provider when it owns a persistent transport."""
        close = getattr(self._provider, "close", None)
        if callable(close):
            close()

    def verify(self, candidate: VerificationFinding, root: str) -> Verdict:
        """Try to refute one candidate against the source tree."""
        code = _read_file(root, candidate.file, self._detection)
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

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = DEFAULT_REVIEW_SETTINGS.verification.confirmer_max_output_tokens,
        content: ContentPaths | None = None,
    ) -> None:
        """Bind the confirmer model that tests whether a refutation holds."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._detection = load_detection(content.detection_file) if content else None

    def close(self) -> None:
        """Release the bound provider when it owns a persistent transport."""
        close = getattr(self._provider, "close", None)
        if callable(close):
            close()

    def holds(self, candidate: VerificationFinding, reason: str, root: str) -> bool:
        """Report whether an independent read upholds the refutation."""
        code = _read_file(root, candidate.file, self._detection)
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


@dataclass(frozen=True, kw_only=True)
class _CandidateVerification[T]:
    candidate: T
    real: bool
    reason: str = ""
    errors: tuple[str, ...] = ()
    incomplete: bool = False


def _applicable(confirmers: list[Confirmer], found_by: tuple[str, ...]) -> list[RefutationChecker]:
    """Exclude confirmers whose model already surfaced the finding."""
    seen = set(found_by)
    return [chk for label, chk in confirmers if not label or label not in seen]


def _finish_trace(
    trace: Trace | None,
    candidate: VerificationFinding,
    *,
    verdict: str = "",
    status: str = "",
    reason: str = "",
) -> None:
    fields = {
        "stage": "finished",
        "source": getattr(candidate, "source", ""),
        "finding_id": getattr(candidate, "finding_id", ""),
    }
    if verdict:
        fields["verdict"] = verdict
    if status:
        fields["status"] = status
    if reason:
        fields["reason"] = reason[:500]
    emit_trace(trace, "verification", **fields)


def _verify_candidate[T: VerificationFinding](
    candidate: T,
    verifier: Verifier,
    root: str,
    *,
    confirmers: list[Confirmer],
    votes: int,
    trace: Trace | None,
) -> _CandidateVerification[T]:
    emit_trace(
        trace,
        "verification",
        stage="started",
        source=getattr(candidate, "source", ""),
        finding_id=getattr(candidate, "finding_id", ""),
        file=candidate.file,
        line=candidate.line,
        category=candidate.category,
    )
    verdicts: list[Verdict] = []
    errors: list[str] = []
    for _ in range(votes):
        try:
            verdicts.append(verifier.verify(candidate, root))
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
    if not verdicts:
        _finish_trace(trace, candidate, status="incomplete")
        return _CandidateVerification(candidate=candidate, real=True, errors=tuple(errors), incomplete=True)
    if errors:
        _finish_trace(trace, candidate, status="incomplete")
        return _CandidateVerification(candidate=candidate, real=True, errors=tuple(errors), incomplete=True)
    if any(verdict.real for verdict in verdicts):
        _finish_trace(trace, candidate, verdict="real")
        return _CandidateVerification(candidate=candidate, real=True, errors=tuple(errors))

    reason = next((verdict.reason for verdict in verdicts if not verdict.real), "")
    applicable = _applicable(confirmers, candidate.found_by)
    if not applicable:
        _finish_trace(trace, candidate, verdict="real")
        return _CandidateVerification(candidate=candidate, real=True, errors=tuple(errors))
    try:
        upheld = all(checker.holds(candidate, reason, root) for checker in applicable)
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        _finish_trace(trace, candidate, status="incomplete")
        return _CandidateVerification(candidate=candidate, real=True, errors=tuple(errors), incomplete=True)
    if upheld:
        _finish_trace(trace, candidate, verdict="refuted", reason=reason)
        return _CandidateVerification(candidate=candidate, real=False, reason=reason, errors=tuple(errors))
    _finish_trace(trace, candidate, verdict="real")
    return _CandidateVerification(candidate=candidate, real=True, errors=tuple(errors))


def verify_findings[T: VerificationFinding](
    candidates: list[T],
    verifier: Verifier,
    root: str,
    *,
    confirmers: list[Confirmer] | None = None,
    votes: int = DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required,
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
    on_verify: Callable[[int, int, float], None] | None = None,
    trace: Trace | None = None,
) -> VerifyResult[T]:
    """Drop a candidate only when every independent completed check supports refutation."""
    if isinstance(votes, bool) or not isinstance(votes, int) or votes < 1:
        raise ValueError("verification votes must be positive")
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency < 1:
        raise ValueError("verification concurrency must be positive")
    confirmers = confirmers or []

    def verify_one(candidate: T) -> _CandidateVerification[T]:
        return _verify_candidate(
            candidate,
            verifier,
            root,
            confirmers=confirmers,
            votes=votes,
            trace=trace,
        )

    fn: Callable[[T], _CandidateVerification[T]] = verify_one
    if on_verify is not None:
        total = len(candidates)
        lock = threading.Lock()
        done = 0

        def timed(candidate: T) -> _CandidateVerification[T]:
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

    confirmed = [result.candidate for result in results if result.real]
    refuted = [(result.candidate, result.reason) for result in results if not result.real]
    error_details = [detail for result in results for detail in result.errors]
    incomplete = [result.candidate for result in results if result.real and result.incomplete]
    return VerifyResult(
        confirmed=confirmed,
        refuted=refuted,
        errors=len(error_details),
        error_details=error_details,
        incomplete=incomplete,
    )
