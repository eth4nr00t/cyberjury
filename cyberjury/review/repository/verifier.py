"""Adversarial verification.

try to REFUTE each candidate, drop only a confirmed refutation. High recall comes from
the union of diverse passes, but that also lets false positives and bounded-but-real-
looking misreads through. This stage is the precision counterweight, the part that earns
the right to surface everything: each candidate is handed to an independent skeptic
whose job is to DISPROVE it by reading the code, judging against production semantics,
not a shallow read. A select_for_update holds the row lock on a real RDBMS even if its
result is discarded. A check defined in a base class still fires on the subclass. A
value an attacker cannot reach is not a sink. A candidate that survives is confirmed. A
refutation alone is an opinion, not a deletion, and a single skeptic that misreads drops
a real finding, the worst outcome for recall. So a refuted candidate is dropped only
when every independent confirmer, a `RefutationChecker` for the judge and for each peer
model that did not itself surface the finding, upholds that the controlling fact
genuinely neutralizes the finding on its real path, the rate==0 reason rejected for a
bug that bites at rate>0. With no applicable confirmer, one confirmer that does not
uphold it, or any keep vote, the finding stays. Every drop is recorded, so it is
auditable. The skeptic sees only the finding's own file, so a refutation that rests on a
control in another file it was not shown is an assumption, not a refutation, the failure
that dropped a real cross-file authorization gap by trusting an upstream check that did
not exist. Such a finding is kept for cross-file confirmation, not dropped. Injectable
like the reviewer, so the skeptic can be a single grounded model call today or a tool-
using agent later. Errors never silently refute a finding: a failed verification keeps
the candidate and is counted, because dropping a real finding on a failed call is the
worst outcome for recall.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from time import perf_counter

from cyberjury.domains.base import ContentPaths
from cyberjury.json_parse import optional_json_object
from cyberjury.providers.base import Message, Provider
from cyberjury.resources import FALSE_POSITIVE_TRAPS_FILE
from cyberjury.review.repository.paths import resolve_source_path
from cyberjury.review.repository.union import Candidate

_READ_MAX = 40_000


@dataclass(frozen=True, kw_only=True)
class Verdict:
    """Verifier decision for one candidate and the reason behind it."""

    real: bool
    reason: str = ""


class VerifyError(RuntimeError):
    """A verifier produced no usable verdict, an unparseable or unusable model reply.

    It is a failed verification step, not a keep vote, so the caller counts it and re-
    attempts it on resume rather than freezing an unparsed reply as a confirmation,
    invariant 4.
    """


class Verifier(ABC):
    """Interface for candidate refutation checks."""

    @abstractmethod
    def verify(self, candidate: Candidate, root: str) -> Verdict:
        """Try to refute one candidate. Return real or refuted, with the reason."""


@dataclass(frozen=True, kw_only=True)
class VerifyResult:
    """Verified candidates, refutations, and incomplete verification state."""

    confirmed: list[Candidate] = field(default_factory=list)
    refuted: list[tuple[Candidate, str]] = field(default_factory=list)
    errors: int = 0
    incomplete: list[Candidate] = field(default_factory=list)
    unlocatable: list[Candidate] = field(default_factory=list)


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
    """The file a controlling fact cites, without a trailing line.

    empty when the skeptic named none.
    """
    return ref.strip().strip("`").split(":", 1)[0].strip()


def _control_is_on_file(control: str, candidate_file: str) -> bool:
    """Whether the cited control is the file the skeptic was actually shown.

    A control that names a directory must match the candidate's full path, so a same-named
    file in another directory is not read as on-file, invariant 2. A bare filename still
    matches on name, since the skeptic often cites the shown file loosely.
    """
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

    def verify(self, candidate: Candidate, root: str) -> Verdict:
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
        if obj.get("real"):
            return Verdict(real=True, reason=str(obj.get("reason", "")))
        control = _control_ref(str(obj.get("control_file", "")))
        if control and not _control_is_on_file(control, candidate.file):
            return Verdict(real=True, reason=f"refuted on unshown {control}, kept for cross-file check")
        return Verdict(real=False, reason=str(obj.get("reason", "")))


class RefutationChecker(ABC):
    """Independent checker for a proposed refutation."""

    @abstractmethod
    def holds(self, candidate: Candidate, reason: str, root: str) -> bool:
        """Independently check whether a refutation's controlling fact genuinely neutralizes the.

        finding on its real exploit path. True only when it clearly does, so a deletion rests on
        confirmed evidence, not a single skeptic's opinion.
        """


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
    """Default checker: one independent grounded call that audits whether a refutation holds.

    A different angle from the skeptic, defending the finding rather than refuting it, so a
    deletion needs two independent reads to agree, not one skeptic's possibly shared blind
    spot.
    """

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 1024) -> None:
        """Bind the confirmer model that tests whether a refutation holds."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def holds(self, candidate: Candidate, reason: str, root: str) -> bool:
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
            return False
        return bool(obj.get("holds"))


Confirmer = tuple[str, RefutationChecker]


def _applicable(confirmers: list[Confirmer], found_by: tuple) -> list[RefutationChecker]:
    """The confirmers that can independently audit this finding's refutation.

    A confirmer labeled with a model that surfaced the finding is excluded, it cannot give a
    read independent of its own, the cross-model independence the deletion rests on. The
    dedicated judge has an empty label and always applies.
    """
    seen = set(found_by)
    return [chk for label, chk in confirmers if not label or label not in seen]


def verify_findings(
    candidates: list[Candidate],
    verifier: Verifier,
    root: str,
    *,
    confirmers: list[Confirmer] | None = None,
    votes: int = 1,
    concurrency: int = 6,
    on_verify: Callable[[int, int, float], None] | None = None,
) -> VerifyResult:
    """Verify every candidate through one route.

    A finding is dropped only when every completed skeptic vote refutes it AND every
    applicable confirmer independently agrees the refutation holds. Any keep vote saves it,
    asymmetric since dropping a real finding is the worst outcome for recall. With no
    completed vote, no applicable confirmer, a single confirmer that does not uphold the
    refutation, or a failed confirmer, the finding is kept, so one opinion or a shared blind
    spot can never drop it. A confirmer labeled with a model that found the finding is
    skipped, it is not an independent read. Errors are counted, never read as a refutation.
    Candidates run concurrently.
    """
    confirmers = confirmers or []

    def verify_one(candidate: Candidate):
        verdicts: list[Verdict] = []
        errors = 0
        for _ in range(max(1, votes)):
            try:
                verdicts.append(verifier.verify(candidate, root))
            except Exception:
                errors += 1
        if not verdicts:
            return candidate, True, "", errors, True
        if any(v.real for v in verdicts):
            return candidate, True, "", errors, False
        reason = next((v.reason for v in verdicts if not v.real), "")
        applicable = _applicable(confirmers, candidate.found_by)
        if not applicable:
            return candidate, True, "", errors, False
        try:
            upheld = all(chk.holds(candidate, reason, root) for chk in applicable)
        except Exception:
            return candidate, True, "", errors + 1, True
        if upheld:
            return candidate, False, reason, errors, False
        return candidate, True, "", errors, False

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
    errors = sum(e for _c, _real, _r, e, _i in results)
    incomplete = [c for c, real, _r, _e, inc in results if real and inc]
    return VerifyResult(confirmed=confirmed, refuted=refuted, errors=errors, incomplete=incomplete)
