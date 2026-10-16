"""Apply one recall-safe verification contract to every review target."""

from __future__ import annotations

import hashlib
import json
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Literal, Protocol

from cyberjury.canonical import canonical_sha256
from cyberjury.numbering import numbered_source, split_lines
from cyberjury.providers.base import Message, Provider, ResponseSchema
from cyberjury.providers.metering import model_call_context, record_model_parse
from cyberjury.review.checkpoint import CheckpointStore
from cyberjury.review.engine import parse_role_response
from cyberjury.review.knowledge import load_review_brief
from cyberjury.review.paths import normalized_location_path, resolve_source_path
from cyberjury.review.prompts import UNTRUSTED_SOURCE_RULE, fenced_source, one_line_source
from cyberjury.review.schemas import closed_object
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SETTINGS = DEFAULT_REVIEW_SETTINGS.verification
VERIFICATION_SCHEMA = "cyberjury.verification/v3"


class VerificationFinding(Protocol):
    """The evidence fields required by the shared verification route."""

    candidate_id: str
    title: str
    category: str
    entrypoint: str
    file: str
    line: int
    severity: str
    evidence: str
    attack_path: str
    found_by: tuple[str, ...]
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class Verdict:
    """Verifier decision for one candidate and the reason behind it."""

    real: bool
    reason: str = ""
    control_file: str = ""
    control_line: int | None = None


class VerifyError(RuntimeError):
    """A verifier produced no usable verdict for a completed review step."""


@dataclass(frozen=True, kw_only=True)
class VerificationActorFingerprint:
    """Stable public identity for one verification model role."""

    actor: str
    settings: tuple[tuple[str, str], ...] = ()
    configured_seat_id: str = ""

    def to_data(self) -> dict[str, object]:
        """Return deterministic checkpoint data for this role."""
        value: dict[str, object] = {
            "actor": self.actor,
            "settings": dict(self.settings),
        }
        if self.configured_seat_id:
            value["configured_seat_id"] = self.configured_seat_id
        return value

    @property
    def actor_id(self) -> str:
        """Identify one configured verification role for audit records."""
        encoded = json.dumps(self.to_data(), sort_keys=True, separators=(",", ":"))
        return f"actor-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:20]}"

    @property
    def seat_id(self) -> str:
        """Identify the configured model seat used for independence checks."""
        return self.configured_seat_id or self.actor_id


class Verifier(ABC):
    """Interface for candidate refutation checks."""

    def checkpoint_fingerprint(self) -> VerificationActorFingerprint:
        """Identify response affecting verifier configuration for resume."""
        return VerificationActorFingerprint(actor=f"{type(self).__module__}.{type(self).__qualname__}")

    @abstractmethod
    def verify(self, candidate: VerificationFinding, root: str) -> Verdict:
        """Try to refute one candidate. Return real or refuted, with the reason."""


@dataclass(frozen=True, kw_only=True)
class VerifyResult[T]:
    """Retained candidates, completed verification, and incomplete state."""

    retained: list[T] = field(default_factory=list)
    verified: list[T] = field(default_factory=list)
    refuted: list[tuple[T, str]] = field(default_factory=list)
    errors: int = 0
    error_details: list[str] = field(default_factory=list)
    incomplete: list[T] = field(default_factory=list)
    records: list[VerificationRecord[T]] = field(default_factory=list)
    candidate_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class VerificationVote:
    """One skeptic or confirmer decision retained for deletion audit."""

    role: Literal["skeptic", "confirmer"]
    actor_id: str
    seat_id: str
    verdict: Literal["real", "refuted", "upheld", "rejected", "error"]
    reason: str
    control_file: str = ""
    control_line: int | None = None


@dataclass(frozen=True, kw_only=True)
class VerificationRecord[T]:
    """Complete vote history for one candidate verification decision."""

    candidate: T
    outcome: Literal["retained", "refuted", "incomplete"]
    votes: tuple[VerificationVote, ...]
    reason: str = ""
    required_confirmer_seat_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class VerificationDecision:
    """One candidate outcome in the attempt verification artifact."""

    candidate_id: str
    outcome: Literal["retained", "refuted", "incomplete"]
    reason: str
    required_confirmer_seat_ids: tuple[str, ...] = ()
    votes: tuple[VerificationVote, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return one strict candidate decision."""
        return {
            "candidate_id": self.candidate_id,
            "outcome": self.outcome,
            "reason": self.reason,
            "required_confirmer_seat_ids": list(self.required_confirmer_seat_ids),
            "votes": [_vote_to_data(vote) for vote in self.votes],
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationReceipt:
    """One attempt's complete candidate deletion decisions."""

    request_sha256: str
    enabled: bool
    candidate_ids: tuple[str, ...]
    decisions: tuple[VerificationDecision, ...]
    content_sha256: str
    schema: str = VERIFICATION_SCHEMA

    @classmethod
    def create(
        cls,
        *,
        request_sha256: str,
        enabled: bool,
        candidate_ids: tuple[str, ...],
        records: tuple[VerificationRecord, ...] = (),
    ) -> VerificationReceipt:
        """Create one complete receipt from shared verification results."""
        if not enabled:
            decisions: tuple[VerificationDecision, ...] = ()
        else:
            record_ids = tuple(record.candidate.candidate_id for record in records)
            if len(record_ids) != len(set(record_ids)):
                raise ValueError("verification records contain duplicate candidates")
            by_id = {
                candidate_id: VerificationDecision(
                    candidate_id=candidate_id,
                    outcome=record.outcome,
                    reason=record.reason,
                    required_confirmer_seat_ids=record.required_confirmer_seat_ids,
                    votes=record.votes,
                )
                for candidate_id, record in zip(record_ids, records, strict=True)
            }
            unknown = set(by_id).difference(candidate_ids)
            missing = set(candidate_ids).difference(by_id)
            if unknown or missing:
                raise ValueError("verification decisions do not match the candidate input")
            decisions = tuple(by_id[candidate_id] for candidate_id in candidate_ids)
        semantic = {
            "request_sha256": request_sha256,
            "enabled": enabled,
            "candidate_ids": candidate_ids,
            "decisions": tuple(decision.to_dict() for decision in decisions),
        }
        return cls(
            request_sha256=request_sha256,
            enabled=enabled,
            candidate_ids=candidate_ids,
            decisions=decisions,
            content_sha256=canonical_sha256(semantic),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the strict persisted receipt."""
        return {
            "schema": self.schema,
            "request_sha256": self.request_sha256,
            "enabled": self.enabled,
            "candidate_ids": list(self.candidate_ids),
            "decisions": [decision.to_dict() for decision in self.decisions],
            "content_sha256": self.content_sha256,
        }


def _vote_to_data(vote: VerificationVote) -> dict[str, object]:
    return {
        "role": vote.role,
        "actor_id": vote.actor_id,
        "seat_id": vote.seat_id,
        "verdict": vote.verdict,
        "reason": vote.reason,
        "control_file": vote.control_file,
        "control_line": vote.control_line,
    }


_VOTE_FIELDS = frozenset({"role", "actor_id", "seat_id", "verdict", "reason", "control_file", "control_line"})
_DECISION_FIELDS = frozenset({"outcome", "reason", "required_confirmer_seat_ids", "votes"})
_ROLE_VERDICTS = {"skeptic": ("real", "refuted"), "confirmer": ("upheld", "rejected")}


def _vote_from_data(data: object, identity: VerificationActorFingerprint, role: str) -> VerificationVote:
    if not isinstance(data, dict) or set(data) != _VOTE_FIELDS:
        raise ValueError("verification vote fields are invalid")
    if data["role"] != role:
        raise ValueError(f"verification vote must be a {role} vote")
    if data["actor_id"] != identity.actor_id or data["seat_id"] != identity.seat_id:
        raise ValueError(f"verification {role} vote does not match the current verification policy")
    if data["verdict"] not in _ROLE_VERDICTS[role]:
        raise ValueError(f"verification {role} verdict is invalid")
    if not isinstance(data["reason"], str) or not isinstance(data["control_file"], str):
        raise ValueError("verification vote text fields must be strings")
    control_line = data["control_line"]
    if control_line is not None and (isinstance(control_line, bool) or not isinstance(control_line, int)):
        raise ValueError("verification vote control line must be an integer or null")
    return VerificationVote(
        role=data["role"],
        actor_id=data["actor_id"],
        seat_id=data["seat_id"],
        verdict=data["verdict"],
        reason=data["reason"],
        control_file=data["control_file"],
        control_line=control_line,
    )


def completed_decision_from_dict(
    data: object,
    *,
    candidate_id: str,
    skeptic: VerificationActorFingerprint,
    confirmers: tuple[VerificationActorFingerprint, ...],
) -> VerificationDecision:
    """Validate one checkpointed completed decision against the route the current policy requires."""
    if not isinstance(data, dict) or set(data) != _DECISION_FIELDS:
        raise ValueError("verification decision fields are invalid")
    outcome = data["outcome"]
    if outcome not in ("retained", "refuted"):
        raise ValueError("verification decision outcome must be retained or refuted")
    if not isinstance(data["reason"], str) or not data["reason"].strip():
        raise ValueError("verification decision reason must be nonempty")
    if not confirmers:
        raise ValueError("verification decision has no independent confirmer")
    if data["required_confirmer_seat_ids"] != [confirmer.seat_id for confirmer in confirmers]:
        raise ValueError("verification decision confirmers do not match the current verification policy")
    votes = data["votes"]
    if not isinstance(votes, list) or not votes or len(votes) > 1 + len(confirmers):
        raise ValueError("verification decision votes do not match its route")
    parsed = (
        _vote_from_data(votes[0], skeptic, "skeptic"),
        *(
            _vote_from_data(vote, confirmer, "confirmer")
            for vote, confirmer in zip(votes[1:], confirmers, strict=False)
        ),
    )
    skeptic_vote, confirmer_votes = parsed[0], parsed[1:]
    if outcome == "refuted":
        valid = (
            skeptic_vote.verdict == "refuted"
            and len(confirmer_votes) == len(confirmers)
            and all(vote.verdict == "upheld" for vote in confirmer_votes)
        )
    elif skeptic_vote.verdict == "real":
        valid = not confirmer_votes
    else:
        valid = (
            bool(confirmer_votes)
            and confirmer_votes[-1].verdict == "rejected"
            and all(vote.verdict == "upheld" for vote in confirmer_votes[:-1])
        )
    if not valid:
        raise ValueError(f"verification decision votes do not support a {outcome} outcome")
    return VerificationDecision(
        candidate_id=candidate_id,
        outcome=outcome,
        reason=data["reason"],
        required_confirmer_seat_ids=tuple(confirmer.seat_id for confirmer in confirmers),
        votes=parsed,
    )


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
    "You are a skeptical security reviewer. Try to refute the proposed finding by finding the controlling fact "
    "in the shown code that makes it unexploitable under production semantics. You are shown only the code in "
    "the finding's own file, so refute only on a controlling fact visible there. A control in a file you were "
    "not shown cannot justify deletion. " + UNTRUSTED_SOURCE_RULE + "\n\n"
    "# Output Fields\n\n"
    "The provider enforces the response schema. Field meanings:\n"
    "- `real`: false only when a controlling fact in the shown code makes the finding unexploitable; "
    "true otherwise.\n"
    "- `reason`: the controlling fact that refutes the finding, or the control the shown code lacks.\n"
    "- `control_file`: the exact shown repository path of the controlling fact when `real` is false; "
    "empty when `real` is true.\n"
    "- `control_line`: the existing line of the controlling fact when `real` is false; 0 when `real` is true."
)
_FINDING_FIELDS = ("title", "category", "entrypoint", "location", "claimed evidence", "claimed attack path")
_SKEPTIC_PROMPT_TEMPLATE = "{finding}\n\nCode at {file}:\n{code}"


def _finding_block(candidate: VerificationFinding) -> str:
    """Render the claim under review once, as single line untrusted values, omitting empty fields."""
    values = (
        candidate.title,
        candidate.category,
        candidate.entrypoint,
        f"{candidate.file}:{candidate.line}",
        candidate.evidence,
        candidate.attack_path,
    )
    lines = [
        f"- {label}: {one_line_source(value)}" for label, value in zip(_FINDING_FIELDS, values, strict=True) if value
    ]
    return "\n".join(("Finding under review:", *lines))


_VERDICT_RESPONSE_SCHEMA = ResponseSchema(
    name="verification_verdict",
    schema=closed_object(
        {
            "real": {"type": "boolean"},
            "reason": {"type": "string"},
            "control_file": {"type": "string"},
            "control_line": {"type": "integer"},
        }
    ),
)


def _control_ref(ref: str) -> str:
    """Return the cited control file without a trailing line number."""
    return ref.strip().strip("`").split(":", 1)[0].strip()


def _same_source_file(root: str, first: str, second: str) -> bool:
    """Compare two source references only through their resolved repository paths."""

    def resolve(reference: str) -> Path | None:
        return resolve_source_path(root, normalized_location_path(reference))

    first_path = resolve(first)
    second_path = resolve(second)
    return first_path is not None and second_path is not None and first_path == second_path


def _source_window(text: str, line: int | None, max_chars: int) -> tuple[str, int]:
    """Return a line aligned window centered on the candidate location."""
    lines = split_lines(text, keepends=True)
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1 or line > len(lines)):
        return "", 1
    if len(text) <= max_chars:
        return text, 1
    if line is None:
        return text[:max_chars], 1
    offset = sum(len(value) for value in lines[: line - 1])
    start = max(0, offset - max_chars // 2)
    end = min(len(text), start + max_chars)
    if start:
        newline = text.find("\n", start)
        start = newline + 1 if newline >= 0 else start
    if end < len(text):
        newline = text.rfind("\n", start, end)
        end = newline + 1 if newline >= 0 else end
    first_line = text[:start].count("\n") + 1
    return text[start:end], first_line


def _read_source(root: str, rel: str, *, line: int | None = None) -> tuple[str, range]:
    """Return the numbered source window shown to a model and the line numbers it covers."""
    path = resolve_source_path(root, rel)
    if path is None:
        return "", range(0)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return "", range(0)
    window, first_line = _source_window(text, line, _SETTINGS.max_source_chars_per_finding)
    if not window:
        return "", range(0)
    return numbered_source(rel, window, first_line), range(first_line, first_line + len(split_lines(window)))


class _ModelSeat:
    """One configured verification model call bound to the security kernel."""

    _system: str
    _prompt_template: str
    _response_schema: ResponseSchema
    _default_max_tokens: int

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        seat_id: str,
        max_tokens: int | None = None,
    ) -> None:
        """Bind one seat to its model, output bound, and security kernel."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens or self._default_max_tokens
        self._seat_id = seat_id
        self._review_brief = load_review_brief()

    def checkpoint_fingerprint(self) -> VerificationActorFingerprint:
        """Identify the seat, model, and prompt contract, never transport policy such as timeout or retries."""
        return VerificationActorFingerprint(
            actor=f"{type(self).__module__}.{type(self).__qualname__}",
            settings=(
                ("kernel_sha256", self._review_brief.content_sha256),
                ("max_tokens", str(self._max_tokens)),
                ("model", self._model),
                (
                    "prompt_contract_sha256",
                    canonical_sha256(
                        {
                            "system": self._system,
                            "finding_fields": list(_FINDING_FIELDS),
                            "prompt_template": self._prompt_template,
                            "response_schema": self._response_schema.schema,
                        }
                    ),
                ),
            ),
            configured_seat_id=self._seat_id,
        )

    def _complete[R](
        self,
        prompt: str,
        *,
        role: str,
        trigger: str,
        candidate_id: str,
        decide: Callable[[dict[str, object]], R],
    ) -> R:
        """Ask the seat once, validate the reply, and record any semantic violation on the same call."""
        with model_call_context(
            role=role,
            trigger=trigger,
            candidate_id=candidate_id,
        ):
            result = self._provider.complete(
                system=f"{self._system}\n\n{self._review_brief.render().strip()}",
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                response_schema=self._response_schema,
            )
            reply = parse_role_response(result.text, role=role, response_schema=self._response_schema)
            try:
                return decide(reply)
            except VerifyError as exc:
                record_model_parse(str(exc))
                raise


class ModelVerifier(_ModelSeat, Verifier):
    """Default skeptic: one grounded model call that tries to refute the candidate."""

    _system = _SYSTEM
    _prompt_template = _SKEPTIC_PROMPT_TEMPLATE
    _response_schema = _VERDICT_RESPONSE_SCHEMA

    _default_max_tokens = _SETTINGS.skeptic_max_output_tokens

    def verify(self, candidate: VerificationFinding, root: str) -> Verdict:
        """Try to refute one candidate against the source tree."""
        code, shown_lines = _read_source(root, candidate.file, line=candidate.line)
        if not code.strip():
            raise VerifyError("candidate source location is unavailable for verification")
        prompt = _SKEPTIC_PROMPT_TEMPLATE.format(
            finding=_finding_block(candidate),
            file=one_line_source(candidate.file),
            code=fenced_source(code),
        )

        def decide(obj: dict[str, object]) -> Verdict:
            reason = obj["reason"].strip()
            control = _control_ref(obj["control_file"])
            control_line = obj["control_line"]
            if not reason:
                raise VerifyError("verification reply requires a nonempty reason")
            if obj["real"]:
                if control or control_line != 0:
                    raise VerifyError("a retained verification must not cite a deletion control")
                return Verdict(real=True, reason=reason)
            if not control:
                raise VerifyError("verification refutation requires a control_file")
            if control_line < 1:
                raise VerifyError("verification refutation requires a positive control_line")
            if not _same_source_file(root, control, candidate.file):
                raise VerifyError("verification refutation cites a control outside the shown candidate file")
            if control_line not in shown_lines:
                raise VerifyError("verification refutation cites a control line outside the shown source")
            return Verdict(real=False, reason=reason, control_file=candidate.file, control_line=control_line)

        return self._complete(
            prompt,
            role="skeptic",
            trigger="verification",
            candidate_id=candidate.candidate_id,
            decide=decide,
        )


class RefutationChecker(ABC):
    """Independent checker for a proposed refutation."""

    def checkpoint_fingerprint(self) -> VerificationActorFingerprint:
        """Identify response affecting confirmer configuration for resume."""
        return VerificationActorFingerprint(actor=f"{type(self).__module__}.{type(self).__qualname__}")

    @abstractmethod
    def holds(self, candidate: VerificationFinding, refutation: Verdict, root: str) -> RefutationCheck:
        """Uphold a refutation only when its controlling fact neutralizes the real path."""


@dataclass(frozen=True, kw_only=True)
class RefutationCheck:
    """One independent confirmer decision with its audit reason."""

    holds: bool
    reason: str


_CHECK_SYSTEM = (
    "You audit a proposed refutation, not the finding. A reviewer claims a security finding is safe because of "
    "one controlling fact. Assume the finding is real and test whether that fact neutralizes it: the fact may be "
    "true yet guard a different path, precondition, or function than the one the finding exploits. The "
    "refutation holds only when the controlling fact clearly and completely makes the finding unexploitable on "
    "its real path. With any doubt or gap, the refutation does not hold and the finding stays. "
    + UNTRUSTED_SOURCE_RULE
    + "\n\n# Output Fields\n\n"
    "The provider enforces the response schema. Field meanings:\n"
    "- `holds`: true only when the controlling fact completely neutralizes the finding on its real path.\n"
    "- `reason`: why the controlling fact does or does not neutralize the finding."
)
_CHECK_PROMPT_TEMPLATE = (
    "{finding}\n\n"
    "Refutation's controlling fact: {control_file}:{control_line}\n"
    "Reason it is called safe:\n{refutation_reason}\n\n"
    "Code at {file}:\n{code}"
)
_REFUTATION_RESPONSE_SCHEMA = ResponseSchema(
    name="refutation_verdict",
    schema=closed_object(
        {
            "holds": {"type": "boolean"},
            "reason": {"type": "string"},
        }
    ),
)


class ModelRefutationChecker(_ModelSeat, RefutationChecker):
    """Require an independent grounded call before accepting a refutation."""

    _system = _CHECK_SYSTEM
    _prompt_template = _CHECK_PROMPT_TEMPLATE
    _response_schema = _REFUTATION_RESPONSE_SCHEMA

    _default_max_tokens = _SETTINGS.confirmer_max_output_tokens

    def holds(self, candidate: VerificationFinding, refutation: Verdict, root: str) -> RefutationCheck:
        """Report whether an independent read upholds the refutation."""
        candidate_code = _read_source(root, candidate.file, line=candidate.line)[0]
        control_code = _read_source(root, candidate.file, line=refutation.control_line)[0]
        if not candidate_code.strip() or not control_code.strip():
            return RefutationCheck(holds=False, reason="the candidate or controlling source could not be read")
        code = "\n\n".join(dict.fromkeys((candidate_code, control_code)))
        prompt = _CHECK_PROMPT_TEMPLATE.format(
            finding=_finding_block(candidate),
            file=one_line_source(candidate.file),
            control_file=one_line_source(refutation.control_file),
            control_line=refutation.control_line,
            refutation_reason=refutation.reason,
            code=fenced_source(code),
        )

        def decide(obj: dict[str, object]) -> RefutationCheck:
            if not obj["reason"].strip():
                raise VerifyError("a refutation check requires a nonempty reason")
            return RefutationCheck(holds=obj["holds"], reason=obj["reason"].strip())

        return self._complete(
            prompt,
            role="confirmer",
            trigger="refutation_confirmation",
            candidate_id=candidate.candidate_id,
            decide=decide,
        )


Confirmer = tuple[str, RefutationChecker]


@dataclass(frozen=True, kw_only=True)
class _CandidateVerification[T]:
    candidate: T
    real: bool
    reason: str = ""
    errors: tuple[str, ...] = ()
    incomplete: bool = False
    votes: tuple[VerificationVote, ...] = ()
    required_confirmer_seat_ids: tuple[str, ...] = ()


def _applicable(confirmers: list[Confirmer], found_by: tuple[str, ...]) -> list[Confirmer]:
    """Exclude confirmers whose model already surfaced the finding."""
    seen = set(found_by)
    return [(label, checker) for label, checker in confirmers if label not in seen]


def _verify_candidate[T: VerificationFinding](
    candidate: T,
    verifier: Verifier,
    root: str,
    *,
    confirmers: list[Confirmer],
) -> _CandidateVerification[T]:
    applicable = _applicable(confirmers, candidate.found_by)
    required_confirmer_seat_ids = tuple(checker.checkpoint_fingerprint().seat_id for _label, checker in applicable)
    if not applicable:
        reason = "no independent confirmer can authorize deletion"
        return _CandidateVerification(candidate=candidate, real=True, reason=reason)
    verifier_identity = verifier.checkpoint_fingerprint()
    recorded_votes: list[VerificationVote] = []

    def incomplete(error: str) -> _CandidateVerification[T]:
        return _CandidateVerification(
            candidate=candidate,
            real=True,
            reason=error,
            errors=(error,),
            incomplete=True,
            votes=tuple(recorded_votes),
            required_confirmer_seat_ids=required_confirmer_seat_ids,
        )

    try:
        refutation = verifier.verify(candidate, root)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        recorded_votes.append(
            VerificationVote(
                role="skeptic",
                actor_id=verifier_identity.actor_id,
                seat_id=verifier_identity.seat_id,
                verdict="error",
                reason=error,
            )
        )
        return incomplete(error)
    recorded_votes.append(
        VerificationVote(
            role="skeptic",
            actor_id=verifier_identity.actor_id,
            seat_id=verifier_identity.seat_id,
            verdict="real" if refutation.real else "refuted",
            reason=refutation.reason,
            control_file=refutation.control_file,
            control_line=refutation.control_line,
        )
    )
    if refutation.real:
        return _CandidateVerification(
            candidate=candidate,
            real=True,
            reason=refutation.reason,
            votes=tuple(recorded_votes),
            required_confirmer_seat_ids=required_confirmer_seat_ids,
        )
    reason = f"{refutation.control_file}:{refutation.control_line}: {refutation.reason}"
    for _label, checker in applicable:
        checker_identity = checker.checkpoint_fingerprint()
        try:
            check = checker.holds(candidate, refutation, root)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            recorded_votes.append(
                VerificationVote(
                    role="confirmer",
                    actor_id=checker_identity.actor_id,
                    seat_id=checker_identity.seat_id,
                    verdict="error",
                    reason=error,
                    control_file=refutation.control_file,
                    control_line=refutation.control_line,
                )
            )
            return incomplete(error)
        recorded_votes.append(
            VerificationVote(
                role="confirmer",
                actor_id=checker_identity.actor_id,
                seat_id=checker_identity.seat_id,
                verdict="upheld" if check.holds else "rejected",
                reason=check.reason,
                control_file=refutation.control_file,
                control_line=refutation.control_line,
            )
        )
        if not check.holds:
            retained_reason = f"refutation rejected: {check.reason}"
            return _CandidateVerification(
                candidate=candidate,
                real=True,
                reason=retained_reason,
                votes=tuple(recorded_votes),
                required_confirmer_seat_ids=required_confirmer_seat_ids,
            )
    return _CandidateVerification(
        candidate=candidate,
        real=False,
        reason=reason,
        votes=tuple(recorded_votes),
        required_confirmer_seat_ids=required_confirmer_seat_ids,
    )


def _policy_sha256(verifier: Verifier, confirmers: list[Confirmer]) -> str:
    return canonical_sha256(
        {
            "verifier": verifier.checkpoint_fingerprint().to_data(),
            "confirmers": [
                {"label": label, "checker": checker.checkpoint_fingerprint().to_data()} for label, checker in confirmers
            ],
        }
    )


def _checkpoint_key(candidate: VerificationFinding, policy_sha256: str) -> str:
    """Identify exactly what the skeptic and confirmers see, and the route the finding's provenance selects."""
    return canonical_sha256(
        {
            "finding": _finding_block(candidate),
            "found_by": list(candidate.found_by),
            "policy_sha256": policy_sha256,
        }
    )


def verify_findings[T: VerificationFinding](
    candidates: list[T],
    verifier: Verifier,
    root: str,
    *,
    confirmers: list[Confirmer] | None = None,
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
    on_verify: Callable[[int, int, float], None] | None = None,
    checkpoint: CheckpointStore | None = None,
) -> VerifyResult[T]:
    """Drop a candidate only when every independent completed check supports refutation.

    With a checkpoint, each completed decision is saved as soon as it is made and reused for
    the same verification input, so failed checks are retried and never frozen.
    """
    confirmers = list(confirmers or [])
    verifier_seat = verifier.checkpoint_fingerprint().seat_id
    confirmer_seats = [checker.checkpoint_fingerprint().seat_id for _label, checker in confirmers]
    if len(set(confirmer_seats)) != len(confirmer_seats):
        raise ValueError("verification confirmers must use distinct model seats")
    if verifier_seat in confirmer_seats:
        raise ValueError("the skeptic and confirmers must use distinct model seats")
    policy_sha256 = _policy_sha256(verifier, confirmers)

    def restore(candidate: T) -> _CandidateVerification[T] | None:
        if checkpoint is None:
            return None
        decision = checkpoint.restore(
            _checkpoint_key(candidate, policy_sha256),
            lambda data: completed_decision_from_dict(
                data,
                candidate_id=candidate.candidate_id,
                skeptic=verifier.checkpoint_fingerprint(),
                confirmers=tuple(
                    checker.checkpoint_fingerprint() for _label, checker in _applicable(confirmers, candidate.found_by)
                ),
            ),
        )
        if decision is None:
            return None
        return _CandidateVerification(
            candidate=candidate,
            real=decision.outcome == "retained",
            reason=decision.reason,
            votes=decision.votes,
            required_confirmer_seat_ids=decision.required_confirmer_seat_ids,
        )

    restored = [restore(candidate) for candidate in candidates]
    open_candidates = [candidate for candidate, prior in zip(candidates, restored, strict=True) if prior is None]
    lock = threading.Lock()
    done = 0

    def verify_one(candidate: T) -> _CandidateVerification[T]:
        nonlocal done
        started = perf_counter()
        result = _verify_candidate(candidate, verifier, root, confirmers=confirmers)
        if checkpoint is not None and result.votes and not result.incomplete:
            decision = VerificationDecision(
                candidate_id=candidate.candidate_id,
                outcome="retained" if result.real else "refuted",
                reason=result.reason,
                required_confirmer_seat_ids=result.required_confirmer_seat_ids,
                votes=result.votes,
            ).to_dict()
            del decision["candidate_id"]
            checkpoint.save(_checkpoint_key(candidate, policy_sha256), decision)
        if on_verify is not None:
            with lock:
                done += 1
                on_verify(done, len(open_candidates), round(perf_counter() - started, 1))
        return result

    if concurrency > 1 and len(open_candidates) > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            verified_now = iter(list(pool.map(verify_one, open_candidates)))
    else:
        verified_now = iter([verify_one(candidate) for candidate in open_candidates])
    results = [prior if prior is not None else next(verified_now) for prior in restored]

    retained = [result.candidate for result in results if result.real]
    verified = [result.candidate for result in results if result.real and not result.incomplete and result.votes]
    refuted = [(result.candidate, result.reason) for result in results if not result.real]
    error_details = [detail for result in results for detail in result.errors]
    incomplete = [result.candidate for result in results if result.real and result.incomplete]
    records = [
        VerificationRecord(
            candidate=result.candidate,
            outcome="incomplete" if result.incomplete else "retained" if result.real else "refuted",
            votes=result.votes,
            reason=result.reason,
            required_confirmer_seat_ids=result.required_confirmer_seat_ids,
        )
        for result in results
    ]
    return VerifyResult(
        retained=retained,
        verified=verified,
        refuted=refuted,
        errors=len(error_details),
        error_details=error_details,
        incomplete=incomplete,
        records=records,
        candidate_ids=tuple(candidate.candidate_id for candidate in candidates),
    )
