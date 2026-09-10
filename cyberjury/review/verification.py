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

from cyberjury.detection import Detection, load_detection
from cyberjury.json_parse import parse_json_object
from cyberjury.numbering import numbered_source
from cyberjury.profiles.base import ContentPaths
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.base import Message, Provider, ProviderFingerprint, ResponseSchema
from cyberjury.providers.metering import model_call_context, record_model_parse
from cyberjury.review.knowledge import ReviewBrief, load_review_brief
from cyberjury.review.paths import resolve_source_path, safe_repository_path
from cyberjury.review.schemas import closed_object, validate_response_object
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace, emit_trace
from cyberjury.sources.snapshot import SourceSnapshot

_SETTINGS = DEFAULT_REVIEW_SETTINGS.verification
VERIFICATION_SCHEMA = "cyberjury.verification/v1"


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _content_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def verification_candidate_id(candidate: object) -> str:
    """Return the canonical candidate identity used by verification artifacts."""
    for field_name in ("finding_id", "candidate_id"):
        value = getattr(candidate, field_name, "")
        if isinstance(value, str) and value:
            return value
    raise ValueError("verification candidate has no stable identity")


class VerificationFinding(Protocol):
    """The evidence fields required by the shared verification route."""

    title: str
    category: str
    decision_rule_id: str
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
    decision_rule_id: str = ""
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
    control_file: str = ""
    control_line: int | None = None


class VerifyError(RuntimeError):
    """A verifier produced no usable verdict for a completed review step."""


@dataclass(frozen=True, kw_only=True)
class VerificationActorFingerprint:
    """Stable public identity for one verification model role."""

    actor: str
    settings: tuple[tuple[str, str], ...] = ()
    provider: ProviderFingerprint | None = None
    configured_seat_id: str = ""

    def to_data(self) -> dict[str, object]:
        """Return deterministic checkpoint data for this role."""
        value: dict[str, object] = {
            "actor": self.actor,
            "settings": dict(self.settings),
        }
        if self.provider is not None:
            value["provider"] = self.provider.to_data()
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
        """Identify the underlying model seat used for independence checks."""
        if self.configured_seat_id:
            return self.configured_seat_id
        settings = dict(self.settings)
        value = {
            "provider": self.provider.to_data() if self.provider is not None else None,
            "model": settings.get("model", ""),
            "custom_actor": self.actor if self.provider is None else "",
        }
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return f"seat-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:20]}"


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
    unlocatable: list[T] = field(default_factory=list)
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

    def __post_init__(self) -> None:
        """Reject votes that cannot explain one actor decision."""
        allowed = {"real", "refuted", "error"} if self.role == "skeptic" else {"upheld", "rejected", "error"}
        if self.role not in {"skeptic", "confirmer"} or self.verdict not in allowed:
            raise ValueError("verification vote role and verdict are inconsistent")
        if not self.actor_id or not self.seat_id or not self.reason:
            raise ValueError("verification vote identities and reason must be nonempty")
        if not isinstance(self.control_file, str):
            raise ValueError("verification vote control file must be a string")
        if self.control_line is not None and (
            isinstance(self.control_line, bool) or not isinstance(self.control_line, int) or self.control_line < 1
        ):
            raise ValueError("verification vote control line must be positive or null")
        if self.role == "skeptic" and self.verdict == "real" and (self.control_file or self.control_line is not None):
            raise ValueError("a real skeptic vote cannot cite a deletion control")
        if self.verdict in {"refuted", "upheld", "rejected"} and (not self.control_file or self.control_line is None):
            raise ValueError("a completed refutation vote requires its controlling source")


@dataclass(frozen=True, kw_only=True)
class VerificationRecord[T]:
    """Complete vote history for one candidate verification decision."""

    candidate: T
    outcome: Literal["retained", "refuted", "incomplete"]
    votes: tuple[VerificationVote, ...]
    reason: str = ""
    required_confirmer_seat_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require one internally consistent candidate decision."""
        if self.outcome not in {"retained", "refuted", "incomplete"}:
            raise ValueError("verification record outcome is invalid")
        if not isinstance(self.votes, tuple) or not all(isinstance(vote, VerificationVote) for vote in self.votes):
            raise ValueError("verification record votes must be a vote tuple")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("verification record reason must be nonempty")
        required = self.required_confirmer_seat_ids
        if (
            not isinstance(required, tuple)
            or any(not isinstance(seat_id, str) or not seat_id for seat_id in required)
            or len(required) != len(set(required))
        ):
            raise ValueError("verification required confirmer seats must be unique nonempty strings")
        errors = [vote for vote in self.votes if vote.verdict == "error"]
        skeptic_votes = [vote for vote in self.votes if vote.role == "skeptic"]
        confirmer_votes = [vote for vote in self.votes if vote.role == "confirmer"]
        if self.votes and not skeptic_votes:
            raise ValueError("verification decisions must begin with a skeptic vote")
        first_confirmer = next((index for index, vote in enumerate(self.votes) if vote.role == "confirmer"), None)
        if first_confirmer is not None and any(vote.role == "skeptic" for vote in self.votes[first_confirmer:]):
            raise ValueError("verification skeptic votes cannot follow confirmer votes")
        if len({vote.seat_id for vote in confirmer_votes}) != len(confirmer_votes):
            raise ValueError("verification confirmer seats cannot vote twice")
        if any(vote.seat_id not in required for vote in confirmer_votes):
            raise ValueError("verification record contains an unrequired confirmer vote")
        if self.outcome == "incomplete":
            if not errors:
                raise ValueError("incomplete verification requires an error vote")
            return
        if errors:
            raise ValueError("completed verification cannot contain error votes")
        if self.outcome == "refuted":
            if not required or not skeptic_votes or any(vote.verdict != "refuted" for vote in skeptic_votes):
                raise ValueError("refuted verification requires unanimous skeptic refutation")
            upheld = {vote.seat_id for vote in confirmer_votes if vote.verdict == "upheld"}
            if upheld != set(required) or any(vote.verdict != "upheld" for vote in confirmer_votes):
                raise ValueError("refuted verification requires every independent confirmer")
            return
        if not self.votes:
            if required:
                raise ValueError("retained verification with required confirmers needs a skeptic vote")
            return
        if (
            skeptic_votes
            and all(vote.verdict == "refuted" for vote in skeptic_votes)
            and not any(vote.verdict == "rejected" for vote in confirmer_votes)
        ):
            raise ValueError("retained refutation requires an independent rejection")


@dataclass(frozen=True, kw_only=True)
class VerificationDecision:
    """One candidate outcome in the attempt verification artifact."""

    candidate_id: str
    outcome: Literal["retained", "refuted", "incomplete", "unlocatable"]
    reason: str
    required_confirmer_seat_ids: tuple[str, ...] = ()
    votes: tuple[VerificationVote, ...] = ()

    def __post_init__(self) -> None:
        """Validate an observable decision through the shared record contract."""
        if not isinstance(self.candidate_id, str) or not self.candidate_id:
            raise ValueError("verification decision candidate id must be nonempty")
        if self.outcome == "unlocatable":
            if not self.reason or self.required_confirmer_seat_ids or self.votes:
                raise ValueError("unlocatable verification must contain only its reason")
            return
        VerificationRecord(
            candidate=None,
            outcome=self.outcome,
            votes=self.votes,
            reason=self.reason,
            required_confirmer_seat_ids=self.required_confirmer_seat_ids,
        )

    def to_dict(self) -> dict[str, object]:
        """Return one strict candidate decision."""
        return {
            "candidate_id": self.candidate_id,
            "outcome": self.outcome,
            "reason": self.reason,
            "required_confirmer_seat_ids": list(self.required_confirmer_seat_ids),
            "votes": [_vote_to_data(vote) for vote in self.votes],
        }

    @classmethod
    def from_dict(cls, value: object) -> VerificationDecision:
        """Parse one strict candidate decision."""
        fields = {"candidate_id", "outcome", "reason", "required_confirmer_seat_ids", "votes"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("verification decision has an invalid shape")
        required = value["required_confirmer_seat_ids"]
        votes = value["votes"]
        if not isinstance(required, list) or not isinstance(votes, list):
            raise ValueError("verification decision seats and votes must be lists")
        return cls(
            candidate_id=value["candidate_id"],
            outcome=value["outcome"],
            reason=value["reason"],
            required_confirmer_seat_ids=tuple(required),
            votes=tuple(_vote_from_data(vote) for vote in votes),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationReceipt:
    """One attempt's complete candidate deletion decisions."""

    request_sha256: str
    enabled: bool
    candidate_ids: tuple[str, ...]
    decisions: tuple[VerificationDecision, ...]
    content_sha256: str
    schema: str = VERIFICATION_SCHEMA

    def __post_init__(self) -> None:
        """Reject an artifact that cannot account for its candidate input."""
        if self.schema != VERIFICATION_SCHEMA:
            raise ValueError("verification receipt schema is unsupported")
        if (
            not isinstance(self.request_sha256, str)
            or len(self.request_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.request_sha256)
        ):
            raise ValueError("verification request sha256 must be a SHA-256 digest")
        if not isinstance(self.enabled, bool):
            raise ValueError("verification enabled state must be boolean")
        if (
            not isinstance(self.candidate_ids, tuple)
            or any(not isinstance(candidate_id, str) or not candidate_id for candidate_id in self.candidate_ids)
            or len(self.candidate_ids) != len(set(self.candidate_ids))
        ):
            raise ValueError("verification candidate ids must be unique nonempty strings")
        if not isinstance(self.decisions, tuple) or not all(
            isinstance(decision, VerificationDecision) for decision in self.decisions
        ):
            raise ValueError("verification decisions must be a decision tuple")
        if self.enabled:
            if tuple(decision.candidate_id for decision in self.decisions) != self.candidate_ids:
                raise ValueError("enabled verification must decide every candidate in input order")
        elif self.decisions:
            raise ValueError("disabled verification cannot contain decisions")
        if self.content_sha256 != _content_sha256(self.semantic_dict()):
            raise ValueError("verification content hash does not match its receipt")

    @classmethod
    def create(
        cls,
        *,
        request_sha256: str,
        enabled: bool,
        candidate_ids: tuple[str, ...],
        records: tuple[VerificationRecord, ...] = (),
        unlocatable_ids: tuple[str, ...] = (),
    ) -> VerificationReceipt:
        """Create one complete receipt from shared verification results."""
        if not enabled:
            decisions: tuple[VerificationDecision, ...] = ()
        else:
            record_ids = tuple(verification_candidate_id(record.candidate) for record in records)
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
            for candidate_id in unlocatable_ids:
                if candidate_id in by_id:
                    raise ValueError("unlocatable candidate also has a verification decision")
                by_id[candidate_id] = VerificationDecision(
                    candidate_id=candidate_id,
                    outcome="unlocatable",
                    reason="candidate source location does not resolve inside the repository",
                )
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
            content_sha256=_content_sha256(semantic),
        )

    def semantic_dict(self) -> dict[str, object]:
        """Return the behavior fields covered by the content hash."""
        return {
            "request_sha256": self.request_sha256,
            "enabled": self.enabled,
            "candidate_ids": self.candidate_ids,
            "decisions": tuple(decision.to_dict() for decision in self.decisions),
        }

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

    @classmethod
    def from_dict(cls, value: object) -> VerificationReceipt:
        """Parse and validate one persisted receipt."""
        fields = {"schema", "request_sha256", "enabled", "candidate_ids", "decisions", "content_sha256"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("verification receipt has an invalid shape")
        candidate_ids = value["candidate_ids"]
        decisions = value["decisions"]
        if not isinstance(candidate_ids, list) or not isinstance(decisions, list):
            raise ValueError("verification receipt candidates and decisions must be lists")
        return cls(
            schema=value["schema"],
            request_sha256=value["request_sha256"],
            enabled=value["enabled"],
            candidate_ids=tuple(candidate_ids),
            decisions=tuple(VerificationDecision.from_dict(decision) for decision in decisions),
            content_sha256=value["content_sha256"],
        )


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


def _vote_from_data(value: object) -> VerificationVote:
    fields = {"role", "actor_id", "seat_id", "verdict", "reason", "control_file", "control_line"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("verification vote has an invalid shape")
    return VerificationVote(**value)


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
    "guarantee. A control in another file you were not shown cannot authorize deletion. In that "
    "case return real true, explain the missing control in reason, leave control_file empty, and "
    "set control_line to 0. A real finding also uses an empty control_file and control_line 0. A "
    "refutation must cite the exact shown repository path and an existing positive line. Respond "
    "with a single JSON object and nothing else."
)

_JSON_SHAPE = (
    '{"real": true, "reason": "the controlling fact at file:line", '
    '"control_file": "the file holding that fact, empty if real", '
    '"control_line": 0}'
)
_SKEPTIC_CACHE_TEMPLATE = (
    "Try to REFUTE this proposed finding. Read the code and decide whether a "
    "controlling fact makes it genuinely safe, judging against PRODUCTION "
    "semantics, not a shallow read.\n\n"
    "Traps to check against, in both directions, refuting a real finding as "
    "wrongly as confirming a safe one:\n{traps}\n\n{rule_block}"
)
_SKEPTIC_PROMPT_TEMPLATE = (
    "{cache_head}Proposed finding:\n- {title}\n- category: {category}\n"
    "- endpoint: {endpoint}\n- location: {file}:{line}\n- claimed evidence: {evidence}\n\n"
    "Code at {file}:\n```\n{code}\n```\n\n"
    "Respond with a single JSON object exactly like:\n{shape}"
)
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


def _parse_model_object(text: str, schema: ResponseSchema, label: str) -> tuple[dict[str, object], str]:
    """Apply the same strict local schema check used by review roles."""
    parsed = parse_json_object(text)
    obj = parsed.value if parsed is not None and parsed.complete else None
    source = parsed.source if parsed is not None else "none"
    if obj is None:
        record_model_parse(source, status="failed", failure_reason=f"unparseable {label}")
        raise VerifyError(f"unparseable {label}")
    try:
        validated = validate_response_object(obj, schema)
    except ValueError as exc:
        reason = f"{label} violates {schema.name}: {exc}"
        record_model_parse(source, status="failed", failure_reason=reason)
        raise VerifyError(reason) from exc
    return validated, source


def _control_ref(ref: str) -> str:
    """Return the cited control file without a trailing line number."""
    return ref.strip().strip("`").split(":", 1)[0].strip()


def _same_source_file(root: str, first: str, second: str, detection: Detection | None) -> bool:
    """Compare two source references only through their resolved repository paths."""

    def resolve(reference: str) -> Path | None:
        normalized = reference.strip().replace("\\", "/").removeprefix("./")
        if "/" in normalized:
            exact = safe_repository_path(root, normalized)
            return exact if exact is not None and exact.is_file() else None
        return resolve_source_path(root, normalized, detection=detection)

    first_path = resolve(first)
    second_path = resolve(second)
    return first_path is not None and second_path is not None and first_path == second_path


def _source_window(text: str, line: int | None, max_chars: int) -> tuple[str, int]:
    """Return a line aligned window centered on the candidate location."""
    lines = text.splitlines(keepends=True)
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


def _read_file(root: str, rel: str, detection: Detection | None = None, *, line: int | None = None) -> str:
    path = resolve_source_path(root, rel, detection=detection)
    if path is None:
        return ""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    window, first_line = _source_window(text, line, _SETTINGS.max_source_chars_per_finding)
    return numbered_source(rel, window, first_line) if window else ""


def _decision_rules_sha256(brief: ReviewBrief) -> str:
    """Bind verifier checkpoints to the complete decision contracts."""
    rendered = brief.render_rule_details(brief.rule_ids)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _candidate_rule_details(brief: ReviewBrief, candidate: VerificationFinding) -> str:
    """Return the candidate's exact rule or fail on an invalid knowledge reference."""
    if not candidate.category:
        return ""
    try:
        return brief.details_for_binding(candidate.decision_rule_id, candidate.category)
    except ValueError as exc:
        raise VerifyError(f"candidate decision rule is invalid: {exc}") from exc


class ModelVerifier(Verifier):
    """Default skeptic: one grounded model call that tries to refute the candidate."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = DEFAULT_REVIEW_SETTINGS.verification.skeptic_max_output_tokens,
        content: ContentPaths | None = None,
        seat_id: str = "",
    ) -> None:
        """Bind the skeptic model and false positive traps for one candidate check."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._seat_id = seat_id
        paths = content or default_profile().paths
        self._detection = load_detection(paths.detection_file)
        self._detection_sha256 = _file_sha256(paths.detection_file)
        traps_file = paths.false_positive_traps_file
        self._traps = traps_file.read_text(encoding="utf-8")
        self._review_brief = load_review_brief(
            kernel_id=f"{paths.root.name}-security",
            kernel_file=paths.security_kernel_file,
            catalog_file=paths.security_catalog_file,
        )

    def checkpoint_fingerprint(self) -> VerificationActorFingerprint:
        """Identify the skeptic model, prompt data, and provider configuration."""
        return VerificationActorFingerprint(
            actor=f"{type(self).__module__}.{type(self).__qualname__}",
            settings=(
                ("detection_sha256", self._detection_sha256),
                ("knowledge_sha256", hashlib.sha256(self._traps.encode("utf-8")).hexdigest()),
                ("decision_rules_sha256", _decision_rules_sha256(self._review_brief)),
                ("max_tokens", str(self._max_tokens)),
                ("model", self._model),
                (
                    "prompt_contract_sha256",
                    _content_sha256(
                        {
                            "system": _SYSTEM,
                            "cache_template": _SKEPTIC_CACHE_TEMPLATE,
                            "prompt_template": _SKEPTIC_PROMPT_TEMPLATE,
                            "shape": _JSON_SHAPE,
                            "response_schema": _VERDICT_RESPONSE_SCHEMA.schema,
                        }
                    ),
                ),
            ),
            provider=self._provider.checkpoint_fingerprint(),
            configured_seat_id=self._seat_id,
        )

    def close(self) -> None:
        """Release the bound provider when it owns a persistent transport."""
        close = getattr(self._provider, "close", None)
        if callable(close):
            close()

    def verify(self, candidate: VerificationFinding, root: str) -> Verdict:
        """Try to refute one candidate against the source tree."""
        code = _read_file(root, candidate.file, self._detection, line=candidate.line)
        if not code.strip():
            raise VerifyError("candidate source location is unavailable for verification")
        rule_details = _candidate_rule_details(self._review_brief, candidate)
        rule_block = f"Decision rule for this candidate:\n{rule_details}\n\n" if rule_details else ""
        cache_head = _SKEPTIC_CACHE_TEMPLATE.format(traps=self._traps, rule_block=rule_block)
        prompt = _SKEPTIC_PROMPT_TEMPLATE.format(
            cache_head=cache_head,
            title=candidate.title,
            category=candidate.category,
            endpoint=candidate.endpoint,
            file=candidate.file,
            line=candidate.line,
            evidence=candidate.evidence,
            code=code,
            shape=_JSON_SHAPE,
        )
        with model_call_context(
            role="skeptic",
            trigger="verification",
            candidate_id=verification_candidate_id(candidate),
            review_brief_sha256=self._review_brief.content_sha256,
            decision_rule_ids=(candidate.decision_rule_id,) if candidate.decision_rule_id else (),
        ):
            result = self._provider.complete(
                system=_SYSTEM,
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                cache_prefix=cache_head,
                response_schema=_VERDICT_RESPONSE_SCHEMA,
            )
            obj, parse_source = _parse_model_object(result.text, _VERDICT_RESPONSE_SCHEMA, "verification reply")
            try:
                real = obj["real"]
                reason = obj["reason"]
                control = _control_ref(obj["control_file"])
                control_line = obj["control_line"]
                if not reason.strip():
                    raise VerifyError("verification reply requires a nonempty reason")
                if real:
                    if control or control_line != 0:
                        raise VerifyError("a retained verification must not cite a deletion control")
                    verdict = Verdict(real=True, reason=reason.strip())
                else:
                    if not control:
                        raise VerifyError("verification refutation requires a control_file")
                    if control_line < 1:
                        raise VerifyError("verification refutation requires a positive control_line")
                    if not _same_source_file(root, control, candidate.file, self._detection):
                        raise VerifyError("verification refutation cites a control outside the shown candidate file")
                    if not _read_file(root, candidate.file, self._detection, line=control_line):
                        raise VerifyError("verification refutation cites a control line that does not exist")
                    verdict = Verdict(
                        real=False,
                        reason=reason.strip(),
                        control_file=candidate.file,
                        control_line=control_line,
                    )
            except VerifyError as exc:
                record_model_parse(parse_source, status="failed", failure_reason=str(exc))
                raise
            record_model_parse(parse_source)
        return verdict


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
_CHECK_PROMPT_TEMPLATE = (
    "Audit this refutation. Does the controlling fact genuinely make the finding "
    "unexploitable on its real path, or does it guard a different path or precondition?\n\n"
    "Finding:\n- {title}\n- category: {category}\n"
    "- location: {file}:{line}\n- claimed evidence: {evidence}\n\n"
    "Refutation's controlling fact: {control_file}:{control_line}\n"
    "Reason it is called safe:\n{refutation_reason}\n\n"
    "{rule_block}Code at {file}:\n```\n{code}\n```\n\n"
    "Respond with a single JSON object exactly like:\n{shape}"
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


class ModelRefutationChecker(RefutationChecker):
    """Require an independent grounded call before accepting a refutation."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = DEFAULT_REVIEW_SETTINGS.verification.confirmer_max_output_tokens,
        content: ContentPaths | None = None,
        seat_id: str = "",
    ) -> None:
        """Bind the confirmer model that tests whether a refutation holds."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._seat_id = seat_id
        paths = content or default_profile().paths
        self._detection = load_detection(paths.detection_file)
        self._detection_sha256 = _file_sha256(paths.detection_file)
        self._review_brief = load_review_brief(
            kernel_id=f"{paths.root.name}-security",
            kernel_file=paths.security_kernel_file,
            catalog_file=paths.security_catalog_file,
        )

    def checkpoint_fingerprint(self) -> VerificationActorFingerprint:
        """Identify the confirmer model and provider configuration."""
        return VerificationActorFingerprint(
            actor=f"{type(self).__module__}.{type(self).__qualname__}",
            settings=(
                ("detection_sha256", self._detection_sha256),
                ("decision_rules_sha256", _decision_rules_sha256(self._review_brief)),
                ("max_tokens", str(self._max_tokens)),
                ("model", self._model),
                (
                    "prompt_contract_sha256",
                    _content_sha256(
                        {
                            "system": _CHECK_SYSTEM,
                            "prompt_template": _CHECK_PROMPT_TEMPLATE,
                            "shape": _CHECK_SHAPE,
                            "response_schema": _REFUTATION_RESPONSE_SCHEMA.schema,
                        }
                    ),
                ),
            ),
            provider=self._provider.checkpoint_fingerprint(),
            configured_seat_id=self._seat_id,
        )

    def close(self) -> None:
        """Release the bound provider when it owns a persistent transport."""
        close = getattr(self._provider, "close", None)
        if callable(close):
            close()

    def holds(self, candidate: VerificationFinding, refutation: Verdict, root: str) -> RefutationCheck:
        """Report whether an independent read upholds the refutation."""
        if not _same_source_file(root, refutation.control_file, candidate.file, self._detection):
            return RefutationCheck(holds=False, reason="the controlling fact is outside the candidate file")
        candidate_code = _read_file(root, candidate.file, self._detection, line=candidate.line)
        control_code = _read_file(root, candidate.file, self._detection, line=refutation.control_line)
        if not candidate_code.strip() or not control_code.strip():
            return RefutationCheck(holds=False, reason="the candidate or controlling source could not be read")
        code = "\n\n".join(dict.fromkeys((candidate_code, control_code)))
        rule_details = _candidate_rule_details(self._review_brief, candidate)
        rule_block = f"Decision rule for this candidate:\n{rule_details}\n\n" if rule_details else ""
        prompt = _CHECK_PROMPT_TEMPLATE.format(
            title=candidate.title,
            category=candidate.category,
            file=candidate.file,
            line=candidate.line,
            evidence=candidate.evidence,
            control_file=refutation.control_file,
            control_line=refutation.control_line,
            refutation_reason=refutation.reason,
            rule_block=rule_block,
            code=code,
            shape=_CHECK_SHAPE,
        )
        with model_call_context(
            role="confirmer",
            trigger="refutation_confirmation",
            candidate_id=verification_candidate_id(candidate),
            review_brief_sha256=self._review_brief.content_sha256,
            decision_rule_ids=(candidate.decision_rule_id,) if candidate.decision_rule_id else (),
        ):
            result = self._provider.complete(
                system=_CHECK_SYSTEM,
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                response_schema=_REFUTATION_RESPONSE_SCHEMA,
            )
            obj, parse_source = _parse_model_object(
                result.text,
                _REFUTATION_RESPONSE_SCHEMA,
                "refutation check reply",
            )
            holds = obj["holds"]
            reason = obj["reason"]
            if not reason.strip():
                error = "a refutation check requires a nonempty reason"
                record_model_parse(parse_source, status="failed", failure_reason=error)
                raise VerifyError(error)
            record_model_parse(parse_source)
        return RefutationCheck(holds=holds, reason=reason.strip())


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
    return [(label, checker) for label, checker in confirmers if not label or label not in seen]


def _validate_refutation_source(candidate: VerificationFinding, verdict: Verdict, root: str) -> None:
    """Require a deletion control to identify existing source in the candidate file."""
    if (
        not verdict.reason.strip()
        or not verdict.control_file
        or verdict.control_line is None
        or isinstance(verdict.control_line, bool)
        or not isinstance(verdict.control_line, int)
        or verdict.control_line < 1
    ):
        raise VerifyError("a refutation requires a controlling file, line, and reason")
    if not _same_source_file(root, verdict.control_file, candidate.file, None):
        raise VerifyError("a refutation control must resolve to the candidate file")
    if not _read_file(root, candidate.file, line=verdict.control_line):
        raise VerifyError("a refutation control line does not exist")


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
    source_snapshot: SourceSnapshot | None,
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
    applicable = _applicable(confirmers, candidate.found_by)
    required_confirmer_seat_ids = tuple(checker.checkpoint_fingerprint().seat_id for _label, checker in applicable)
    if not applicable:
        reason = "no independent confirmer can authorize deletion"
        _finish_trace(trace, candidate, verdict="real", reason=reason)
        return _CandidateVerification(candidate=candidate, real=True, reason=reason)
    verifier_identity = verifier.checkpoint_fingerprint()
    refutations: list[Verdict] = []
    recorded_votes: list[VerificationVote] = []
    errors: list[str] = []
    for _ in range(votes):
        try:
            _validate_source_snapshot(source_snapshot, candidate.file)
            verdict = verifier.verify(candidate, root)
            _validate_source_snapshot(source_snapshot, candidate.file)
            if not isinstance(verdict, Verdict):
                raise VerifyError("a verifier must return Verdict with a reason")
            if not verdict.reason.strip():
                raise VerifyError("a verifier decision requires a nonempty reason")
            if not verdict.real:
                _validate_refutation_source(candidate, verdict, root)
                refutations.append(verdict)
            recorded_votes.append(
                VerificationVote(
                    role="skeptic",
                    actor_id=verifier_identity.actor_id,
                    seat_id=verifier_identity.seat_id,
                    verdict="real" if verdict.real else "refuted",
                    reason=verdict.reason,
                    control_file=verdict.control_file,
                    control_line=verdict.control_line,
                )
            )
            if verdict.real:
                _finish_trace(trace, candidate, verdict="real", reason=verdict.reason)
                return _CandidateVerification(
                    candidate=candidate,
                    real=True,
                    reason=verdict.reason,
                    votes=tuple(recorded_votes),
                    required_confirmer_seat_ids=required_confirmer_seat_ids,
                )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            errors.append(error)
            recorded_votes.append(
                VerificationVote(
                    role="skeptic",
                    actor_id=verifier_identity.actor_id,
                    seat_id=verifier_identity.seat_id,
                    verdict="error",
                    reason=error,
                )
            )
            break
    if errors or not refutations:
        reason = "; ".join(errors) or "verification produced no complete skeptic decision"
        _finish_trace(trace, candidate, status="incomplete")
        return _CandidateVerification(
            candidate=candidate,
            real=True,
            reason=reason,
            errors=tuple(errors),
            incomplete=True,
            votes=tuple(recorded_votes),
            required_confirmer_seat_ids=required_confirmer_seat_ids,
        )
    refutation = refutations[0]
    reason = f"{refutation.control_file}:{refutation.control_line}: {refutation.reason}"
    for _label, checker in applicable:
        checker_identity = checker.checkpoint_fingerprint()
        try:
            _validate_source_snapshot(source_snapshot, candidate.file)
            check = checker.holds(candidate, refutation, root)
            if not isinstance(check, RefutationCheck):
                raise VerifyError("a confirmer must return RefutationCheck with a reason")
            if not check.reason.strip():
                raise VerifyError("a confirmer decision requires a nonempty reason")
            _validate_source_snapshot(source_snapshot, candidate.file)
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
                _finish_trace(trace, candidate, verdict="real", reason=retained_reason)
                return _CandidateVerification(
                    candidate=candidate,
                    real=True,
                    reason=retained_reason,
                    votes=tuple(recorded_votes),
                    required_confirmer_seat_ids=required_confirmer_seat_ids,
                )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            errors.append(error)
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
            break
    if errors:
        incomplete_reason = "; ".join(errors)
        _finish_trace(trace, candidate, status="incomplete")
        return _CandidateVerification(
            candidate=candidate,
            real=True,
            reason=incomplete_reason,
            errors=tuple(errors),
            incomplete=True,
            votes=tuple(recorded_votes),
            required_confirmer_seat_ids=required_confirmer_seat_ids,
        )
    _finish_trace(trace, candidate, verdict="refuted", reason=reason)
    return _CandidateVerification(
        candidate=candidate,
        real=False,
        reason=reason,
        votes=tuple(recorded_votes),
        required_confirmer_seat_ids=required_confirmer_seat_ids,
    )


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
    source_snapshot: SourceSnapshot | None = None,
) -> VerifyResult[T]:
    """Drop a candidate only when every independent completed check supports refutation."""
    if isinstance(votes, bool) or not isinstance(votes, int) or votes < 1:
        raise ValueError("verification votes must be positive")
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency < 1:
        raise ValueError("verification concurrency must be positive")
    confirmers = confirmers or []
    if any(
        not isinstance(confirmer, tuple)
        or len(confirmer) != 2
        or not isinstance(confirmer[0], str)
        or not confirmer[0]
        or not isinstance(confirmer[1], RefutationChecker)
        for confirmer in confirmers
    ):
        raise ValueError("verification confirmers require a nonempty provenance label and checker")
    labels = [label for label, _checker in confirmers]
    if len(set(labels)) != len(labels):
        raise ValueError("verification confirmer provenance labels must be unique")
    confirmer_objects = [checker for _label, checker in confirmers]
    if len({id(checker) for checker in confirmer_objects}) != len(confirmer_objects):
        raise ValueError("verification confirmers must be distinct checker objects")
    verifier_seat = verifier.checkpoint_fingerprint().seat_id
    confirmer_seats = [checker.checkpoint_fingerprint().seat_id for checker in confirmer_objects]
    if len(set(confirmer_seats)) != len(confirmer_seats):
        raise ValueError("verification confirmers must use distinct model seats")
    if verifier_seat in confirmer_seats:
        raise ValueError("the skeptic and confirmers must use distinct model seats")

    def verify_one(candidate: T) -> _CandidateVerification[T]:
        return _verify_candidate(
            candidate,
            verifier,
            root,
            confirmers=confirmers,
            votes=votes,
            trace=trace,
            source_snapshot=source_snapshot,
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

    retained = [result.candidate for result in results if result.real]
    verified = [result.candidate for result in results if result.real and not result.incomplete]
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
        candidate_ids=tuple(verification_candidate_id(candidate) for candidate in candidates),
    )


def _file_sha256(path: Path) -> str:
    """Hash one public configuration file used by model verification."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_source_snapshot(source_snapshot: SourceSnapshot | None, file: str) -> None:
    """Reject verification work after any reviewed source content changes."""
    if source_snapshot is not None and not source_snapshot.matches_scope_and_files((file,)):
        raise VerifyError("repository source changed after the reviewed evidence revision")
