"""Group reported findings into issues: findings that one code change fixes."""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Literal, Protocol

from cyberjury.canonical import canonical_sha256
from cyberjury.numbering import numbered_source, split_lines
from cyberjury.providers.base import Message, Provider, ProviderAccessError, ResponseSchema
from cyberjury.providers.metering import model_call_context, model_call_scope
from cyberjury.record import Record, RecordError, error_message, utc_timestamp
from cyberjury.review.failures import exception_reason
from cyberjury.review.finding import Finding, report_order
from cyberjury.review.items import ItemStore
from cyberjury.review.paths import normalized_location_path, resolve_source_path
from cyberjury.review.prompts import CLAIM_FIELDS, UNTRUSTED_SOURCE_RULE, fenced_source, finding_claim
from cyberjury.review.recorder import Recorder
from cyberjury.review.replies import parse_role_response
from cyberjury.review.schemas import closed_object
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SETTINGS = DEFAULT_REVIEW_SETTINGS.issues

type LinkKind = Literal["location", "judgment"]


def issue_id(member_ids: Iterable[str]) -> str:
    """Identify one issue by its member candidate set, independent of member order."""
    return f"issue-{canonical_sha256(sorted(member_ids))[:20]}"


@dataclass(frozen=True, kw_only=True)
class Issue:
    """Findings that one code change fixes, in report order, with the links that joined them."""

    members: tuple[Finding, ...]
    linked_by: tuple[LinkKind, ...] = ()

    @property
    def id(self) -> str:
        """Identify the issue by its member set, independent of member order."""
        return issue_id(item.candidate_id for item in self.members)

    @property
    def representative(self) -> Finding:
        """Return the first member in report order: the most severe, then the earliest location."""
        return self.members[0]


def _group_key(finding: Finding) -> tuple[str, int, str]:
    return (normalized_location_path(finding.file), finding.line, finding.category)


def group_issues(findings: Sequence[Finding], links: Iterable[tuple[str, str]]) -> tuple[Issue, ...]:
    """Union findings over equal locations and categories and accepted judgment links, keeping every finding."""
    position = {finding.candidate_id: index for index, finding in enumerate(findings)}
    parent = list(range(len(findings)))
    joined: list[tuple[int, LinkKind]] = []

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(first: int, second: int, kind: LinkKind) -> None:
        first_root, second_root = root(first), root(second)
        if first_root != second_root:
            parent[max(first_root, second_root)] = min(first_root, second_root)
            joined.append((first, kind))

    first_in_group: dict[tuple[str, int, str], int] = {}
    for index, finding in enumerate(findings):
        union(first_in_group.setdefault(_group_key(finding), index), index, "location")
    for first, second in links:
        union(position[first], position[second], "judgment")
    members: dict[int, list[Finding]] = {}
    for index, finding in enumerate(findings):
        members.setdefault(root(index), []).append(finding)
    kinds: dict[int, set[LinkKind]] = {}
    for index, kind in joined:
        kinds.setdefault(root(index), set()).add(kind)
    return tuple(
        Issue(members=tuple(sorted(group, key=report_order)), linked_by=tuple(sorted(kinds.get(index, ()))))
        for index, group in members.items()
    )


def _covers(finding: Finding, other: Finding) -> bool:
    file = normalized_location_path(other.file)
    return any(span.file == file and span.start_line <= other.line <= span.end_line for span in finding.cited_spans)


def _shares_cited_source(first: Finding, second: Finding) -> bool:
    return any(
        left.file == right.file and left.start_line <= right.end_line and right.start_line <= left.end_line
        for left in first.cited_spans
        for right in second.cited_spans
    )


def _traces_same_source(first: Finding, second: Finding) -> bool:
    forward, backward = _covers(first, second), _covers(second, first)
    return (forward and backward) or ((forward or backward) and _shares_cited_source(first, second))


def link_candidates(findings: Sequence[Finding]) -> tuple[tuple[Finding, Finding], ...]:
    """Select one candidate pair per pair of deterministic groups whose findings trace the same source."""
    ordered = sorted(findings, key=lambda finding: finding.candidate_id)
    pairs: dict[tuple[tuple[str, int, str], ...], tuple[Finding, Finding]] = {}
    for index, first in enumerate(ordered):
        for second in ordered[index + 1 :]:
            groups = tuple(sorted((_group_key(first), _group_key(second))))
            if groups[0] == groups[1] or groups in pairs:
                continue
            if _traces_same_source(first, second):
                pairs[groups] = (first, second)
    return tuple(pairs.values())


_SYSTEM = (
    "You compare two security findings that independent reviewers reported for the same code. Decide whether "
    "one code change fixes both findings.\n\n"
    "Answer true when either holds:\n"
    "- One change at one place removes the defect that each finding describes.\n"
    "- One finding's defect is one of the places the other finding already requires changing, so the change "
    "that fixes the broader finding also fixes the narrower one.\n\n"
    "Answer false when the findings describe distinct defects that each need their own change, even when they "
    "share an entrypoint, a file, a sink, or cited code. " + UNTRUSTED_SOURCE_RULE + "\n\n"
    "# Output Fields\n\n"
    "The provider enforces the response schema. Field meanings:\n"
    "- `same_fix`: true only when one code change fixes both findings.\n"
    "- `rationale`: the one change that fixes both findings, or why each finding needs its own change."
)
_PROMPT_TEMPLATE = (
    "{first}\n\n{second}\n\nCode at finding A's location:\n{first_code}\n\nCode at finding B's location:\n{second_code}"
)
_RESPONSE_SCHEMA = ResponseSchema(
    name="issue_link",
    schema=closed_object({"same_fix": {"type": "boolean"}, "rationale": {"type": "string"}}),
)


class IssueLinkError(RuntimeError):
    """An issue link judgment produced no usable decision."""


def _source_window(root: str, finding: Finding) -> str:
    path = resolve_source_path(root, normalized_location_path(finding.file))
    if path is None:
        raise IssueLinkError(f"source of {finding.file} is unavailable for the issue link judgment")
    try:
        lines = split_lines(path.read_text(encoding="utf-8"), keepends=True)
    except (OSError, UnicodeDecodeError) as exc:
        raise IssueLinkError(f"source of {finding.file} is unreadable for the issue link judgment") from exc
    if not 1 <= finding.line <= len(lines):
        raise IssueLinkError(f"{finding.file}:{finding.line} is outside its source")
    span = _SETTINGS.max_source_lines_per_finding
    start = max(1, min(finding.line - span // 2, len(lines) - span + 1))
    window = "".join(lines[start - 1 : start - 1 + span])
    return fenced_source(numbered_source(finding.file, window, start))


def link_prompt(first: Finding, second: Finding, root: str) -> str:
    """Build the stable same-fix question for one candidate pair in candidate id order."""
    return _PROMPT_TEMPLATE.format(
        first=finding_claim("Finding A:", first),
        second=finding_claim("Finding B:", second),
        first_code=_source_window(root, first),
        second_code=_source_window(root, second),
    )


@dataclass(frozen=True, kw_only=True)
class LinkDecision:
    """One same-fix answer for a candidate pair and the rationale behind it."""

    same_fix: bool
    rationale: str

    @classmethod
    def from_dict(cls, value: object) -> LinkDecision:
        """Parse one decision restored from the attributes of its link item record."""
        if not isinstance(value, dict) or set(value) != {"same_fix", "rationale"}:
            raise ValueError("issue link decision fields are invalid")
        if not isinstance(value["same_fix"], bool) or not isinstance(value["rationale"], str) or not value["rationale"]:
            raise ValueError("issue link decision values are invalid")
        return cls(same_fix=value["same_fix"], rationale=value["rationale"])


class IssueJudge(Protocol):
    """The seat that answers one same-fix question per candidate pair."""

    @property
    def fingerprint(self) -> str:
        """Identify the seat, model, and prompt contract that a recorded decision was made under."""

    def judge(self, prompt: str, *, pair: tuple[str, str]) -> LinkDecision:
        """Answer whether one code change fixes both findings of the prompt."""


class ModelIssueJudge:
    """One closed-schema same-fix judgment on a configured model seat."""

    def __init__(self, *, provider: Provider, model: str, seat_id: str) -> None:
        """Bind the seat and its model."""
        self._provider = provider
        self._model = model
        self._seat_id = seat_id

    @property
    def fingerprint(self) -> str:
        """Identify the seat, model, and prompt contract, never transport policy."""
        return canonical_sha256(
            {
                "seat_id": self._seat_id,
                "model": self._model,
                "max_tokens": _SETTINGS.max_output_tokens,
                "system": _SYSTEM,
                "finding_fields": list(CLAIM_FIELDS),
                "prompt_template": _PROMPT_TEMPLATE,
                "response_schema": _RESPONSE_SCHEMA.schema,
            }
        )

    def judge(self, prompt: str, *, pair: tuple[str, str]) -> LinkDecision:
        """Ask the seat once and require a nonempty rationale."""
        with model_call_context(role="issue linker", trigger="issue_link", candidate_id=pair[0]):
            result = self._provider.complete(
                system=_SYSTEM,
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=_SETTINGS.max_output_tokens,
                response_schema=_RESPONSE_SCHEMA,
            )
            reply = parse_role_response(result.text, role="issue linker", response_schema=_RESPONSE_SCHEMA)
        rationale = reply["rationale"].strip()
        if not rationale:
            raise IssueLinkError("issue link reply requires a nonempty rationale")
        return LinkDecision(same_fix=reply["same_fix"], rationale=rationale)


@dataclass(frozen=True, kw_only=True)
class IssueLinks:
    """Accepted judgment links, how many pairs were judged or restored, and the pairs whose judgment failed."""

    links: tuple[tuple[str, str], ...] = ()
    judged: int = 0
    restored: int = 0
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _PairOutcome:
    ids: tuple[str, str]
    decision: LinkDecision | None
    error: str = ""
    restored: bool = False


def _restored_decision(record: Record, _payload: object) -> LinkDecision | None:
    if record.status != "ok":
        return None
    return LinkDecision.from_dict(
        {"same_fix": record.attributes.get("same_fix"), "rationale": record.attributes.get("rationale")}
    )


def link_issues(
    findings: Sequence[Finding],
    judge: IssueJudge,
    root: str,
    *,
    store: ItemStore,
    concurrency: int,
    recorder: Recorder,
) -> IssueLinks:
    """Judge every candidate pair once, `concurrency` at a time, and keep the pairs one code change fixes."""

    def decide(pair: tuple[Finding, Finding]) -> _PairOutcome:
        first, second = pair
        ids = (first.candidate_id, second.candidate_id)
        try:
            prompt = link_prompt(first, second, root)
        except IssueLinkError as exc:
            return _PairOutcome(ids=ids, decision=None, error=f"issue link {ids[0]} {ids[1]}: {exc}")
        name = f"pair-{canonical_sha256({'prompt': prompt, 'judge': judge.fingerprint})[:20]}"
        decision = store.restore(name, _restored_decision)
        if decision is not None:
            return _PairOutcome(ids=ids, decision=decision, restored=True)
        started_at, started = utc_timestamp(), time.monotonic()
        error = ""
        try:
            with model_call_scope(unit_id=name):
                decision = judge.judge(prompt, pair=ids)
        except ProviderAccessError:
            raise
        except Exception as exc:
            error = f"issue link {ids[0]} {ids[1]}: {exception_reason(exc)}"
        item = Record(
            id=f"link/{name}",
            status="ok" if decision is not None else "failed",
            started_at=started_at,
            duration_seconds=round(time.monotonic() - started, 3),
            metrics=recorder.unit_usage(name),
            attributes={
                "pair": f"{ids[0]} {ids[1]}",
                "same_fix": decision.same_fix if decision is not None else None,
                "rationale": decision.rationale if decision is not None else None,
            },
            error=RecordError(code="model", message=error_message(error)) if error else None,
        )
        store.save(item)
        recorder.item(item)
        return _PairOutcome(ids=ids, decision=decision, error=error)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(decide, link_candidates(findings)))
    return IssueLinks(
        links=tuple(item.ids for item in results if item.decision is not None and item.decision.same_fix),
        judged=sum(1 for item in results if item.decision is not None and not item.restored),
        restored=sum(1 for item in results if item.restored),
        errors=tuple(item.error for item in results if item.error),
    )
