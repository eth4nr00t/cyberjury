"""Group retained findings into issues: findings that one code change fixes.

Grouping never removes a finding; every member is still reported and counted. Findings
that report the same category at the same primary location, one file and one line, form one
issue without a model. Findings of different groups become a candidate pair when each cites
source covering the other's primary location, or when one does and both cite overlapping lines
of one source file. Each candidate pair receives one closed-schema judgment on the finder seat,
and only a `same_fix` answer links the two issues.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Literal, Protocol

from cyberjury.canonical import canonical_sha256
from cyberjury.numbering import numbered_source, split_lines
from cyberjury.providers.base import Message, Provider, ResponseSchema
from cyberjury.providers.metering import model_call_context
from cyberjury.review.checkpoint import CheckpointStore
from cyberjury.review.engine import parse_role_response
from cyberjury.review.finding import Finding
from cyberjury.review.paths import normalized_location_path, resolve_source_path
from cyberjury.review.prompts import CLAIM_FIELDS, UNTRUSTED_SOURCE_RULE, fenced_source, finding_claim
from cyberjury.review.schemas import closed_object
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SETTINGS = DEFAULT_REVIEW_SETTINGS.issues

type LinkKind = Literal["location", "judgment"]


def issue_id(member_ids: Iterable[str]) -> str:
    """Identify one issue by its member candidate set, independent of member order."""
    return f"issue-{canonical_sha256(sorted(member_ids))[:20]}"


@dataclass(frozen=True, kw_only=True)
class Issue:
    """Findings that one code change fixes, in union order, with the links that joined them."""

    members: tuple[Finding, ...]
    linked_by: tuple[LinkKind, ...] = ()

    @property
    def id(self) -> str:
        """Identify the issue by its member set, independent of member order."""
        return issue_id(item.candidate_id for item in self.members)

    @property
    def representative(self) -> Finding:
        """Return the first member in the deterministic union order."""
        return self.members[0]


def _group_key(finding: Finding) -> tuple[str, int, str]:
    """Return the deterministic grouping key: one primary location and one reported category."""
    return (normalized_location_path(finding.file), finding.line, finding.category)


def group_issues(findings: Sequence[Finding], links: Iterable[tuple[str, str]] = ()) -> tuple[Issue, ...]:
    """Union findings over equal locations and categories and accepted judgment links, keeping every finding.

    Issues and their members follow the input order, so the first finding of an issue is its
    representative. Issue ids depend only on member sets.
    """
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
        Issue(members=tuple(group), linked_by=tuple(sorted(kinds.get(index, ())))) for index, group in members.items()
    )


def _covers(finding: Finding, other: Finding) -> bool:
    """Report whether the finding cites source that covers the other finding's primary location."""
    file = normalized_location_path(other.file)
    return any(span.file == file and span.start_line <= other.line <= span.end_line for span in finding.cited_spans)


def _shares_cited_source(first: Finding, second: Finding) -> bool:
    """Report whether the two findings cite overlapping lines of one source file."""
    return any(
        left.file == right.file and left.start_line <= right.end_line and right.start_line <= left.end_line
        for left in first.cited_spans
        for right in second.cited_spans
    )


def _traces_same_source(first: Finding, second: Finding) -> bool:
    """Require mutual coverage, or one-sided coverage of a location plus overlapping cited source."""
    forward, backward = _covers(first, second), _covers(second, first)
    return (forward and backward) or ((forward or backward) and _shares_cited_source(first, second))


def link_candidates(findings: Sequence[Finding]) -> tuple[tuple[Finding, Finding], ...]:
    """Select one candidate pair per pair of deterministic groups whose findings trace the same source.

    Pairs are formed in candidate id order, so the selection does not depend on input order.
    """
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
    "- `reason`: the one change that fixes both findings, or why each finding needs its own change."
)
_PROMPT_TEMPLATE = (
    "{first}\n\n{second}\n\nCode at finding A's location:\n{first_code}\n\nCode at finding B's location:\n{second_code}"
)
_RESPONSE_SCHEMA = ResponseSchema(
    name="issue_link",
    schema=closed_object({"same_fix": {"type": "boolean"}, "reason": {"type": "string"}}),
)


class IssueLinkError(RuntimeError):
    """An issue link judgment produced no usable decision."""


def _source_window(root: str, finding: Finding) -> str:
    """Return the numbered source lines around one finding's primary location."""
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
    """One same-fix answer for a candidate pair and the reason behind it."""

    same_fix: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        """Return the checkpoint form."""
        return {"same_fix": self.same_fix, "reason": self.reason}

    @classmethod
    def from_dict(cls, value: object) -> LinkDecision:
        """Parse one checkpointed decision written by `to_dict`."""
        if not isinstance(value, dict) or set(value) != {"same_fix", "reason"}:
            raise ValueError("issue link decision fields are invalid")
        if not isinstance(value["same_fix"], bool) or not isinstance(value["reason"], str) or not value["reason"]:
            raise ValueError("issue link decision values are invalid")
        return cls(same_fix=value["same_fix"], reason=value["reason"])


class IssueJudge(Protocol):
    """The seat that answers one same-fix question per candidate pair."""

    @property
    def fingerprint(self) -> str:
        """Identify the seat, model, and prompt contract for checkpoint reuse."""

    def judge(self, prompt: str, *, pair: tuple[str, str]) -> LinkDecision:
        """Answer whether one code change fixes both findings of the prompt."""


class ModelIssueJudge:
    """One closed-schema same-fix judgment on a configured model seat."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        seat_id: str,
        max_tokens: int = _SETTINGS.max_output_tokens,
    ) -> None:
        """Bind the seat, its model, and its output bound."""
        self._provider = provider
        self._model = model
        self._seat_id = seat_id
        self._max_tokens = max_tokens

    @property
    def fingerprint(self) -> str:
        """Identify the seat, model, and prompt contract, never transport policy."""
        return canonical_sha256(
            {
                "seat_id": self._seat_id,
                "model": self._model,
                "max_tokens": self._max_tokens,
                "system": _SYSTEM,
                "finding_fields": list(CLAIM_FIELDS),
                "prompt_template": _PROMPT_TEMPLATE,
                "response_schema": _RESPONSE_SCHEMA.schema,
            }
        )

    def judge(self, prompt: str, *, pair: tuple[str, str]) -> LinkDecision:
        """Ask the seat once and require a nonempty reason."""
        with model_call_context(role="issue linker", trigger="issue_link", candidate_id=pair[0]):
            result = self._provider.complete(
                system=_SYSTEM,
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                response_schema=_RESPONSE_SCHEMA,
            )
            reply = parse_role_response(result.text, role="issue linker", response_schema=_RESPONSE_SCHEMA)
        reason = reply["reason"].strip()
        if not reason:
            raise IssueLinkError("issue link reply requires a nonempty reason")
        return LinkDecision(same_fix=reply["same_fix"], reason=reason)


@dataclass(frozen=True, kw_only=True)
class IssueLinks:
    """Accepted judgment links and the candidate pairs whose judgment failed."""

    links: tuple[tuple[str, str], ...] = ()
    errors: tuple[str, ...] = ()


def link_issues(
    findings: Sequence[Finding],
    judge: IssueJudge,
    root: str,
    *,
    checkpoint: CheckpointStore | None = None,
    concurrency: int = 1,
) -> IssueLinks:
    """Judge every candidate pair once, `concurrency` at a time, and keep the pairs one code change fixes.

    With a checkpoint, each completed decision is saved as soon as it is made and reused for the
    same prompt and judge. A failed judgment links nothing and is never saved, so a resume retries it.
    """

    def decide(pair: tuple[Finding, Finding]) -> tuple[tuple[str, str], LinkDecision | None, str]:
        first, second = pair
        ids = (first.candidate_id, second.candidate_id)
        try:
            prompt = link_prompt(first, second, root)
        except IssueLinkError as exc:
            return ids, None, f"issue link {ids[0]} {ids[1]}: {exc}"
        key = canonical_sha256({"prompt": prompt, "judge": judge.fingerprint})
        decision = checkpoint.restore(key, LinkDecision.from_dict) if checkpoint is not None else None
        if decision is None:
            try:
                decision = judge.judge(prompt, pair=ids)
            except Exception as exc:
                return ids, None, f"issue link {ids[0]} {ids[1]}: {type(exc).__name__}: {exc}"
            if checkpoint is not None:
                checkpoint.save(key, decision.to_dict())
        return ids, decision, ""

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        results = list(pool.map(decide, link_candidates(findings)))
    return IssueLinks(
        links=tuple(ids for ids, decision, _error in results if decision is not None and decision.same_fix),
        errors=tuple(error for _ids, _decision, error in results if error),
    )
