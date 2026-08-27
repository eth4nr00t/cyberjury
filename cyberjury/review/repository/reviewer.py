"""Adapt repository units and provider replies to shared role contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from time import perf_counter
from typing import cast

from cyberjury.profiles.base import ContentPaths
from cyberjury.providers.base import Message, Provider
from cyberjury.resources import SEVERITY_RUBRIC_FILE, UNIT_REVIEW_FILE, VULNERABILITIES_DIR
from cyberjury.review.context import EvidencePromptContext, GroundingContext
from cyberjury.review.engine import (
    EvidenceJudgment,
    JudgmentProgress,
    PendingWorkRecord,
    RebuttalRecord,
    ReviewCycle,
    RoleChallenge,
    RoleJudgment,
    RoleReply,
    RoleResponseError,
    parse_role_response,
    run_evidence_judgment,
    run_role_round,
    run_standard_judgments,
)
from cyberjury.review.paths import is_unsafe_rel
from cyberjury.review.repository.context import Unit, gather_context
from cyberjury.review.repository.prompts import (
    CHALLENGER_SYSTEM,
    FINDER_SYSTEM,
    JUDGE_SYSTEM,
    challenger_prompt,
    finder_prompt,
    judge_prompt,
    standard_finder_prompt_plan,
)
from cyberjury.review.repository.union import Candidate, candidate_accumulator
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.vulnerabilities import KnowledgePack, KnowledgePlan, VulnerabilityCatalog


class RepositoryReviewError(RuntimeError):
    """A unit reply cannot support a complete review result."""


type CandidateRecord = dict[str, object]


def _role_response(
    text: str,
    role: str,
    *required_keys: str,
    optional_list_keys: tuple[str, ...] = (),
) -> RoleReply:
    """Translate the shared role contract failure into the repository public error."""
    try:
        return parse_role_response(
            text,
            role=role,
            required_keys=required_keys,
            optional_list_keys=optional_list_keys,
        )
    except RoleResponseError as exc:
        raise RepositoryReviewError(f"{role} failed review: {exc}") from exc


_SETTINGS = DEFAULT_REVIEW_SETTINGS.repository


@dataclass(frozen=True, kw_only=True)
class _PromptMaterial:
    """One unit's evidence prefixes and complete knowledge work."""

    standard_head: str
    adversarial_head: str
    unit_name: str
    grounding: GroundingContext
    knowledge: KnowledgePlan

    def standard_prefix(self, context: EvidencePromptContext) -> str:
        """Render one standard prompt prefix with the current evidence window."""
        controls = f"Repository grounding controls:\n{context.controls}\n\n" if context.controls else ""
        return (
            f"{self.standard_head}Unit `{self.unit_name}`, the code to review:\n```\n{context.source}\n```\n\n"
            f"{controls}"
        )

    @property
    def adversarial_prefix(self) -> str:
        """Render the adversarial prefix from the initial evidence window."""
        return self.adversarial_prefix_for(self.grounding.prompt)

    def adversarial_prefix_for(self, context: EvidencePromptContext) -> str:
        """Render an adversarial prefix with the current evidence window."""
        controls = f"Repository grounding controls:\n{context.controls}\n\n" if context.controls else ""
        return (
            f"{self.adversarial_head}Unit `{self.unit_name}`, the code to review:\n```\n{context.source}\n```\n\n"
            f"{controls}"
        )


def candidates_from_obj(obj: object) -> list[Candidate]:
    """Map a valid role reply without silently dropping malformed candidate work."""
    if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
        raise RepositoryReviewError("role findings must be a list")
    out: list[Candidate] = []
    for index, d in enumerate(obj["findings"]):
        if not isinstance(d, dict):
            raise RepositoryReviewError(f"role findings[{index}] must be an object")
        title = str(d.get("title") or d.get("description") or "").strip()
        if not title:
            raise RepositoryReviewError(f"role findings[{index}] must have a title")
        line = d.get("line")
        sev = str(d.get("severity", "")).strip().upper()
        rel = str(d.get("file", "")).strip()
        if not rel or is_unsafe_rel(rel):
            raise RepositoryReviewError(f"role findings[{index}] must name a safe source file")
        if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            raise RepositoryReviewError(f"role findings[{index}] has an invalid severity")
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 0):
            raise RepositoryReviewError(f"role findings[{index}] has an invalid line")
        status = str(d.get("status", "")).strip().lower()
        if status not in {"confirmed", "blocked"}:
            raise RepositoryReviewError(f"role findings[{index}] has an invalid status")
        refs = d.get("evidence_refs")
        if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) and ref for ref in refs):
            raise RepositoryReviewError(f"role findings[{index}].evidence_refs must be a nonempty string list")
        out.append(
            Candidate(
                title=title,
                category=str(d.get("category", "")).strip(),
                endpoint=str(d.get("endpoint") or d.get("source") or "").strip(),
                symbol=str(d.get("symbol") or "").strip(),
                file=rel,
                line=line if line and line >= 1 else None,
                severity=sev,
                evidence=str(d.get("evidence", "")).strip(),
                status=status,
                evidence_refs=tuple(refs),
            )
        )
    return out


def candidates_to_obj(
    candidates: list[Candidate],
    *,
    include_evidence_refs: bool = True,
) -> list[CandidateRecord]:
    """Serialize candidates into the compact prompt form used across role passes."""
    out: list[CandidateRecord] = []
    for cand in candidates:
        item: CandidateRecord = {
            "title": cand.title,
            "category": cand.category,
            "symbol": cand.symbol,
            "endpoint": cand.endpoint,
            "file": cand.file,
            "line": cand.line,
            "severity": cand.severity,
            "evidence": cand.evidence,
            "status": cand.status,
        }
        if include_evidence_refs:
            item["evidence_refs"] = list(cand.evidence_refs)
        out.append(item)
    return out


def _validate_candidate_evidence_refs(candidates: list[Candidate], grounding: GroundingContext) -> None:
    """Reject model candidates that cite source outside the active evidence window."""
    available = {"seed", *grounding.coverage.references}
    for index, candidate in enumerate(candidates):
        unknown = tuple(ref for ref in candidate.evidence_refs if ref not in available)
        if unknown:
            raise RepositoryReviewError(
                f"role findings[{index}].evidence_refs contain unread source ids: {', '.join(unknown)}"
            )


UnitChallenge = RoleChallenge


class UnitReviewer(ABC):
    """Interface for reviewing one repository unit."""

    @abstractmethod
    def review(self, unit: Unit, *, shared_context: str = "") -> list[Candidate]:
        """Deeply review one unit and return candidate findings."""

    def review_round(
        self,
        unit: Unit,
        *,
        shared_context: str = "",
        finder_label: str,
        known: list[Candidate] | None = None,
        on_judgment: JudgmentProgress | None = None,
    ) -> ReviewCycle[Candidate]:
        """Expose one standard review through the shared completion contract."""
        started = perf_counter()
        role_round = run_role_round(
            find=lambda: _find(self, unit, shared_context, known or []),
            finder_label=finder_label,
            key=lambda candidate: candidate.key(),
            title=lambda candidate: candidate.title,
        )
        if on_judgment is not None:
            on_judgment(1, 1, "general review", round(perf_counter() - started, 1))
        return ReviewCycle(
            findings=role_round.findings,
            errors=0 if role_round.clean else 1,
            failure_reason=role_round.failure_reason,
        )


class UnitRoleReviewer(UnitReviewer):
    """Interface for reviewing one repository unit through the shared role loop."""

    def find(
        self,
        unit: Unit,
        *,
        shared_context: str = "",
        known: list[Candidate] | None = None,
    ) -> list[Candidate] | EvidenceJudgment[Candidate]:
        """Find candidates for one unit while carrying known findings forward."""
        return self.review(unit, shared_context=shared_context)

    def challenge(
        self,
        unit: Unit,
        finder_findings: list[Candidate],
        *,
        shared_context: str = "",
        known: list[Candidate] | None = None,
    ) -> UnitChallenge:
        """Refute finder candidates and independently scan for missed candidates."""
        return UnitChallenge(rebuttals=[], new_findings=[])

    def judge(
        self,
        unit: Unit,
        finder_findings: list[Candidate],
        rebuttals: list[RebuttalRecord],
        new_findings: list[Candidate],
        *,
        shared_context: str = "",
        known: list[Candidate] | None = None,
    ) -> RoleJudgment[Candidate]:
        """Rule on finder and challenger candidates for one unit."""
        return RoleJudgment(findings=[*finder_findings, *new_findings])


def reviewer_label(reviewer: UnitReviewer, fallback: str) -> str:
    """Return the reviewer label used for finding provenance."""
    return getattr(reviewer, "label", "") or fallback


def _find(
    reviewer: UnitReviewer,
    unit: Unit,
    shared_context: str,
    known: list[Candidate],
) -> list[Candidate] | EvidenceJudgment[Candidate]:
    find = getattr(reviewer, "find", None)
    if callable(find):
        return find(unit, shared_context=shared_context, known=known)
    return reviewer.review(unit, shared_context=shared_context)


def _challenge(
    reviewer: UnitReviewer,
    unit: Unit,
    finder_findings: list[Candidate],
    shared_context: str,
    known: list[Candidate],
) -> RoleChallenge[Candidate]:
    challenge = getattr(reviewer, "challenge", None)
    if callable(challenge):
        return challenge(unit, finder_findings, shared_context=shared_context, known=known)
    return RoleChallenge(rebuttals=[], new_findings=[])


def _judge(
    reviewer: UnitReviewer,
    unit: Unit,
    finder_findings: list[Candidate],
    challenged: RoleChallenge[Candidate],
    shared_context: str,
    known: list[Candidate],
) -> RoleJudgment[Candidate]:
    judge = getattr(reviewer, "judge", None)
    if not callable(judge):
        return RoleJudgment(findings=[*finder_findings, *challenged.new_findings])
    result = judge(
        unit,
        finder_findings,
        challenged.rebuttals,
        challenged.new_findings,
        shared_context=shared_context,
        known=known,
    )
    return result if isinstance(result, RoleJudgment) else RoleJudgment(findings=result)


def review_round(
    unit: Unit,
    finder: UnitReviewer,
    *,
    finder_label: str,
    challenger: UnitReviewer | None = None,
    judge: UnitReviewer | None = None,
    shared_context: str = "",
    known: list[Candidate] | None = None,
    on_judgment: JudgmentProgress | None = None,
) -> ReviewCycle[Candidate]:
    """Adapt repository role reviewers to one shared review cycle."""
    if (challenger is None) != (judge is None):
        raise ValueError("challenger and judge reviewers must be configured together")
    prior = known or []
    if challenger is None:
        return finder.review_round(
            unit,
            shared_context=shared_context,
            finder_label=finder_label,
            known=prior,
            on_judgment=on_judgment,
        )

    active_unit = unit

    def find() -> list[Candidate] | EvidenceJudgment[Candidate]:
        nonlocal active_unit
        result = _find(finder, unit, shared_context, prior)
        if isinstance(result, EvidenceJudgment) and result.prompt_context:
            base = unit.grounding or GroundingContext(text="")
            active_unit = replace(
                unit,
                grounding=replace(
                    base,
                    text=result.prompt_context,
                    controls=result.prompt_controls,
                    coverage=result.grounding,
                    evidence=(),
                    navigator=None,
                ),
            )
        return result

    def challenge_role(finder_findings: list[Candidate]) -> RoleChallenge[Candidate]:
        return _challenge(challenger, active_unit, finder_findings, shared_context, prior)

    def judge_role(
        finder_findings: list[Candidate],
        challenged: RoleChallenge[Candidate],
    ) -> RoleJudgment[Candidate]:
        return _judge(judge, active_unit, finder_findings, challenged, shared_context, prior)

    role_round = run_role_round(
        find=find,
        finder_label=finder_label,
        challenge=challenge_role if challenger is not None else None,
        challenger_label=reviewer_label(challenger, "challenger") if challenger is not None else "",
        judge=judge_role if judge is not None else None,
        judge_label=reviewer_label(judge, "judge") if judge is not None else "",
        key=lambda candidate: candidate.key(),
        title=lambda candidate: candidate.title,
    )
    return ReviewCycle(
        findings=role_round.findings,
        pending=role_round.pending,
        errors=0 if role_round.clean else 1,
        failure_reason=role_round.failure_reason,
        grounding=role_round.grounding,
    )


class ModelReviewer(UnitRoleReviewer):
    """Default reviewer: grounded model judgments over one repository unit."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = DEFAULT_REVIEW_SETTINGS.execution.reviewer_max_output_tokens,
        content: ContentPaths | None = None,
        facts_by_file: dict[str, str] | None = None,
    ) -> None:
        """Bind the provider, content paths, and optional facts used for unit review."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        mandate_file = content.unit_review_file if content else UNIT_REVIEW_FILE
        rubric_file = content.severity_rubric_file if content else SEVERITY_RUBRIC_FILE
        self._mandate = mandate_file.read_text(encoding="utf-8")
        self._rubric = rubric_file.read_text(encoding="utf-8")
        vulnerabilities_dir = content.vulnerabilities_dir if content else VULNERABILITIES_DIR
        self._vulnerability_catalog = VulnerabilityCatalog.load(vulnerabilities_dir)
        self._allowed_categories = ", ".join(sorted(self._vulnerability_catalog.ids))
        self._facts_by_file = facts_by_file or {}
        self._facts_by_base: dict[str, list[tuple[str, str]]] = {}
        for rel, block in self._facts_by_file.items():
            self._facts_by_base.setdefault(rel.rsplit("/", 1)[-1], []).append((rel, block))

    @property
    def label(self) -> str:
        """The model name, used to tag which model surfaced a finding."""
        return self._model

    def _facts_for(self, unit: Unit) -> str:
        """Keep file-level facts available when a unit contains only one source slice."""
        if not self._facts_by_file:
            return ""
        seen: set[str] = set()
        blocks: list[str] = []
        total = 0
        for rel in unit.files:
            block = self._facts_by_file.get(rel)
            if block is None:
                matches = self._facts_by_base.get(rel.rsplit("/", 1)[-1], [])
                if len(matches) > 1:
                    paths = ", ".join(path for path, _ in matches)
                    raise RepositoryReviewError(f"facts path {rel!r} is ambiguous across {paths}")
                if matches:
                    block = matches[0][1]
            if not block or block in seen:
                continue
            seen.add(block)
            blocks.append(block)
            total += len(block)
            if total >= _SETTINGS.max_facts_chars_per_unit:
                break
        text = "\n".join(blocks)
        return text[: _SETTINGS.max_facts_chars_per_unit] if len(text) > _SETTINGS.max_facts_chars_per_unit else text

    def _prompt_material(self, unit: Unit, shared_context: str) -> _PromptMaterial:
        grounding = gather_context(unit)
        unit_facts = self._facts_for(unit)
        knowledge = self._vulnerability_catalog.plan(grounding.selection_text, unit_facts)
        head = (
            f"{self._mandate}\n\n---\nSeverity rubric:\n{self._rubric}\n\n---\n"
            + (f"Shared review context:\n{shared_context}\n\n" if shared_context else "")
            + (
                f"Tool-extracted facts for this unit, the call graph and other structure "
                f"the slice below may not show in full:\n{unit_facts}\n\n"
                if unit_facts
                else ""
            )
            + f"Allowed finding categories:\n{self._allowed_categories}\n\n"
        )
        vulnerabilities = self._vulnerability_catalog.render(list(knowledge.selected))
        knowledge_block = (
            f"Vulnerability classes evidenced by this unit:\n{vulnerabilities}\n\n" if vulnerabilities else ""
        )
        return _PromptMaterial(
            standard_head=head,
            adversarial_head=f"{head}{knowledge_block}",
            unit_name=unit.name,
            grounding=grounding,
            knowledge=knowledge,
        )

    def _run_standard_judgment(
        self,
        material: _PromptMaterial,
        pack: KnowledgePack,
        *,
        known: list[Candidate],
        cache: bool,
    ) -> EvidenceJudgment[Candidate]:
        def ask(prompt_context: EvidencePromptContext) -> RoleReply:
            prompt = standard_finder_prompt_plan(
                material.standard_prefix(prompt_context),
                vulnerability_categories=pack.categories,
                selected_vulnerability_categories=tuple(item.id for item in material.knowledge.selected),
                vulnerabilities=pack.body,
                known=candidates_to_obj(known, include_evidence_refs=False),
            )
            result = self._provider.complete(
                system=FINDER_SYSTEM,
                messages=[Message(role="user", content=prompt.text)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=cache,
                cache_prefix=prompt.stable_prefix if cache else "",
            )
            return _role_response(
                result.text,
                "unit finder",
                "findings",
                optional_list_keys=("evidence_requests", "source_queries"),
            )

        return run_evidence_judgment(
            material.grounding,
            ask=ask,
            findings_from_reply=candidates_from_obj,
            accumulator=candidate_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            evidence_refs=lambda candidate: candidate.evidence_refs,
        )

    def review_round(
        self,
        unit: Unit,
        *,
        shared_context: str = "",
        finder_label: str,
        known: list[Candidate] | None = None,
        on_judgment: JudgmentProgress | None = None,
    ) -> ReviewCycle[Candidate]:
        """Complete every selected knowledge judgment for one standard unit review."""
        material = self._prompt_material(unit, shared_context)
        prior = known or []
        return run_standard_judgments(
            material.knowledge.packs,
            execute_judgment=lambda pack, cache: self._run_standard_judgment(
                material,
                pack,
                known=prior,
                cache=cache,
            ),
            describe_judgment=lambda pack: pack.label,
            finder_label=finder_label,
            accumulator=candidate_accumulator(),
            key=lambda candidate: candidate.key(),
            title=lambda candidate: candidate.title,
            on_judgment=on_judgment,
        )

    def review(self, unit: Unit, *, shared_context: str = "") -> list[Candidate]:
        """Return complete standard findings for callers outside the coded scheduler."""
        cycle = self.review_round(unit, shared_context=shared_context, finder_label=self.label)
        if not cycle.clean:
            raise RepositoryReviewError(cycle.failure_reason)
        return cycle.findings

    def find(
        self,
        unit: Unit,
        *,
        shared_context: str = "",
        known: list[Candidate] | None = None,
    ) -> EvidenceJudgment[Candidate]:
        """Find candidates for a role-loop pass, carrying known findings forward."""
        material = self._prompt_material(unit, shared_context)

        def ask(prompt_context: EvidencePromptContext) -> RoleReply:
            prefix = material.adversarial_prefix_for(prompt_context)
            prompt = finder_prompt(prefix, candidates_to_obj(known or [], include_evidence_refs=False))
            result = self._provider.complete(
                system=FINDER_SYSTEM,
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                cache_prefix=prefix,
            )
            return _role_response(
                result.text,
                "finder",
                "findings",
                optional_list_keys=("evidence_requests", "source_queries"),
            )

        return run_evidence_judgment(
            material.grounding,
            ask=ask,
            findings_from_reply=candidates_from_obj,
            accumulator=candidate_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            evidence_refs=lambda candidate: candidate.evidence_refs,
        )

    def challenge(
        self,
        unit: Unit,
        finder_findings: list[Candidate],
        *,
        shared_context: str = "",
        known: list[Candidate] | None = None,
    ) -> UnitChallenge:
        """Refute finder candidates and independently scan for missed candidates."""
        material = self._prompt_material(unit, shared_context)
        prompt = challenger_prompt(
            material.adversarial_prefix,
            candidates_to_obj(finder_findings),
            candidates_to_obj(known or [], include_evidence_refs=False),
        )
        result = self._provider.complete(
            system=CHALLENGER_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
            cache_prefix=material.adversarial_prefix,
        )
        obj = _role_response(result.text, "challenger", "rebuttals", "new_findings")
        new_findings = candidates_from_obj({"findings": obj.get("new_findings", [])})
        _validate_candidate_evidence_refs(new_findings, material.grounding)
        return UnitChallenge(
            rebuttals=cast("list[RebuttalRecord]", [r for r in obj.get("rebuttals", []) if isinstance(r, dict)]),
            new_findings=new_findings,
        )

    def judge(
        self,
        unit: Unit,
        finder_findings: list[Candidate],
        rebuttals: list[RebuttalRecord],
        new_findings: list[Candidate],
        *,
        shared_context: str = "",
        known: list[Candidate] | None = None,
    ) -> RoleJudgment[Candidate]:
        """Rule on finder and challenger candidates for one role-loop pass."""
        material = self._prompt_material(unit, shared_context)
        prompt = judge_prompt(
            material.adversarial_prefix,
            candidates_to_obj(finder_findings),
            rebuttals,
            candidates_to_obj(new_findings),
            candidates_to_obj(known or [], include_evidence_refs=False),
        )
        result = self._provider.complete(
            system=JUDGE_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
            cache_prefix=material.adversarial_prefix,
        )
        obj = _role_response(result.text, "judge", "findings", optional_list_keys=("investigate",))
        findings = candidates_from_obj(obj)
        _validate_candidate_evidence_refs(findings, material.grounding)
        return RoleJudgment(
            findings=findings,
            pending=cast(
                "list[PendingWorkRecord]",
                [item for item in obj.get("investigate", []) if isinstance(item, dict)],
            ),
        )
