"""Adapt repository units and provider replies to shared role contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, replace
from time import perf_counter
from typing import ClassVar, cast

from cyberjury.profiles.base import ContentPaths
from cyberjury.providers.base import Message, Provider
from cyberjury.resources import SEVERITY_RUBRIC_FILE, UNIT_REVIEW_FILE, VULNERABILITIES_DIR
from cyberjury.review.context import (
    EvidencePromptContext,
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    merge_grounding_coverage,
    source_location_is_grounded,
    with_source_evidence,
)
from cyberjury.review.engine import (
    EvidenceJudgment,
    GroundedJudgmentTask,
    JudgmentProgress,
    PendingWorkRecord,
    RebuttalRecord,
    ReviewCycle,
    RoleChallenge,
    RoleJudgment,
    RoleReply,
    RoleResponseError,
    RoleRound,
    parse_role_response,
    run_evidence_judgment,
    run_grounded_role_judgments,
    run_grounded_standard_judgments,
    run_role_round,
    validate_pending_records,
    validate_rebuttal_records,
)
from cyberjury.review.navigation import SourceNavigationSession
from cyberjury.review.paths import is_unsafe_rel
from cyberjury.review.repository.context import Unit, facts_for_unit, gather_context
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
from cyberjury.review.vulnerabilities import KnowledgePack, VulnerabilityCatalog


class RepositoryReviewError(RuntimeError):
    """A unit reply cannot support a complete review result."""


type CandidateRecord = dict[str, object]


def _role_response(
    text: str,
    role: str,
    *required_keys: str,
    optional_list_keys: tuple[str, ...] = (),
    object_list_keys: tuple[str, ...] = (),
) -> RoleReply:
    """Translate the shared role contract failure into the repository public error."""
    try:
        return parse_role_response(
            text,
            role=role,
            required_keys=required_keys,
            optional_list_keys=optional_list_keys,
            object_list_keys=object_list_keys,
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


def candidates_from_obj(
    obj: object,
    *,
    canonicalize: Callable[[str], str] | None = None,
) -> list[Candidate]:
    """Map a valid role reply without silently dropping malformed candidate work."""
    if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
        raise RepositoryReviewError("role findings must be a list")
    out: list[Candidate] = []
    for index, d in enumerate(obj["findings"]):
        if not isinstance(d, dict):
            raise RepositoryReviewError(f"role findings[{index}] must be an object")
        allowed = {
            "candidate_id",
            "title",
            "category",
            "symbol",
            "endpoint",
            "file",
            "line",
            "severity",
            "attack_path",
            "evidence",
            "status",
            "evidence_refs",
        }
        unexpected = set(d).difference(allowed)
        if unexpected:
            raise RepositoryReviewError(f"role findings[{index}] has unknown fields: {', '.join(sorted(unexpected))}")
        title = d.get("title")
        if not isinstance(title, str) or not title.strip():
            raise RepositoryReviewError(f"role findings[{index}] must have a title")
        title = title.strip()
        line = d.get("line")
        severity = d.get("severity")
        if not isinstance(severity, str):
            raise RepositoryReviewError(f"role findings[{index}] has an invalid severity")
        sev = severity.strip().upper()
        file = d.get("file")
        if not isinstance(file, str):
            raise RepositoryReviewError(f"role findings[{index}] must name a safe source file")
        rel = file.strip()
        if not rel or is_unsafe_rel(rel):
            raise RepositoryReviewError(f"role findings[{index}] must name a safe source file")
        if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            raise RepositoryReviewError(f"role findings[{index}] has an invalid severity")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise RepositoryReviewError(f"role findings[{index}] must have a positive line")
        raw_status = d.get("status")
        status = raw_status.strip().lower() if isinstance(raw_status, str) else ""
        if status != "confirmed":
            raise RepositoryReviewError(f"role findings[{index}] must have confirmed status")
        refs = d.get("evidence_refs")
        if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) and ref for ref in refs):
            raise RepositoryReviewError(f"role findings[{index}].evidence_refs must be a nonempty string list")
        category = d.get("category")
        if not isinstance(category, str) or not category.strip():
            raise RepositoryReviewError(f"role findings[{index}] must have a category")
        evidence = d.get("evidence")
        if not isinstance(evidence, str) or not evidence.strip():
            raise RepositoryReviewError(f"role findings[{index}] must have concrete evidence")
        attack_path = d.get("attack_path")
        if not isinstance(attack_path, str) or not attack_path.strip():
            raise RepositoryReviewError(f"role findings[{index}] must have an attack_path")
        category = canonicalize(category.strip()) if canonicalize is not None else category.strip()
        optional_text: dict[str, str] = {}
        for field in ("endpoint", "symbol"):
            value = d.get(field, "")
            if not isinstance(value, str):
                raise RepositoryReviewError(f"role findings[{index}].{field} must be a string")
            optional_text[field] = value.strip()
        candidate = Candidate(
            title=title,
            category=category,
            endpoint=optional_text["endpoint"],
            symbol=optional_text["symbol"],
            file=rel,
            line=line,
            severity=sev,
            attack_path=attack_path.strip(),
            evidence=evidence.strip(),
            status=status,
            evidence_refs=tuple(refs),
        )
        supplied_id = d.get("candidate_id")
        if supplied_id is not None and supplied_id != candidate.candidate_id:
            raise RepositoryReviewError(f"role findings[{index}].candidate_id does not match its source identity")
        out.append(candidate)
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
            "attack_path": cand.attack_path,
            "evidence": cand.evidence,
            "status": cand.status,
            "attack_path_id": cand.attack_path_id,
            "candidate_id": cand.candidate_id,
        }
        if include_evidence_refs:
            item["evidence_refs"] = list(cand.evidence_refs)
        out.append(item)
    return out


def candidates_to_memory(candidates: list[Candidate]) -> list[CandidateRecord]:
    """Return the stable minimum needed to recognize established violations."""
    return [
        {
            "candidate_id": candidate.candidate_id,
            "attack_path_id": candidate.attack_path_id,
            "category": candidate.category,
            "file": candidate.file,
            "line": candidate.line,
            "symbol": candidate.symbol,
            "endpoint": candidate.endpoint,
        }
        for candidate in candidates
    ]


def validate_candidate_locations(
    cycle: ReviewCycle[Candidate],
    grounding: GroundingContext,
) -> ReviewCycle[Candidate]:
    """Keep only candidates whose cited source receipt covers their primary location."""
    valid: list[Candidate] = []
    incomplete = list(cycle.incomplete)
    for candidate in cycle.findings:
        if not candidate.evidence_refs:
            valid.append(candidate)
            continue
        if candidate.line is not None and source_location_is_grounded(
            file=candidate.file,
            line=candidate.line,
            evidence_refs=candidate.evidence_refs,
            seed_spans=grounding.source_spans,
            source_evidence=tuple(dict.fromkeys((*grounding.source_evidence, *cycle.source_evidence))),
        ):
            valid.append(candidate)
        else:
            incomplete.append(candidate)
    if len(valid) == len(cycle.findings):
        return cycle
    reason = "one or more findings lack a cited source receipt for their primary location"
    return replace(
        cycle,
        findings=valid,
        incomplete=incomplete,
        errors=cycle.errors + 1,
        failure_reason="; ".join(filter(None, (cycle.failure_reason, reason))),
    )


UnitChallenge = RoleChallenge


class UnitReviewer(ABC):
    """Interface for reviewing one repository unit."""

    supports_pending_work: ClassVar[bool] = False

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
        union = candidate_accumulator()
        role_round = run_role_round(
            find=lambda: _find(self, unit, shared_context, known or []),
            finder_label=finder_label,
            key=lambda candidate: candidate.candidate_id,
            fold=union.fold,
            title=lambda candidate: candidate.title,
        )
        if on_judgment is not None:
            on_judgment(1, 1, "general review", round(perf_counter() - started, 1))
        return ReviewCycle(
            findings=role_round.findings,
            errors=0 if role_round.clean else 1,
            failure_reason=role_round.failure_reason,
            source_evidence=role_round.source_evidence,
        )

    def plan_role_judgments(
        self,
        unit: Unit,
        context: GroundingContext,
    ) -> tuple[KnowledgePack, ...]:
        """Return one generic judgment when a reviewer owns no knowledge catalog."""
        return (KnowledgePack(items=()),)


class UnitRoleReviewer(UnitReviewer):
    """Interface for reviewing one repository unit through the shared role loop."""

    supports_pending_work: ClassVar[bool] = True

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
        pending: tuple[PendingWorkRecord, ...] = (),
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
    pending: tuple[PendingWorkRecord, ...],
) -> RoleJudgment[Candidate]:
    judge = getattr(reviewer, "judge", None)
    if not callable(judge):
        return RoleJudgment(findings=[*finder_findings, *challenged.new_findings])
    kwargs = {"shared_context": shared_context, "known": known}
    if reviewer.supports_pending_work:
        kwargs["pending"] = pending
    result = judge(unit, finder_findings, challenged.rebuttals, challenged.new_findings, **kwargs)
    return result if isinstance(result, RoleJudgment) else RoleJudgment(findings=result)


def review_role_judgment(
    unit: Unit,
    finder: UnitReviewer,
    challenger: UnitReviewer,
    judge: UnitReviewer,
    *,
    finder_label: str,
    shared_context: str,
    known: list[Candidate],
    pending: tuple[PendingWorkRecord, ...],
) -> RoleRound[Candidate]:
    """Run one repository role sequence and retain its evidence accounting."""
    active_unit = unit

    def advance(
        evidence: tuple[SourceEvidence, ...],
        coverage: GroundingCoverage,
        exchanges: int,
    ) -> None:
        nonlocal active_unit
        base = active_unit.grounding or gather_context(active_unit)
        grounded = with_source_evidence(base, evidence)
        remaining = active_unit.remaining_followups
        if remaining is not None:
            remaining -= exchanges
            if remaining < 0:
                raise AssertionError("role evidence exchanges exceeded the judgment budget")
        active_unit = replace(
            active_unit,
            grounding=replace(
                grounded,
                coverage=merge_grounding_coverage((grounded.coverage, coverage)),
            ),
            remaining_followups=remaining,
        )

    def find() -> list[Candidate] | EvidenceJudgment[Candidate]:
        result = _find(finder, active_unit, shared_context, known)
        if isinstance(result, EvidenceJudgment):
            advance(result.source_evidence, result.grounding, result.evidence_exchanges)
        return result

    def challenge_role(finder_findings: list[Candidate]) -> RoleChallenge[Candidate]:
        challenged = _challenge(challenger, active_unit, finder_findings, shared_context, known)
        advance(challenged.source_evidence, challenged.grounding, challenged.evidence_exchanges)
        return challenged

    def judge_role(
        finder_findings: list[Candidate],
        challenged: RoleChallenge[Candidate],
    ) -> RoleJudgment[Candidate]:
        return _judge(judge, active_unit, finder_findings, challenged, shared_context, known, pending)

    union = candidate_accumulator()
    return run_role_round(
        find=find,
        finder_label=finder_label,
        challenge=challenge_role,
        challenger_label=reviewer_label(challenger, "challenger"),
        judge=judge_role,
        judge_label=reviewer_label(judge, "judge"),
        key=lambda candidate: candidate.candidate_id,
        fold=union.fold,
        title=lambda candidate: candidate.title,
    )


def review_round(
    unit: Unit,
    finder: UnitReviewer,
    *,
    finder_label: str,
    challenger: UnitReviewer | None = None,
    judge: UnitReviewer | None = None,
    shared_context: str = "",
    known: list[Candidate] | None = None,
    pending: tuple[PendingWorkRecord, ...] = (),
    on_judgment: JudgmentProgress | None = None,
) -> ReviewCycle[Candidate]:
    """Adapt repository role reviewers to one shared review cycle."""
    if (challenger is None) != (judge is None):
        raise ValueError("challenger and judge reviewers must be configured together")
    prior = known or []
    if challenger is None:
        cycle = finder.review_round(
            unit,
            shared_context=shared_context,
            finder_label=finder_label,
            known=prior,
            on_judgment=on_judgment,
        )
        return validate_candidate_locations(cycle, unit.grounding or gather_context(unit))

    grounding = unit.grounding or gather_context(unit)
    navigation = grounding.navigator.session() if grounding.navigator is not None else None

    def plan(current: GroundingContext):
        return finder.plan_role_judgments(unit, current)

    def execute(task: GroundedJudgmentTask[KnowledgePack]):
        planned_unit = replace(
            unit,
            grounding=task.context,
            knowledge_pack=task.judgment,
            navigation_session=task.navigation,
            remaining_followups=task.remaining_followups,
        )
        return review_role_judgment(
            planned_unit,
            finder,
            challenger,
            judge,
            finder_label=finder_label,
            shared_context=shared_context,
            known=[*prior, *cast("tuple[Candidate, ...]", task.known)],
            pending=pending,
        )

    cycle = run_grounded_role_judgments(
        grounding,
        plan_judgments=plan,
        execute_judgment=execute,
        describe_judgment=lambda pack: pack.label,
        accumulator=candidate_accumulator(),
        max_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
        navigation_session=navigation,
        on_judgment=on_judgment,
    )
    return validate_candidate_locations(cycle, grounding)


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

    @property
    def label(self) -> str:
        """The model name, used to tag which model surfaced a finding."""
        return self._model

    def _facts_for(self, unit: Unit) -> str:
        """Return the facts bound during grounding or derive the exact-path fallback."""
        if unit.grounding is not None and unit.grounding.facts:
            return unit.grounding.facts
        return facts_for_unit(unit, self._facts_by_file)

    def _candidates_from_reply(self, obj: object) -> list[Candidate]:
        """Parse candidates under this reviewer's canonical category catalog."""
        return candidates_from_obj(obj, canonicalize=self._vulnerability_catalog.close_category)

    def plan_role_judgments(
        self,
        unit: Unit,
        context: GroundingContext,
    ) -> tuple[KnowledgePack, ...]:
        """Use the same bounded catalog plan as standard repository review."""
        return self._vulnerability_catalog.plan(context.selection_text, self._facts_for(unit)).packs

    def _prompt_material(
        self,
        unit: Unit,
        shared_context: str,
        *,
        include_knowledge: bool = True,
    ) -> _PromptMaterial:
        grounding = gather_context(unit)
        unit_facts = self._facts_for(unit)
        head = (
            f"{self._mandate}\n\n---\nSeverity rubric:\n{self._rubric}\n\n---\n"
            + (f"Shared review context:\n{shared_context}\n\n" if shared_context else "")
            + (
                f"Tool-extracted structure clues for this unit that the source slice below "
                f"may not show in full. Calls and targets are evidence, not final relationships:\n{unit_facts}\n\n"
                if unit_facts
                else ""
            )
            + f"Allowed finding categories:\n{self._allowed_categories}\n\n"
        )
        selected = (
            unit.knowledge_pack.items
            if unit.knowledge_pack is not None
            else self._vulnerability_catalog.plan(grounding.selection_text, unit_facts).selected
            if include_knowledge
            else ()
        )
        vulnerabilities = self._vulnerability_catalog.render(list(selected))
        knowledge_block = (
            f"Vulnerability classes evidenced by this unit:\n{vulnerabilities}\n\n" if vulnerabilities else ""
        )
        return _PromptMaterial(
            standard_head=head,
            adversarial_head=f"{head}{knowledge_block}",
            unit_name=unit.name,
            grounding=grounding,
        )

    def _run_standard_judgment(
        self,
        material: _PromptMaterial,
        pack: KnowledgePack,
        *,
        known: list[Candidate],
        cache: bool,
        context: GroundingContext | None = None,
        selected_categories: tuple[str, ...],
        navigation_session: SourceNavigationSession | None = None,
        max_followups: int = DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
    ) -> EvidenceJudgment[Candidate]:
        grounded = context or material.grounding

        def ask(prompt_context: EvidencePromptContext) -> RoleReply:
            prompt = standard_finder_prompt_plan(
                material.standard_prefix(prompt_context),
                vulnerability_categories=pack.categories,
                selected_vulnerability_categories=selected_categories,
                vulnerabilities=pack.body,
                known=candidates_to_memory(known),
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
            grounded,
            ask=ask,
            findings_from_reply=self._candidates_from_reply,
            accumulator=candidate_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=max_followups,
            evidence_refs=lambda candidate: candidate.evidence_refs,
            navigation_session=navigation_session,
            assigned_categories=pack.categories,
            finding_category=lambda candidate: candidate.category,
            known_categories={candidate.category for candidate in known},
            assessment_role="repository finder",
            model_role="finder",
            model_unit_id=material.unit_name,
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
        material = self._prompt_material(unit, shared_context, include_knowledge=False)
        prior = known or []
        navigation = material.grounding.navigator.session() if material.grounding.navigator is not None else None

        def plan(current: GroundingContext):
            return self._vulnerability_catalog.plan(current.selection_text, self._facts_for(unit)).packs

        def execute(task: GroundedJudgmentTask):
            selected = tuple(item.id for pack in task.plan for item in pack.items)
            return self._run_standard_judgment(
                material,
                task.judgment,
                known=[*prior, *cast("tuple[Candidate, ...]", task.known)],
                cache=task.cache,
                context=task.context,
                selected_categories=selected,
                navigation_session=task.navigation,
                max_followups=task.remaining_followups,
            )

        cycle = run_grounded_standard_judgments(
            material.grounding,
            plan_judgments=plan,
            execute_judgment=execute,
            describe_judgment=lambda pack: pack.label,
            finder_label=finder_label,
            accumulator=candidate_accumulator(),
            key=lambda candidate: candidate.candidate_id,
            title=lambda candidate: candidate.title,
            max_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            navigation_session=navigation,
            remaining_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            on_judgment=on_judgment,
        )
        return validate_candidate_locations(cycle, material.grounding)

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
        navigation = (
            unit.navigation_session
            if unit.navigation_session is not None
            else material.grounding.navigator.session()
            if material.grounding.navigator is not None
            else None
        )

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
            findings_from_reply=self._candidates_from_reply,
            accumulator=candidate_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=(
                unit.remaining_followups
                if unit.remaining_followups is not None
                else DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups
            ),
            evidence_refs=lambda candidate: candidate.evidence_refs,
            navigation_session=navigation,
            model_role="finder",
            model_unit_id=material.unit_name,
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
        navigation = (
            unit.navigation_session
            if unit.navigation_session is not None
            else material.grounding.navigator.session()
            if material.grounding.navigator is not None
            else None
        )
        last_reply: RoleReply = {}

        def ask(prompt_context: EvidencePromptContext) -> RoleReply:
            nonlocal last_reply
            prefix = material.adversarial_prefix_for(prompt_context)
            prompt = challenger_prompt(
                prefix,
                candidates_to_obj(finder_findings),
                candidates_to_obj(known or [], include_evidence_refs=False),
            )
            result = self._provider.complete(
                system=CHALLENGER_SYSTEM,
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                cache_prefix=prefix,
            )
            last_reply = _role_response(
                result.text,
                "challenger",
                "rebuttals",
                "new_findings",
                optional_list_keys=("evidence_requests", "source_queries"),
                object_list_keys=("rebuttals",),
            )
            return last_reply

        judgment = run_evidence_judgment(
            material.grounding,
            ask=ask,
            findings_from_reply=lambda reply: self._candidates_from_reply({"findings": reply.get("new_findings", [])}),
            accumulator=candidate_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=(
                unit.remaining_followups
                if unit.remaining_followups is not None
                else DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups
            ),
            evidence_refs=lambda candidate: candidate.evidence_refs,
            navigation_session=navigation,
            model_role="challenger",
            model_unit_id=material.unit_name,
        )
        if judgment.failure_reason:
            raise RepositoryReviewError(judgment.failure_reason)
        return UnitChallenge(
            rebuttals=validate_rebuttal_records(
                last_reply["rebuttals"],
                role="repository challenger",
                candidate_ids={candidate.candidate_id for candidate in finder_findings},
                available_evidence_refs={
                    "seed",
                    *material.grounding.coverage.references,
                    *judgment.grounding.references,
                },
            ),
            new_findings=judgment.findings,
            grounding=judgment.grounding,
            source_evidence=judgment.source_evidence,
            evidence_exchanges=judgment.evidence_exchanges,
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
        pending: tuple[PendingWorkRecord, ...] = (),
    ) -> RoleJudgment[Candidate]:
        """Rule on finder and challenger candidates for one role-loop pass."""
        material = self._prompt_material(unit, shared_context)
        navigation = (
            unit.navigation_session
            if unit.navigation_session is not None
            else material.grounding.navigator.session()
            if material.grounding.navigator is not None
            else None
        )
        last_reply: RoleReply = {}

        def ask(prompt_context: EvidencePromptContext) -> RoleReply:
            nonlocal last_reply
            prefix = material.adversarial_prefix_for(prompt_context)
            prompt = judge_prompt(
                prefix,
                candidates_to_obj(finder_findings),
                rebuttals,
                candidates_to_obj(new_findings),
                candidates_to_obj(known or [], include_evidence_refs=False),
                vulnerability_categories=(unit.knowledge_pack.categories if unit.knowledge_pack is not None else ()),
                pending=list(pending),
            )
            result = self._provider.complete(
                system=JUDGE_SYSTEM,
                messages=[Message(role="user", content=prompt)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                cache_prefix=prefix,
            )
            last_reply = _role_response(
                result.text,
                "judge",
                "findings",
                optional_list_keys=("investigate", "resolved_pending", "evidence_requests", "source_queries"),
                object_list_keys=("investigate",),
            )
            return last_reply

        judgment = run_evidence_judgment(
            material.grounding,
            ask=ask,
            findings_from_reply=self._candidates_from_reply,
            accumulator=candidate_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=(
                unit.remaining_followups
                if unit.remaining_followups is not None
                else DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups
            ),
            evidence_refs=lambda candidate: candidate.evidence_refs,
            navigation_session=navigation,
            assigned_categories=unit.knowledge_pack.categories if unit.knowledge_pack is not None else (),
            finding_category=lambda candidate: candidate.category,
            known_categories={candidate.category for candidate in (known or ())},
            assessment_role="repository judge",
            model_role="judge",
            model_unit_id=material.unit_name,
        )
        if judgment.failure_reason:
            raise RepositoryReviewError(judgment.failure_reason)
        resolved = last_reply.get("resolved_pending", [])
        if not all(isinstance(item, str) for item in resolved):
            raise RepositoryReviewError("resolved_pending must contain string ids")
        known_pending = {item.get("id") for item in pending}
        unknown = [item for item in resolved if item not in known_pending]
        if unknown:
            raise RepositoryReviewError(f"resolved_pending contains unknown ids: {', '.join(unknown)}")
        return RoleJudgment(
            findings=judgment.findings,
            pending=cast(
                "list[PendingWorkRecord]",
                validate_pending_records(
                    last_reply.get("investigate", []),
                    role="repository judge",
                    candidate_ids={
                        candidate.candidate_id for candidate in (*finder_findings, *new_findings, *judgment.findings)
                    },
                ),
            ),
            resolved_pending=tuple(resolved),
            grounding=judgment.grounding,
            source_evidence=judgment.source_evidence,
            evidence_exchanges=judgment.evidence_exchanges,
            assessments=judgment.assessments,
        )
