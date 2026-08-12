"""Adapt repository units and provider replies to shared role contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from time import perf_counter

from cyberjury.domains.base import ContentPaths
from cyberjury.providers.base import Message, Provider
from cyberjury.resources import SEVERITY_RUBRIC_FILE, UNIT_REVIEW_FILE, VULNERABILITIES_DIR
from cyberjury.review.engine import (
    JudgmentProgress,
    ReviewCycle,
    RoleChallenge,
    RoleJudgment,
    RoleResponseError,
    parse_role_response,
    run_role_round,
    run_standard_judgments,
)
from cyberjury.review.paths import is_unsafe_rel
from cyberjury.review.repository.context import Unit, gather
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
from cyberjury.review.vulnerabilities import KnowledgePack, KnowledgePlan, VulnerabilityCatalog


class RepositoryReviewError(RuntimeError):
    """A unit reply cannot support a complete review result."""


def _role_response(
    text: str,
    role: str,
    *required_keys: str,
    optional_list_keys: tuple[str, ...] = (),
) -> dict:
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


_FACTS_PER_UNIT = 16_000


@dataclass(frozen=True, kw_only=True)
class _PromptMaterial:
    """One unit's evidence prefixes and complete knowledge work."""

    standard_prefix: str
    adversarial_prefix: str
    knowledge: KnowledgePlan


def candidates_from_obj(obj: object) -> list[Candidate]:
    """Map a model reply's `findings` list onto Candidates, tolerant of junk."""
    if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
        return []
    out: list[Candidate] = []
    for d in obj["findings"]:
        if not isinstance(d, dict):
            continue
        title = str(d.get("title") or d.get("description") or "").strip()
        if not title:
            continue
        line = d.get("line")
        sev = str(d.get("severity", "")).strip().upper()
        rel = str(d.get("file", "")).strip()
        file = "" if is_unsafe_rel(rel) else rel
        out.append(
            Candidate(
                title=title,
                category=str(d.get("category", "")).strip(),
                endpoint=str(d.get("endpoint") or d.get("source") or "").strip(),
                symbol=str(d.get("symbol") or "").strip(),
                file=file,
                line=line if isinstance(line, int) and not isinstance(line, bool) and line >= 1 else None,
                severity=sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
                evidence=str(d.get("evidence", "")).strip(),
                status="blocked" if str(d.get("status", "")).strip().lower() == "blocked" else "confirmed",
            )
        )
    return out


def candidates_to_obj(candidates: list[Candidate]) -> list[dict]:
    """Serialize candidates into the compact prompt form used across role passes."""
    out: list[dict] = []
    for cand in candidates:
        out.append(
            {
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
        )
    return out


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

    def find(self, unit: Unit, *, shared_context: str = "", known: list[Candidate] | None = None) -> list[Candidate]:
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
        rebuttals: list[dict],
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
) -> list[Candidate]:
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

    def find() -> list[Candidate]:
        return _find(finder, unit, shared_context, prior)

    def challenge_role(finder_findings: list[Candidate]) -> RoleChallenge[Candidate]:
        return _challenge(challenger, unit, finder_findings, shared_context, prior)

    def judge_role(
        finder_findings: list[Candidate],
        challenged: RoleChallenge[Candidate],
    ) -> RoleJudgment[Candidate]:
        return _judge(judge, unit, finder_findings, challenged, shared_context, prior)

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
    )


class ModelReviewer(UnitRoleReviewer):
    """Default reviewer: grounded model judgments over one repository unit."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = 4096,
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
        self._facts_by_base: dict[str, str] = {}
        for rel, block in self._facts_by_file.items():
            self._facts_by_base.setdefault(rel.rsplit("/", 1)[-1], block)

    @property
    def label(self) -> str:
        """The model name, used to tag which model surfaced a finding."""
        return self._model

    def _facts_for(self, unit: Unit) -> str:
        """Keep whole-file facts available when a unit contains only one source slice."""
        if not self._facts_by_file:
            return ""
        seen: set[str] = set()
        blocks: list[str] = []
        total = 0
        for rel in unit.files:
            block = self._facts_by_file.get(rel) or self._facts_by_base.get(rel.rsplit("/", 1)[-1])
            if not block or block in seen:
                continue
            seen.add(block)
            blocks.append(block)
            total += len(block)
            if total >= _FACTS_PER_UNIT:
                break
        text = "\n".join(blocks)
        return text[:_FACTS_PER_UNIT] if len(text) > _FACTS_PER_UNIT else text

    def _prompt_material(self, unit: Unit, shared_context: str) -> _PromptMaterial:
        source = gather(unit)
        unit_facts = self._facts_for(unit)
        knowledge = self._vulnerability_catalog.plan(source, unit_facts)
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
        source_block = f"Unit `{unit.name}`, the code to review:\n```\n{source}\n```\n\n"
        vulnerabilities = self._vulnerability_catalog.render(list(knowledge.selected))
        knowledge_block = (
            f"Vulnerability classes evidenced by this unit:\n{vulnerabilities}\n\n" if vulnerabilities else ""
        )
        return _PromptMaterial(
            standard_prefix=f"{head}{source_block}",
            adversarial_prefix=f"{head}{knowledge_block}{source_block}",
            knowledge=knowledge,
        )

    def _run_standard_judgment(
        self,
        material: _PromptMaterial,
        pack: KnowledgePack,
        *,
        known: list[Candidate],
        cache: bool,
    ) -> list[Candidate]:
        prompt = standard_finder_prompt_plan(
            material.standard_prefix,
            vulnerability_categories=pack.categories,
            selected_vulnerability_categories=tuple(item.id for item in material.knowledge.selected),
            vulnerabilities=pack.body,
            known=candidates_to_obj(known),
        )
        result = self._provider.complete(
            system=FINDER_SYSTEM,
            messages=[Message(role="user", content=prompt.text)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=cache,
            cache_prefix=prompt.stable_prefix if cache else "",
        )
        obj = _role_response(result.text, "unit finder", "findings")
        return candidates_from_obj(obj)

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

    def find(self, unit: Unit, *, shared_context: str = "", known: list[Candidate] | None = None) -> list[Candidate]:
        """Find candidates for a role-loop pass, carrying known findings forward."""
        material = self._prompt_material(unit, shared_context)
        prompt = finder_prompt(material.adversarial_prefix, candidates_to_obj(known or []))
        result = self._provider.complete(
            system=FINDER_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
            cache_prefix=material.adversarial_prefix,
        )
        obj = _role_response(result.text, "finder", "findings")
        return candidates_from_obj(obj)

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
            candidates_to_obj(known or []),
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
        return UnitChallenge(
            rebuttals=[r for r in obj.get("rebuttals", []) if isinstance(r, dict)],
            new_findings=candidates_from_obj({"findings": obj.get("new_findings", [])}),
        )

    def judge(
        self,
        unit: Unit,
        finder_findings: list[Candidate],
        rebuttals: list[dict],
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
            candidates_to_obj(known or []),
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
        return RoleJudgment(
            findings=candidates_from_obj(obj),
            pending=[item for item in obj.get("investigate", []) if isinstance(item, dict)],
        )
