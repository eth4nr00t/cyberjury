"""Adapt repository units and provider replies to the shared Finder judgment."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from cyberjury.profiles.base import ContentPaths
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.base import Message, Provider
from cyberjury.review.context import EvidencePromptContext, GroundingContext, source_location_receipt
from cyberjury.review.engine import (
    CorrectableRoleResponseError,
    EvidenceJudgment,
    JudgmentProgress,
    ReviewCycle,
    RoleReply,
    parse_role_response,
    run_evidence_judgment,
    run_grounded_judgment,
)
from cyberjury.review.knowledge import load_review_brief
from cyberjury.review.navigation import SourceNavigationSession, navigation_instructions
from cyberjury.review.paths import is_unsafe_rel
from cyberjury.review.prompts import fenced_source, inline_source
from cyberjury.review.repository.context import Unit
from cyberjury.review.repository.prompts import (
    FINDER_RESPONSE_SCHEMA,
    repository_finder_system,
    repository_prompt_plan,
)
from cyberjury.review.repository.union import Candidate, candidate_accumulator
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

type CandidateRecord = dict[str, object]


@dataclass(frozen=True, kw_only=True)
class _PromptMaterial:
    """One unit's syntax hints, source, and grounding."""

    head: str
    unit_name: str
    unit_id: str
    grounding: GroundingContext

    def evidence(self, context: EvidencePromptContext) -> str:
        """Render the stable unit evidence."""
        return f"{self.head}Unit {inline_source(self.unit_name)}, the code to review:\n{fenced_source(context.source)}"


def candidates_from_obj(
    obj: dict[str, object],
    *,
    canonicalize: Callable[[str], str] | None = None,
) -> list[Candidate]:
    """Map schema-valid findings and request a correction for values the schema cannot reject."""
    out: list[Candidate] = []
    corrections: list[str] = []
    for index, d in enumerate(obj["findings"]):
        violations = _semantic_violations(d, index)
        if violations:
            corrections.extend(violations)
            continue
        category = d["category"].strip()
        out.append(
            Candidate(
                title=d["title"].strip(),
                category=canonicalize(category) if canonicalize is not None else category,
                endpoint=d["endpoint"].strip(),
                symbol=d["symbol"].strip(),
                file=d["file"].strip(),
                line=d["line"],
                severity=d["severity"].strip().upper(),
                attack_path=d["attack_path"].strip(),
                evidence=d["evidence"].strip(),
                evidence_refs=tuple(d["evidence_refs"]),
            )
        )
    if corrections:
        raise CorrectableRoleResponseError(" ".join(corrections), tuple(out), tuple(out))
    return out


def _semantic_violations(d: dict[str, object], index: int) -> list[str]:
    """Name each schema-valid field value that cannot form a candidate."""
    violations = []
    missing = [field for field in ("title", "category", "evidence", "attack_path", "file") if not d[field].strip()]
    if missing:
        violations.append(f"findings[{index}] must have nonempty fields: {', '.join(missing)}.")
    if d["file"].strip() and is_unsafe_rel(d["file"].strip()):
        violations.append(f"findings[{index}].file must be a relative repository path.")
    if d["line"] < 1:
        violations.append(f"findings[{index}].line must be a positive integer.")
    refs = d["evidence_refs"]
    if not refs or not all(refs):
        violations.append(f"findings[{index}].evidence_refs must be a nonempty string list.")
    return violations


def candidates_to_obj(candidates: list[Candidate]) -> list[CandidateRecord]:
    """Serialize candidates into the compact prompt form used for provisional findings."""
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
            "evidence_refs": list(cand.evidence_refs),
        }
        out.append(item)
    return out


def candidates_to_memory(candidates: list[Candidate]) -> list[CandidateRecord]:
    """Return the minimum needed to recognize recorded findings."""
    return [
        {"title": candidate.title, "category": candidate.category, "file": candidate.file, "line": candidate.line}
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
        receipt = (
            source_location_receipt(
                file=candidate.file,
                line=candidate.line,
                evidence_refs=candidate.evidence_refs,
                seed_spans=grounding.source_spans,
                source_evidence=tuple(dict.fromkeys((*grounding.source_evidence, *cycle.source_evidence))),
            )
            if candidate.line is not None
            else None
        )
        if receipt is None:
            incomplete.append(candidate)
            continue
        valid.append(replace(candidate, file=receipt.file))
    if len(valid) == len(cycle.findings):
        return cycle if valid == cycle.findings else replace(cycle, findings=valid)
    reason = "one or more findings lack a cited source receipt for their primary location"
    return replace(
        cycle,
        findings=valid,
        incomplete=incomplete,
        errors=cycle.errors + 1,
        failure_reason="; ".join(filter(None, (cycle.failure_reason, reason))),
    )


class ModelReviewer:
    """Default reviewer: one grounded model judgment over one repository unit."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = DEFAULT_REVIEW_SETTINGS.execution.reviewer_max_output_tokens,
        content: ContentPaths | None = None,
        provenance_label: str = "",
    ) -> None:
        """Bind the provider and content paths used for unit review."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._provenance_label = provenance_label or model
        paths = content or default_profile().paths
        self._review_brief = load_review_brief(kernel_file=paths.security_kernel_file)
        rubric = paths.severity_rubric_file.read_text(encoding="utf-8")
        self._systems = {
            navigation: repository_finder_system(
                review_brief=self._review_brief.render(),
                severity_rubric=rubric,
                navigation=navigation_instructions() if navigation else "",
            )
            for navigation in (False, True)
        }

    @property
    def label(self) -> str:
        """The configured seat identity used for finding provenance."""
        return self._provenance_label

    def _candidates_from_reply(self, obj: object) -> list[Candidate]:
        """Normalize categories without a closed security taxonomy."""
        return candidates_from_obj(
            obj,
            canonicalize=self._review_brief.canonicalize_category,
        )

    def _prompt_material(self, unit: Unit, shared_context: str) -> _PromptMaterial:
        grounding = unit.grounding
        if grounding is None:
            raise ValueError(f"repository unit {unit.name} lacks initial grounding")
        unit_facts = grounding.facts
        head = (f"{shared_context.strip()}\n\n" if shared_context else "") + (
            f"Syntax hints for this unit (unverified; cite only delivered source):\n{unit_facts}\n\n"
            if unit_facts
            else ""
        )
        return _PromptMaterial(
            head=head,
            unit_name=unit.name,
            unit_id=unit.id or unit.name,
            grounding=grounding,
        )

    def _run_judgment(
        self,
        material: _PromptMaterial,
        navigation_session: SourceNavigationSession | None,
        *,
        known: list[Candidate],
    ) -> EvidenceJudgment[Candidate]:
        known_records = candidates_to_memory(known)

        def ask(prompt_context: EvidencePromptContext) -> RoleReply:
            prompt = repository_prompt_plan(
                material.evidence(prompt_context),
                known=known_records,
                catalog=prompt_context.catalog,
                followup=prompt_context.followup,
            )
            response_schema = FINDER_RESPONSE_SCHEMA
            result = self._provider.complete(
                system=self._systems[prompt_context.navigation_available],
                messages=[Message(role="user", content=prompt.text)],
                model=self._model,
                max_tokens=self._max_tokens,
                cache=True,
                cache_prefix=prompt.stable_prefix,
                response_schema=response_schema,
            )
            return parse_role_response(result.text, role="unit finder", response_schema=response_schema)

        return run_evidence_judgment(
            material.grounding,
            ask=ask,
            findings_from_reply=self._candidates_from_reply,
            accumulator=candidate_accumulator(),
            target_chars=DEFAULT_REVIEW_SETTINGS.execution.target_evidence_request_chars,
            max_followups=DEFAULT_REVIEW_SETTINGS.execution.max_source_navigation_followups,
            evidence_refs=lambda candidate: candidate.evidence_refs,
            navigation_session=navigation_session,
            model_role="finder",
            model_unit_id=material.unit_id,
            review_brief_sha256=self._review_brief.content_sha256,
            finding_prompt_record=lambda candidate: candidates_to_obj([candidate])[0],
        )

    def review_unit(
        self,
        unit: Unit,
        *,
        shared_context: str = "",
        finder_label: str,
        known: list[Candidate] | None = None,
        on_judgment: JudgmentProgress | None = None,
    ) -> ReviewCycle[Candidate]:
        """Complete one grounded brief judgment for a unit review."""
        material = self._prompt_material(unit, shared_context)
        cycle = run_grounded_judgment(
            material.grounding,
            run_judgment=lambda navigation: self._run_judgment(material, navigation, known=known or []),
            label=self._review_brief.label,
            finder_label=finder_label,
            on_judgment=on_judgment,
        )
        return validate_candidate_locations(cycle, material.grounding)
