"""The per-unit reviewer: review one unit deeply and return its candidate findings.

This is the seam between the coded orchestration and the model judgment. The
orchestration owns what is mechanical, the worklist, the role passes, the union, and
the convergence. The reviewer owns the one thing that is judgment, reading a small slice
of code deeply and deciding what is exploitable. It is an interface so the judgment
backend can change, a single grounded model call today, a tool-using agent later,
without touching the orchestration. The default `ModelReviewer` makes one
`provider.complete` call per unit per pass: it gathers the unit's code, prepends the
shared mandate and the severity rubric, and parses the returned JSON into `Candidate`s.
It names no language, the unit's files come from the data-driven worklist.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass

from cyberjury.domains.base import ContentPaths
from cyberjury.json_parse import require_json_object
from cyberjury.providers.base import Message, Provider
from cyberjury.resources import SEVERITY_RUBRIC_FILE, UNIT_REVIEW_FILE, VULNERABILITIES_DIR
from cyberjury.review.repository.paths import is_unsafe_rel
from cyberjury.review.repository.shapes import JSON_SHAPE, Unit, gather, review_focus
from cyberjury.review.repository.union import Candidate
from cyberjury.review.vulnerabilities import load_vulnerabilities, vulnerabilities_for_review


class RepositoryReviewError(RuntimeError):
    """A unit review reply could not be parsed into a result, so it is a failed review.

    not an empty one. Raised instead of returning no findings, mirroring the diff engine's
    AuditError, so the pass-loop counts the failure and never reads an unusable reply such
    as a refusal or an error page as a clean unit.
    """


_FACTS_PER_UNIT = 16_000


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


@dataclass(frozen=True, kw_only=True)
class UnitChallenge:
    """Challenger output for one unit role pass."""

    rebuttals: list[dict]
    new_findings: list[Candidate]


class UnitReviewer(ABC):
    """Interface for reviewing one repository unit."""

    @abstractmethod
    def review(self, unit: Unit, *, shared_context: str = "") -> list[Candidate]:
        """Deeply review one unit and return candidate findings."""


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
    ) -> list[Candidate]:
        """Rule on finder and challenger candidates for one unit."""
        return finder_findings + new_findings


_SYSTEM = (
    "You are a senior application security engineer reviewing one slice of a codebase. "
    "Report only real, evidenced findings, each graded by the rubric and located at a "
    "file:line. Respond with a single JSON object and nothing else."
)

_CHALLENGER_SYSTEM = (
    "You are a skeptical security reviewer. Refute unsafe claims only when the unit shows "
    "a controlling safety fact, and independently report real issues the finder missed. "
    "Respond with a single JSON object and nothing else."
)

_JUDGE_SYSTEM = (
    "You are an impartial security judge. Weigh the finder and challenger evidence for "
    "one repository unit and keep every candidate the code supports. Respond with a "
    "single JSON object and nothing else."
)

_CHALLENGE_SHAPE = (
    '{"rebuttals": [{"target": "finding title or file:line", "verdict": "dismiss|downgrade", '
    '"reason": "controlling fact at file:line"}], "new_findings": '
    '[{"title": "...", "category": "<class id>", "symbol": "identifier", "endpoint": "METHOD /path or empty", '
    '"file": "path", "line": 0, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
    '"evidence": "controlling fact at file:line", "status": "confirmed|blocked"}]}'
)

_JUDGE_SHAPE = (
    '{"findings": [{"title": "...", "category": "<class id>", "symbol": "identifier", '
    '"endpoint": "METHOD /path or empty", "file": "path", "line": 0, '
    '"severity": "CRITICAL|HIGH|MEDIUM|LOW", "evidence": "controlling fact at file:line", '
    '"status": "confirmed|blocked"}], "investigate": [{"target": "...", "reason": "..."}], '
    '"converged": true}'
)


def _known_block(known: list[Candidate] | None) -> str:
    if not known:
        return ""
    return (
        "Findings carried from earlier repository passes. Do not rewrite these unless the "
        "current unit adds a stronger location, evidence, or a distinct exploit path:\n"
        f"{json.dumps(candidates_to_obj(known), ensure_ascii=False)}\n\n"
    )


class ModelReviewer(UnitRoleReviewer):
    """Default reviewer: one grounded model call per unit per pass."""

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
        self._vulnerability_catalog = load_vulnerabilities(vulnerabilities_dir)
        self._allowed_categories = ", ".join(vulnerability.id for vulnerability in self._vulnerability_catalog)
        self._facts_by_file = facts_by_file or {}
        self._facts_by_base: dict[str, str] = {}
        for rel, block in self._facts_by_file.items():
            self._facts_by_base.setdefault(rel.rsplit("/", 1)[-1], block)

    @property
    def label(self) -> str:
        """The model name, used to tag which model surfaced a finding."""
        return self._model

    def _facts_for(self, unit: Unit) -> str:
        """The facts for the files this unit owns.

        so a unit reviewing one slice of a large file still carries that file's whole call
        graph, the cross-slice signal.
        """
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

    def _stable_prefix(self, unit: Unit, shared_context: str) -> str:
        source = gather(unit)
        unit_facts = self._facts_for(unit)
        vulnerabilities = vulnerabilities_for_review(
            source,
            context=unit_facts,
            catalog=self._vulnerability_catalog,
        )
        return (
            f"{self._mandate}\n\n---\nSeverity rubric:\n{self._rubric}\n\n---\n"
            + (f"Shared review context:\n{shared_context}\n\n" if shared_context else "")
            + (
                f"Tool-extracted facts for this unit, the call graph and other structure "
                f"the slice below may not show in full:\n{unit_facts}\n\n"
                if unit_facts
                else ""
            )
            + f"Allowed finding categories:\n{self._allowed_categories}\n\n"
            + (f"Vulnerability classes evidenced by this unit:\n{vulnerabilities}\n\n" if vulnerabilities else "")
            + f"Unit `{unit.name}`, the code to review:\n```\n{source}\n```\n\n"
        )

    def review(self, unit: Unit, *, shared_context: str = "") -> list[Candidate]:
        """The focus line trails the stable cache prefix."""
        stable_prefix = self._stable_prefix(unit, shared_context)
        prompt = stable_prefix + review_focus() + f"Respond with a single JSON object exactly like:\n{JSON_SHAPE}"
        result = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
            cache_prefix=stable_prefix,
        )
        obj = require_json_object(
            result.text,
            required_key="findings",
            error=RepositoryReviewError,
            message="the unit review reply had no JSON object, or a JSON object without a "
            "findings key, so it is a failed review rather than a clean unit",
        )
        return candidates_from_obj(obj)

    def find(self, unit: Unit, *, shared_context: str = "", known: list[Candidate] | None = None) -> list[Candidate]:
        """Find candidates for a role-loop pass, carrying known findings forward."""
        stable_prefix = self._stable_prefix(unit, shared_context)
        prompt = (
            stable_prefix
            + "Find every exploitable vulnerability in this unit.\n\n"
            + _known_block(known)
            + f"Respond with a single JSON object exactly like:\n{JSON_SHAPE}"
        )
        result = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
            cache_prefix=stable_prefix,
        )
        obj = require_json_object(
            result.text,
            required_key="findings",
            error=RepositoryReviewError,
            message="the finder reply had no JSON object, or a JSON object without a findings key, "
            "so it is a failed review rather than a clean unit",
        )
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
        stable_prefix = self._stable_prefix(unit, shared_context)
        prompt = (
            stable_prefix
            + "Two tasks for this repository unit.\n"
            + "1. Rebut a reported finding only when this unit shows the controlling fact that makes it safe.\n"
            + "2. Independently scan the same unit and report any real issue the finder missed.\n\n"
            + _known_block(known)
            + f"Finder findings:\n{json.dumps(candidates_to_obj(finder_findings), ensure_ascii=False)}\n\n"
            + f"Respond with a single JSON object exactly like:\n{_CHALLENGE_SHAPE}"
        )
        result = self._provider.complete(
            system=_CHALLENGER_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
            cache_prefix=stable_prefix,
        )
        obj = require_json_object(
            result.text,
            required_key="rebuttals",
            error=RepositoryReviewError,
            message="the challenger reply had no JSON object, or a JSON object without a rebuttals key, "
            "so it is a failed review rather than a clean unit",
        )
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
    ) -> list[Candidate]:
        """Rule on finder and challenger candidates for one role-loop pass."""
        stable_prefix = self._stable_prefix(unit, shared_context)
        prompt = (
            stable_prefix
            + "Rule on each candidate finding from the two independent reviews below.\n"
            + "Keep every finding the unit supports. Dismiss only when this unit shows the controlling safety fact.\n\n"
            + _known_block(known)
            + f"Finder findings:\n{json.dumps(candidates_to_obj(finder_findings), ensure_ascii=False)}\n\n"
            + f"Challenger rebuttals:\n{json.dumps(rebuttals, ensure_ascii=False)}\n\n"
            + f"Challenger independent findings:\n{json.dumps(candidates_to_obj(new_findings), ensure_ascii=False)}\n\n"
            + f"Respond with a single JSON object exactly like:\n{_JUDGE_SHAPE}"
        )
        result = self._provider.complete(
            system=_JUDGE_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=True,
            cache_prefix=stable_prefix,
        )
        obj = require_json_object(
            result.text,
            required_key="findings",
            error=RepositoryReviewError,
            message="the judge reply had no JSON object, or a JSON object without a findings key, "
            "so it is a failed review rather than a clean unit",
        )
        return candidates_from_obj(obj)
