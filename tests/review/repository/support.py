"""Drive repository review through the model reviewer with scripted provider replies."""

import json
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from cyberjury.review.facts import Facts
from cyberjury.review.finder import UnitFinder
from cyberjury.review.repository.context import ground_repository_unit
from cyberjury.review.repository.finder import REPOSITORY_TARGET
from cyberjury.review.repository.model import RepositoryUnit
from cyberjury.review.repository.prepare import prepare_repository_review
from cyberjury.review.run import ReviewRun
from cyberjury.review.seats import ReviewSeats
from cyberjury.sources.snapshot import capture_source_snapshot
from tests.review.support import StubIssueJudge, recorder, run_prepared, shared_grounding
from tests.support import MockProvider

EMPTY_REPLY = '{"findings": [], "evidence_requests": [], "source_queries": []}'

_SEED_FILE = re.compile(r"cited as `seed`:\n[`~]{3,}\n# file: (.+?) lines \d+-\d+\n")

type UnitReply = list[dict] | BaseException


def source_unit(root, file: str, *, name: str = "", **fields: object) -> RepositoryUnit:
    """Return one ungrounded unit that reviews a whole source file."""
    size = len((Path(root) / file).read_text(encoding="utf-8"))
    name = name or file
    return RepositoryUnit(name=name, root=str(root), file=file, span=(0, size), **{"id": f"unit-{name}", **fields})


def finding(file: str, line: int, title: str = "finding", **fields: object) -> dict:
    """Return one complete finder finding citing the unit seed evidence."""
    return {
        "title": title,
        "category": "insecure-direct-object-reference",
        "severity": "HIGH",
        "entrypoint": "GET /records/<id>",
        "file": file,
        "line": line,
        "attack_path": "attacker request reaches the unchecked operation",
        "evidence": f"{file}:{line} has no ownership check",
        "evidence_refs": ["seed"],
        **fields,
    }


def finder_reply(
    findings: list[dict] | None = None,
    *,
    evidence_requests: list[str] | None = None,
    source_queries: list[dict] | None = None,
) -> str:
    """Return one finder reply with the given findings, evidence requests, and source queries."""
    return json.dumps(
        {
            "findings": findings or [],
            "evidence_requests": evidence_requests or [],
            "source_queries": source_queries or [],
        }
    )


def prompt_unit(prompt: str) -> str:
    """Return the source file of the code under review in one finder prompt."""
    match = _SEED_FILE.search(prompt)
    if match is None:
        raise AssertionError("finder prompt has no code under review")
    return match.group(1)


def unit_provider(reply_for: Callable[[str], UnitReply]) -> MockProvider:
    """Answer each finder call from its reviewed file, raising a returned exception."""

    def respond(_system, prompt):
        reply = reply_for(prompt_unit(prompt))
        if isinstance(reply, BaseException):
            raise reply
        return finder_reply(reply)

    return MockProvider(responder=respond)


def ground(units, *, limitations=(), navigator=None) -> list[RepositoryUnit]:
    """Ground ungrounded units against one shared context with explicit limitations and navigation."""
    shared = shared_grounding(Path(units[0].root), facts=Facts(limitations=tuple(limitations)), navigator=navigator)
    return [replace(unit, grounding=ground_repository_unit(unit, shared)) for unit in units]


def finder(provider, *, model: str = "mock") -> UnitFinder[RepositoryUnit]:
    """Return the Repository Finder bound to one test provider."""
    return UnitFinder(REPOSITORY_TARGET, provider=provider, model=model)


class UnitReviewError(RuntimeError):
    """A reviewed unit did not complete cleanly."""


def review(reviewer, unit):
    """Ground an ungrounded unit, then return clean unit findings or raise the unit failure."""
    if unit.grounding is None:
        [unit] = ground([unit])
    cycle = reviewer.review_unit(unit)
    if not cycle.clean:
        raise UnitReviewError(cycle.failure_reason)
    return cycle.findings


def run_repository_review(
    target,
    workspace,
    *,
    provider=None,
    concurrency=1,
    issue_judge=None,
    stages=None,
) -> ReviewRun:
    """Prepare and run one resumable repository review."""
    prepared = prepare_repository_review(capture_source_snapshot(target), recorder=recorder())
    return run_prepared(
        prepared,
        target=REPOSITORY_TARGET,
        seats=ReviewSeats(
            finder=provider or MockProvider(default=EMPTY_REPLY),
            finder_model="mock",
            issue_judge=issue_judge or StubIssueJudge(lambda _pair: False),
        ),
        concurrency=concurrency,
        review=Path(workspace),
        stages=stages,
    )
