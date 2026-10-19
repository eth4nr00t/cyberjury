"""Drive repository review through the model reviewer with scripted provider replies."""

import json
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from cyberjury.providers.mock import MockProvider
from cyberjury.review.facts import Facts
from cyberjury.review.finder import UnitFinder
from cyberjury.review.repository.context import Unit, ground_repository_unit
from cyberjury.review.repository.finder import REPOSITORY_TARGET
from cyberjury.review.repository.prepare import prepare_repository_review
from cyberjury.review.run import ReviewRun, run_review
from cyberjury.review.seats import ReviewSeats
from cyberjury.sources.snapshot import capture_source_snapshot
from tests.review.support import StubChecker, shared_grounding

EMPTY_REPLY = '{"findings": [], "evidence_requests": [], "source_queries": []}'

_SEED_FILE = re.compile(r"cited as `seed`:\n[`~]{3,}\n# file: (.+?) lines \d+-\d+\n")

type UnitReply = list[dict] | BaseException


def source_unit(root, file: str, *, name: str = "", **fields: object) -> Unit:
    """Return one ungrounded unit that reviews a whole source file."""
    size = len((Path(root) / file).read_text(encoding="utf-8"))
    name = name or file
    return Unit(name=name, root=str(root), file=file, span=(0, size), **{"id": f"unit-{name}", **fields})


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


def finder_reply(findings: list[dict] | None = None) -> str:
    """Return one finder reply with no evidence requests."""
    return json.dumps({"findings": findings or [], "evidence_requests": [], "source_queries": []})


def prompt_unit(messages) -> str:
    """Return the source file of the code under review in one finder prompt."""
    match = _SEED_FILE.search(messages[-1].content)
    if match is None:
        raise AssertionError("finder prompt has no code under review")
    return match.group(1)


def unit_provider(reply_for: Callable[[str], UnitReply]) -> MockProvider:
    """Answer each finder call from its reviewed file, raising a returned exception."""

    def respond(_system, messages):
        reply = reply_for(prompt_unit(messages))
        if isinstance(reply, BaseException):
            raise reply
        return finder_reply(reply)

    return MockProvider(responder=respond)


def ground(units, *, limitations=(), navigator=None) -> list[Unit]:
    """Ground ungrounded units against one shared context with explicit limitations and navigation."""
    shared = shared_grounding(Path(units[0].root), facts=Facts(limitations=tuple(limitations)), navigator=navigator)
    return [replace(unit, grounding=ground_repository_unit(unit, shared)) for unit in units]


def finder(provider, *, model: str = "mock") -> UnitFinder[Unit]:
    """Return the Repository Finder bound to one test provider."""
    return UnitFinder(REPOSITORY_TARGET, provider=provider, model=model, label=model)


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
    verifier=None,
    concurrency=1,
    finder_label="mock",
    confirmers=None,
    issue_judge=None,
    **values,
) -> ReviewRun:
    """Prepare and run one resumable repository review, rejecting refutations independently when verified."""
    if verifier is not None and confirmers is None:
        confirmers = (("independent", StubChecker(seat="independent")),)
    prepared = prepare_repository_review(capture_source_snapshot(target))
    return run_review(
        prepared,
        target=REPOSITORY_TARGET,
        seats=ReviewSeats(
            finder=provider or MockProvider(default=EMPTY_REPLY),
            finder_model="mock",
            finder_label=finder_label,
            verifier=verifier,
            confirmers=tuple(confirmers or ()),
            issue_judge=issue_judge,
        ),
        concurrency=concurrency,
        verification_concurrency=concurrency,
        work=Path(workspace) / prepared.shared.root.name,
        **values,
    )
