"""Drive repository review through the model reviewer with scripted provider replies."""

import json
import re
from collections.abc import Callable

from cyberjury.providers.mock import MockProvider
from cyberjury.review.repository.context import ground_units
from cyberjury.review.repository.engine import (
    RepositoryExecutionOptions,
    RepositoryLifecycleOptions,
    RepositoryOutputOptions,
    RepositoryRoleOptions,
    RepositoryRunOptions,
    RepositoryVerificationOptions,
    run_repository_review,
)
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.verification import RefutationCheck, RefutationChecker
from cyberjury.sources.snapshot import capture_source_snapshot

EMPTY_REPLY = '{"findings": [], "evidence_requests": [], "source_queries": []}'

_UNIT = re.compile(r"Unit `([^`\n]+)`, the code to review:")

type UnitReply = list[dict] | Exception


def finding(file: str, line: int, title: str = "finding", **fields: object) -> dict:
    """Return one complete finder finding citing the unit seed evidence."""
    return {
        "title": title,
        "category": "insecure-direct-object-reference",
        "symbol": "",
        "endpoint": "",
        "file": file,
        "line": line,
        "severity": "HIGH",
        "attack_path": "attacker request reaches the unchecked operation",
        "evidence": f"{file}:{line} has no ownership check",
        "evidence_refs": ["seed"],
        **fields,
    }


def finder_reply(findings: list[dict] | None = None) -> str:
    """Return one finder reply with no evidence requests."""
    return json.dumps({"findings": findings or [], "evidence_requests": [], "source_queries": []})


def prompt_unit(messages) -> str:
    """Return the unit name rendered into one finder prompt."""
    match = _UNIT.search(messages[-1].content)
    if match is None:
        raise AssertionError("finder prompt names no unit")
    return match.group(1)


def unit_provider(reply_for: Callable[[str], UnitReply]) -> MockProvider:
    """Answer each finder call from its unit name, raising a returned exception."""

    def respond(_system, messages):
        reply = reply_for(prompt_unit(messages))
        if isinstance(reply, Exception):
            raise reply
        return finder_reply(reply)

    return MockProvider(responder=respond)


class UnitReviewError(RuntimeError):
    """A reviewed unit did not complete cleanly."""


def review(reviewer, unit, **values):
    """Ground an ungrounded unit, then return clean unit findings or raise the unit failure."""
    if unit.grounding is None:
        [unit] = ground_units(
            (unit,),
            facts_by_file={},
            limitations=(),
            navigator=None,
            source_snapshot=capture_source_snapshot(unit.root),
        )
    cycle = reviewer.review_unit(unit, finder_label=reviewer.label, **values)
    if not cycle.clean:
        raise UnitReviewError(cycle.failure_reason)
    return cycle.findings


class IndependentChecker(RefutationChecker):
    """Reject every refutation so verification retains the candidate."""

    def holds(self, candidate, refutation, root):
        """Keep the candidate."""
        return RefutationCheck(holds=False, reason="the candidate remains exploitable")


def run_review(target, workspace, **values):
    """Run one repository review from flat test options."""
    concurrency = values.pop("concurrency", DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency)
    roles = RepositoryRoleOptions(
        provider=values.pop("provider", None) or MockProvider(default=EMPTY_REPLY),
        model=values.pop("model", "mock"),
        **{key: values.pop(key) for key in ("finder_label",) if key in values},
    )
    if "verifier" in values and "confirmers" not in values:
        values["confirmers"] = (("independent", IndependentChecker()),)
    verification = RepositoryVerificationOptions(
        enabled=values.pop("verify", "verifier" in values),
        concurrency=concurrency,
        **{key: values.pop(key) for key in ("verifier", "confirmers", "on_verify") if key in values},
    )
    execution = RepositoryExecutionOptions(
        concurrency=concurrency,
        **{key: values.pop(key) for key in ("on_judgment",) if key in values},
    )
    output = RepositoryOutputOptions(
        **{key: values.pop(key) for key in ("profile", "poc_backend", "meter") if key in values}
    )
    lifecycle = RepositoryLifecycleOptions(fresh=values.pop("fresh", False))
    assert not values
    return run_repository_review(
        target,
        workspace,
        options=RepositoryRunOptions(
            roles=roles,
            verification=verification,
            execution=execution,
            lifecycle=lifecycle,
            output=output,
        ),
    )
