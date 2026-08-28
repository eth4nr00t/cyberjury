"""Shared verified finding coverage keeps every path unless coverage is explicit."""

from dataclasses import dataclass

from cyberjury.providers.base import Message, Provider
from cyberjury.providers.mock import MockProvider
from cyberjury.review.consolidation import consolidate_verified_findings


@dataclass(frozen=True)
class _Finding:
    name: str
    category: str = "missing-authorization"


def _record(finding: _Finding) -> dict[str, str]:
    return {"category": finding.category, "description": finding.name}


def _reply(decisions: str) -> str:
    return f'{{"decisions":[{decisions}]}}'


def _keep(candidate_id: str) -> str:
    return f'{{"candidate_id":"{candidate_id}","verdict":"keep","covered_by":[],"reason":"independent path"}}'


def _covered(candidate_id: str, targets: str) -> str:
    return (
        f'{{"candidate_id":"{candidate_id}","verdict":"covered",'
        f'"covered_by":[{targets}],"reason":"all paths are represented"}}'
    )


def test_umbrella_may_be_covered_by_multiple_kept_findings():
    account = _Finding("account path")
    rule = _Finding("rule path")
    umbrella = _Finding("account and rule paths")
    provider = MockProvider(
        default=_reply(
            ",".join(
                (
                    _keep("candidate-1"),
                    _keep("candidate-2"),
                    _covered("candidate-3", '"candidate-1","candidate-2"'),
                )
            )
        )
    )

    result = consolidate_verified_findings(
        [account, rule, umbrella],
        provider=provider,
        model="model",
        record=_record,
    )

    assert result.findings == [account, rule]
    assert result.covered[0].finding == umbrella
    assert result.covered[0].covered_by == (account, rule)
    assert result.errors == 0


def test_missing_decision_keeps_every_verified_finding_and_fails_loud():
    findings = [_Finding("one"), _Finding("two")]
    provider = MockProvider(default=_reply(_keep("candidate-1")))

    result = consolidate_verified_findings(findings, provider=provider, model="model", record=_record)

    assert result.findings == findings
    assert result.covered == []
    assert result.errors == 1
    assert "every verified candidate" in result.error_details[0]


def test_distinct_vulnerability_classes_skip_coverage_adjudication():
    findings = [_Finding("authorization"), _Finding("injection", "sql-injection")]
    provider = MockProvider(default=_reply(",".join((_keep("candidate-1"), _covered("candidate-2", '"candidate-1"')))))

    result = consolidate_verified_findings(findings, provider=provider, model="model", record=_record)

    assert result.findings == findings
    assert result.errors == 0
    assert provider.calls == []


def test_uncategorized_findings_skip_coverage_adjudication():
    findings = [_Finding("first", ""), _Finding("second", "")]
    provider = MockProvider(default=_reply(_covered("candidate-1", '"candidate-2"')))

    result = consolidate_verified_findings(findings, provider=provider, model="model", record=_record)

    assert result.findings == findings
    assert result.errors == 0
    assert provider.calls == []


def test_repeated_category_is_consolidated_without_singleton_categories():
    findings = [
        _Finding("authorization one"),
        _Finding("authorization two"),
        _Finding("injection", "sql-injection"),
    ]
    provider = MockProvider(default=_reply(",".join((_keep("candidate-1"), _covered("candidate-2", '"candidate-1"')))))

    result = consolidate_verified_findings(findings, provider=provider, model="model", record=_record)

    assert result.findings == [findings[0], findings[2]]
    assert result.covered[0].finding == findings[1]
    assert result.errors == 0
    assert "injection" not in provider.calls[0]["messages"][0].content


def test_each_repeated_category_has_an_isolated_decision():
    findings = [
        _Finding("authorization one"),
        _Finding("injection one", "sql-injection"),
        _Finding("authorization two"),
        _Finding("injection two", "sql-injection"),
    ]
    provider = MockProvider(
        responses=[
            _reply(",".join((_keep("candidate-1"), _covered("candidate-2", '"candidate-1"')))),
            _reply(",".join((_keep("candidate-1"), _covered("candidate-2", '"candidate-1"')))),
        ]
    )

    result = consolidate_verified_findings(findings, provider=provider, model="model", record=_record)

    assert result.findings == [findings[0], findings[1]]
    assert [item.finding for item in result.covered] == [findings[2], findings[3]]
    assert len(provider.calls) == 2
    assert "sql-injection" not in provider.calls[0]["messages"][0].content
    assert "missing-authorization" not in provider.calls[1]["messages"][0].content


def test_later_group_failure_preserves_every_original_finding():
    findings = [
        _Finding("authorization one"),
        _Finding("injection one", "sql-injection"),
        _Finding("authorization two"),
        _Finding("injection two", "sql-injection"),
    ]
    provider = MockProvider(
        responses=[
            _reply(",".join((_keep("candidate-1"), _covered("candidate-2", '"candidate-1"')))),
            _reply(_keep("candidate-1")),
        ]
    )

    result = consolidate_verified_findings(findings, provider=provider, model="model", record=_record)

    assert result.findings == findings
    assert result.covered == []
    assert result.errors == 1
    assert "every verified candidate" in result.error_details[0]


def test_covered_finding_cannot_depend_on_another_covered_finding():
    findings = [_Finding("one"), _Finding("two"), _Finding("three")]
    provider = MockProvider(
        default=_reply(
            ",".join(
                (
                    _keep("candidate-1"),
                    _covered("candidate-2", '"candidate-1"'),
                    _covered("candidate-3", '"candidate-2"'),
                )
            )
        )
    )

    result = consolidate_verified_findings(findings, provider=provider, model="model", record=_record)

    assert result.findings == findings
    assert result.errors == 1
    assert "non-kept candidate" in result.error_details[0]


class _BrokenProvider(Provider):
    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
        cache_prefix: str = "",
    ):
        raise RuntimeError("rate limited")


def test_provider_failure_preserves_all_verified_findings():
    findings = [_Finding("one"), _Finding("two")]

    result = consolidate_verified_findings(
        findings,
        provider=_BrokenProvider(),
        model="model",
        record=_record,
    )

    assert result.findings == findings
    assert result.errors == 1
    assert result.error_details == ["RuntimeError: rate limited"]
