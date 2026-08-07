"""Diff-path eval runner: run diff benchmark tasks through the audit engine and score.

It runs real project diffs through audit_diff against a real provider and tallies which planted
issues the current model, prompt, and rules catch, and which safe lookalikes they wrongly flag.
Real patch benchmarks come from project tasks in local or public eval sources. They are grouped by
the knowledge guides taxonomy, see diff_cases.py for the loader, so adding one is a data change.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path

from cyberjury.domains.registry import get_domain
from cyberjury.finding import Finding
from cyberjury.review.diff.context import build_diff_context_collector
from cyberjury.review.diff.engine import audit_diff
from cyberjury.review.repository.verifier import ModelRefutationChecker, ModelVerifier
from evals.diff_cases import (
    DiffCase,
    default_cases,
    diff_text,
    git_target_root,
    load_project_diff_cases,
)
from evals.results import Result
from evals.schema import Report
from evals.scorers.score import score

__all__ = [
    "DiffCase",
    "default_cases",
    "load_project_diff_cases",
    "run_diff_cases",
]


def run_diff_cases(
    cases: list[DiffCase],
    *,
    provider,
    model: str,
    mode: str = "standard",
    rounds: int = 3,
    finder_provider=None,
    finder_model=None,
    challenger_provider=None,
    challenger_model=None,
    judge_provider=None,
    judge_model=None,
) -> Result:
    """Run every case through audit_diff and fold into a Result. A positive is found when
    the audit returns any finding, a safe case is a false positive when it does. Each case
    runs under its own domain, so a Solidity case scores against the evm knowledge and
    prompt rather than the web default. The seats and rounds come from the same wiring the
    `review diff` CLI builds, so the benchmark reviews a diff the way the product does. An
    unusable model reply is counted as an error, not silently a clean pass, invariant 4."""
    res = Result(target="diff", n_planted=sum(_planted_count(c) for c in cases))
    for c in cases:
        try:
            diff = diff_text(c)
            domain = get_domain(c.domain)
            with _source_root(c) as root:
                context_for_diff = None
                context = c.context
                if not context and root:
                    context_collector = build_diff_context_collector(root, domain)
                    context = context_collector.collect(diff).text
                    context_for_diff = context_collector.text_for_diff
                verifier = None
                verification_confirmers = None
                if root is not None:
                    verifier_provider = challenger_provider or provider
                    verifier_model = challenger_model or model
                    checker_provider = judge_provider or provider
                    checker_model = judge_model or model
                    verifier = ModelVerifier(provider=verifier_provider, model=verifier_model, content=domain.paths)
                    verification_confirmers = [
                        ("", ModelRefutationChecker(provider=checker_provider, model=checker_model))
                    ]
                kept, _dropped, degraded = audit_diff(
                    diff,
                    provider=provider,
                    model=model,
                    mode=mode,
                    max_rounds=rounds,
                    finder_provider=finder_provider,
                    finder_model=finder_model,
                    challenger_provider=challenger_provider,
                    challenger_model=challenger_model,
                    judge_provider=judge_provider,
                    judge_model=judge_model,
                    verification_root=str(root) if root else None,
                    verifier=verifier,
                    verification_confirmers=verification_confirmers,
                    domain=domain,
                    context=context,
                    context_for_diff=context_for_diff,
                )
                if c.answer_key and not degraded:
                    scored = score(c.answer_key, _reports_from_findings(kept), source_root=str(root) if root else None)
        except Exception:
            # a failed or unparsable model call is a failed case, counted not hidden,
            # so a provider outage cannot read as a clean benchmark run, invariant 4
            res.errors += 1
            continue
        if degraded:
            # a degraded audit, such as an unusable judge or verifier, is a failed step too,
            # not a clean zero-finding result, invariant 4
            res.errors += 1
            continue
        if c.answer_key:
            res.n_reports += scored.n_reports
            res.found.extend(scored.found)
            res.missed.extend(scored.missed)
            res.false_positives.extend(scored.false_positives)
            res.extra.extend(scored.extra)
            continue
        res.n_reports += len(kept)
        hit = len(kept) > 0
        if c.is_positive:
            (res.found if hit else res.missed).append(c.name)
        elif hit:
            res.false_positives.append(c.name)
    return res


def _planted_count(case: DiffCase) -> int:
    if case.answer_key:
        return len(case.answer_key.planted)
    return 1 if case.is_positive else 0


def _reports_from_findings(findings: list[Finding]) -> list[Report]:
    out: list[Report] = []
    for i, finding in enumerate(findings):
        text = " ".join(
            (
                finding.description,
                finding.exploit_scenario,
                finding.recommendation,
            )
        )
        lines = [finding.line] if finding.line else []
        out.append(
            Report.make(
                f"{finding.file}:{finding.line or 0}:{i}",
                "",
                finding.category,
                [finding.file],
                text=text,
                lines=lines,
            )
        )
    return out


@contextmanager
def _source_root(case: DiffCase) -> Iterator[Path | None]:
    target = case.target
    if target.get("type") != "git":
        with nullcontext(None) as root:
            yield root
        return
    root = git_target_root(target)
    if root is None:
        with nullcontext(None) as source:
            yield source
        return
    with _target_tree(root, target.get("ref")) as source:
        yield source


@contextmanager
def _target_tree(root: Path, ref: str | None) -> Iterator[Path]:
    if not ref:
        yield root
        return
    tmp = Path(tempfile.mkdtemp(prefix="cyberjury-diff-target-"))
    try:
        subprocess.run(
            ["git", "-C", str(root), "worktree", "add", "--detach", "--quiet", str(tmp), str(ref)],
            check=True,
            capture_output=True,
            text=True,
        )
        yield tmp
    finally:
        subprocess.run(
            ["git", "-C", str(root), "worktree", "remove", "--force", str(tmp)],
            check=False,
            capture_output=True,
            text=True,
        )
        shutil.rmtree(tmp, ignore_errors=True)
