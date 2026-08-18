"""Evaluate benchmark cases through the coded Diff Review path.

It runs real project diffs through the review engine against a real provider and tallies which
findings checks the current model, prompt, and rules catch, and which clean checks
they wrongly flag. Real patch benchmarks come from project tasks in local or public eval
sources. They are grouped by the knowledge guides taxonomy and materialized by
`benchmarks.cases`, so adding one is a data change.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path

from cyberjury.finding import Finding
from cyberjury.profiles.base import ReviewProfile
from cyberjury.profiles.registry import get_profile
from cyberjury.providers.base import Provider
from cyberjury.review.diff.context import build_diff_context_collector
from cyberjury.review.diff.engine import run_diff_review
from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.trace import Trace, emit_trace
from cyberjury.review.verification import Confirmer, ModelRefutationChecker, ModelVerifier, Verifier
from evals.benchmarks.cases import (
    DiffCase,
    diff_text,
    ensure_git_target_refs,
    git_target_root,
)
from evals.benchmarks.prepare import prepare_git_scope
from evals.score.engine import score
from evals.score.report import Report
from evals.score.result import RepeatedResult, Result

Progress = Callable[[dict[str, object]], None]

__all__ = [
    "evaluate",
    "run_diff_cases",
]


def evaluate(
    cases: list[DiffCase],
    *,
    mode: str | None = None,
    rounds: int = 3,
    model_override: str | None = None,
    runs: int = 1,
    target: str = "diff",
    progress: Progress | None = None,
    trace: Trace | None = None,
) -> Result | RepeatedResult:
    """Run diff benchmark cases with product provider wiring."""
    from cyberjury.cli import build_diff_providers, diff_args_from_env

    provider_mode = mode or _default_provider_mode(cases)
    diff_args = diff_args_from_env(provider_mode, rounds=rounds)
    if model_override:
        diff_args.model = model_override
    provider, model, finder, finder_model, challenger, challenger_model, judge, judge_model = build_diff_providers(
        diff_args
    )
    run_count = max(1, runs)
    results = []
    for run_index in range(1, run_count + 1):
        result = run_diff_cases(
            cases,
            provider=provider,
            model=model,
            mode=mode,
            rounds=diff_args.rounds,
            finder_provider=finder,
            finder_model=finder_model,
            challenger_provider=challenger,
            challenger_model=challenger_model,
            judge_provider=judge,
            judge_model=judge_model,
            progress=_run_progress(progress, run_index, run_count),
            trace=_run_progress(trace, run_index, run_count),
        )
        result.target = target
        results.append(result)
    return RepeatedResult.from_runs(target, results) if run_count > 1 else results[0]


def _default_provider_mode(cases: list[DiffCase]) -> str:
    return "adversarial" if any(case.review_mode == "adversarial" for case in cases) else "standard"


def _run_progress(progress: Progress | None, run: int, runs: int) -> Progress | None:
    if progress is None:
        return None

    def write(event: dict[str, object]) -> None:
        progress({**event, "run": run, "runs": runs})

    return write


def run_diff_cases(
    cases: list[DiffCase],
    *,
    provider: Provider,
    model: str,
    mode: str | None = None,
    rounds: int = 3,
    finder_provider: Provider | None = None,
    finder_model: str | None = None,
    challenger_provider: Provider | None = None,
    challenger_model: str | None = None,
    judge_provider: Provider | None = None,
    judge_model: str | None = None,
    progress: Progress | None = None,
    trace: Trace | None = None,
) -> Result:
    """Run each diff case and fold its result into one batch score."""
    result = Result(target="diff")
    total = len(cases)
    for index, case in enumerate(cases, 1):
        case_result = _run_diff_case(
            case,
            index=index,
            total=total,
            provider=provider,
            model=model,
            mode=mode,
            rounds=rounds,
            finder_provider=finder_provider,
            finder_model=finder_model,
            challenger_provider=challenger_provider,
            challenger_model=challenger_model,
            judge_provider=judge_provider,
            judge_model=judge_model,
            progress=progress,
            trace=trace,
        )
        _merge_result(result, case_result)
    return result


def _merge_result(result: Result, case_result: Result) -> None:
    """Add one case score to the batch without changing score semantics."""
    result.found.extend(case_result.found)
    result.missed.extend(case_result.missed)
    result.false_positives.extend(case_result.false_positives)
    result.extra.extend(case_result.extra)
    result.file_found.extend(case_result.file_found)
    result.file_missed.extend(case_result.file_missed)
    result.n_findings += case_result.n_findings
    result.n_file_findings += case_result.n_file_findings
    result.n_reports += case_result.n_reports
    result.errors += case_result.errors
    result.error_details.extend(case_result.error_details)


def _run_diff_case(
    case: DiffCase,
    *,
    index: int,
    total: int,
    provider: Provider,
    model: str,
    mode: str | None,
    rounds: int,
    finder_provider: Provider | None,
    finder_model: str | None,
    challenger_provider: Provider | None,
    challenger_model: str | None,
    judge_provider: Provider | None,
    judge_model: str | None,
    progress: Progress | None,
    trace: Trace | None,
) -> Result:
    """Keep one case's lifecycle failures visible while delegating review mechanics."""
    res = Result(
        target="diff",
        n_findings=_finding_count(case),
        n_file_findings=_file_finding_count(case),
    )
    roles = _case_roles(
        case,
        mode=mode,
        model=model,
        finder_provider=finder_provider,
        finder_model=finder_model,
        challenger_provider=challenger_provider,
        challenger_model=challenger_model,
        judge_provider=judge_provider,
        judge_model=judge_model,
    )
    started = time.monotonic()
    _emit_progress(progress, "case_started", case, index, total, mode=roles.mode, model=model)
    case_trace = _case_trace(trace, case, index, total)
    on_batch, on_judgment = _case_progress_callbacks(progress, case, index, total, roles.mode, model, started)
    try:
        execution = _execute_case(
            case,
            provider=provider,
            model=model,
            rounds=rounds,
            roles=roles,
            on_batch=on_batch,
            on_judgment=on_judgment,
            trace=case_trace,
        )
    except Exception as exc:
        _record_case_failure(res, case, index, total, roles.mode, model, started, progress, exc)
        return res
    if execution.outcome.degraded:
        _record_case_failure(
            res,
            case,
            index,
            total,
            roles.mode,
            model,
            started,
            progress,
            _failure_summary(execution.outcome),
        )
        return res
    if execution.scored is not None:
        _finish_scored_case(res, execution.scored, case, index, total, roles.mode, model, started, progress)
        return res
    _finish_unkeyed_case(res, execution.findings, case, index, total, roles.mode, model, started, progress)
    return res


@dataclass(frozen=True, kw_only=True)
class _CaseRoles:
    mode: str
    finder_provider: Provider | None
    finder_model: str | None
    challenger_provider: Provider | None
    challenger_model: str | None
    judge_provider: Provider | None
    judge_model: str | None
    finder_label: str
    challenger_label: str
    judge_label: str


@dataclass(frozen=True, kw_only=True)
class _CaseExecution:
    outcome: ReviewOutcome[Finding]
    findings: list[Finding]
    scored: Result | None


def _case_roles(
    case: DiffCase,
    *,
    mode: str | None,
    model: str,
    finder_provider: Provider | None,
    finder_model: str | None,
    challenger_provider: Provider | None,
    challenger_model: str | None,
    judge_provider: Provider | None,
    judge_model: str | None,
) -> _CaseRoles:
    case_mode = mode or case.review_mode
    adversarial = case_mode == "adversarial"
    return _CaseRoles(
        mode=case_mode,
        finder_provider=finder_provider if adversarial else None,
        finder_model=finder_model if adversarial else None,
        challenger_provider=challenger_provider if adversarial else None,
        challenger_model=challenger_model if adversarial else None,
        judge_provider=judge_provider if adversarial else None,
        judge_model=judge_model if adversarial else None,
        finder_label=(finder_model if adversarial else None) or model,
        challenger_label=(challenger_model if adversarial else None) or model,
        judge_label=(judge_model if adversarial else None) or model,
    )


def _case_trace(trace: Trace | None, case: DiffCase, index: int, total: int) -> Trace | None:
    if trace is None:
        return None

    def write(event: dict[str, object]) -> None:
        event_name = str(event.get("event", "trace"))
        fields = {key: value for key, value in event.items() if key not in {"event", "schema"}}
        emit_trace(
            trace,
            event_name,
            **fields,
            case=case.name,
            index=index,
            total=total,
            run_context=case.review_context,
            profile=case.profile,
        )

    return write


def _case_progress_callbacks(
    progress: Progress | None,
    case: DiffCase,
    index: int,
    total: int,
    mode: str,
    model: str,
    started: float,
) -> tuple[Callable[[int, int, float], None], Callable[[int, int, str, float], None]]:
    def on_batch(done: int, batch_total: int, seconds: float) -> None:
        _emit_progress(
            progress,
            "case_batch_finished",
            case,
            index,
            total,
            mode=mode,
            model=model,
            elapsed_seconds=time.monotonic() - started,
            batch=done,
            batches=batch_total,
            batch_seconds=seconds,
        )

    def on_judgment(done: int, judgment_total: int, label: str, seconds: float) -> None:
        _emit_progress(
            progress,
            "case_judgment_finished",
            case,
            index,
            total,
            mode=mode,
            model=model,
            elapsed_seconds=time.monotonic() - started,
            judgment=done,
            judgments=judgment_total,
            judgment_label=label,
            judgment_seconds=seconds,
        )

    return on_batch, on_judgment


def _execute_case(
    case: DiffCase,
    *,
    provider: Provider,
    model: str,
    rounds: int,
    roles: _CaseRoles,
    on_batch: Callable[[int, int, float], None],
    on_judgment: Callable[[int, int, str, float], None],
    trace: Trace | None,
) -> _CaseExecution:
    diff = diff_text(case)
    profile = get_profile(case.profile)
    with _source_root(case) as root:
        review_root = _review_root(root, case.target) if root is not None else None
        _prepare_case_target(case, root, review_root)
        context, context_for_diff = _case_context(case, root, review_root, profile, diff)
        verifier, confirmers, found_by = _case_verification(case, root, profile, provider, roles)
        review = run_diff_review(
            diff,
            provider=provider,
            model=model,
            mode=roles.mode,
            max_rounds=rounds,
            finder_provider=roles.finder_provider,
            finder_model=roles.finder_model,
            challenger_provider=roles.challenger_provider,
            challenger_model=roles.challenger_model,
            judge_provider=roles.judge_provider,
            judge_model=roles.judge_model,
            finder_label=roles.finder_label,
            challenger_label=roles.challenger_label,
            judge_label=roles.judge_label,
            verification_root=str(root) if root and case.review_context == "repository" else None,
            verifier=verifier,
            verification_confirmers=confirmers,
            verification_found_by=found_by,
            profile=profile,
            context=context,
            context_for_diff=context_for_diff,
            on_batch=on_batch,
            on_judgment=on_judgment,
            trace=trace,
        )
        findings = review.outcome.findings
        scored = _score_case(case, findings, root, trace) if not review.outcome.degraded else None
        return _CaseExecution(outcome=review.outcome, findings=findings, scored=scored)


def _prepare_case_target(case: DiffCase, root: Path | None, review_root: Path | None) -> None:
    if root is None or review_root is None or case.profile != "evm" or case.review_context != "repository":
        return
    prepared = prepare_git_scope(case.name, case.target, root, review_root, verify=False)
    if not prepared.ok:
        raise RuntimeError(f"EVM target preparation failed: {prepared.detail}")


def _case_context(
    case: DiffCase,
    root: Path | None,
    review_root: Path | None,
    profile: ReviewProfile,
    diff: str,
) -> tuple[str, Callable[[str], str] | None]:
    if case.review_context != "repository":
        return "", None
    if case.context or root is None:
        return case.context, None
    collector = build_diff_context_collector(root, profile, facts_root=review_root, review_diff=diff)
    return collector.collect(diff).text, collector.text_for_diff


def _case_verification(
    case: DiffCase,
    root: Path | None,
    profile: ReviewProfile,
    provider: Provider,
    roles: _CaseRoles,
) -> tuple[Verifier | None, list[Confirmer] | None, tuple[str, ...]]:
    if root is None or case.review_context != "repository":
        return None, None, ()
    verifier_provider = roles.challenger_provider or provider
    verifier = ModelVerifier(provider=verifier_provider, model=roles.challenger_label, content=profile.paths)
    seen = {(verifier_provider, roles.challenger_label)}
    confirmers: list[Confirmer] = []
    judge_provider = roles.judge_provider or provider
    if roles.judge_label != roles.challenger_label and judge_provider is not None:
        confirmers.append((roles.judge_label, ModelRefutationChecker(provider=judge_provider, model=roles.judge_label)))
        seen.add((judge_provider, roles.judge_label))
    finder_provider = roles.finder_provider or provider
    if finder_provider is not None and (finder_provider, roles.finder_label) not in seen:
        confirmers.append(
            (roles.finder_label, ModelRefutationChecker(provider=finder_provider, model=roles.finder_label))
        )
    found_by = (roles.finder_label,) if roles.mode == "standard" else ()
    return verifier, confirmers, found_by


def _score_case(case: DiffCase, findings: list[Finding], root: Path | None, trace: Trace | None) -> Result | None:
    if case.answer_key is None:
        return None
    scored = score(
        case.answer_key,
        _reports_from_findings(findings),
        source_root=str(root) if root else None,
        endpoint_required=False,
        trace=trace,
    )
    if trace is not None:
        trace(
            {
                "event": "score",
                "stage": "finished",
                "reports": scored.n_reports,
                "found": scored.found,
                "missed": scored.missed,
                "extra": scored.extra,
            }
        )
    return scored


def _record_case_failure(
    result: Result,
    case: DiffCase,
    index: int,
    total: int,
    mode: str,
    model: str,
    started: float,
    progress: Progress | None,
    failure: Exception | str,
) -> None:
    error = f"{type(failure).__name__}: {failure}" if isinstance(failure, Exception) else failure
    result.errors += 1
    result.error_details.append(f"{case.name}: {error}")
    _emit_progress(
        progress,
        "case_failed",
        case,
        index,
        total,
        mode=mode,
        model=model,
        elapsed_seconds=time.monotonic() - started,
        error=error,
    )


def _finish_scored_case(
    result: Result,
    scored: Result,
    case: DiffCase,
    index: int,
    total: int,
    mode: str,
    model: str,
    started: float,
    progress: Progress | None,
) -> None:
    result.n_reports += scored.n_reports
    result.found.extend(scored.found)
    result.missed.extend(scored.missed)
    result.false_positives.extend(scored.false_positives)
    result.extra.extend(scored.extra)
    result.file_found.extend(scored.file_found)
    result.file_missed.extend(scored.file_missed)
    _emit_progress(
        progress,
        "case_finished",
        case,
        index,
        total,
        mode=mode,
        model=model,
        elapsed_seconds=time.monotonic() - started,
        reports=scored.n_reports,
        found=len(scored.found),
        missed=len(scored.missed),
        false_positives=len(scored.false_positives),
        extra=len(scored.extra),
    )


def _finish_unkeyed_case(
    result: Result,
    findings: list[Finding],
    case: DiffCase,
    index: int,
    total: int,
    mode: str,
    model: str,
    started: float,
    progress: Progress | None,
) -> None:
    result.n_reports += len(findings)
    hit = bool(findings)
    if case.is_positive:
        (result.found if hit else result.missed).append(case.name)
    elif hit:
        result.false_positives.append(case.name)
    _emit_progress(
        progress,
        "case_finished",
        case,
        index,
        total,
        mode=mode,
        model=model,
        elapsed_seconds=time.monotonic() - started,
        reports=len(findings),
        found=1 if case.is_positive and hit else 0,
        missed=1 if case.is_positive and not hit else 0,
        false_positives=1 if not case.is_positive and hit else 0,
        extra=0,
    )


def _emit_progress(
    progress: Progress | None,
    event: str,
    case: DiffCase,
    index: int,
    total: int,
    *,
    mode: str,
    model: str,
    elapsed_seconds: float | None = None,
    **extra: object,
) -> None:
    if progress is None:
        return
    payload: dict[str, object] = {
        "event": event,
        "case": case.name,
        "index": index,
        "total": total,
        "mode": mode,
        "model": model,
        "profile": case.profile,
        "review_context": case.review_context,
        "review_mode": case.review_mode,
    }
    if elapsed_seconds is not None:
        payload["elapsed_seconds"] = round(elapsed_seconds, 3)
    payload.update(extra)
    progress(payload)


def _finding_count(case: DiffCase) -> int:
    if case.answer_key:
        return len(case.answer_key.findings)
    return 1 if case.is_positive else 0


def _file_finding_count(case: DiffCase) -> int:
    if not case.answer_key:
        return 0
    return sum(1 for check in case.answer_key.findings if check.files)


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


def _failure_summary(outcome: ReviewOutcome[object]) -> str:
    """Return the specific degraded reason when the review can provide one."""
    states = []
    if outcome.failures:
        first = outcome.failures[0]
        suffix = f", and {len(outcome.failures) - 1} more" if len(outcome.failures) > 1 else ""
        states.append(f"{first.reason}{suffix}")
    if outcome.failure_reason:
        states.append(outcome.failure_reason)
    if outcome.errors:
        states.append(f"{outcome.errors} review or verification errors")
    if outcome.incomplete:
        states.append(f"{len(outcome.incomplete)} incomplete findings")
    if outcome.pending:
        states.append(f"{len(outcome.pending)} pending investigations")
    if outcome.requires_convergence and not outcome.converged:
        states.append("review did not converge")
    return ", ".join(states) or "review degraded"


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
    ensure_git_target_refs(target, root)
    with _target_tree(root, target.get("ref")) as source:
        yield source


def _review_root(root: Path, target: dict) -> Path:
    path = str(target.get("path") or "").strip()
    if not (target.get("url") or target.get("root")) or not path or path == ".":
        return root
    rel = Path(path)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"target path {path!r} must stay inside the repository")
    scoped = (root / rel).resolve()
    if not scoped.is_dir():
        raise ValueError(f"target path {path!r} does not exist in the checked out repository")
    return scoped


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
