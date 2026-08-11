"""Diff-path eval runner: run diff benchmark tasks through the audit engine and score.

It runs real project diffs through audit_diff against a real provider and tallies which
planted issues the current model, prompt, and rules catch, and which safe lookalikes
they wrongly flag. Real patch benchmarks come from project tasks in local or public eval
sources. They are grouped by the knowledge guides taxonomy, see diff_cases.py for the
loader, so adding one is a data change.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path

from cyberjury.domains.registry import get_domain
from cyberjury.finding import Finding
from cyberjury.review.diff.context import build_diff_context_collector
from cyberjury.review.diff.engine import audit_diff
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.repository.verifier import ModelRefutationChecker, ModelVerifier
from evals.diff_cases import (
    DiffCase,
    default_cases,
    diff_text,
    ensure_git_target_refs,
    git_target_root,
    load_project_diff_cases,
)
from evals.prepare import prepare_git_scope
from evals.results import Result
from evals.schema import Report
from evals.scorers.score import score

Progress = Callable[[dict[str, object]], None]

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
    mode: str | None = None,
    rounds: int = 3,
    finder_provider=None,
    finder_model=None,
    challenger_provider=None,
    challenger_model=None,
    judge_provider=None,
    judge_model=None,
    progress: Progress | None = None,
) -> Result:
    """Run every case through audit_diff and fold into a Result.

    A positive is found when the audit returns any finding, a safe case is a false positive
    when it does. Each case runs under its own domain, so a Solidity case scores against the
    evm knowledge and prompt rather than the web default. The seats and rounds come from the
    same wiring the `review diff` CLI builds, so the benchmark reviews a diff the way the
    product does. An unusable model reply is counted as an error, not silently a clean pass,
    invariant 4.
    """
    res = Result(
        target="diff",
        n_planted=sum(_planted_count(c) for c in cases),
        n_file_planted=sum(_file_planted_count(c) for c in cases),
    )
    total = len(cases)
    for index, c in enumerate(cases, 1):
        case_mode = mode or c.review_mode
        case_finder_provider = finder_provider if case_mode == "adversarial" else None
        case_finder_model = finder_model if case_mode == "adversarial" else None
        case_challenger_provider = challenger_provider if case_mode == "adversarial" else None
        case_challenger_model = challenger_model if case_mode == "adversarial" else None
        case_judge_provider = judge_provider if case_mode == "adversarial" else None
        case_judge_model = judge_model if case_mode == "adversarial" else None
        started = time.monotonic()
        _emit_progress(progress, "case_started", c, index, total, mode=case_mode, model=model)
        try:
            diff = diff_text(c)
            domain = get_domain(c.domain)

            def on_batch(
                done: int,
                batch_total: int,
                seconds: float,
                *,
                case: DiffCase = c,
                case_index: int = index,
                case_started: float = started,
                case_review_mode: str = case_mode,
            ) -> None:
                _emit_progress(
                    progress,
                    "case_batch_finished",
                    case,
                    case_index,
                    total,
                    mode=case_review_mode,
                    model=model,
                    elapsed_seconds=time.monotonic() - case_started,
                    batch=done,
                    batches=batch_total,
                    batch_seconds=seconds,
                )

            with _source_root(c) as root:
                context_for_diff = None
                context = c.context if c.review_context == "repository" else ""
                review_root = _review_root(root, c.target) if root is not None else None
                if (
                    root is not None
                    and review_root is not None
                    and c.domain == "evm"
                    and c.review_context == "repository"
                ):
                    prepared = prepare_git_scope(c.name, c.target, root, review_root, verify=False)
                    if not prepared.ok:
                        raise RuntimeError(f"EVM target preparation failed: {prepared.detail}")
                if not context and root and c.review_context == "repository":
                    context_collector = build_diff_context_collector(
                        root,
                        domain,
                        facts_root=review_root,
                        review_diff=diff,
                    )
                    context = context_collector.collect(diff).text
                    context_for_diff = context_collector.text_for_diff
                verifier = None
                verification_confirmers = None
                verification_found_by: tuple[str, ...] = ()
                finder_label = case_finder_model or model
                challenger_label = case_challenger_model or model
                judge_label = case_judge_model or model
                if root is not None and c.review_context == "repository":
                    verifier_provider = case_challenger_provider or provider
                    verifier_model = challenger_label
                    verifier = ModelVerifier(provider=verifier_provider, model=verifier_model, content=domain.paths)
                    seen_confirmers = {(verifier_provider, verifier_model)}
                    verification_confirmers = []
                    judge_checker_provider = case_judge_provider or provider
                    if judge_label != verifier_model and judge_checker_provider is not None:
                        verification_confirmers.append(
                            (
                                judge_label,
                                ModelRefutationChecker(provider=judge_checker_provider, model=judge_label),
                            )
                        )
                        seen_confirmers.add((judge_checker_provider, judge_label))
                    if case_mode == "standard":
                        verification_found_by = (finder_label,)
                    finder_checker_provider = case_finder_provider or provider
                    if finder_checker_provider is not None:
                        finder_key = (finder_checker_provider, finder_label)
                        if finder_key not in seen_confirmers:
                            verification_confirmers.append(
                                (
                                    finder_label,
                                    ModelRefutationChecker(provider=finder_checker_provider, model=finder_label),
                                )
                            )
                batch_failures: list[ReviewUnitFailure] = []
                kept, _dropped, degraded = audit_diff(
                    diff,
                    provider=provider,
                    model=model,
                    mode=case_mode,
                    max_rounds=rounds,
                    finder_provider=case_finder_provider,
                    finder_model=case_finder_model,
                    challenger_provider=case_challenger_provider,
                    challenger_model=case_challenger_model,
                    judge_provider=case_judge_provider,
                    judge_model=case_judge_model,
                    finder_label=finder_label,
                    challenger_label=challenger_label,
                    judge_label=judge_label,
                    verification_root=str(root) if root and c.review_context == "repository" else None,
                    verifier=verifier,
                    verification_confirmers=verification_confirmers,
                    verification_found_by=verification_found_by,
                    domain=domain,
                    context=context,
                    context_for_diff=context_for_diff,
                    on_batch=on_batch,
                    batch_failures=batch_failures,
                )
                if c.answer_key and not degraded:
                    scored = score(c.answer_key, _reports_from_findings(kept), source_root=str(root) if root else None)
        except Exception as exc:
            res.errors += 1
            error = f"{type(exc).__name__}: {exc}"
            res.error_details.append(f"{c.name}: {error}")
            _emit_progress(
                progress,
                "case_failed",
                c,
                index,
                total,
                mode=case_mode,
                model=model,
                elapsed_seconds=time.monotonic() - started,
                error=error,
            )
            continue
        if degraded:
            res.errors += 1
            error = _failure_summary(batch_failures)
            res.error_details.append(f"{c.name}: {error}")
            _emit_progress(
                progress,
                "case_failed",
                c,
                index,
                total,
                mode=case_mode,
                model=model,
                elapsed_seconds=time.monotonic() - started,
                error=error,
            )
            continue
        if c.answer_key:
            res.n_reports += scored.n_reports
            res.found.extend(scored.found)
            res.missed.extend(scored.missed)
            res.false_positives.extend(scored.false_positives)
            res.extra.extend(scored.extra)
            res.file_found.extend(scored.file_found)
            res.file_missed.extend(scored.file_missed)
            _emit_progress(
                progress,
                "case_finished",
                c,
                index,
                total,
                mode=case_mode,
                model=model,
                elapsed_seconds=time.monotonic() - started,
                reports=scored.n_reports,
                found=len(scored.found),
                missed=len(scored.missed),
                false_positives=len(scored.false_positives),
                extra=len(scored.extra),
            )
            continue
        res.n_reports += len(kept)
        hit = len(kept) > 0
        if c.is_positive:
            (res.found if hit else res.missed).append(c.name)
        elif hit:
            res.false_positives.append(c.name)
        _emit_progress(
            progress,
            "case_finished",
            c,
            index,
            total,
            mode=case_mode,
            model=model,
            elapsed_seconds=time.monotonic() - started,
            reports=len(kept),
            found=1 if c.is_positive and hit else 0,
            missed=1 if c.is_positive and not hit else 0,
            false_positives=1 if not c.is_positive and hit else 0,
            extra=0,
        )
    return res


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
        "domain": case.domain,
        "review_context": case.review_context,
        "review_mode": case.review_mode,
    }
    if elapsed_seconds is not None:
        payload["elapsed_seconds"] = round(elapsed_seconds, 3)
    payload.update(extra)
    progress(payload)


def _planted_count(case: DiffCase) -> int:
    if case.answer_key:
        return len(case.answer_key.planted)
    return 1 if case.is_positive else 0


def _file_planted_count(case: DiffCase) -> int:
    if not case.answer_key:
        return 0
    return sum(1 for entry in case.answer_key.planted if entry.files)


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


def _failure_summary(failures: list[ReviewUnitFailure]) -> str:
    """Return the specific degraded reason when audit_diff can provide one."""
    if not failures:
        return "review degraded"
    first = failures[0]
    suffix = f", and {len(failures) - 1} more" if len(failures) > 1 else ""
    return f"{first.reason}{suffix}"


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
    if not target.get("url") or not path or path == ".":
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
