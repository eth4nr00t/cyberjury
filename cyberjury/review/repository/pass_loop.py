"""The pass loop runs deterministic unit review rounds to convergence."""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from time import perf_counter

from cyberjury.review.repository.reviewer import UnitChallenge, UnitReviewer
from cyberjury.review.repository.shapes import Unit
from cyberjury.review.repository.union import Accumulator, Candidate


def _review_label(rv: UnitReviewer, fallback: str) -> str:
    return getattr(rv, "label", "") or fallback


def _known_for_unit(acc: Accumulator, unit: Unit) -> list:
    files = set(unit.files)
    return [cand for cand in acc.findings if not cand.file or cand.file in files]


def _find(rv: UnitReviewer, unit: Unit, shared_context: str, known: list):
    find = getattr(rv, "find", None)
    if callable(find):
        return find(unit, shared_context=shared_context, known=known)
    return rv.review(unit, shared_context=shared_context)


def _challenge(
    rv: UnitReviewer,
    unit: Unit,
    finder_findings: list,
    shared_context: str,
    known: list,
) -> UnitChallenge:
    challenge = getattr(rv, "challenge", None)
    if callable(challenge):
        return challenge(unit, finder_findings, shared_context=shared_context, known=known)
    return UnitChallenge(rebuttals=[], new_findings=[])


def _judge(
    rv: UnitReviewer,
    unit: Unit,
    finder_findings: list,
    rebuttals: list[dict],
    new_findings: list,
    shared_context: str,
    known: list,
):
    judge = getattr(rv, "judge", None)
    if callable(judge):
        return judge(
            unit,
            finder_findings,
            rebuttals,
            new_findings,
            shared_context=shared_context,
            known=known,
        )
    return finder_findings + new_findings


def _tag(candidates: list[Candidate], *labels: str) -> list[Candidate]:
    source_labels = {label for label in labels if label}
    return [replace(c, found_by=tuple(sorted(set(c.found_by) | source_labels))) for c in candidates]


def _labels_for_judged(
    judged: list[Candidate],
    finder_findings: list[Candidate],
    challenger_findings: list[Candidate],
    *,
    finder_label: str,
    challenger_label: str,
    judge_label: str,
) -> list[Candidate]:
    finder_keys = {c.key() for c in finder_findings}
    finder_titles = {c.title for c in finder_findings}
    challenger_keys = {c.key() for c in challenger_findings}
    challenger_titles = {c.title for c in challenger_findings}
    out = []
    for cand in judged:
        labels: set[str] = set(cand.found_by)
        if cand.key() in finder_keys or cand.title in finder_titles:
            labels.add(finder_label)
        if cand.key() in challenger_keys or cand.title in challenger_titles:
            labels.add(challenger_label)
        if not labels and judge_label:
            labels.add(judge_label)
        out.append(replace(cand, found_by=tuple(sorted(labels))))
    return out


def run_passes(
    units: list[Unit],
    reviewer: UnitReviewer | list[UnitReviewer],
    *,
    challenger: UnitReviewer | None = None,
    judge: UnitReviewer | None = None,
    converge_after: int = 2,
    min_rounds: int = 2,
    max_passes: int = 24,
    shared_context: str = "",
    concurrency: int = 8,
    on_pass: Callable[[int, str, int, int], None] | None = None,
    on_unit: Callable[[str, float], None] | None = None,
    persist: Callable[[list], None] | None = None,
    accumulator: Accumulator | None = None,
) -> Accumulator:
    """Run role passes over the worklist until the union converges or `max_passes`."""
    acc = accumulator if accumulator is not None else Accumulator(converge_after=converge_after)
    reviewers = list(reviewer) if isinstance(reviewer, (list, tuple)) else [reviewer]
    labels = [_review_label(rv, f"model-{k}") for k, rv in enumerate(reviewers)]
    floor = max(min_rounds, len(reviewers))
    reviewed_ok: set[str] = set()

    unit_lock = threading.Lock()

    def review_unit(unit: Unit, rv: UnitReviewer, finder_label: str):
        started = perf_counter()
        known = _known_for_unit(acc, unit)
        try:
            finder_findings = _find(rv, unit, shared_context, known)
        except Exception as exc:
            result = [], exc
        else:
            finder_findings = _tag(finder_findings, finder_label)
            result = finder_findings, None
            if challenger is not None and judge is not None:
                try:
                    challenged = _challenge(challenger, unit, finder_findings, shared_context, known)
                    challenger_label = _review_label(challenger, "challenger")
                    challenger_findings = _tag(challenged.new_findings, challenger_label)
                    judged = _judge(
                        judge,
                        unit,
                        finder_findings,
                        challenged.rebuttals,
                        challenger_findings,
                        shared_context,
                        known,
                    )
                    result = (
                        _labels_for_judged(
                            judged,
                            finder_findings,
                            challenger_findings,
                            finder_label=finder_label,
                            challenger_label=challenger_label,
                            judge_label=_review_label(judge, "judge"),
                        ),
                        None,
                    )
                except Exception as exc:
                    result = finder_findings, exc
        if on_unit is not None:
            with unit_lock:
                on_unit(unit.name, round(perf_counter() - started, 1))
        return result

    for i in range(max_passes):
        mi = i % len(reviewers)
        rv = reviewers[mi]
        finder_label = labels[mi]
        if concurrency > 1 and len(units) > 1:
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                per_unit = list(
                    pool.map(
                        lambda u, rv=rv, finder_label=finder_label: review_unit(u, rv, finder_label),
                        units,
                    )
                )
        else:
            per_unit = [review_unit(u, rv, finder_label) for u in units]
        candidates = [c for cands, _err in per_unit for c in cands]
        pass_errors = sum(1 for _cands, err in per_unit if err is not None)
        acc.errors += pass_errors
        reviewed_ok.update(u.name for u, (_cands, err) in zip(units, per_unit, strict=True) if err is None)
        n_new = acc.add_pass(candidates, clean=pass_errors == 0)
        if persist is not None:
            persist(acc.findings)
        if on_pass is not None:
            on_pass(i + 1, labels[mi], n_new, len(acc.findings))
        covered = i + 1 >= floor
        if covered and acc.converged:
            break
    acc.failed_units = {u.name for u in units} - reviewed_ok
    return acc
