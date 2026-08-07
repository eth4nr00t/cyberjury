"""The pass-loop: the deterministic multi-pass orchestration of a repository review.

This is the part that is mechanical, not a matter of the agent's judgment, so it is
code, not prose. It runs the whole unit worklist every pass, cycles a different lens
each pass so the passes' blind spots land in different places, folds every pass into the
running union, and stops only when the union has converged. The per-unit judgment is
delegated to an injected `UnitReviewer`. Everything here, coverage, diversity,
accumulation, and the stop condition, is fixed by code, so the orchestration does not
vary run to run, even though the model's per-unit findings do.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from time import perf_counter

from cyberjury.domains.registry import default_domain
from cyberjury.review.repository.reviewer import UnitReviewer
from cyberjury.review.repository.shapes import Unit
from cyberjury.review.repository.union import Accumulator

DEFAULT_LENSES = default_domain().lenses


def run_passes(
    units: list[Unit],
    reviewer: UnitReviewer | list[UnitReviewer],
    *,
    lenses: tuple[str, ...] = DEFAULT_LENSES,
    converge_after: int = 2,
    min_lens_shots: int = 2,
    max_passes: int = 24,
    shared_context: str = "",
    concurrency: int = 6,
    on_pass: Callable[[int, str, int, int], None] | None = None,
    on_unit: Callable[[str, float], None] | None = None,
    persist: Callable[[list], None] | None = None,
    accumulator: Accumulator | None = None,
) -> Accumulator:
    """Run diverse passes over the worklist until the union converges or `max_passes`.

    Every pass reviews every unit, so coverage is total each pass. The lens rotates so
    diversity drives the union. `reviewer` may be several models, rotated one per lens
    cycle: a single model's blind spots cap recall no matter how many passes, so different
    models each review and the union takes whatever any of them finds, raising the recall
    ceiling. Passes run in order, but the units within a pass are independent, so they run
    concurrently up to `concurrency`, since each is a network bound model call. Results are
    merged in unit order, so the converged finding set is the same as a serial run. The pass
    callback is called after each pass. The unit callback is called as each unit review
    completes, with its name and elapsed seconds, serialized since the units run
    concurrently. Convergence needs two signals, not one. The union must have saturated, the
    last `converge_after` passes added nothing, and every lens must have fired at least
    `min_lens_shots` times. A small repository saturates in a few passes, before the lens
    rotation has re-tried each class, so saturation alone stops the run with a hard class
    such as reentrancy reviewed once and never again. Generation is probabilistic, one shot
    is a coin flip, so the coverage gate keeps the run going until each lens has had its
    shots. With several models the floor rises to at least one lens cycle per model, so no
    model is skipped before the run can stop. It binds only where the union saturates early,
    on a large repository every lens already fired many times by the time it goes quiet.
    """
    acc = accumulator if accumulator is not None else Accumulator(converge_after=converge_after)
    lenses = lenses or ("",)
    reviewers = list(reviewer) if isinstance(reviewer, (list, tuple)) else [reviewer]
    labels = [getattr(rv, "label", "") or f"model-{k}" for k, rv in enumerate(reviewers)]
    floor = max(min_lens_shots, len(reviewers))
    reviewed_ok: set[str] = set()
    lens_shots: dict[str, int] = {}

    unit_lock = threading.Lock()

    def review_unit(unit: Unit, lens: str, rv: UnitReviewer):
        started = perf_counter()
        try:
            result = rv.review(unit, lens, shared_context=shared_context), None
        except Exception as exc:
            result = [], exc
        if on_unit is not None:
            with unit_lock:
                on_unit(unit.name, round(perf_counter() - started, 1))
        return result

    for i in range(max_passes):
        lens = lenses[i % len(lenses)]
        mi = (i // len(lenses)) % len(reviewers)
        rv = reviewers[mi]
        lens_shots[lens] = lens_shots.get(lens, 0) + 1
        if concurrency > 1 and len(units) > 1:
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                per_unit = list(pool.map(lambda u, lens=lens, rv=rv: review_unit(u, lens, rv), units))
        else:
            per_unit = [review_unit(u, lens, rv) for u in units]
        candidates = [replace(c, found_by=(labels[mi],)) for cands, _err in per_unit for c in cands]
        pass_errors = sum(1 for _cands, err in per_unit if err is not None)
        acc.errors += pass_errors
        reviewed_ok.update(u.name for u, (_cands, err) in zip(units, per_unit, strict=True) if err is None)
        n_new = acc.add_pass(candidates, clean=pass_errors == 0)
        if persist is not None:
            persist(acc.findings)
        if on_pass is not None:
            on_pass(i + 1, lens, n_new, len(acc.findings))
        covered = all(lens_shots.get(ln, 0) >= floor for ln in lenses)
        if covered and acc.converged:
            break
    acc.failed_units = {u.name for u in units} - reviewed_ok
    return acc
