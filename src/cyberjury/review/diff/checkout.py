"""Compose one grounded and verified Diff Review over a pinned checkout."""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from time import perf_counter

from cyberjury.detection import load_detection
from cyberjury.profiles.base import ReviewProfile
from cyberjury.providers.base import Provider
from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat, provider_for_seat
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.review.diff.context import build_diff_context_collector
from cyberjury.review.diff.engine import (
    DiffExecutionOptions,
    DiffGroundingOptions,
    DiffReviewOptions,
    DiffReviewResult,
    DiffVerificationOptions,
    run_diff_review,
)
from cyberjury.review.diff.model import batch_paths, diff_unit_plan_receipt, strip_unreviewable_files
from cyberjury.review.engine import JudgmentProgress
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.seats import provider_seat_id, verification_route
from cyberjury.review.settings import positive_concurrency
from cyberjury.review.trace import Trace
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.review.verification import Confirmer, Verifier
from cyberjury.sources.snapshot import SourceSnapshot

DRY_RUN_SEAT = ProviderSeat(provider="mock", model="mock")


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffGroundingReceipts:
    """Receipts published after grounding and before any model work."""

    native_analysis: NativeAnalysisReceipt
    facts_resolution: FactsResolutionReceipt
    unit_plan: UnitPlanReceipt
    grounding: GroundingReceipt
    grounding_seconds: float
    review_paths: tuple[str, ...]


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffCheckoutHooks:
    """Caller observers for one checkout Diff Review."""

    on_skipped: Callable[[tuple[str, ...]], None] | None = None
    on_grounded: Callable[[DiffGroundingReceipts], None] | None = None
    on_reviewed: Callable[[DiffReviewResult], None] | None = None
    on_batch: Callable[[int, int, float], None] | None = None
    on_judgment: JudgmentProgress | None = None
    trace: Trace | None = None
    stage: Callable[[str], AbstractContextManager[None]] | None = None


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffCheckoutReview:
    """Review result with the source snapshot and receipts it is bound to."""

    result: DiffReviewResult
    source_snapshot: SourceSnapshot
    receipts: DiffGroundingReceipts
    finder_model: str


@dataclasses.dataclass(frozen=True, kw_only=True)
class _Seats:
    finder: Provider
    finder_model: str
    finder_label: str
    verifier: Verifier | None
    confirmers: tuple[Confirmer, ...]


def review_diff_checkout(
    diff: str,
    *,
    root: Path,
    profile: ReviewProfile,
    configuration: ProviderConfiguration,
    meter: UsageMeter,
    concurrency: int,
    verification_concurrency: int | None = None,
    scope: Path | None = None,
    source_snapshot: SourceSnapshot | None = None,
    dry_run_provider: Provider | None = None,
    hooks: DiffCheckoutHooks | None = None,
) -> DiffCheckoutReview:
    """Ground, review, and verify one diff against a pinned checkout.

    `scope` limits facts extraction to a directory inside `root`. A bound
    `source_snapshot` must cover `root`. A `dry_run_provider` replaces the finder seat
    and disables verification. The source must stay unchanged through the review.
    """
    positive_concurrency(concurrency, "review concurrency")
    if verification_concurrency is not None:
        positive_concurrency(verification_concurrency, "verification concurrency")
    hooks = hooks or DiffCheckoutHooks()
    seats = _seats(configuration, profile, meter, dry_run_provider)
    review_diff, skipped = strip_unreviewable_files(diff, load_detection(profile.paths.detection_file))
    if skipped and hooks.on_skipped is not None:
        hooks.on_skipped(skipped)
    with _stage(hooks, "diff context"):
        collector = build_diff_context_collector(
            root,
            profile,
            facts_root=scope,
            review_diff=review_diff,
            source_snapshot=source_snapshot,
        )
    snapshot = collector.source_snapshot
    if collector.native_analysis is None:
        raise RuntimeError("diff context did not produce a native analysis receipt")
    if collector.facts_resolution is None:
        raise RuntimeError("diff context did not produce a facts resolution receipt")
    units = collector.plan(review_diff)
    unit_plan = diff_unit_plan_receipt(
        units,
        collector.facts_resolution,
        expected_owned_paths=batch_paths(review_diff) if review_diff else (),
    )
    units = [dataclasses.replace(unit, id=record.id) for unit, record in zip(units, unit_plan.units, strict=True)]
    grounding_started = perf_counter()
    units = collector.ground(units)
    receipts = DiffGroundingReceipts(
        native_analysis=collector.native_analysis,
        facts_resolution=collector.facts_resolution,
        unit_plan=unit_plan,
        grounding=GroundingReceipt.create(
            unit_plan=unit_plan,
            contexts=tuple(unit.grounding for unit in units if unit.grounding is not None),
        ),
        grounding_seconds=round(perf_counter() - grounding_started, 3),
        review_paths=collector.review_paths,
    )
    if hooks.on_grounded is not None:
        hooks.on_grounded(receipts)
    with _stage(hooks, "diff review"):
        result = run_diff_review(
            review_diff,
            provider=seats.finder,
            model=seats.finder_model,
            finder_label=seats.finder_label,
            options=DiffReviewOptions(
                grounding=DiffGroundingOptions(
                    prepare_diff=lambda _diff: units,
                    source_snapshot=snapshot,
                    navigator=collector.navigator,
                ),
                verification=DiffVerificationOptions(
                    root=str(root),
                    verifier=seats.verifier,
                    confirmers=seats.confirmers,
                    found_by=(seats.finder_label,),
                    concurrency=verification_concurrency or concurrency,
                ),
                execution=DiffExecutionOptions(
                    concurrency=concurrency,
                    profile=profile,
                    on_batch=hooks.on_batch,
                    on_judgment=hooks.on_judgment,
                    trace=hooks.trace,
                    meter=meter,
                ),
            ),
        )
    if hooks.on_reviewed is not None:
        hooks.on_reviewed(result)
    if not snapshot.matches():
        raise RuntimeError("diff source changed while the review was running")
    return DiffCheckoutReview(
        result=result,
        source_snapshot=snapshot,
        receipts=receipts,
        finder_model=seats.finder_model,
    )


def _seats(
    configuration: ProviderConfiguration,
    profile: ReviewProfile,
    meter: UsageMeter,
    dry_run_provider: Provider | None,
) -> _Seats:
    if dry_run_provider is not None:
        return _Seats(
            finder=MeteringProvider(dry_run_provider, meter),
            finder_model=DRY_RUN_SEAT.model,
            finder_label=provider_seat_id(DRY_RUN_SEAT),
            verifier=None,
            confirmers=(),
        )
    finder = configuration.finder
    finder_provider = provider_for_seat(configuration, finder, meter=meter)
    verifier, confirmers = verification_route(configuration, profile.paths, meter=meter)
    return _Seats(
        finder=finder_provider,
        finder_model=finder.model,
        finder_label=provider_seat_id(finder),
        verifier=verifier,
        confirmers=tuple(confirmers),
    )


def _stage(hooks: DiffCheckoutHooks, name: str) -> AbstractContextManager[None]:
    return hooks.stage(name) if hooks.stage is not None else contextlib.nullcontext()
