"""Run the coded repository review engine end to end.

The library entry behind `review repository --run`. It scaffolds the workspace, reviews
each open unit once with a model backed reviewer, and verifies the accumulated findings.
`_run.json` records which units reviewed cleanly, so a resume retries only open work.
The strict `findings.json` and `outcome.json` artifacts are the final machine result.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from time import perf_counter

from cyberjury.profiles.base import PoCBackend, ReviewProfile, bind_profile_content, profile_binding
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.base import Provider
from cyberjury.providers.metering import UsageMeter, model_call_context, record_model_parse
from cyberjury.review.context import GroundingCoverage
from cyberjury.review.engine import ReviewOutcome, extend_review_outcome
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.paths import resolve_source_path
from cyberjury.review.repository.context import (
    Unit,
    facts_summary,
    load_facts_by_file,
    load_facts_limitations,
)
from cyberjury.review.repository.reviewer import ModelReviewer
from cyberjury.review.repository.runner import run_units
from cyberjury.review.repository.scaffold import ScaffoldResult, scaffold
from cyberjury.review.repository.union import Accumulator, Candidate
from cyberjury.review.repository.verify import apply_verification
from cyberjury.review.result import FindingRecord, FindingsArtifact, OutcomeArtifact
from cyberjury.review.scheduling import SchedulingReceipt
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.review.verification import (
    RefutationChecker,
    Verifier,
    VerifyResult,
    verification_failure_reason,
)
from cyberjury.sources.snapshot import SourceSnapshot
from cyberjury.workspace import WorkspaceCorruptionError, read_json_object, write_json_atomic

type JudgmentCallback = Callable[[str, str, float], None]
type NativeAnalysisCallback = Callable[[NativeAnalysisReceipt], None]
type FactsResolutionCallback = Callable[[FactsResolutionReceipt], None]
type UnitPlanCallback = Callable[[UnitPlanReceipt], None]
type GroundingCallback = Callable[[GroundingReceipt, float], None]
type VerifyCallback = Callable[[int, int, float], None]


@dataclass(frozen=True, kw_only=True)
class RepositoryRoleOptions:
    """Finder seat for one repository review."""

    provider: Provider
    model: str
    finder_label: str = ""


@dataclass(frozen=True, kw_only=True)
class RepositoryVerificationOptions:
    """Candidate verification route and progress for repository review."""

    enabled: bool = False
    verifier: Verifier | None = None
    confirmers: tuple[tuple[str, RefutationChecker], ...] | None = None
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency
    on_verify: VerifyCallback | None = None

    def __post_init__(self) -> None:
        """Require the configured verifier whenever verification is enabled."""
        if self.enabled and self.verifier is None:
            raise ValueError("repository verification requires a verifier")


@dataclass(frozen=True, kw_only=True)
class RepositoryExecutionOptions:
    """Unit concurrency, receipts, and progress for repository review."""

    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency
    on_judgment: JudgmentCallback | None = None
    expected_snapshot_id: str = ""
    on_native_analysis: NativeAnalysisCallback | None = None
    on_facts_resolution: FactsResolutionCallback | None = None
    on_unit_plan: UnitPlanCallback | None = None
    on_grounding: GroundingCallback | None = None


@dataclass(frozen=True, kw_only=True)
class RepositoryOutputOptions:
    """Profile, PoC, and metering resources for one repository review run."""

    profile: ReviewProfile | None = None
    poc_backend: PoCBackend | None = None
    meter: UsageMeter | None = None


@dataclass(frozen=True, kw_only=True)
class RepositoryLifecycleOptions:
    """Workspace lifecycle policy for one repository review run."""

    fresh: bool = False
    target_identity: str | None = None


@dataclass(frozen=True, kw_only=True)
class RepositoryRunOptions:
    """Coherent option groups for one repository review run."""

    roles: RepositoryRoleOptions
    verification: RepositoryVerificationOptions = field(default_factory=RepositoryVerificationOptions)
    execution: RepositoryExecutionOptions = field(default_factory=RepositoryExecutionOptions)
    lifecycle: RepositoryLifecycleOptions = field(default_factory=RepositoryLifecycleOptions)
    output: RepositoryOutputOptions = field(default_factory=RepositoryOutputOptions)


def _poc_name(path: Path) -> str:
    """The finding name a PoC file maps to, preserving multi suffix extensions."""
    for suffix in ("".join(path.suffixes), path.suffix):
        if suffix and path.name.endswith(suffix):
            return path.name[: -len(suffix)]
    return path.stem


def _finding_record(candidate: Candidate, verified_ids: frozenset[str] = frozenset()) -> FindingRecord:
    """Map one repository candidate into the shared machine output contract."""
    if candidate.line is None:
        raise ValueError("repository output finding requires a source line")
    return FindingRecord(
        id=candidate.candidate_id,
        category=candidate.category or "other",
        severity=candidate.severity,
        file=candidate.file,
        line=candidate.line,
        entrypoint=candidate.endpoint or candidate.symbol,
        summary=candidate.title,
        evidence=candidate.evidence.strip(),
        attack_path=candidate.attack_path,
        recommendation="",
        status="confirmed" if candidate.candidate_id in verified_ids else "candidate",
        evidence_refs=tuple(dict.fromkeys(candidate.evidence_refs)),
        supporting_reviewers=tuple(sorted(set(candidate.found_by))),
    )


def _write_findings(
    ws: Path, findings: list[Candidate], *, verified_ids: frozenset[str] = frozenset()
) -> FindingsArtifact:
    """Write the canonical machine finding set."""
    artifact = FindingsArtifact.create(
        tuple(_finding_record(candidate, verified_ids) for candidate in findings),
    )
    write_json_atomic(ws / "findings.json", artifact.to_dict())
    return artifact


def _write_pocs_report(ws: Path, findings: list[Candidate], failures: tuple[str, ...]) -> None:
    """Reconcile pocs/ against retained findings, recorded not enforced.

    A finding may need a PoC only an operator can run, and a PoC may outlive a candidate
    verification later refuted. Surface both, and every failed generation, so none is lost.
    """
    pocs = ws / "pocs"
    poc_files = sorted(p for p in pocs.iterdir() if p.is_file()) if pocs.is_dir() else []
    if not poc_files and not failures:
        return
    names = {c.candidate_id for c in findings}
    poc_names = {_poc_name(p) for p in poc_files}
    missing = [c for c in findings if c.candidate_id not in poc_names]
    orphan = [p for p in poc_files if _poc_name(p) not in names]
    lines = [
        "# PoC Reconciliation",
        "",
        "Retained findings matched to PoCs by candidate id. Recorded, not gated: a finding "
        "may need a PoC only an operator can run, and a PoC may outlive a refuted candidate.",
        "",
        "## Retained findings with no PoC",
        "",
    ]
    lines += [f"- **{c.title}** `{c.candidate_id}` `{c.file}:{c.line}`" for c in missing] or [
        "None, every retained finding has a PoC."
    ]
    lines += ["", "## PoC files with no retained finding", ""]
    lines += [f"- `pocs/{p.name}`" for p in orphan] or ["None, every PoC maps to a retained finding."]
    lines += ["", "## Failed PoC generation", ""]
    lines += [f"- {failure}" for failure in failures] or ["None."]
    (ws / "_pocs.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_UNION_SCHEMA = 5
_CHECKPOINT_STRINGS = (
    "attack_path_id",
    "candidate_id",
    "title",
    "category",
    "source_operation_id",
    "endpoint",
    "symbol",
    "file",
    "severity",
    "attack_path",
    "evidence",
)


def _cand_to_dict(c: Candidate) -> dict:
    return {
        "attack_path_id": c.attack_path_id,
        "candidate_id": c.candidate_id,
        "title": c.title,
        "category": c.category,
        "source_operation_id": c.source_operation_id,
        "endpoint": c.endpoint,
        "symbol": c.symbol,
        "file": c.file,
        "line": c.line,
        "severity": c.severity,
        "attack_path": c.attack_path,
        "evidence": c.evidence,
        "evidence_refs": list(c.evidence_refs),
        "found_by": list(c.found_by),
    }


def _checkpoint_candidate(value: object) -> Candidate:
    if not isinstance(value, dict):
        raise TypeError("each finding must be an object")
    if set(value) != {*_CHECKPOINT_STRINGS, "line", "evidence_refs", "found_by"}:
        raise TypeError("finding checkpoint must contain the exact supported fields")
    for name in _CHECKPOINT_STRINGS:
        if not isinstance(value[name], str):
            raise TypeError(f"finding field {name!r} must be a string")
    if not value["title"].strip():
        raise TypeError("finding field 'title' must be a nonempty string")
    if value["severity"] not in _SEVERITIES:
        raise TypeError("finding field 'severity' must be a known severity")
    if value["source_operation_id"] and not value["source_operation_id"].startswith("call-"):
        raise TypeError("finding field 'source_operation_id' must be a callsite id")
    line = value["line"]
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        raise TypeError("finding field 'line' must be a positive integer or null")
    found_by = value["found_by"]
    if not isinstance(found_by, list) or not all(isinstance(label, str) for label in found_by):
        raise TypeError("finding field 'found_by' must be a list of strings")
    evidence_refs = value["evidence_refs"]
    if not isinstance(evidence_refs, list) or not all(isinstance(ref, str) and ref for ref in evidence_refs):
        raise TypeError("finding field 'evidence_refs' must be a list of nonempty strings")
    candidate = Candidate(
        title=value["title"],
        category=value["category"],
        source_operation_id=value["source_operation_id"],
        endpoint=value["endpoint"],
        symbol=value["symbol"],
        file=value["file"],
        line=line,
        severity=value["severity"],
        attack_path=value["attack_path"],
        evidence=value["evidence"],
        evidence_refs=tuple(evidence_refs),
        found_by=tuple(found_by),
    )
    if value["attack_path_id"] != candidate.attack_path_id:
        raise TypeError("finding field 'attack_path_id' does not match its entry path")
    if value["candidate_id"] != candidate.candidate_id:
        raise TypeError("finding field 'candidate_id' does not match its source identity")
    return candidate


def _save_union(ws: Path, cands: list[Candidate], *, severity_votes: dict[tuple, list[str]]) -> None:
    (ws / "_union.json").write_text(
        json.dumps(
            {
                "schema": _UNION_SCHEMA,
                "findings": [_cand_to_dict(c) for c in cands],
                "severity_votes": {
                    candidate.candidate_id: list(severity_votes.get(candidate.key(), [candidate.severity]))
                    for candidate in cands
                },
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


_RUN_STATUS_SCHEMA = "cyberjury.repository-run/v3"
_RUN_STATUS_REQUIRED = {
    "schema",
    "units_total",
    "reviewed_units",
    "failed_units",
    "unit_failures",
    "errors",
    "verify_errors",
    "facts_limitations",
    "complete",
    "state",
    "source_revision",
    "model_calls",
    "content_sha256",
}
_RUN_STATUS_OPTIONAL = {
    "retained",
    "verified",
    "refuted",
    "incomplete",
    "unlocatable",
    "failure_reason",
    "timing",
    "usage",
}


def _checkpoint_sha256(value: dict[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _load_run_status(ws: Path) -> dict[str, object] | None:
    path = ws / "_run.json"
    if not path.is_file():
        return None
    try:
        value = read_json_object(path)
    except (OSError, ValueError, WorkspaceCorruptionError) as exc:
        raise _resume_corrupt(path, exc) from exc
    if value.get("schema") != _RUN_STATUS_SCHEMA:
        raise _resume_corrupt(path, ValueError("repository run schema is unsupported"))
    fields = set(value)
    if not _RUN_STATUS_REQUIRED.issubset(fields) or fields.difference(_RUN_STATUS_REQUIRED | _RUN_STATUS_OPTIONAL):
        raise _resume_corrupt(path, TypeError("status must use the exact repository run schema"))
    content_sha256 = value["content_sha256"]
    semantic = {key: item for key, item in value.items() if key != "content_sha256"}
    if not isinstance(content_sha256, str) or content_sha256 != _checkpoint_sha256(semantic):
        raise _resume_corrupt(path, ValueError("repository run content hash does not match"))
    reviewed = value["reviewed_units"]
    if not isinstance(reviewed, list) or not all(isinstance(name, str) and name for name in reviewed):
        raise _resume_corrupt(path, TypeError("reviewed units must be a list of unit names"))
    return value


def _restored_scheduler_outcome(
    status: dict[str, object],
    findings: list[Candidate],
    grounding: GroundingCoverage,
    path: Path,
) -> ReviewOutcome[Candidate]:
    if status.get("complete") is True:
        zero_counters = ("errors", "verify_errors", "facts_limitations")
        if any(status.get(name, 0) != 0 for name in zero_counters):
            raise _resume_corrupt(path, ValueError("complete status still contains failed or incomplete work"))
        empty_collections = ("failed_units", "unit_failures")
        if any(status.get(name, []) != [] for name in empty_collections) or status.get("failure_reason"):
            raise _resume_corrupt(path, ValueError("complete status still contains failure records"))
    return ReviewOutcome(
        findings=tuple(findings),
        grounding=grounding,
        scheduling=SchedulingReceipt.empty(stop_reason="no_open_units"),
    )


def _save_run_status(
    ws: Path,
    *,
    units_total: int,
    reviewed_units: set[str],
    acc: Accumulator,
    verify: VerifyResult | None,
    outcome: ReviewOutcome[Candidate] | None = None,
    timing: dict | None = None,
    usage: dict[str, int] | None = None,
    facts_limitations: int = 0,
    state: str = "running",
    source_revision: str = "",
    model_calls: list[dict[str, object]] | None = None,
) -> None:
    """Persist the coded run's resume, coverage, and failure state.

    `reviewed_units` drives resume. A running snapshot survives interruption. The final
    snapshot records `timing` and `usage`.
    """
    status = {
        "schema": _RUN_STATUS_SCHEMA,
        "units_total": units_total,
        "reviewed_units": sorted(reviewed_units),
        "failed_units": sorted(acc.failed_units),
        "unit_failures": [asdict(failure) for failure in acc.unit_failures],
        "errors": acc.errors,
        "verify_errors": verify.errors if verify else 0,
        "facts_limitations": facts_limitations,
        "complete": outcome.complete if outcome is not None else False,
        "state": state,
        "source_revision": source_revision,
        "model_calls": model_calls or [],
    }
    if verify is not None:
        status["retained"] = len(verify.retained)
        status["verified"] = len(verify.verified)
        status["refuted"] = len(verify.refuted)
        status["unlocatable"] = len(verify.unlocatable)
    if outcome is not None:
        status["incomplete"] = len(outcome.incomplete)
    failure_reason = ". ".join(
        dict.fromkeys(
            reason
            for reason in (
                outcome.failure_reason if outcome is not None else "",
                verification_failure_reason(verify.error_details) if verify is not None else "",
            )
            if reason
        )
    )
    if failure_reason:
        status["failure_reason"] = failure_reason
    if timing is not None:
        status["timing"] = timing
    if usage is not None:
        status["usage"] = usage
    status["content_sha256"] = _checkpoint_sha256(status)
    write_json_atomic(ws / "_run.json", status)


def _resume_corrupt(p: Path, exc: Exception) -> ValueError:
    return ValueError(
        f"resume checkpoint {p} is unreadable or corrupt: {exc}. "
        "Remove the workspace to discard prior state and start over."
    )


@dataclass(frozen=True, kw_only=True)
class _UnionCheckpoint:
    pool: dict[tuple, Candidate]
    severity_votes: dict[tuple, list[str]]


def _load_union_checkpoint(ws: Path) -> _UnionCheckpoint:
    p = ws / "_union.json"
    if not p.is_file():
        return _UnionCheckpoint(pool={}, severity_votes={})
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if (
            not isinstance(data, dict)
            or set(data) != {"schema", "findings", "severity_votes"}
            or data["schema"] != _UNION_SCHEMA
        ):
            raise TypeError(f"expected a schema {_UNION_SCHEMA} object containing findings and severity_votes")
        findings = data["findings"]
        if not isinstance(findings, list):
            raise TypeError("findings must be a list")
        candidates = [_checkpoint_candidate(value) for value in findings]
        raw_votes = data["severity_votes"]
        ids = [candidate.candidate_id for candidate in candidates]
        keys = [candidate.key() for candidate in candidates]
        if len(set(ids)) != len(ids) or len(set(keys)) != len(keys):
            raise TypeError("findings must have unique identities")
        if not isinstance(raw_votes, dict) or set(raw_votes) != set(ids):
            raise TypeError("severity_votes must contain every candidate id exactly once")
        if any(
            not isinstance(values, list) or not values or any(value not in _SEVERITIES for value in values)
            for values in raw_votes.values()
        ):
            raise TypeError("severity_votes values must be nonempty severity lists")
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise _resume_corrupt(p, exc) from exc
    pool = {candidate.key(): candidate for candidate in candidates}
    votes = {candidate.key(): list(raw_votes[candidate.candidate_id]) for candidate in candidates}
    return _UnionCheckpoint(pool=pool, severity_votes=votes)


def _poc_source(root: str, candidate: Candidate, source_snapshot: SourceSnapshot) -> str:
    """Read the finding file only while it still matches the reviewed snapshot."""
    path = resolve_source_path(root, candidate.file)
    if path is None:
        raise ValueError(f"{candidate.file} is not a reviewed source file")
    text = path.read_text(encoding="utf-8")
    if not source_snapshot.matches_files((candidate.file,)):
        raise ValueError(f"{candidate.file} no longer matches the reviewed source snapshot")
    return text


def _run_pocs(
    ws: Path,
    findings: list[Candidate],
    backend: PoCBackend,
    root: str,
    source_snapshot: SourceSnapshot,
) -> tuple[list[Candidate], tuple[str, ...]]:
    """Write manual sandbox PoCs and record each failure without changing the findings."""
    pocs = ws / "pocs"
    pocs.mkdir(exist_ok=True)
    annotated: list[Candidate] = []
    failures: list[str] = []
    for c in findings:
        with model_call_context(
            role="poc",
            trigger="proof_generation",
            unit_id=c.candidate_id,
        ):
            try:
                art = backend.generate(
                    title=c.title,
                    analysis=c.evidence,
                    symbol=c.symbol,
                    file=c.file,
                    line=c.line,
                    endpoint=c.endpoint,
                    source=_poc_source(root, c, source_snapshot),
                )
                record_model_parse("poc")
            except Exception as exc:
                reason = f"{type(exc).__name__}: {exc}"
                record_model_parse("poc", status="failed", failure_reason=reason)
                failures.append(f"`{c.candidate_id}`: {reason}")
                annotated.append(c)
                continue
        (pocs / f"{c.candidate_id}.{backend.ext}").write_text(art.source, encoding="utf-8")
        note = f"PoC written, run it manually: {art.run_hint}"
        annotated.append(replace(c, evidence=f"{c.evidence}\n\n[{note}]".strip()))
    return annotated, tuple(failures)


@dataclass(frozen=True, kw_only=True)
class RunResult:
    """Coded repository run output and persisted run counters."""

    scaffold: ScaffoldResult
    accumulator: Accumulator
    units: int
    verify: VerifyResult | None = None
    outcome: ReviewOutcome[Candidate] | None = None
    findings_artifact: FindingsArtifact | None = None
    outcome_artifact: OutcomeArtifact | None = None
    poc_failures: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _PreparedRun:
    """Validated workspace state and worklist ready for model execution."""

    profile: ReviewProfile
    root: str
    scaffold: ScaffoldResult
    units: list[Unit]
    open_units: list[Unit]
    reviewed_units: set[str]
    accumulator: Accumulator
    shared_context: str
    facts_grounding: GroundingCoverage


@dataclass(frozen=True, kw_only=True)
class _RunTiming:
    """Raw timing records collected during unit execution."""

    started: float
    units: list[tuple[str, float]]


@dataclass(frozen=True, kw_only=True)
class _PostprocessedRun:
    """Canonical findings and verification accounting ready to persist."""

    findings: list[Candidate]
    verify: VerifyResult | None
    unlocatable: tuple[Candidate, ...]
    poc_failures: tuple[str, ...]


def run_repository_review(
    target: str | Path,
    workspace: str | Path,
    *,
    options: RepositoryRunOptions,
) -> RunResult:
    """Run the coded repository review workflow."""
    prepared = _prepare_run_state(target, workspace, options)
    if (
        options.execution.expected_snapshot_id
        and prepared.scaffold.source_snapshot.snapshot_id != options.execution.expected_snapshot_id
    ):
        raise ValueError("repository source changed after the attempt snapshot was captured")
    if options.execution.on_native_analysis is not None:
        options.execution.on_native_analysis(prepared.scaffold.native_analysis)
    if options.execution.on_facts_resolution is not None:
        options.execution.on_facts_resolution(prepared.scaffold.facts_resolution)
    if options.execution.on_unit_plan is not None:
        options.execution.on_unit_plan(prepared.scaffold.unit_plan)
    if options.execution.on_grounding is not None:
        options.execution.on_grounding(
            prepared.scaffold.grounding_receipt,
            prepared.scaffold.grounding_seconds,
        )
    reviewer = ModelReviewer(
        provider=options.roles.provider,
        model=options.roles.model,
        content=prepared.profile.paths,
        provenance_label=options.roles.finder_label,
    )
    timing = _execute_repository_units(prepared, reviewer, options)
    postprocessed = _postprocess_repository_run(prepared, options)
    if not prepared.scaffold.source_snapshot.matches():
        raise ValueError("repository source changed before review output could be persisted")
    if profile_binding(prepared.profile).profile_sha256 != prepared.scaffold.profile_sha256:
        raise ValueError("review profile changed before review output could be persisted")
    return _persist_repository_run(
        prepared,
        postprocessed,
        timing,
        options.output,
    )


def _prepare_run_state(
    target: str | Path,
    workspace: str | Path,
    options: RepositoryRunOptions,
) -> _PreparedRun:
    """Scaffold the workspace and restore resumable state."""
    lifecycle = options.lifecycle
    profile = bind_profile_content(options.output.profile or default_profile())
    root = str(Path(target).resolve())
    expected_workspace = Path(workspace) / Path(root).name
    run_status_path = expected_workspace / "_run.json"
    prior_status = None if lifecycle.fresh else _load_run_status(expected_workspace)
    res = scaffold(
        target,
        workspace,
        fresh=lifecycle.fresh,
        profile=profile,
        expected_snapshot_id=options.execution.expected_snapshot_id,
        target_identity=lifecycle.target_identity,
    )
    ws = res.workspace
    limitations = load_facts_limitations(ws)
    units = list(res.units)
    if not units:
        raise ValueError(f"no readable production source files found under {root}")

    names = {unit.name for unit in units}
    reviewed = set(prior_status["reviewed_units"]) & names if prior_status is not None else set()
    if reviewed and not (ws / "_union.json").is_file():
        raise ValueError(
            f"resume found reviewed units under {ws} but no _union.json checkpoint, the prior "
            "findings are lost. Re-run with --fresh to discard the prior run and start over."
        )
    open_units = [u for u in units if u.name not in reviewed]
    union = _UnionCheckpoint(pool={}, severity_votes={}) if lifecycle.fresh else _load_union_checkpoint(ws)
    acc = Accumulator(pool=union.pool, sev_votes=union.severity_votes)

    facts_grounding = GroundingCoverage(limitations=tuple(item.identity for item in limitations))
    if not open_units:
        acc.outcome = _restored_scheduler_outcome(
            prior_status,
            acc.findings,
            facts_grounding,
            run_status_path,
        )
    return _PreparedRun(
        profile=profile,
        root=root,
        scaffold=res,
        units=units,
        open_units=open_units,
        reviewed_units=reviewed,
        accumulator=acc,
        shared_context="" if load_facts_by_file(ws) else facts_summary(ws),
        facts_grounding=facts_grounding,
    )


def _execute_repository_units(
    prepared: _PreparedRun,
    reviewer: ModelReviewer,
    options: RepositoryRunOptions,
) -> _RunTiming:
    """Review open units once, persist the monotonic finding union, and record clean units."""
    execution = options.execution
    ws = prepared.scaffold.workspace
    acc = prepared.accumulator
    source_revision = prepared.scaffold.source_snapshot.snapshot_id
    run_started = perf_counter()
    unit_times: list[tuple[str, float]] = []

    def save_running_status() -> None:
        _save_run_status(
            ws,
            units_total=len(prepared.units),
            reviewed_units=prepared.reviewed_units,
            acc=acc,
            verify=None,
            facts_limitations=len(prepared.facts_grounding.limitations),
            source_revision=source_revision,
        )

    if prepared.open_units:
        save_running_status()
        run_units(
            prepared.open_units,
            reviewer,
            shared_context=prepared.shared_context,
            concurrency=execution.concurrency,
            on_unit=lambda name, secs: unit_times.append((name, secs)),
            on_judgment=execution.on_judgment,
            accumulator=acc,
        )
    _save_union(ws, acc.findings, severity_votes=acc.sev_votes)
    prepared.reviewed_units.update(unit.name for unit in prepared.open_units if unit.name not in acc.failed_units)
    save_running_status()
    return _RunTiming(started=run_started, units=unit_times)


def _postprocess_repository_run(
    prepared: _PreparedRun,
    options: RepositoryRunOptions,
) -> _PostprocessedRun:
    """Verify the accumulated candidates and write optional PoCs."""
    verification = options.verification
    output = options.output
    ws = prepared.scaffold.workspace
    findings = prepared.accumulator.findings
    vr: VerifyResult | None = None
    if verification.enabled:
        findings, vr = apply_verification(
            ws,
            findings,
            root=prepared.root,
            verifier=verification.verifier,
            confirmers=list(verification.confirmers) if verification.confirmers is not None else None,
            concurrency=verification.concurrency,
            fresh=options.lifecycle.fresh,
            on_verify=verification.on_verify,
            source_snapshot=prepared.scaffold.source_snapshot,
        )

    unlocatable = tuple(
        dict.fromkeys(
            (
                *(vr.unlocatable if vr is not None else ()),
                *(candidate for candidate in findings if candidate.line is None),
            )
        )
    )
    unlocatable_ids = {candidate.candidate_id for candidate in unlocatable}
    findings = [candidate for candidate in findings if candidate.candidate_id not in unlocatable_ids]
    poc_failures: tuple[str, ...] = ()
    source_snapshot = prepared.scaffold.source_snapshot
    if output.poc_backend is not None and findings:
        findings, poc_failures = _run_pocs(ws, findings, output.poc_backend, prepared.root, source_snapshot)
    return _PostprocessedRun(
        findings=findings,
        verify=vr,
        unlocatable=unlocatable,
        poc_failures=poc_failures,
    )


def _persist_repository_run(
    prepared: _PreparedRun,
    postprocessed: _PostprocessedRun,
    raw_timing: _RunTiming,
    output: RepositoryOutputOptions,
) -> RunResult:
    """Persist coverage, timing, findings, and the final completion state."""
    ws = prepared.scaffold.workspace
    acc = prepared.accumulator
    findings = postprocessed.findings
    vr = postprocessed.verify
    unit_totals: dict[str, float] = {}
    for name, secs in raw_timing.units:
        unit_totals[name] = round(unit_totals.get(name, 0.0) + secs, 1)
    by_cost = sorted(unit_totals.items(), key=lambda t: t[1], reverse=True)
    timing = {
        "total_seconds": round(perf_counter() - raw_timing.started, 1),
        "unit_seconds": [{"unit": name, "seconds": secs} for name, secs in by_cost],
    }
    usage_total = output.meter.snapshot() if output.meter is not None else None
    if usage_total is not None:
        usage_total["unit_review_calls"] = len(raw_timing.units)
    incomplete = [
        *(vr.incomplete if vr is not None else ()),
        *postprocessed.unlocatable,
    ]
    cycle_outcome = acc.outcome or ReviewOutcome(findings=tuple(acc.findings))
    outcome = extend_review_outcome(
        cycle_outcome,
        findings=findings,
        failures=acc.unit_failures,
        incomplete=incomplete,
        errors=vr.errors if vr is not None else 0,
        failure_reason=verification_failure_reason(vr.error_details) if vr is not None else "",
        grounding=prepared.facts_grounding,
    )
    state = "complete" if outcome.complete else "incomplete"
    verified_ids = frozenset(candidate.candidate_id for candidate in vr.verified) if vr is not None else frozenset()
    findings_artifact = _write_findings(ws, findings, verified_ids=verified_ids)
    source_snapshot = prepared.scaffold.source_snapshot
    outcome_artifact = OutcomeArtifact.create(
        target="repository",
        source_revision=source_snapshot.snapshot_id,
        findings=findings_artifact,
        outcome=outcome,
    )
    write_json_atomic(ws / "outcome.json", outcome_artifact.to_dict())
    _save_run_status(
        ws,
        units_total=len(prepared.units),
        reviewed_units=prepared.reviewed_units,
        acc=acc,
        verify=vr,
        outcome=outcome,
        timing=timing,
        usage=usage_total,
        facts_limitations=len(prepared.facts_grounding.limitations),
        state=state,
        source_revision=source_snapshot.snapshot_id,
        model_calls=output.meter.call_snapshot() if output.meter is not None else [],
    )
    _write_pocs_report(ws, findings, postprocessed.poc_failures)
    return RunResult(
        scaffold=prepared.scaffold,
        accumulator=acc,
        units=len(prepared.units),
        verify=vr,
        outcome=outcome,
        findings_artifact=findings_artifact,
        outcome_artifact=outcome_artifact,
        poc_failures=postprocessed.poc_failures,
    )
