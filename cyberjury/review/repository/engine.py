"""Run the coded repository review engine end to end.

The library entry behind `review repository --run`. It scaffolds the workspace, builds
the unit worklist from the seeded candidates, runs the deterministic pass loop with a
model-backed reviewer, then writes findings into the workspace. Standard mode marks each
successful unit reviewed and leaves active failures open. An adversarial unit stage that
has not converged leaves its current worklist open for resume. Adversarial mode runs role
rounds until convergence or the round cap. Precision is tightened by verification. Findings
are written both as `findings/*.md` and a machine-readable `findings.json`, so a run can be
scored against an answer key.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from difflib import SequenceMatcher
from functools import cache
from pathlib import Path
from time import perf_counter
from typing import cast

from cyberjury.detection import load_detection
from cyberjury.markdown_docs import md_field
from cyberjury.profiles.base import PoCBackend, ReproducingPoCBackend, ReviewProfile, profile_content_fingerprint
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.base import Provider
from cyberjury.providers.metering import UsageMeter
from cyberjury.review.context import GroundingCoverage
from cyberjury.review.coverage import (
    CoverageAnalysisResult,
    coverage_analysis_failure_reason,
    suggest_finding_coverage,
)
from cyberjury.review.engine import (
    PendingWorkRecord,
    ReviewCycle,
    ReviewOutcome,
    ReviewSchedule,
    extend_review_outcome,
    review_schedule,
)
from cyberjury.review.facts import FactLimitation
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.paths import is_unsafe_rel, repository_files, safe_repository_path, source_navigation_files
from cyberjury.review.repository.context import (
    Unit,
    load_facts_by_file,
    load_facts_graph,
    load_facts_limitations,
    load_facts_unit_specs,
    load_relationship_evidence,
    repository_context,
    with_facts_summary,
)
from cyberjury.review.repository.model import build_units
from cyberjury.review.repository.reviewer import ModelReviewer, UnitReviewer
from cyberjury.review.repository.runner import run_passes
from cyberjury.review.repository.scaffold import (
    WORKSPACE_MARKER,
    ScaffoldResult,
    _unit_md,
    scaffold,
    unit_slug,
)
from cyberjury.review.repository.union import Accumulator, Candidate, candidate_accumulator, collapse_colocated
from cyberjury.review.repository.verify import apply_verification
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.storage import SourceSnapshot
from cyberjury.review.verification import (
    RefutationChecker,
    Verifier,
    VerifyResult,
    verification_failure_reason,
)
from cyberjury.review.vulnerabilities import VulnerabilityCatalog
from cyberjury.sources.metadata import SourceMeta, read_source_meta_file

type PassCallback = Callable[[int, str, int, int], None]
type JudgmentCallback = Callable[[str, int, int, str, float], None]
type VerifyCallback = Callable[[int, int, float], None]
type FinderBackend = tuple[Provider, str]


@dataclass(frozen=True, kw_only=True)
class RepositoryRoleOptions:
    """Finder, Challenger, and Judge seats for one repository review."""

    mode: str = "standard"
    provider: Provider | None = None
    model: str = ""
    challenger_provider: Provider | None = None
    challenger_model: str = ""
    judge_provider: Provider | None = None
    judge_model: str = ""
    reviewer: UnitReviewer | None = None
    challenger_reviewer: UnitReviewer | None = None
    judge_reviewer: UnitReviewer | None = None
    extra_finder_backends: tuple[FinderBackend, ...] = ()

    def __post_init__(self) -> None:
        """Keep finder backend ownership stable after option construction."""
        if not isinstance(self.extra_finder_backends, tuple):
            object.__setattr__(self, "extra_finder_backends", tuple(self.extra_finder_backends))


@dataclass(frozen=True, kw_only=True)
class RepositoryVerificationOptions:
    """Candidate verification route, votes, and progress for repository review."""

    enabled: bool = True
    verifier: Verifier | None = None
    confirmers: tuple[tuple[str, RefutationChecker], ...] | None = None
    provider: Provider | None = None
    model: str = ""
    votes: int = DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency
    on_verify: VerifyCallback | None = None

    def __post_init__(self) -> None:
        """Keep confirmer ownership stable after option construction."""
        if self.confirmers is not None and not isinstance(self.confirmers, tuple):
            object.__setattr__(self, "confirmers", tuple(self.confirmers))


@dataclass(frozen=True, kw_only=True)
class RepositoryExecutionOptions:
    """Round scheduling, concurrency, and progress for repository review."""

    max_passes: int | None = None
    converge_after: int = DEFAULT_REVIEW_SETTINGS.execution.clean_rounds_to_converge
    min_rounds: int = DEFAULT_REVIEW_SETTINGS.repository.min_adversarial_rounds
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency
    on_pass: PassCallback | None = None
    on_judgment: JudgmentCallback | None = None


@dataclass(frozen=True, kw_only=True)
class RepositoryOutputOptions:
    """Profile, PoC, and metering resources shared by run and finalize."""

    profile: ReviewProfile | None = None
    poc_backend: PoCBackend | None = None
    meter: UsageMeter | None = None


@dataclass(frozen=True, kw_only=True)
class RepositoryLifecycleOptions:
    """Workspace lifecycle policy for one repository review run."""

    fresh: bool = False


@dataclass(frozen=True, kw_only=True)
class RepositoryRunOptions:
    """Coherent option groups for one repository review run."""

    roles: RepositoryRoleOptions = field(default_factory=RepositoryRoleOptions)
    verification: RepositoryVerificationOptions = field(default_factory=RepositoryVerificationOptions)
    execution: RepositoryExecutionOptions = field(default_factory=RepositoryExecutionOptions)
    lifecycle: RepositoryLifecycleOptions = field(default_factory=RepositoryLifecycleOptions)
    output: RepositoryOutputOptions = field(default_factory=RepositoryOutputOptions)


@dataclass(frozen=True, kw_only=True)
class RepositoryFinalizeOptions:
    """Verification and output policy for one repository finalize step."""

    verification: RepositoryVerificationOptions = field(default_factory=RepositoryVerificationOptions)
    output: RepositoryOutputOptions = field(default_factory=RepositoryOutputOptions)


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _validate_confirmers(confirmers: object) -> None:
    if confirmers is None:
        return
    if not isinstance(confirmers, (list, tuple)):
        raise ValueError("verification confirmers must be a sequence")
    for index, confirmer in enumerate(confirmers):
        if (
            not isinstance(confirmer, tuple)
            or len(confirmer) != 2
            or not isinstance(confirmer[0], str)
            or not callable(getattr(confirmer[1], "holds", None))
        ):
            raise ValueError(f"verification confirmer {index + 1} is invalid")


def _validate_repository_run_options(options: RepositoryRunOptions) -> ReviewSchedule:
    roles = options.roles
    execution = options.execution
    verification = options.verification
    max_rounds = execution.max_passes
    if max_rounds is None:
        max_rounds = 1 if roles.mode == "standard" else DEFAULT_REVIEW_SETTINGS.repository.default_max_rounds
    plan = review_schedule(
        roles.mode,
        max_rounds=max_rounds,
        min_rounds=1 if roles.mode == "standard" else execution.min_rounds,
        converge_after=execution.converge_after,
        stop_on_failure=False,
    )
    _positive_integer(execution.concurrency, "review concurrency")
    _positive_integer(verification.votes, "verification votes")
    _positive_integer(verification.concurrency, "verification concurrency")
    if roles.reviewer is None and roles.provider is None:
        raise ValueError("run_repository_review needs a provider, or an injected reviewer")
    if not roles.model and roles.reviewer is None:
        raise ValueError("repository review model must be a nonempty string")
    if roles.mode == "adversarial":
        challenger_ready = roles.challenger_reviewer is not None or (
            roles.challenger_provider is not None and bool(roles.challenger_model)
        )
        judge_ready = roles.judge_reviewer is not None or (roles.judge_provider is not None and bool(roles.judge_model))
        if not challenger_ready or not judge_ready:
            raise ValueError("adversarial mode requires challenger and judge reviewers")
    finder_count = 1 + len(roles.extra_finder_backends)
    if finder_count > plan.max_rounds:
        raise ValueError(f"{finder_count} finder reviewers cannot run within the {plan.max_rounds} round cap")
    for _provider, model in roles.extra_finder_backends:
        if not model:
            raise ValueError("extra finder model must be a nonempty string")
    if verification.enabled and verification.verifier is None:
        provider = verification.provider or roles.provider
        model = verification.model or roles.model
        if provider is None:
            raise ValueError("verification needs a provider, or an injected verifier")
        if not model:
            raise ValueError("verification model must be a nonempty string")
    _validate_confirmers(verification.confirmers)
    return plan


def _validate_repository_finalize_options(options: RepositoryFinalizeOptions) -> None:
    verification = options.verification
    _positive_integer(verification.votes, "verification votes")
    _positive_integer(verification.concurrency, "verification concurrency")
    if verification.enabled and verification.verifier is None:
        if verification.provider is None:
            raise ValueError("verification needs a provider, or an injected verifier")
        if not verification.model:
            raise ValueError("verification model must be a nonempty string")
    _validate_confirmers(verification.confirmers)


def _finding_slug(text: str) -> str:
    return ("".join(c if c.isalnum() else "-" for c in text).strip("-").lower() or "finding")[:80]


def _normalized_evidence_block(text: str) -> str:
    return " ".join(re.findall(r"\w+", text.lower()))


def _evidence_compare_text(text: str) -> str:
    lines = text.splitlines()
    while lines and lines[0].lstrip().startswith("#"):
        lines = lines[1:]
    return "\n".join(lines).strip() or text


def _near_duplicate_evidence(text: str, seen: list[str]) -> bool:
    norm = _normalized_evidence_block(_evidence_compare_text(text))
    if not norm:
        return True
    settings = DEFAULT_REVIEW_SETTINGS.deduplication
    for prior in seen:
        if norm == prior:
            return True
        if (
            len(norm) >= settings.min_evidence_chars_for_similarity
            and SequenceMatcher(None, norm, prior).ratio() >= settings.near_duplicate_similarity_threshold
        ):
            return True
    seen.append(norm)
    return False


def _dedupe_evidence(text: str) -> str:
    body = text.strip()
    if not body:
        return ""
    if "\n\n" in body:
        blocks = [block.strip() for block in re.split(r"\n{2,}", body)]
        joiner = "\n\n"
    elif "; " in body:
        blocks = [block.strip() for block in body.split("; ")]
        joiner = "; "
    else:
        return body
    kept: list[str] = []
    seen: list[str] = []
    for block in blocks:
        if not block:
            continue
        duplicate = _near_duplicate_evidence(block, seen)
        if block.startswith("#") or not duplicate:
            kept.append(block)
    return joiner.join(kept)


def _finding_md(c: Candidate, owner: str = "") -> str:
    src = c.endpoint or c.file or "(no location)"
    head = (
        f"# {c.title}\n\n"
        f"- Risk: {c.severity}\n"
        f"- Type: {c.category or 'other'}\n"
        f"- Source: `{src}`\n"
        f"- Status: {c.status}\n" + (f"- Owner: {owner}\n" if owner else "") + "\n"
    )
    body = _dedupe_evidence(c.evidence)
    if body.startswith("#"):
        return head + body + "\n"
    return head + f"## Analysis\n{body or '(see code)'}\n"


def _finding_name(c: Candidate) -> str:
    """The shared name tying a finding to its source candidate and its PoC.

    Workspace candidates carry their markdown basename on `source`. Coded run candidates
    have no candidate file, so fall back to a slug of the dedup identity, location plus
    class. The class matters: two findings on one endpoint kept distinct by their category,
    a missing binding and a race, would otherwise slug alike and one would overwrite the
    other.
    """
    if c.source.endswith(".md"):
        return Path(c.source).stem
    return _finding_slug(f"{c.endpoint or c.file or c.title} {c.category}")


def _poc_for(ws: Path, name: str) -> str:
    """The PoC whose basename matches a finding's name.

    The workflow links candidates/<name>.md and pocs/<name>.<ext> by basename. It matches
    the whole extension, so an extension in several parts such as `.t.sol` links too, where
    `Path.stem` would keep the `.t` and never match.
    """
    pocs = ws / "pocs"
    if not pocs.is_dir():
        return ""
    for p in sorted(pocs.iterdir()):
        if p.is_file() and (p.name == name or p.name.startswith(f"{name}.")):
            return f"pocs/{p.name}"
    return ""


def _poc_name(path: Path) -> str:
    """The finding name a PoC file maps to, preserving multi suffix extensions."""
    for suffix in ("".join(path.suffixes), path.suffix):
        if suffix and path.name.endswith(suffix):
            return path.name[: -len(suffix)]
    return path.stem


_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_GIT_BLAME_TIMEOUT_SECONDS = 10
_GIT_CONFIG_TIMEOUT_SECONDS = 2


def _confidence(c: Candidate) -> int:
    """Count independent model support for finding rank."""
    return len(set(c.found_by))


def _git_blame_owner(root: str, file: str, line: int | None) -> str:
    """The last author to touch a finding's line, by git blame, so a report names an owner.

    Best-effort and fail-soft: empty on a non-git target, an uncommitted or moved file, a
    missing line, or no root. Blame is an annotation, never a gate, so a failure here never
    fails the review, invariant 4 lives on the review steps not on this.
    """
    if not root or not file or not line or line < 1:
        return ""
    if safe_repository_path(root, file) is None:
        return ""
    try:
        out = subprocess.run(
            ["git", "-C", root, "blame", "-L", f"{line},{line}", "--porcelain", "--", file],
            capture_output=True,
            text=True,
            timeout=_GIT_BLAME_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if out.returncode != 0:
        return ""
    name = ""
    email = ""
    for ln in out.stdout.splitlines():
        if ln.startswith("author ") and not name:
            name = ln[len("author ") :].strip()
        elif ln.startswith("author-mail "):
            email = ln[len("author-mail ") :].strip().strip("<>")
        if name and email:
            break
    if name and email:
        return f"{name} <{email}>"
    return name


def _git_blame_available(root: str) -> bool:
    """True when blame can run without lazy fetching blobs during report writing."""
    if not root:
        return False
    try:
        out = subprocess.run(
            ["git", "-C", root, "config", "--get", "remote.origin.promisor"],
            capture_output=True,
            text=True,
            timeout=_GIT_CONFIG_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.stdout.strip().lower() != "true"


def _finding_entry(ws: Path, c: Candidate, owner: str = "") -> dict:
    candidate = f"candidates/{c.source}" if c.source.endswith(".md") else ""
    return {
        "title": c.title,
        "category": c.category,
        "entry": c.endpoint,
        "file": c.file,
        "line": c.line,
        "severity": c.severity,
        "status": c.status,
        "analysis": _dedupe_evidence(c.evidence),
        "owner": owner,
        "found_by": list(c.found_by),
        "models": _confidence(c),
        "candidate": candidate,
        "poc": _poc_for(ws, _finding_name(c)),
    }


def _load_source_meta(root: str) -> SourceMeta | None:
    """Optional provenance for a fetched target, read at report time from the target root.

    It never reaches a finding decision, invariants 2 and 3, it only annotates the report.
    """
    if not root:
        return None
    return read_source_meta_file(Path(root) / "cyberjury-source.json")


def _target_md(meta: SourceMeta) -> str:
    """A Target section for the report, printing only the fields that are present."""
    lines = ["## Target", ""]
    lines += [f"- {label}: {value}" for label, value in meta.display_rows()]
    lines.append("")
    return "\n".join(lines)


def _write_findings(ws: Path, findings: list[Candidate], root: str = "") -> None:
    """Write the confirmed findings, the code-owned output.

    Ranked by how many models agreed then severity, so a cross-model consensus surfaces
    above a lone model's finding. findings/ is cleared and rewritten in full, so a shrunk or
    refuted set leaves no stale file behind, and candidates/ and pocs/ are never
    touched. When a target root can answer blame without lazy fetching blobs, each finding
    is annotated with the owner of its line. Optional source provenance from
    cyberjury-source.json is added to the report.
    """
    meta = _load_source_meta(root)
    findings = sorted(findings, key=lambda c: (-_confidence(c), _SEV_RANK.get(c.severity, 4)))
    owners = {id(c): _git_blame_owner(root, c.file, c.line) for c in findings} if _git_blame_available(root) else {}
    findings_dir = ws / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    for p in findings_dir.glob("*.md"):
        p.unlink()
    used: set[str] = set()
    for c in findings:
        base = _finding_name(c)
        name = base
        n = 2
        while name in used:
            name = f"{base}-{n}"
            n += 1
        used.add(name)
        (findings_dir / f"{name}.md").write_text(_finding_md(c, owners.get(id(c), "")), encoding="utf-8")
    report: dict = {"findings": [_finding_entry(ws, c, owners.get(id(c), "")) for c in findings]}
    if meta is not None:
        report["target"] = meta.to_dict()
        (ws / "_target.md").write_text(_target_md(meta), encoding="utf-8")
    (ws / "findings.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_coverage_suggestions(ws: Path, result: CoverageAnalysisResult[Candidate]) -> None:
    """Persist optional coverage suggestions without changing findings."""
    lines = [
        "# Finding Coverage Suggestions",
        "",
        "Verified candidates grouped by the coverage model. Every candidate remains in the final report.",
        "",
    ]
    for item in result.suggestions:
        targets = ", ".join(f"`{target.file}:{target.line}` {target.title}" for target in item.represented_by)
        lines.extend(
            (
                f"- **{item.finding.title}** at `{item.finding.file}:{item.finding.line}`",
                f"  - Represented by: {targets}",
                f"  - Reason: {item.reason}",
            )
        )
    (ws / "_coverage_suggestions.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_pocs_report(ws: Path, findings: list[Candidate]) -> None:
    """Reconcile pocs/ against the confirmed findings, recorded not enforced.

    A finding may need a PoC only an operator can run, invariant 6, and a PoC may outlive a
    candidate the verifier later refuted. Surface both so neither is silently lost.
    """
    pocs = ws / "pocs"
    poc_files = sorted(p for p in pocs.iterdir() if p.is_file()) if pocs.is_dir() else []
    if not poc_files and not any(c.source.endswith(".md") for c in findings):
        return
    names = {_finding_name(c) for c in findings}
    poc_names = {_poc_name(p) for p in poc_files}
    missing = [c for c in findings if _finding_name(c) not in poc_names]
    orphan = [p for p in poc_files if _poc_name(p) not in names]
    lines = [
        "# PoC Reconciliation",
        "",
        "Confirmed findings matched to PoCs by name. Recorded, not gated: a finding "
        "may need a PoC only an operator can run, and a PoC may outlive a refuted candidate.",
        "",
        "## Confirmed findings with no PoC",
        "",
    ]
    lines += [f"- **{c.title}** `{c.endpoint or c.file}`" for c in missing] or [
        "None, every confirmed finding has a PoC."
    ]
    lines += ["", "## PoC files with no confirmed finding", ""]
    lines += [f"- `pocs/{p.name}`" for p in orphan] or ["None, every PoC maps to a confirmed finding."]
    (ws / "_pocs.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_surface(ws: Path, units: list[Unit], reviewed_slugs: set[str]) -> None:
    """Populate the attack-surface inventory from the unit worklist.

    In a coded run the enumerated surface is the worklist, one row per unit, so the
    denominator is explicit and the gate's surface check is satisfied. Unit markers are the
    resume contract, so active failures and nonconverged work remain open here too.
    """
    lines = [
        "# Attack Surface Inventory",
        "",
        "Enumerated by the coded engine from the unit worklist, one row per unit.",
        "",
        "| Package | Owned files | Unit | Status |",
        "|---|---|---|---|",
    ]
    for u in units:
        owned = u.files[0] if u.files else u.name
        pkg = Path(owned).parts[0] if Path(owned).parts else ""
        status = "reviewed" if unit_slug(u.name) in reviewed_slugs else "open"
        owned_files = "<br>".join(u.files) if u.files else u.name
        lines.append(f"| {pkg} | {owned_files} | {u.name} | {status} |")
    (ws / "inventory" / "_surface.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _seed_run_units(ws: Path, units: list[Unit], paths) -> None:
    """Reconcile the units worklist to the coded run's actual units.

    Scaffold seeds one file per candidate file, but the run splits a large file into several
    window units and adds the focused units a facts backend drives, whose names are not
    candidate paths. Without a file per run unit those units have nothing to mark reviewed,
    so a resume re-reviews them and the orphan candidate file is left open forever. Seed a
    file per run unit and drop the stale ones so resume, marking, and the gate all key on
    the same set. Existing files are kept, so a reviewed unit is not reset.
    """
    udir = ws / "units"
    wanted = {unit_slug(u.name): u for u in units}
    for f in udir.glob("*.md"):
        if f.stem not in wanted:
            f.unlink()
    mandate = paths.unit_review_file.read_text(encoding="utf-8")
    for slug, u in wanted.items():
        up = udir / f"{slug}.md"
        if not up.exists():
            up.write_text(_unit_md(u.name, mandate, owned_paths=u.files), encoding="utf-8")


def _mark_units_reviewed(ws: Path, reviewed_slugs: set) -> None:
    """Flip a unit from open to reviewed only when it reviewed cleanly this run.

    A unit that raised on every pass is left open, so the gate catches it and a later resume
    retries it, never reporting a failed review as covered.
    """
    for u in (ws / "units").glob("*.md"):
        if u.stem not in reviewed_slugs:
            continue
        text = u.read_text(encoding="utf-8")
        u.write_text(re.sub(r"(?im)^-\s*Status:\s*open\s*$", "- Status: reviewed", text), encoding="utf-8")


def _cand_to_dict(c: Candidate) -> dict:
    return {
        "attack_path_id": c.attack_path_id,
        "candidate_id": c.candidate_id,
        "title": c.title,
        "category": c.category,
        "endpoint": c.endpoint,
        "symbol": c.symbol,
        "file": c.file,
        "line": c.line,
        "severity": c.severity,
        "attack_path": c.attack_path,
        "evidence": c.evidence,
        "status": c.status,
        "source": c.source,
        "evidence_refs": list(c.evidence_refs),
        "found_by": list(c.found_by),
    }


def _cand_from_dict(d: dict) -> Candidate:
    return Candidate(
        title=d.get("title", ""),
        category=d.get("category", ""),
        endpoint=d.get("endpoint", ""),
        symbol=d.get("symbol", ""),
        file=d.get("file", ""),
        line=d.get("line"),
        severity=d.get("severity", "MEDIUM"),
        attack_path=d.get("attack_path", ""),
        evidence=d.get("evidence", ""),
        status=d.get("status", "confirmed"),
        source=d.get("source", ""),
        evidence_refs=tuple(d.get("evidence_refs", ())),
        found_by=tuple(d.get("found_by", ())),
    )


def _checkpoint_candidate(value: object) -> Candidate:
    if not isinstance(value, dict):
        raise TypeError("each finding must be an object")
    strings = (
        "attack_path_id",
        "candidate_id",
        "title",
        "category",
        "endpoint",
        "symbol",
        "file",
        "severity",
        "attack_path",
        "evidence",
        "status",
        "source",
    )
    for name in strings:
        field = value.get(name, "MEDIUM" if name == "severity" else "confirmed" if name == "status" else "")
        if not isinstance(field, str):
            raise TypeError(f"finding field {name!r} must be a string")
    if not value.get("title", "").strip():
        raise TypeError("finding field 'title' must be a nonempty string")
    if value.get("severity", "MEDIUM") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        raise TypeError("finding field 'severity' must be a known severity")
    if value.get("status", "confirmed") not in ("blocked", "confirmed"):
        raise TypeError("finding field 'status' must be blocked or confirmed")
    line = value.get("line")
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        raise TypeError("finding field 'line' must be a positive integer or null")
    found_by = value.get("found_by", [])
    if not isinstance(found_by, list) or not all(isinstance(label, str) for label in found_by):
        raise TypeError("finding field 'found_by' must be a list of strings")
    evidence_refs = value.get("evidence_refs", [])
    if not isinstance(evidence_refs, list) or not all(isinstance(ref, str) and ref for ref in evidence_refs):
        raise TypeError("finding field 'evidence_refs' must be a list of nonempty strings")
    candidate = _cand_from_dict(value)
    if value["attack_path_id"] != candidate.attack_path_id:
        raise TypeError("finding field 'attack_path_id' does not match its entry path")
    if value["candidate_id"] != candidate.candidate_id:
        raise TypeError("finding field 'candidate_id' does not match its source identity")
    return candidate


def _save_union(
    ws: Path,
    cands: list[Candidate],
    *,
    severity_votes: dict[tuple, list[str]] | None = None,
    by_file: bool = False,
) -> None:
    votes = severity_votes or {}
    (ws / "_union.json").write_text(
        json.dumps(
            {
                "schema": 3,
                "findings": [_cand_to_dict(c) for c in cands],
                "severity_votes": {
                    candidate.candidate_id: list(votes.get(candidate.key(by_file), [candidate.severity]))
                    for candidate in cands
                },
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def _policy_record(plan: ReviewSchedule) -> dict[str, object]:
    return {
        "schema": 1,
        "mode": plan.mode,
        "completion": plan.completion,
        "min_rounds": plan.min_rounds,
        "converge_after": plan.converge_after,
        "stop_on_failure": plan.stop_on_failure,
    }


def _load_run_status(ws: Path) -> dict[str, object] | None:
    path = ws / "_run.json"
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise _resume_corrupt(path, exc) from exc
    if not isinstance(value, dict):
        raise _resume_corrupt(path, TypeError("status must be an object"))
    return value


def _validate_prior_policy(status: dict[str, object] | None, plan: ReviewSchedule, *, fresh: bool, ws: Path) -> None:
    if fresh or status is None:
        return
    prior = status.get("policy")
    if prior != _policy_record(plan):
        raise ValueError(
            f"repository review policy changed since the run at {ws}. "
            "Re-run with --fresh so reviewed units are evaluated under one policy."
        )


def _restored_complete_outcome(
    status: dict[str, object] | None,
    findings: list[Candidate],
    grounding: GroundingCoverage,
    plan: ReviewSchedule,
    path: Path,
) -> ReviewOutcome[Candidate] | None:
    if status is None or status.get("complete") is not True:
        return None
    converged = status.get("converged")
    requires_convergence = status.get("requires_convergence")
    rounds = status.get("rounds")
    expected_convergence = plan.completion == "converge"
    if not isinstance(converged, bool) or not isinstance(requires_convergence, bool):
        raise _resume_corrupt(path, TypeError("complete status has invalid convergence fields"))
    if requires_convergence != expected_convergence or converged != expected_convergence:
        raise _resume_corrupt(path, ValueError("complete status contradicts its review policy"))
    if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 0:
        raise _resume_corrupt(path, TypeError("complete status has invalid rounds"))
    if rounds < plan.min_rounds:
        raise _resume_corrupt(path, ValueError("complete status has insufficient completed rounds"))
    if _pending_from_status(status, path):
        raise _resume_corrupt(path, ValueError("complete status still contains pending work"))
    zero_counters = ("errors", "verify_errors", "coverage_analysis_errors", "facts_limitations")
    if any(status.get(name, 0) != 0 for name in zero_counters):
        raise _resume_corrupt(path, ValueError("complete status still contains failed or incomplete work"))
    empty_collections = ("failed_units", "unit_failures")
    if any(status.get(name, []) != [] for name in empty_collections) or status.get("failure_reason"):
        raise _resume_corrupt(path, ValueError("complete status still contains failure records"))
    return ReviewOutcome(
        findings=tuple(findings),
        converged=converged,
        requires_convergence=requires_convergence,
        rounds=rounds,
        grounding=grounding,
    )


def _pending_from_status(status: dict[str, object] | None, path: Path) -> tuple[PendingWorkRecord, ...]:
    if status is None:
        return ()
    values = status.get("pending", [])
    if not isinstance(values, list) or not all(isinstance(value, dict) for value in values):
        raise _resume_corrupt(path, TypeError("pending must be an object list"))
    return tuple(cast("PendingWorkRecord", dict(value)) for value in values)


def _save_run_status(
    ws: Path,
    *,
    units_total: int,
    acc: Accumulator,
    verify: VerifyResult | None,
    plan: ReviewSchedule,
    outcome: ReviewOutcome[Candidate] | None = None,
    rounds: int = 0,
    pending: tuple[PendingWorkRecord, ...] = (),
    timing: dict | None = None,
    usage: dict[str, int] | None = None,
    facts_limitations: int = 0,
    state: str = "running",
    coverage_analysis: CoverageAnalysisResult[Candidate] | None = None,
    source_revision: str = "",
    model_calls: list[dict[str, object]] | None = None,
) -> None:
    """Persist the coded run's coverage and failure state.

    The unit markers drive resume while this record lets finalize and the gate inspect
    completion, convergence, and failures. A running snapshot survives interruption. The
    final snapshot records `timing`, `usage`, and the reviewed marker count.
    """
    complete = outcome.complete if outcome is not None else False
    converged = outcome.converged if outcome is not None else acc.converged
    requires_convergence = outcome.requires_convergence if outcome is not None else plan.completion == "converge"
    recorded_rounds = outcome.rounds if outcome is not None else rounds
    status = {
        "policy": _policy_record(plan),
        "units_total": units_total,
        "units_reviewed": len(_reviewed_slugs(ws)),
        "failed_units": sorted(acc.failed_units),
        "unit_failures": [asdict(failure) for failure in acc.unit_failures],
        "recovered_unit_failures": [
            asdict(failure) for failure in (outcome.recovered_failures if outcome is not None else ())
        ],
        "errors": acc.errors,
        "verify_errors": verify.errors if verify else 0,
        "coverage_analysis_errors": coverage_analysis.errors if coverage_analysis else 0,
        "coverage_suggestions": len(coverage_analysis.suggestions) if coverage_analysis else 0,
        "facts_limitations": facts_limitations,
        "converged": converged,
        "requires_convergence": requires_convergence,
        "rounds": recorded_rounds,
        "complete": complete,
        "state": state,
        "source_revision": source_revision,
        "model_calls": model_calls or [],
        "pending": [dict(item) for item in (outcome.pending if outcome is not None else pending)],
    }
    if verify is not None:
        status["retained"] = len(verify.retained)
        status["verified"] = len(verify.verified)
        status["refuted"] = len(verify.refuted)
        status["incomplete"] = len(verify.incomplete)
        status["unlocatable"] = len(verify.unlocatable)
    failure_reason = ". ".join(
        dict.fromkeys(
            reason
            for reason in (
                outcome.failure_reason if outcome is not None else "",
                verification_failure_reason(verify.error_details) if verify is not None else "",
                coverage_analysis_failure_reason(coverage_analysis.error_details)
                if coverage_analysis is not None
                else "",
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
    (ws / "_run.json").write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")


def _resume_corrupt(p: Path, exc: Exception) -> ValueError:
    return ValueError(
        f"resume checkpoint {p} is unreadable or corrupt: {exc}. "
        "Remove the workspace to discard prior state and start over."
    )


@dataclass(frozen=True, kw_only=True)
class _UnionCheckpoint:
    pool: dict[tuple, Candidate]
    severity_votes: dict[tuple, list[str]]


def _load_union_checkpoint(ws: Path, by_file: bool = False) -> _UnionCheckpoint:
    p = ws / "_union.json"
    if not p.is_file():
        return _UnionCheckpoint(pool={}, severity_votes={})
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) != {"schema", "findings", "severity_votes"} or data["schema"] != 3:
            raise TypeError("expected a schema 3 object containing findings and severity_votes")
        findings = data["findings"]
        if not isinstance(findings, list):
            raise TypeError("findings must be a list")
        candidates = [_checkpoint_candidate(value) for value in findings]
        raw_votes = data["severity_votes"]
        if not isinstance(raw_votes, dict) or set(raw_votes) != {candidate.candidate_id for candidate in candidates}:
            raise TypeError("severity_votes must contain every candidate id exactly once")
        if any(
            not isinstance(values, list)
            or not values
            or any(value not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} for value in values)
            for values in raw_votes.values()
        ):
            raise TypeError("severity_votes values must be nonempty severity lists")
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise _resume_corrupt(p, exc) from exc
    pool = {candidate.key(by_file): candidate for candidate in candidates}
    votes = {candidate.key(by_file): list(raw_votes[candidate.candidate_id]) for candidate in candidates}
    return _UnionCheckpoint(pool=pool, severity_votes=votes)


def _load_union(ws: Path, by_file: bool = False) -> dict:
    """Load only the candidate pool for finalize and compatibility callers."""
    return _load_union_checkpoint(ws, by_file).pool


def _reviewed_slugs(ws: Path) -> set:
    return {
        u.stem
        for u in (ws / "units").glob("*.md")
        if re.search(r"(?im)^-\s*Status:\s*reviewed\s*$", u.read_text(encoding="utf-8"))
    }


def _md_field(text: str, key: str) -> str:
    v = md_field(text, key)
    return v.strip("`").strip() if v is not None else ""


@cache
def _location_re(source_extensions: frozenset[str]) -> re.Pattern:
    """Build a location matcher without naming a language in code.

    Extensions are sorted longest first so a path like `app.tsx` matches the
    `tsx` alternative, not the `ts` prefix of it. Cached per extension set so each profile's
    matcher is built once.
    """
    exts = sorted((e.lstrip(".") for e in source_extensions), key=len, reverse=True)
    alt = "|".join(re.escape(e) for e in exts)
    return re.compile(rf"([\w./-]+\.(?:{alt}))(?::(\d+))?")


def _candidate_body(text: str) -> str:
    """The prose body of a workspace candidate, from its first section heading to the end.

    The finding carries analysis rather than a bare pointer back to the file.
    """
    m = re.search(r"(?m)^##\s", text)
    return text[m.start() :].strip() if m else ""


def _canonicalize_categories(cands: list[Candidate], vulnerabilities_dir: Path) -> list[Candidate]:
    """Apply the shared profile category contract before dedup and reporting."""
    catalog = VulnerabilityCatalog.load(vulnerabilities_dir)
    return [replace(candidate, category=catalog.canonicalize(candidate.category)) for candidate in cands]


def _parse_candidate(path: Path, source_extensions: frozenset[str] | None = None) -> Candidate | None:
    """Parse candidates/<name>.md into a Candidate for coded dedup and verification.

    The source extensions decide what counts as a file location, defaulting to the web
    profile.
    """
    if source_extensions is None:
        source_extensions = load_detection().source_extensions
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    title = next((ln[2:].strip() for ln in text.splitlines() if ln.startswith("# ")), path.stem)
    title = re.sub("(?i)^finding\\s*[:\uff1a]\\s*", "", title).strip() or path.stem
    sev_raw = _md_field(text, "(?:risk|severity)").upper()
    severity = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in sev_raw), "MEDIUM")
    fm = _location_re(source_extensions).search(text)
    if fm is None or is_unsafe_rel(fm.group(1)):
        return None
    status_raw = _md_field(text, "status").lower()
    if status_raw.startswith(("refuted", "clear")) or title.lower().startswith("cleared"):
        return None
    return Candidate(
        title=title or path.stem,
        category=_md_field(text, "type"),
        endpoint=_md_field(text, "source"),
        symbol=_md_field(text, "source"),
        file=fm.group(1),
        line=int(fm.group(2)) if fm.group(2) else None,
        severity=severity,
        evidence=_candidate_body(text),
        status="blocked" if status_raw == "blocked" else "confirmed",
        source=path.name,
    )


@dataclass(frozen=True, kw_only=True)
class FinalizeResult:
    """Finalized findings plus verification and PoC accounting."""

    workspace: Path
    parsed: int
    deduped: int
    verify: VerifyResult | None
    outcome: ReviewOutcome[Candidate]


def finalize_repository_review(
    target: str | Path,
    workspace: str | Path,
    *,
    options: RepositoryFinalizeOptions | None = None,
) -> FinalizeResult:
    """The coded post-fan-out pipeline: dedup, verify, report over the candidates.

    These steps are mechanical: read `candidates/*.md`, or the coded run's `_union.json`
    when no workspace candidates exist, dedup by location and class, adversarially verify
    each survivor, skip any already in `_verified.json`, write refuted candidates to
    `_refuted.md`, then write the confirmed `findings/*.md` and ranked `findings.json`.
    """
    options = options or RepositoryFinalizeOptions()
    _validate_repository_finalize_options(options)
    verification = options.verification
    output = options.output
    profile = output.profile or default_profile()
    paths = profile.paths
    source_extensions = load_detection(paths.detection_file).source_extensions
    ws = Path(workspace) / Path(target).resolve().name
    root = str(Path(target).resolve())
    if not (ws / WORKSPACE_MARKER).is_file():
        raise ValueError(f"{ws} has no {WORKSPACE_MARKER} marker. Run --scaffold or --run before --finalize.")
    if not (ws / "candidates").is_dir() and not (ws / "_union.json").is_file():
        raise ValueError(f"{ws} has no candidates/ or _union.json to finalize")
    source_snapshot = _finalize_source_snapshot(ws, Path(root), profile)

    by_file = profile.dedup_by_file
    cands = [c for c in (_parse_candidate(p, source_extensions) for p in sorted((ws / "candidates").glob("*.md"))) if c]
    if not cands and (ws / "_union.json").is_file():
        cands = list(_load_union(ws, by_file).values())
    cands = _canonicalize_categories(cands, paths.vulnerabilities_dir)
    accumulator = candidate_accumulator(by_file=by_file)
    accumulator.add(cands)
    deduped = collapse_colocated(accumulator.findings)
    deduped_count = len(deduped)

    vr: VerifyResult | None = None
    if verification.enabled and deduped:
        deduped, vr = apply_verification(
            ws,
            deduped,
            root=root,
            verifier=verification.verifier,
            confirmers=verification.confirmers,
            provider=verification.provider,
            model=verification.model,
            votes=verification.votes,
            concurrency=verification.concurrency,
            fresh=False,
            content=paths,
            by_file=by_file,
            on_verify=verification.on_verify,
            source_snapshot=source_snapshot,
        )

    coverage_analysis = _analyze_repository_coverage(
        deduped,
        verify=vr,
        provider=verification.provider,
        model=verification.model,
    )
    deduped = coverage_analysis.findings
    _write_coverage_suggestions(ws, coverage_analysis)

    if output.poc_backend is not None and deduped:
        deduped = _run_pocs(ws, deduped, output.poc_backend, root)
    if deduped and profile.poc_backend is not None:
        deduped = _execute_present_pocs(ws, deduped, profile, root)

    _write_findings(ws, deduped, root)
    _write_pocs_report(ws, deduped)
    limitations = load_facts_limitations(ws)
    outcome = ReviewOutcome(
        findings=deduped,
        incomplete=[*vr.incomplete, *vr.unlocatable] if vr is not None else [],
        errors=(vr.errors if vr is not None else 0) + coverage_analysis.errors,
        failure_reason=coverage_analysis_failure_reason(coverage_analysis.error_details),
        grounding=GroundingCoverage(limitations=tuple(item.identity for item in limitations)),
        requires_convergence=False,
    )
    _save_finalize_status(
        ws,
        parsed=len(cands),
        deduped=deduped_count,
        verify=vr,
        outcome=outcome,
        coverage_analysis=coverage_analysis,
        meter=output.meter,
    )
    return FinalizeResult(
        workspace=ws,
        parsed=len(cands),
        deduped=deduped_count,
        verify=vr,
        outcome=outcome,
    )


def _finalize_source_snapshot(
    workspace: Path,
    root: Path,
    profile: ReviewProfile,
) -> SourceSnapshot | None:
    """Restore and validate the source revision recorded by scaffold."""
    marker = workspace / WORKSPACE_MARKER
    try:
        identity = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"workspace marker {marker} is unreadable: {exc}") from exc
    expected = identity.get("source_fingerprint") if isinstance(identity, dict) else None
    if not isinstance(expected, str) or not expected:
        return None
    detection = load_detection(profile.paths.detection_file)
    backend = profile.facts_backend
    snapshot = SourceSnapshot.capture(
        root,
        repository_files(root, detection),
        profile.name,
        profile_fingerprint=profile_content_fingerprint(profile),
        backend_identity=backend.cache_identity() if backend is not None else "",
    )
    if snapshot.key != expected:
        raise ValueError("repository source changed after the workspace evidence revision was captured")
    return snapshot


def _save_finalize_status(
    ws: Path,
    *,
    parsed: int,
    deduped: int,
    verify: VerifyResult | None,
    outcome: ReviewOutcome[Candidate],
    coverage_analysis: CoverageAnalysisResult[Candidate],
    meter: UsageMeter | None,
) -> None:
    """Persist what finalize did, which otherwise survives only as the findings it wrote."""
    status: dict[str, object] = {
        "parsed": parsed,
        "deduped": deduped,
        "facts_limitations": len(outcome.grounding.limitations),
        "complete": outcome.complete,
        "errors": outcome.errors,
        "coverage_suggestions": len(coverage_analysis.suggestions),
    }
    if outcome.failure_reason:
        status["failure_reason"] = outcome.failure_reason
    if verify is not None:
        status["verify_errors"] = verify.errors
        status["retained"] = len(verify.retained)
        status["verified"] = len(verify.verified)
        status["refuted"] = len(verify.refuted)
        status["incomplete"] = len(verify.incomplete)
        status["unlocatable"] = len(verify.unlocatable)
    if meter is not None:
        status["usage"] = meter.snapshot()
        status["model_calls"] = meter.call_snapshot()
    (ws / "_finalize.json").write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")


def _run_pocs(ws: Path, findings: list[Candidate], backend: PoCBackend, root: str) -> list[Candidate]:
    """Write a PoC for each confirmed finding and run it where the profile supports execution.

    When the toolchain is present, execution records evidence before this method writes
    `pocs/<name>.<ext>` so the reconciliation links it. Adds evidence, never
    drops a finding, invariant 2, so a PoC that fails to reproduce, or one a human must run,
    is recorded and never treated as safe. An executing profile whose toolchain is absent
    degrades to write-only with an install hint, so a missing toolchain never aborts
    finalize and never hides a finding, invariant 4.
    """
    executes = backend.executes
    if executes and not isinstance(backend, ReproducingPoCBackend):
        raise TypeError("an automatically executed PoC backend must implement reproduce")
    runnable = executes and backend.available()
    pocs = ws / "pocs"
    pocs.mkdir(exist_ok=True)
    annotated: list[Candidate] = []
    for c in findings:
        name = _finding_name(c)
        try:
            if runnable:
                res = backend.reproduce(
                    title=c.title, analysis=c.evidence, symbol=c.symbol, file=c.file, line=c.line, root=root
                )
                source = res.test_source
                note = f"PoC reproduced: {res.detail}" if res.reproduced else f"PoC inconclusive: {res.detail}"
            else:
                art = backend.generate(
                    title=c.title,
                    analysis=c.evidence,
                    symbol=c.symbol,
                    file=c.file,
                    line=c.line,
                    endpoint=c.endpoint,
                    root=root,
                )
                source = art.source
                if executes:
                    note = (
                        f"PoC written, not run, toolchain absent. To run it: {backend.install_hint}. "
                        f"Then: {art.run_hint}"
                    )
                else:
                    note = f"PoC written, run it manually: {art.run_hint}"
                if art.note:
                    note = f"{note}. {art.note}"
        except Exception as exc:
            source = ""
            note = f"PoC failed to run: {exc}"
        if source:
            (pocs / f"{name}.{backend.ext}").write_text(source, encoding="utf-8")
        annotated.append(replace(c, evidence=f"{c.evidence}\n\n[{note}]".strip()))
    return annotated


def _execute_present_pocs(
    ws: Path,
    findings: list[Candidate],
    profile: ReviewProfile,
    root: str,
) -> list[Candidate]:
    """Run any PoC already present in `pocs/` through the profile's runner and record the result.

    A profile that never runs its PoC automatically, such as web, is left to the
    reconciliation. A PoC that fails to run is recorded, never a safe verdict, so the
    finding is kept, invariant 2. Local only, invariant 6.
    """
    if profile.poc_backend is None:
        return findings
    runner = profile.poc_backend()
    if not runner.executes:
        return findings
    out: list[Candidate] = []
    for c in findings:
        rel = _poc_for(ws, _finding_name(c))
        if not rel or "[PoC" in c.evidence:
            out.append(c)
            continue
        try:
            source = (ws / rel).read_text(encoding="utf-8")
            res = runner.execute(source=source, root=root)
            if res.ok:
                note = f"PoC reproduced: {res.detail}"
            elif res.ran:
                note = f"PoC inconclusive: {res.detail}"
            else:
                note = f"PoC not executed: {res.detail}"
        except (OSError, UnicodeDecodeError) as exc:
            note = f"PoC not executed: {exc}"
        except Exception as exc:
            note = f"PoC failed to run: {exc}"
        out.append(replace(c, evidence=f"{c.evidence}\n\n[{note}]".strip()))
    return out


@dataclass(frozen=True, kw_only=True)
class RunResult:
    """Coded repository run output and persisted run counters."""

    scaffold: ScaffoldResult
    accumulator: Accumulator
    units: int
    verify: VerifyResult | None = None
    outcome: ReviewOutcome[Candidate] | None = None


@dataclass(frozen=True, kw_only=True)
class _PreparedRun:
    """Validated workspace state and worklist ready for model execution."""

    plan: ReviewSchedule
    profile: ReviewProfile
    root: str
    scaffold: ScaffoldResult
    units: list[Unit]
    open_units: list[Unit]
    accumulator: Accumulator
    facts_by_file: dict[str, str]
    facts_limitations: tuple[FactLimitation, ...]
    shared_context: str
    facts_grounding: GroundingCoverage
    navigator: SourceNavigator | None
    prior_pending: tuple[PendingWorkRecord, ...]


@dataclass(frozen=True, kw_only=True)
class _ReviewerSeats:
    """Resolved repository reviewers for each configured role."""

    finders: list[UnitReviewer]
    challenger: UnitReviewer | None
    judge: UnitReviewer | None


@dataclass(frozen=True, kw_only=True)
class _RunTiming:
    """Raw timing records collected during unit execution."""

    started: float
    passes: list[dict[str, object]]
    units: list[tuple[str, float]]


@dataclass(frozen=True, kw_only=True)
class _PostprocessedRun:
    """Canonical findings and verification accounting ready to persist."""

    findings: list[Candidate]
    verify: VerifyResult | None
    coverage_analysis: CoverageAnalysisResult[Candidate]


def _candidate_coverage_record(candidate: Candidate) -> dict[str, object]:
    """Expose only the evidence needed to compare verified attack paths."""
    return {
        "category": candidate.category,
        "file": candidate.file,
        "line": candidate.line,
        "title": candidate.title,
        "endpoint": candidate.endpoint,
        "symbol": candidate.symbol,
        "evidence": candidate.evidence,
    }


def _analyze_repository_coverage(
    findings: list[Candidate],
    *,
    verify: VerifyResult | None,
    provider: Provider | None,
    model: str,
) -> CoverageAnalysisResult[Candidate]:
    """Suggest coverage only for a complete set of verified repository findings."""
    if verify is None or verify.errors or verify.incomplete or verify.unlocatable:
        return CoverageAnalysisResult(findings=findings)
    return suggest_finding_coverage(
        findings,
        provider=provider,
        model=model,
        record=_candidate_coverage_record,
    )


def run_repository_review(
    target: str | Path,
    workspace: str | Path,
    *,
    options: RepositoryRunOptions | None = None,
) -> RunResult:
    """Run the coded repository review workflow."""
    options = options or RepositoryRunOptions()
    prepared = _prepare_run_state(target, workspace, options)
    reviewers = _repository_reviewers(prepared, options.roles)
    timing = _execute_repository_units(prepared, reviewers, options)
    postprocessed = _postprocess_repository_run(prepared, options)
    return _persist_repository_run(prepared, postprocessed, timing, options.output)


def _prepare_run_state(
    target: str | Path,
    workspace: str | Path,
    options: RepositoryRunOptions,
) -> _PreparedRun:
    """Validate policy, scaffold the workspace, and restore resumable state."""
    lifecycle = options.lifecycle
    plan = _validate_repository_run_options(options)
    profile = options.output.profile or default_profile()
    paths = profile.paths
    root = str(Path(target).resolve())
    expected_workspace = Path(workspace) / Path(root).name
    run_status_path = expected_workspace / "_run.json"
    prior_status = _load_run_status(expected_workspace)
    _validate_prior_policy(prior_status, plan, fresh=lifecycle.fresh, ws=expected_workspace)
    res = scaffold(target, workspace, fresh=lifecycle.fresh, profile=profile)
    ws = res.workspace
    limitations = load_facts_limitations(ws)
    review_files = tuple(
        dict.fromkeys((*res.candidate_files, *res.raw_review_files, *(item.source for item in limitations)))
    )
    facts_graph = load_facts_graph(ws)
    relationship_evidence = load_relationship_evidence(ws)
    detection = load_detection(paths.detection_file)
    navigation_files = source_navigation_files(root, detection)
    fact_unit_specs = load_facts_unit_specs(ws)
    units = build_units(
        root,
        review_files,
        res.trace_targets,
        fact_unit_specs,
        facts_graph,
    )
    if not units:
        raise ValueError(
            f"no candidate entrypoints detected under {root}, so there is nothing to "
            "review. Add a guide for this stack or seed inventory/_entrypoints.md, then re-run."
        )

    _seed_run_units(ws, units, paths)
    reviewed = set() if lifecycle.fresh else _reviewed_slugs(ws)
    if reviewed and not (ws / "_union.json").is_file():
        raise ValueError(
            f"resume found reviewed units under {ws} but no _union.json checkpoint, the prior "
            "findings are lost. Re-run with --fresh to discard the markers and start over."
        )
    open_units = [u for u in units if unit_slug(u.name) not in reviewed]
    union = (
        _UnionCheckpoint(pool={}, severity_votes={})
        if lifecycle.fresh
        else _load_union_checkpoint(ws, profile.dedup_by_file)
    )
    acc = Accumulator(
        converge_after=plan.converge_after,
        pool=union.pool,
        sev_votes=union.severity_votes,
        dedup_by_file=profile.dedup_by_file,
    )

    facts_by_file = load_facts_by_file(ws)
    shared_context = repository_context(ws)
    if not facts_by_file:
        shared_context = with_facts_summary(shared_context, ws)
    facts_grounding = GroundingCoverage(limitations=tuple(item.identity for item in limitations))
    if not open_units:
        acc.outcome = _restored_complete_outcome(
            prior_status,
            acc.findings,
            facts_grounding,
            plan,
            run_status_path,
        )
    return _PreparedRun(
        plan=plan,
        profile=profile,
        root=root,
        scaffold=res,
        units=units,
        open_units=open_units,
        accumulator=acc,
        facts_by_file=facts_by_file,
        facts_limitations=limitations,
        shared_context=shared_context.text,
        facts_grounding=facts_grounding,
        navigator=SourceNavigator.from_graph(
            root,
            facts_graph,
            source_files=navigation_files,
            relationship_evidence=relationship_evidence,
            test_files=(file for file in navigation_files if detection.is_test_path(file)),
        ),
        prior_pending=_pending_from_status(prior_status, run_status_path),
    )


def _repository_reviewers(prepared: _PreparedRun, roles: RepositoryRoleOptions) -> _ReviewerSeats:
    """Resolve injected and model backed reviewers into named role seats."""
    paths = prepared.profile.paths

    def _make_reviewer(p: Provider, m: str) -> UnitReviewer:
        return ModelReviewer(provider=p, model=m, content=paths, facts_by_file=prepared.facts_by_file)

    reviewer = roles.reviewer
    if reviewer is None:
        if roles.provider is None:
            raise ValueError("run_repository_review needs a provider, or an injected reviewer")
        reviewer = _make_reviewer(roles.provider, roles.model)
    reviewers: list[UnitReviewer] = [reviewer]
    for p, m in roles.extra_finder_backends:
        reviewers.append(_make_reviewer(p, m))
    challenger = roles.challenger_reviewer
    judge = roles.judge_reviewer
    if roles.mode == "adversarial":
        challenger = challenger or (
            _make_reviewer(roles.challenger_provider, roles.challenger_model)
            if roles.challenger_provider is not None and roles.challenger_model
            else None
        )
        judge = judge or (
            _make_reviewer(roles.judge_provider, roles.judge_model)
            if roles.judge_provider is not None and roles.judge_model
            else None
        )
        if challenger is None or judge is None:
            raise ValueError("adversarial mode requires challenger and judge reviewers")
    else:
        challenger = None
        judge = None
    return _ReviewerSeats(finders=reviewers, challenger=challenger, judge=judge)


def _execute_repository_units(
    prepared: _PreparedRun,
    reviewers: _ReviewerSeats,
    options: RepositoryRunOptions,
) -> _RunTiming:
    """Run open units and checkpoint the monotonic finding union after each pass."""
    execution = options.execution
    output = options.output
    ws = prepared.scaffold.workspace
    acc = prepared.accumulator
    run_started = perf_counter()
    pass_records: list[dict[str, object]] = []
    unit_times: list[tuple[str, float]] = []
    last_pass_end = run_started
    last_usage: dict[str, int] = {}

    def _checkpoint_cycle(
        pass_no: int,
        label: str,
        new: int,
        union_size: int,
        cycle: ReviewCycle[Candidate],
    ) -> None:
        nonlocal last_pass_end, last_usage
        now = perf_counter()
        record: dict[str, object] = {
            "pass": pass_no,
            "reviewer": label,
            "new": new,
            "seconds": round(now - last_pass_end, 1),
        }
        usage = output.meter.snapshot() if output.meter is not None else None
        if usage is not None:
            record["usage"] = {k: v - last_usage.get(k, 0) for k, v in usage.items()}
            last_usage = usage
        pass_records.append(record)
        last_pass_end = now
        _save_run_status(
            ws,
            units_total=len(prepared.units),
            acc=acc,
            verify=None,
            plan=prepared.plan,
            rounds=pass_no,
            pending=tuple(cycle.pending),
            state="running",
            timing={"total_seconds": round(now - run_started, 1), "per_pass": pass_records},
            usage=usage,
            model_calls=output.meter.call_snapshot() if output.meter is not None else [],
            facts_limitations=len(prepared.facts_grounding.limitations),
            source_revision=(
                prepared.scaffold.source_snapshot.key if prepared.scaffold.source_snapshot is not None else ""
            ),
        )

    def _report_pass(pass_no: int, label: str, new: int, union_size: int) -> None:
        if execution.on_pass is not None:
            execution.on_pass(pass_no, label, new, union_size)

    if prepared.open_units:
        _save_run_status(
            ws,
            units_total=len(prepared.units),
            acc=acc,
            verify=None,
            plan=prepared.plan,
            rounds=0,
            pending=prepared.prior_pending,
            state="running",
            facts_limitations=len(prepared.facts_grounding.limitations),
            source_revision=(
                prepared.scaffold.source_snapshot.key if prepared.scaffold.source_snapshot is not None else ""
            ),
        )
        run_passes(
            prepared.open_units,
            reviewers.finders,
            challenger=reviewers.challenger,
            judge=reviewers.judge,
            plan=prepared.plan,
            shared_context=prepared.shared_context,
            fact_limitations=prepared.facts_limitations,
            initial_pending=prepared.prior_pending,
            navigator=prepared.navigator,
            source_snapshot=prepared.scaffold.source_snapshot,
            concurrency=execution.concurrency,
            checkpoint_cycle=_checkpoint_cycle,
            on_pass=_report_pass,
            on_unit=lambda name, secs: unit_times.append((name, secs)),
            on_judgment=execution.on_judgment,
            persist=lambda findings: _save_union(
                ws,
                findings,
                severity_votes=acc.sev_votes,
                by_file=prepared.profile.dedup_by_file,
            ),
            accumulator=acc,
            canonicalize_category=VulnerabilityCatalog.load(prepared.profile.paths.vulnerabilities_dir).canonicalize,
        )
    _save_union(
        ws,
        acc.findings,
        severity_votes=acc.sev_votes,
        by_file=prepared.profile.dedup_by_file,
    )
    keep_current_worklist_open = (
        acc.outcome is not None and acc.outcome.requires_convergence and not acc.outcome.converged
    )
    reviewed_slugs = (
        set()
        if keep_current_worklist_open
        else {unit_slug(unit.name) for unit in prepared.open_units if unit.name not in acc.failed_units}
    )
    _mark_units_reviewed(ws, reviewed_slugs)
    return _RunTiming(started=run_started, passes=pass_records, units=unit_times)


def _postprocess_repository_run(
    prepared: _PreparedRun,
    options: RepositoryRunOptions,
) -> _PostprocessedRun:
    """Canonicalize, verify, and enrich the accumulated candidates."""
    roles = options.roles
    verification = options.verification
    output = options.output
    profile = prepared.profile
    ws = prepared.scaffold.workspace
    findings = _canonicalize_categories(prepared.accumulator.findings, profile.paths.vulnerabilities_dir)
    if prepared.profile.dedup_by_file:
        findings = collapse_colocated(findings)
    vr: VerifyResult | None = None
    if verification.enabled:
        findings, vr = apply_verification(
            ws,
            findings,
            root=prepared.root,
            verifier=verification.verifier,
            confirmers=verification.confirmers,
            provider=verification.provider or roles.provider,
            model=verification.model or roles.model,
            votes=verification.votes,
            concurrency=verification.concurrency,
            fresh=options.lifecycle.fresh,
            content=profile.paths,
            by_file=profile.dedup_by_file,
            on_verify=verification.on_verify,
            source_snapshot=prepared.scaffold.source_snapshot,
        )

    coverage_analysis = _analyze_repository_coverage(
        findings,
        verify=vr,
        provider=roles.judge_provider or verification.provider or roles.provider,
        model=roles.judge_model or verification.model or roles.model,
    )
    findings = coverage_analysis.findings
    _write_coverage_suggestions(ws, coverage_analysis)

    if output.poc_backend is not None and findings:
        findings = _run_pocs(ws, findings, output.poc_backend, prepared.root)
    if findings and profile.poc_backend is not None:
        findings = _execute_present_pocs(ws, findings, profile, prepared.root)
    return _PostprocessedRun(findings=findings, verify=vr, coverage_analysis=coverage_analysis)


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
    coverage_analysis = postprocessed.coverage_analysis
    _write_surface(ws, prepared.units, _reviewed_slugs(ws))
    unit_totals: dict[str, float] = {}
    for name, secs in raw_timing.units:
        unit_totals[name] = round(unit_totals.get(name, 0.0) + secs, 1)
    by_cost = sorted(unit_totals.items(), key=lambda t: t[1], reverse=True)
    timing = {
        "total_seconds": round(perf_counter() - raw_timing.started, 1),
        "per_pass": raw_timing.passes,
        "unit_seconds": [{"unit": name, "seconds": secs} for name, secs in by_cost],
    }
    usage_total = output.meter.snapshot() if output.meter is not None else None
    if usage_total is not None:
        usage_total["unit_review_calls"] = len(raw_timing.units)
    incomplete = [*vr.incomplete, *vr.unlocatable] if vr is not None else []
    cycle_outcome = acc.outcome or ReviewOutcome(findings=acc.findings)
    outcome = extend_review_outcome(
        cycle_outcome,
        findings=findings,
        failures=acc.unit_failures,
        incomplete=incomplete,
        errors=(vr.errors if vr is not None else 0) + coverage_analysis.errors,
        failure_reason=". ".join(
            reason
            for reason in (
                verification_failure_reason(vr.error_details) if vr is not None else "",
                coverage_analysis_failure_reason(coverage_analysis.error_details),
            )
            if reason
        ),
        grounding=prepared.facts_grounding,
    )
    complete = outcome.complete
    if outcome.degraded:
        state = "incomplete"
    elif acc.converged:
        state = "converged"
    elif complete:
        state = "complete"
    else:
        state = "incomplete"
    _save_run_status(
        ws,
        units_total=len(prepared.units),
        acc=acc,
        verify=vr,
        plan=prepared.plan,
        outcome=outcome,
        timing=timing,
        usage=usage_total,
        facts_limitations=len(prepared.facts_grounding.limitations),
        state=state,
        coverage_analysis=coverage_analysis,
        source_revision=(
            prepared.scaffold.source_snapshot.key if prepared.scaffold.source_snapshot is not None else ""
        ),
        model_calls=output.meter.call_snapshot() if output.meter is not None else [],
    )
    _write_findings(ws, findings, prepared.root)
    _write_pocs_report(ws, findings)
    return RunResult(
        scaffold=prepared.scaffold,
        accumulator=acc,
        units=len(prepared.units),
        verify=vr,
        outcome=outcome,
    )
