"""Run the coded repository review engine end to end.

The library entry behind `review repository --run`. It scaffolds the workspace, builds
the unit worklist from the seeded candidates, runs the deterministic pass loop with a
model-backed reviewer, then writes findings into the workspace and marks every unit
reviewed. Standard mode covers every unit once. Adversarial mode runs role rounds until
convergence or the round cap. Precision is tightened by verification. Findings are
written both as `findings/*.md` and a machine-readable `findings.json`, so a run can be
scored against an answer key.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from difflib import SequenceMatcher
from functools import cache
from pathlib import Path
from time import perf_counter

from cyberjury.detection import load_detection
from cyberjury.markdown_docs import md_field
from cyberjury.profiles.base import ReviewProfile
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.base import Provider
from cyberjury.providers.metering import UsageMeter
from cyberjury.review.engine import ReviewOutcome, extend_review_outcome, review_plan
from cyberjury.review.paths import is_unsafe_rel, safe_repository_path
from cyberjury.review.repository.context import (
    Unit,
    load_facts_by_file,
    load_facts_graph,
    load_facts_unit_specs,
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
from cyberjury.review.verification import (
    RefutationChecker,
    Verifier,
    VerifyResult,
    verification_failure_reason,
)
from cyberjury.review.vulnerabilities import VulnerabilityCatalog
from cyberjury.sources.metadata import SourceMeta, read_source_meta_file


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
    """The shared name tying a finding to its source candidate and its poc.

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
    """The poc whose basename matches a finding's name.

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


def _write_surface(ws: Path, units: list[Unit], failed: set) -> None:
    """Populate the attack-surface inventory from the unit worklist.

    In a coded run the enumerated surface is the worklist, one row per unit, so the
    denominator is explicit and the gate's surface check is satisfied. A unit that never
    reviewed cleanly this run is marked open, not reviewed, so the surface does not claim a
    failed unit was covered.
    """
    lines = [
        "# Attack Surface Inventory",
        "",
        "Enumerated by the coded engine from the unit worklist, one row per unit.",
        "",
        "| Package | Owned file | Unit | Status |",
        "|---|---|---|---|",
    ]
    for u in units:
        owned = u.files[0] if u.files else u.name
        pkg = Path(owned).parts[0] if Path(owned).parts else ""
        status = "open" if u.name in failed else "reviewed"
        lines.append(f"| {pkg} | {owned} | {u.name} | {status} |")
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
            up.write_text(_unit_md(u.name, mandate), encoding="utf-8")


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
        "title": c.title,
        "category": c.category,
        "endpoint": c.endpoint,
        "symbol": c.symbol,
        "file": c.file,
        "line": c.line,
        "severity": c.severity,
        "evidence": c.evidence,
        "status": c.status,
        "source": c.source,
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
        evidence=d.get("evidence", ""),
        status=d.get("status", "confirmed"),
        source=d.get("source", ""),
        found_by=tuple(d.get("found_by", ())),
    )


def _save_union(ws: Path, cands: list[Candidate]) -> None:
    (ws / "_union.json").write_text(
        json.dumps({"findings": [_cand_to_dict(c) for c in cands]}, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _save_run_status(
    ws: Path,
    *,
    units_total: int,
    acc,
    verify,
    timing: dict | None = None,
    usage: dict[str, int] | None = None,
    state: str = "converged",
    complete: bool | None = None,
) -> None:
    """Persist the coded run's coverage and failure state.

    This state otherwise lives only in the accumulator and is lost when the process
    exits. A later finalize or gate can then read whether the run completed, whether the
    union converged, and how many reviews failed, so a failed run stays visible across
    steps and is never resumed as if it were clean, invariant 4. Written once per pass
    with `state` "running" so a kill mid-run leaves a progress snapshot, and once at the
    end with the final state, `timing`, and `usage`.
    """
    complete = acc.converged if complete is None else complete
    status = {
        "units_total": units_total,
        "units_reviewed": units_total - len(acc.failed_units),
        "failed_units": sorted(acc.failed_units),
        "unit_failures": [asdict(failure) for failure in acc.unit_failures],
        "errors": acc.errors,
        "verify_errors": verify.errors if verify else 0,
        "converged": acc.converged,
        "complete": complete,
        "state": state,
    }
    if verify is not None:
        status["confirmed"] = len(verify.confirmed)
        status["refuted"] = len(verify.refuted)
        status["incomplete"] = len(verify.incomplete)
        status["unlocatable"] = len(verify.unlocatable)
        failure_reason = verification_failure_reason(verify.error_details)
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


def _load_union(ws: Path, by_file: bool = False) -> dict:
    p = ws / "_union.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise _resume_corrupt(p, exc) from exc
    pool: dict = {}
    for d in data.get("findings", []):
        c = _cand_from_dict(d)
        pool[c.key(by_file)] = c
    return pool


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
    verifier: Verifier | None = None,
    confirmers: list[tuple[str, RefutationChecker]] | None = None,
    provider: Provider | None = None,
    model: str = "",
    verify: bool = True,
    votes: int = DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required,
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
    profile: ReviewProfile | None = None,
    poc_backend: object | None = None,
    on_verify: Callable[[int, int, float], None] | None = None,
    meter: UsageMeter | None = None,
) -> FinalizeResult:
    """The coded post-fan-out pipeline: dedup, verify, report over the candidates.

    These steps are mechanical: read `candidates/*.md`, or the coded run's `_union.json`
    when no workspace candidates exist, dedup by location and class, adversarially verify
    each survivor, skip any already in `_verified.json`, write refuted candidates to
    `_refuted.md`, then write the confirmed `findings/*.md` and ranked `findings.json`.
    """
    profile = profile or default_profile()
    paths = profile.paths
    source_extensions = load_detection(paths.detection_file).source_extensions
    ws = Path(workspace) / Path(target).resolve().name
    root = str(Path(target).resolve())
    if not (ws / WORKSPACE_MARKER).is_file():
        raise ValueError(f"{ws} has no {WORKSPACE_MARKER} marker. Run --scaffold or --run before --finalize.")
    if not (ws / "candidates").is_dir() and not (ws / "_union.json").is_file():
        raise ValueError(f"{ws} has no candidates/ or _union.json to finalize")

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
    if verify and deduped:
        deduped, vr = apply_verification(
            ws,
            deduped,
            root=root,
            verifier=verifier,
            confirmers=confirmers,
            provider=provider,
            model=model,
            votes=votes,
            concurrency=concurrency,
            fresh=False,
            content=paths,
            by_file=by_file,
            on_verify=on_verify,
        )

    if poc_backend is not None and deduped:
        deduped = _run_pocs(ws, deduped, poc_backend, root)
    if deduped and profile.poc_backend is not None:
        deduped = _execute_present_pocs(ws, deduped, profile, root)

    _write_findings(ws, deduped, root)
    _write_pocs_report(ws, deduped)
    outcome = ReviewOutcome(
        findings=deduped,
        incomplete=[*vr.incomplete, *vr.unlocatable] if vr is not None else [],
        errors=vr.errors if vr is not None else 0,
    )
    _save_finalize_status(
        ws,
        parsed=len(cands),
        deduped=deduped_count,
        verify=vr,
        outcome=outcome,
        meter=meter,
    )
    return FinalizeResult(
        workspace=ws,
        parsed=len(cands),
        deduped=deduped_count,
        verify=vr,
        outcome=outcome,
    )


def _save_finalize_status(
    ws: Path,
    *,
    parsed: int,
    deduped: int,
    verify: VerifyResult | None,
    outcome: ReviewOutcome[Candidate],
    meter: UsageMeter | None,
) -> None:
    """Persist what finalize did, which otherwise survives only as the findings it wrote."""
    status: dict[str, object] = {"parsed": parsed, "deduped": deduped, "complete": outcome.complete}
    if verify is not None:
        status["verify_errors"] = verify.errors
        status["confirmed"] = len(verify.confirmed)
        status["refuted"] = len(verify.refuted)
        status["incomplete"] = len(verify.incomplete)
        status["unlocatable"] = len(verify.unlocatable)
    if meter is not None:
        status["usage"] = meter.snapshot()
    (ws / "_finalize.json").write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")


def _run_pocs(ws: Path, findings: list[Candidate], backend, root: str) -> list[Candidate]:
    """Write a PoC for each confirmed finding and run it where the profile supports execution.

    When the toolchain is present, execution records evidence and
    then write `pocs/<name>.<ext>` so the reconciliation links it. Adds evidence, never
    drops a finding, invariant 2, so a PoC that fails to reproduce, or one a human must run,
    is recorded and never treated as safe. An executing profile whose toolchain is absent
    degrades to write-only with an install hint, so a missing toolchain never aborts
    finalize and never hides a finding, invariant 4.
    """
    executes = getattr(backend, "executes", True)
    runnable = executes and backend.available()
    install_hint = getattr(backend, "install_hint", "")
    ext = getattr(backend, "ext", "t.sol")
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
                    note = f"PoC written, not run, toolchain absent. To run it: {install_hint}. Then: {art.run_hint}"
                else:
                    note = f"PoC written, run it manually: {art.run_hint}"
                if getattr(art, "note", ""):
                    note = f"{note}. {art.note}"
        except Exception as exc:
            source = ""
            note = f"PoC failed to run: {exc}"
        if source:
            (pocs / f"{name}.{ext}").write_text(source, encoding="utf-8")
        annotated.append(replace(c, evidence=f"{c.evidence}\n\n[{note}]".strip()))
    return annotated


def _execute_present_pocs(ws: Path, findings: list[Candidate], profile, root: str) -> list[Candidate]:
    """Run any PoC already present in `pocs/` through the profile's runner and record the result.

    A profile that never runs its PoC automatically, such as web, is left to the
    reconciliation. A PoC that fails to run is recorded, never a safe verdict, so the
    finding is kept, invariant 2. Local only, invariant 6.
    """
    runner = profile.poc_backend()
    if not getattr(runner, "executes", True):
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


def run_repository_review(
    target: str | Path,
    workspace: str | Path,
    *,
    provider: Provider | None = None,
    model: str = "",
    challenger_provider: Provider | None = None,
    challenger_model: str = "",
    judge_provider: Provider | None = None,
    judge_model: str = "",
    reviewer: UnitReviewer | None = None,
    challenger_reviewer: UnitReviewer | None = None,
    judge_reviewer: UnitReviewer | None = None,
    verifier: Verifier | None = None,
    confirmers: list[tuple[str, RefutationChecker]] | None = None,
    verify: bool = True,
    votes: int = DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required,
    mode: str = "standard",
    max_passes: int = DEFAULT_REVIEW_SETTINGS.repository.default_max_rounds,
    converge_after: int = DEFAULT_REVIEW_SETTINGS.execution.clean_rounds_to_converge,
    min_rounds: int = DEFAULT_REVIEW_SETTINGS.repository.min_adversarial_rounds,
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
    fresh: bool = False,
    on_pass=None,
    on_judgment: Callable[[str, int, int, str, float], None] | None = None,
    on_verify: Callable[[int, int, float], None] | None = None,
    profile: ReviewProfile | None = None,
    extra_finder_backends: tuple = (),
    poc_backend: object | None = None,
    meter: UsageMeter | None = None,
) -> RunResult:
    """Run the coded repository review workflow."""
    plan = review_plan(
        mode,
        max_rounds=max_passes,
        min_rounds=1 if mode == "standard" else min_rounds,
        converge_after=converge_after,
        stop_on_failure=False,
    )
    profile = profile or default_profile()
    paths = profile.paths
    root = str(Path(target).resolve())
    res = scaffold(target, workspace, fresh=fresh, profile=profile)
    ws = res.workspace
    units = build_units(
        root,
        res.candidate_files,
        res.trace_targets,
        load_facts_unit_specs(ws),
        load_facts_graph(ws),
    )
    if not units:
        raise ValueError(
            f"no candidate entrypoints detected under {root}, so there is nothing to "
            "review. Add a guide for this stack or seed inventory/_entrypoints.md, then re-run."
        )

    _seed_run_units(ws, units, paths)
    reviewed = set() if fresh else _reviewed_slugs(ws)
    if reviewed and not (ws / "_union.json").is_file():
        raise ValueError(
            f"resume found reviewed units under {ws} but no _union.json checkpoint, the prior "
            "findings are lost. Re-run with --fresh to discard the markers and start over."
        )
    open_units = [u for u in units if unit_slug(u.name) not in reviewed]
    acc = Accumulator(
        converge_after=converge_after,
        pool=({} if fresh else _load_union(ws, profile.dedup_by_file)),
        dedup_by_file=profile.dedup_by_file,
    )

    facts_by_file = load_facts_by_file(ws)
    shared_context = repository_context(ws)
    if not facts_by_file:
        shared_context = with_facts_summary(shared_context, ws)
    shared = shared_context.text

    def _make_reviewer(p: Provider, m: str) -> UnitReviewer:
        return ModelReviewer(provider=p, model=m, content=paths, facts_by_file=facts_by_file)

    if reviewer is None:
        if provider is None:
            raise ValueError("run_repository_review needs a provider, or an injected reviewer")
        reviewer = _make_reviewer(provider, model)
    reviewers: list[UnitReviewer] = [reviewer]
    for p, m in extra_finder_backends:
        reviewers.append(_make_reviewer(p, m))
    if mode == "adversarial":
        challenger_reviewer = challenger_reviewer or (
            _make_reviewer(challenger_provider, challenger_model)
            if challenger_provider is not None and challenger_model
            else None
        )
        judge_reviewer = judge_reviewer or (
            _make_reviewer(judge_provider, judge_model) if judge_provider is not None and judge_model else None
        )
        if challenger_reviewer is None or judge_reviewer is None:
            raise ValueError("adversarial mode requires challenger and judge reviewers")
    else:
        challenger_reviewer = None
        judge_reviewer = None

    run_started = perf_counter()
    pass_records: list[dict] = []
    unit_times: list[tuple[str, float]] = []
    last_pass_end = run_started
    last_usage: dict[str, int] = {}

    def _timed_on_pass(pass_no, reviewer_label, new, union_size):
        nonlocal last_pass_end, last_usage
        now = perf_counter()
        record = {"pass": pass_no, "reviewer": reviewer_label, "new": new, "seconds": round(now - last_pass_end, 1)}
        usage = meter.snapshot() if meter is not None else None
        if usage is not None:
            record["usage"] = {k: v - last_usage.get(k, 0) for k, v in usage.items()}
            last_usage = usage
        pass_records.append(record)
        last_pass_end = now
        _save_run_status(
            ws,
            units_total=len(units),
            acc=acc,
            verify=None,
            state="running",
            timing={"total_seconds": round(now - run_started, 1), "per_pass": pass_records},
            usage=usage,
        )
        if on_pass is not None:
            on_pass(pass_no, reviewer_label, new, union_size)

    run_passes(
        open_units,
        reviewers,
        challenger=challenger_reviewer,
        judge=judge_reviewer,
        plan=plan,
        shared_context=shared,
        concurrency=concurrency,
        on_pass=_timed_on_pass,
        on_unit=lambda name, secs: unit_times.append((name, secs)),
        on_judgment=on_judgment,
        persist=lambda f: _save_union(ws, f),
        accumulator=acc,
    )
    _save_union(ws, acc.findings)
    reviewed_slugs = {unit_slug(u.name) for u in open_units if u.name not in acc.failed_units}
    _mark_units_reviewed(ws, reviewed_slugs)

    findings = _canonicalize_categories(acc.findings, paths.vulnerabilities_dir)
    if profile.dedup_by_file:
        findings = collapse_colocated(findings)
    vr: VerifyResult | None = None
    if verify:
        findings, vr = apply_verification(
            ws,
            findings,
            root=root,
            verifier=verifier,
            confirmers=confirmers,
            provider=provider,
            model=model,
            votes=votes,
            concurrency=concurrency,
            fresh=fresh,
            content=paths,
            by_file=profile.dedup_by_file,
            on_verify=on_verify,
        )

    if poc_backend is not None and findings:
        findings = _run_pocs(ws, findings, poc_backend, root)
    if findings and profile.poc_backend is not None:
        findings = _execute_present_pocs(ws, findings, profile, root)

    _write_surface(ws, units, acc.failed_units)
    unit_totals: dict[str, float] = {}
    for name, secs in unit_times:
        unit_totals[name] = round(unit_totals.get(name, 0.0) + secs, 1)
    by_cost = sorted(unit_totals.items(), key=lambda t: t[1], reverse=True)
    timing = {
        "total_seconds": round(perf_counter() - run_started, 1),
        "per_pass": pass_records,
        "unit_seconds": [{"unit": name, "seconds": secs} for name, secs in by_cost],
    }
    usage_total = meter.snapshot() if meter is not None else None
    if usage_total is not None:
        usage_total["unit_review_calls"] = len(unit_times)
    incomplete = [*vr.incomplete, *vr.unlocatable] if vr is not None else []
    cycle_outcome = acc.outcome or ReviewOutcome(findings=acc.findings)
    outcome = extend_review_outcome(
        cycle_outcome,
        findings=findings,
        failures=acc.unit_failures,
        incomplete=incomplete,
        errors=vr.errors if vr is not None else 0,
        failure_reason=verification_failure_reason(vr.error_details) if vr is not None else "",
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
        units_total=len(units),
        acc=acc,
        verify=vr,
        timing=timing,
        usage=usage_total,
        state=state,
        complete=complete,
    )
    _write_findings(ws, findings, root)
    _write_pocs_report(ws, findings)
    return RunResult(scaffold=res, accumulator=acc, units=len(units), verify=vr, outcome=outcome)
