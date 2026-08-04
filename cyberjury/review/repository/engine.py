"""Run the coded multi-pass repository-review engine end to end.

The library entry behind `review repository --run`. It scaffolds the workspace, builds the
unit worklist from the seeded candidates, runs the deterministic pass-loop with a
model-backed reviewer until the union converges, then writes the findings into the
workspace and marks every unit reviewed. The orchestration is fully coded, so a run
covers every unit every pass and stops on convergence, not on the agent's whim.

Recall is the union across diverse passes. Precision is tightened by a later
verification stage. Findings are written both as `findings/*.md` and a
machine-readable `findings.json`, so a run can be scored against an answer key.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, replace
from functools import cache
from pathlib import Path
from time import perf_counter

from cyberjury.detection import load_detection
from cyberjury.domains.base import ContentPaths, Domain
from cyberjury.domains.registry import default_domain
from cyberjury.markdown_docs import md_field
from cyberjury.providers.base import Provider
from cyberjury.providers.metering import UsageMeter
from cyberjury.review.diff.vulnerabilities import canonical_category, category_aliases
from cyberjury.review.repository.model import char_spans
from cyberjury.review.repository.pass_loop import run_passes
from cyberjury.review.repository.paths import is_unsafe_rel, resolve_source_path, safe_repository_path
from cyberjury.review.repository.reviewer import ModelReviewer, UnitReviewer
from cyberjury.review.repository.scaffold import (
    _AUTH_MODEL_TEMPLATE,
    _INVARIANTS_TEMPLATE,
    ScaffoldResult,
    _unit_md,
    scaffold,
    unit_slug,
)
from cyberjury.review.repository.severity import median
from cyberjury.review.repository.shapes import Unit
from cyberjury.review.repository.union import Accumulator, Candidate, collapse_colocated, merge
from cyberjury.review.repository.verifier import (
    ModelVerifier,
    RefutationChecker,
    Verifier,
    VerifyResult,
    verify_findings,
)
from cyberjury.sources.metadata import SourceMeta, read_source_meta_file

_MAX_RELATED = 20

# equal to model.CHUNK_CHARS, since _windowed cuts an oversized definition with that splitter
_IMPORT_UNIT_CHARS = 24_000


def _finding_slug(text: str) -> str:
    return ("".join(c if c.isalnum() else "-" for c in text).strip("-").lower() or "finding")[:80]


def _file_text(root: str, rel: str) -> str:
    path = safe_repository_path(root, rel)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


# the window splitter lives in model, shared with the scaffold's agent-unit seeding so both
# paths split a large entrypoint file identically. Re-exported under the private name the
# engine and its tests already call.
_spans = char_spans


def _windowed(root: str, file: str, frags: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """The fragments with any single definition over the char cap split into overlapping windows.

    Grouping fragments under a cap only bounds a unit when every fragment fits it. One definition
    can be larger on its own, a single class in a real service can exceed the cap several times
    over, and that unit would be the diluted window the focused packing exists to avoid. Reuses the
    splitter the large-candidate path uses, so an overlong definition is cut on a construct boundary
    with the same overlap."""
    out: list[tuple[str, int, int]] = []
    text = ""
    for rel, start, end in frags:
        if end - start <= _IMPORT_UNIT_CHARS:
            out.append((rel, start, end))
            continue
        text = text or _file_text(root, file)
        windows = _spans(text[start:end])
        if len(windows) == 1:
            out.append((rel, start, end))
            continue
        for w_start, w_end in windows:
            out.append((rel, start + w_start, start + w_end))
    return out


def _import_closure_units(root: str, candidate_files, graph) -> list[Unit]:
    """Focused units over the definitions each candidate entrypoint imports.

    A candidate's downstream is otherwise guessed from path globs, which say nothing about what the
    entrypoint reaches, so a definition it does reach lands in a prompt only when a glob happens to
    name its file. This walks the real edges instead.

    Grouped per source file so definitions sharing a module stay together, then cut at
    `_IMPORT_UNIT_CHARS`, well inside `shapes._GATHER_TOTAL`, since a whole closure does not fit one
    call and a small unit keeps the model on the path. Packing lives here rather than
    in the facts backend because the candidate entrypoints are the engine's, the backend runs
    before they are selected."""
    callgraph = (graph or {}).get("callgraph") or {}
    imports = (graph or {}).get("imports") or {}
    index: dict[str, list[tuple[str, int, int]]] = {}
    for file, defs in callgraph.items():
        for name, entries in (defs or {}).items():
            for info in entries or ():
                span = (info or {}).get("range")
                if isinstance(span, (list, tuple)) and len(span) == 2:
                    index.setdefault(name, []).append((str(file), int(span[0]), int(span[1])))
    units: list[Unit] = []
    seen: set[frozenset] = set()
    for cand in candidate_files:
        per_file: dict[str, list[tuple[str, int, int]]] = {}
        for name in imports.get(cand, ()):
            for frag in index.get(name, ()):
                # a definition in the candidate itself is already covered by its own file unit
                if frag[0] == cand:
                    continue
                bucket = per_file.setdefault(frag[0], [])
                if frag not in bucket:
                    bucket.append(frag)
        for file, frags in per_file.items():
            frags = _windowed(root, file, frags)
            frags.sort(key=lambda f: f[1])
            chunks: list[list[tuple[str, int, int]]] = [[]]
            total = 0
            for frag in frags:
                size = frag[2] - frag[1]
                if chunks[-1] and total + size > _IMPORT_UNIT_CHARS:
                    chunks.append([])
                    total = 0
                chunks[-1].append(frag)
                total += size
            for i, chunk in enumerate(chunks):
                key = frozenset(chunk)
                if not chunk or key in seen:
                    continue
                seen.add(key)
                suffix = f"#{i + 1}" if len(chunks) > 1 else ""
                units.append(Unit(name=f"{cand}->{file}{suffix}", root=root, files=(file,), fragments=tuple(chunk)))
    return units


def build_units(root: str | Path, candidate_files, trace_targets, facts_units=None, facts_graph=None) -> list[Unit]:
    """One unit per candidate entrypoint, packed with the trace-target files that share its
    top-level package, so a single review call can trace across them. A candidate too large
    for one call is split into several units over overlapping char windows, so the whole
    file is covered rather than truncated to its head.

    When the facts backend supplied `facts_units`, focused call-path units are appended, one
    per risk-flagged function packed with its call-graph neighborhood. When it supplied
    `facts_graph`, each candidate is also expanded along its real import edges, see
    `_import_closure_units`. Both are additive: the file units keep coverage of every
    entrypoint, the focused units co-locate a cross-function path the file slices would split,
    bury, or never reach at all, and the union dedups across them."""
    root = str(root)
    targets = list(trace_targets)
    units: list[Unit] = []
    for cand in candidate_files:
        pkg = Path(cand).parts[0] if Path(cand).parts else ""
        related = tuple(t for t in targets if Path(t).parts and Path(t).parts[0] == pkg)[:_MAX_RELATED]
        spans = _spans(_file_text(root, cand))
        if len(spans) == 1:
            units.append(Unit(name=cand, root=root, files=(cand, *related)))
            continue
        for i, span in enumerate(spans):
            units.append(Unit(name=f"{cand}#{i + 1}", root=root, files=(cand, *related), span=span))
    units += _call_path_units(root, facts_units)
    units += _import_closure_units(root, candidate_files, facts_graph)
    return units


def _call_path_units(root: str, facts_units) -> list[Unit]:
    """Materialize the focused call-path units from the facts specs. The packing knowledge,
    which functions group and how tight, lives in the facts backend, here the engine only
    reads each spec's source fragments into a Unit."""
    units: list[Unit] = []
    for spec in facts_units or ():
        frags = tuple(
            (str(f[0]), int(f[1]), int(f[2]))
            for f in spec.get("fragments", [])
            if isinstance(f, (list, tuple)) and len(f) == 3
        )
        if not frags:
            continue
        name = str(spec.get("name") or "")
        files = tuple(dict.fromkeys(f[0] for f in frags))
        units.append(Unit(name=name or files[0], root=root, files=files, fragments=frags))
    return units


def _finding_md(c: Candidate, owner: str = "") -> str:
    src = c.endpoint or c.file or "(no location)"
    head = (
        f"# {c.title}\n\n"
        f"- Risk: {c.severity}\n"
        f"- Type: {c.category or 'other'}\n"
        f"- Source: `{src}`\n"
        f"- Status: {c.status}\n" + (f"- Owner: {owner}\n" if owner else "") + "\n"
    )
    body = c.evidence.strip()
    # the agent body already carries its own ## Analysis and later sections, so emit it
    # whole, the coded run carries only a short fact, so wrap it under Analysis
    if body.startswith("#"):
        return head + body + "\n"
    return head + f"## Analysis\n{body or '(see code)'}\n"


def _finding_name(c: Candidate) -> str:
    """The shared name tying a finding to its source candidate and its poc. In the agent
    flow that name is the candidate file basename, carried on `source`. The coded run has
    no candidate file, so fall back to a slug of the dedup identity, location plus class.
    The class matters: two findings on one endpoint kept distinct by their category, a
    missing binding and a race, would otherwise slug alike and one would overwrite the other."""
    if c.source.endswith(".md"):
        return Path(c.source).stem
    return _finding_slug(f"{c.endpoint or c.file or c.title} {c.category}")


def _poc_for(ws: Path, name: str) -> str:
    """The poc whose basename matches a finding's name, the link the methodology asks
    the agent to keep by naming candidates/<name>.md and pocs/<name>.<ext> alike. It matches the
    whole extension, so an extension in several parts such as `.t.sol` links too, where
    `Path.stem` would keep the `.t` and never match."""
    pocs = ws / "pocs"
    if not pocs.is_dir():
        return ""
    for p in sorted(pocs.iterdir()):
        if p.is_file() and (p.name == name or p.name.startswith(f"{name}.")):
            return f"pocs/{p.name}"
    return ""


_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _confidence(c: Candidate) -> int:
    """How many models independently surfaced this finding, the consensus strength used to rank."""
    return len(set(c.found_by))


def _git_blame_owner(root: str, file: str, line: int | None) -> str:
    """The last author to touch a finding's line, by git blame, so a report names an owner.
    Best-effort and fail-soft: empty on a non-git target, an uncommitted or moved file, a
    missing line, or no root. Blame is an annotation, never a gate, so a failure here never
    fails the review, invariant 4 lives on the review steps not on this."""
    if not root or not file or not line or line < 1:
        return ""
    if safe_repository_path(root, file) is None:
        return ""
    try:
        out = subprocess.run(
            ["git", "-C", root, "blame", "-L", f"{line},{line}", "--porcelain", "--", file],
            capture_output=True,
            text=True,
            timeout=10,
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
        "analysis": c.evidence,
        "owner": owner,
        "found_by": list(c.found_by),
        "models": _confidence(c),
        "candidate": candidate,
        "poc": _poc_for(ws, _finding_name(c)),
    }


def _load_source_meta(root: str) -> SourceMeta | None:
    """Optional provenance for a fetched target, read at report time from the
    target root. It never reaches a finding decision, invariants 2 and 3, it only
    annotates the report."""
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
    """Write the confirmed findings, the code-owned output. Ranked by how many models agreed
    then severity, so a cross-model consensus surfaces above a lone model's finding. findings/
    is cleared and rewritten in full, so a shrunk or refuted set leaves no stale file behind,
    and the agent's candidates/ and pocs/ are never touched. When a target root is given, each
    finding is annotated with the git-blame owner of its line, computed once per finding, and
    optional source provenance from cyberjury-source.json is added to the report."""
    # load provenance first, so a malformed cyberjury-source.json fails loud before any
    # output is written rather than leaving a half-written report, invariant 4
    meta = _load_source_meta(root)
    findings = sorted(findings, key=lambda c: (-_confidence(c), _SEV_RANK.get(c.severity, 4)))
    owners = {id(c): _git_blame_owner(root, c.file, c.line) for c in findings}
    findings_dir = ws / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    for p in findings_dir.glob("*.md"):
        p.unlink()
    used: set[str] = set()
    for c in findings:
        base = _finding_name(c)
        name = base
        # two distinct findings can still slug to one name, never overwrite, invariant 4:
        # disambiguate so no confirmed finding's detail file is silently lost
        n = 2
        while name in used:
            name = f"{base}-{n}"
            n += 1
        used.add(name)
        (findings_dir / f"{name}.md").write_text(_finding_md(c, owners[id(c)]), encoding="utf-8")
    report: dict = {"findings": [_finding_entry(ws, c, owners[id(c)]) for c in findings]}
    if meta is not None:
        report["target"] = meta.to_dict()
        (ws / "_target.md").write_text(_target_md(meta), encoding="utf-8")
    (ws / "findings.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_pocs_report(ws: Path, findings: list[Candidate]) -> None:
    """Reconcile pocs/ against the confirmed findings, recorded not enforced: a finding
    may need a PoC only an operator can run, invariant 6, and a PoC may outlive a
    candidate the verifier later refuted. Surface both so neither is silently lost."""
    pocs = ws / "pocs"
    poc_files = sorted(p for p in pocs.iterdir() if p.is_file()) if pocs.is_dir() else []
    if not poc_files and not any(c.source.endswith(".md") for c in findings):
        # the coded run produces findings with no agent candidates or pocs, so there is
        # nothing to reconcile, skip rather than list every finding as missing a poc
        return
    names = {_finding_name(c) for c in findings}
    poc_names = {p.stem for p in poc_files}
    missing = [c for c in findings if _finding_name(c) not in poc_names]
    orphan = [p for p in poc_files if p.stem not in names]
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
    """Populate the attack-surface inventory from the unit worklist: in a coded run
    the enumerated surface IS the worklist, one row per unit, so the denominator is
    explicit and the gate's surface check is satisfied. A unit that never reviewed
    cleanly this run is marked open, not reviewed, so the surface does not claim a
    failed unit was covered."""
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


def _write_refuted(ws: Path, refuted: list[tuple[Candidate, str]]) -> None:
    """Record what the verifier dropped, so a refutation is auditable, not invisible."""
    lines = [
        "# Refuted candidates",
        "",
        "Surfaced by a review pass, then refuted by the adversarial verifier on a "
        "named controlling fact. Recorded so a wrong refutation is visible.",
        "",
    ]
    for c, reason in refuted:
        lines.append(f"- **{c.title}** ({c.severity} {c.category}) `{c.endpoint or c.file}`: {reason}")
    (ws / "_refuted.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _seed_run_units(ws: Path, units: list[Unit], paths) -> None:
    """Reconcile the units worklist to the coded run's actual units. Scaffold seeds one file per
    candidate file, but the run splits a large file into several window units and adds the focused
    units a facts backend drives, whose names are not candidate paths. Without a file per run unit
    those units have nothing to mark reviewed, so a resume re-reviews them and the orphan candidate
    file is left open forever. Seed a file per run unit and drop the stale ones so resume, marking, and
    the gate all key on the same set. Existing files are kept, so a reviewed unit is not reset."""
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
    """Flip a unit from open to reviewed only when it reviewed cleanly this run. A unit
    that raised on every pass is left open, so the gate catches it and a later resume
    retries it, never reporting a failed review as covered."""
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


def _keystr(c: Candidate, by_file: bool = False) -> str:
    # the resume key for _verified.json. by_file must match across the run and a later finalize,
    # else the same finding recomputes a different key and is re-verified or mis-resumed
    return "|".join(str(p) for p in c.key(by_file))


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
) -> None:
    """Persist the coded run's coverage and failure state, which otherwise lives only in the
    accumulator in memory and is lost when the process exits. A later finalize or gate can then
    read whether the run converged and how many reviews failed, so a failed run stays visible
    across steps and is never resumed as if it were clean, invariant 4. Written once per pass with
    `state` "running" so a kill mid-run leaves a progress snapshot, and once at the end with the
    final state, `timing`, and `usage`."""
    status = {
        "units_total": units_total,
        "units_reviewed": units_total - len(acc.failed_units),
        "failed_units": sorted(acc.failed_units),
        "errors": acc.errors,
        "verify_errors": verify.errors if verify else 0,
        "converged": acc.converged,
        "state": state,
    }
    if verify is not None:
        status["confirmed"] = len(verify.confirmed)
        status["refuted"] = len(verify.refuted)
        status["incomplete"] = len(verify.incomplete)
        status["unlocatable"] = len(verify.unlocatable)
    if timing is not None:
        status["timing"] = timing
    if usage is not None:
        status["usage"] = usage
    (ws / "_run.json").write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")


def _resume_corrupt(p: Path, exc: Exception) -> ValueError:
    # a present-but-corrupt checkpoint must fail loud, never fall back to an empty pool:
    # on a resume the units are already reviewed, so an empty pool would write a zero
    # finding report and exit clean, hiding the lost progress. Invariant 4.
    return ValueError(
        f"resume checkpoint {p} is unreadable or corrupt: {exc}. "
        "Re-run with --fresh to discard prior state and start over."
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


def _load_verified(ws: Path) -> dict:
    p = ws / "_verified.json"
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise _resume_corrupt(p, exc) from exc


def _save_verified(ws: Path, verified: dict) -> None:
    (ws / "_verified.json").write_text(json.dumps(verified, indent=2, ensure_ascii=False), encoding="utf-8")


def _reviewed_slugs(ws: Path) -> set:
    return {
        u.stem
        for u in (ws / "units").glob("*.md")
        if re.search(r"(?im)^-\s*Status:\s*reviewed\s*$", u.read_text(encoding="utf-8"))
    }


def apply_verification(
    ws: Path,
    findings: list[Candidate],
    *,
    root: str,
    verifier: Verifier | None,
    provider: Provider | None,
    model: str,
    votes: int,
    concurrency: int,
    fresh: bool,
    content: ContentPaths | None = None,
    confirmers: list[tuple[str, RefutationChecker]] | None = None,
    by_file: bool = False,
    on_verify: Callable[[int, int, float], None] | None = None,
) -> tuple[list[Candidate], VerifyResult]:
    """Verify a finding list, resumable via `_verified.json`, and record the refuted. The single
    home and the single route the coded run and the finalize pass both share. A finding two models
    surfaced independently is kept on that consensus and skips the route, as does one whose recorded
    location matches no file in the repository. Otherwise the skeptic tries
    to refute it, and a refuted finding is dropped only when every independent confirmer, a model
    that did not itself surface it, upholds the refutation. A failed call keeps the finding and is
    counted, never silently dropped, invariant 4."""
    if verifier is None:
        if provider is None:
            raise ValueError("verification needs a provider, or an injected verifier")
        verifier = ModelVerifier(provider=provider, model=model, content=content)
    verified = {} if fresh else _load_verified(ws)
    pending = [c for c in findings if _keystr(c, by_file) not in verified]
    # consensus skips the verify route: two models surfacing the same finding independently is a
    # strong signal, so verifying it spends calls for little gain and risks a wrong drop
    consensus: list[Candidate] = []
    singletons: list[Candidate] = []
    for c in pending:
        (consensus if len(set(c.found_by)) >= 2 else singletons).append(c)
    for c in consensus:
        verified[_keystr(c, by_file)] = {"real": True, "reason": "consensus of models"}
    locatable: list[Candidate] = []
    unlocatable: list[Candidate] = []
    for c in singletons:
        (locatable if resolve_source_path(root, c.file) is not None else unlocatable).append(c)
    # a finding kept only because a verify call could not complete is kept for this run but never
    # written to _verified.json, so a resume re-attempts it rather than freezing the failure as
    # confirmed, the resume-integrity rule of invariant 4
    vr = verify_findings(
        locatable, verifier, root, confirmers=confirmers, votes=votes, concurrency=concurrency, on_verify=on_verify
    )
    unfrozen = {_keystr(c, by_file) for c in (*vr.incomplete, *unlocatable)}
    for c in vr.confirmed:
        if _keystr(c, by_file) not in unfrozen:
            verified[_keystr(c, by_file)] = {"real": True, "reason": ""}
    for c, reason in vr.refuted:
        verified[_keystr(c, by_file)] = {"real": False, "reason": reason}
    errors = vr.errors
    _save_verified(ws, verified)
    confirmed = [c for c in findings if verified.get(_keystr(c, by_file), {"real": True})["real"]]
    refuted = [
        (c, verified[_keystr(c, by_file)]["reason"])
        for c in findings
        if not verified.get(_keystr(c, by_file), {"real": True})["real"]
    ]
    _write_refuted(ws, refuted)
    return confirmed, VerifyResult(
        confirmed=confirmed, refuted=refuted, errors=errors, incomplete=vr.incomplete, unlocatable=unlocatable
    )


def _md_field(text: str, key: str) -> str:
    v = md_field(text, key)
    return v.strip("`").strip() if v is not None else ""


@cache
def _location_re(source_extensions: frozenset[str]) -> re.Pattern:
    """The location matcher, built from the data-driven source extensions so no
    language is named in code. Extensions are sorted longest first so a path like
    `app.tsx` matches the `tsx` alternative, not the `ts` prefix of it. Cached per
    extension set so each domain's matcher is built once."""
    exts = sorted((e.lstrip(".") for e in source_extensions), key=len, reverse=True)
    alt = "|".join(re.escape(e) for e in exts)
    return re.compile(rf"([\w./-]+\.(?:{alt}))(?::(\d+))?")


def _candidate_body(text: str) -> str:
    """The prose body of an agent candidate, from its first section heading to the end, so
    a finding carries the agent's analysis rather than a bare pointer back to the file."""
    m = re.search(r"(?m)^##\s", text)
    return text[m.start() :].strip() if m else ""


def _canonicalize_categories(cands: list[Candidate], vulnerabilities_dir: Path) -> list[Candidate]:
    """Fold each candidate's model-emitted category onto its canonical class id, so label
    variants of one class such as `oracle` and `oracle-manipulation` dedup and collapse as
    one defect. Data-driven from the domain's declared class aliases. An empty map leaves the
    list untouched, so a domain that declares no aliases such as web is unchanged."""
    aliases = category_aliases(vulnerabilities_dir)
    if not aliases:
        return cands
    return [replace(c, category=canonical_category(c.category, aliases)) for c in cands]


def _parse_candidate(path: Path, source_extensions: frozenset[str] | None = None) -> Candidate | None:
    """Parse an agent-written candidates/<name>.md into a Candidate for coded dedup and
    verification, so those steps do not depend on the agent's prose. The source
    extensions decide what counts as a file location, defaulting to the web domain."""
    if source_extensions is None:
        source_extensions = load_detection().source_extensions
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    title = next((ln[2:].strip() for ln in text.splitlines() if ln.startswith("# ")), path.stem)
    # agents write the H1 freely, some prefix "Finding:", so strip it for a uniform title
    title = re.sub("(?i)^finding\\s*[:\uff1a]\\s*", "", title).strip() or path.stem
    sev_raw = _md_field(text, "(?:risk|severity)").upper()
    severity = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in sev_raw), "MEDIUM")
    fm = _location_re(source_extensions).search(text)
    if fm is None or is_unsafe_rel(fm.group(1)):
        # with no file location the issue is not reportable, invariant 3. An absolute or
        # parent-traversing path is not a location inside the repository, a tampered or
        # hallucinated issue file, so it is dropped, not read.
        return None
    status_raw = _md_field(text, "status").lower()
    if status_raw.startswith(("refuted", "clear")) or title.lower().startswith("cleared"):
        # A reviewer sometimes records a cleared or refuted control as a candidate so a
        # wrong clear stays visible, but that is a determination of no finding, not a
        # proposed one. Counting it as confirmed inflated findings.json, so drop it here. The
        # title guard catches the common "Cleared controls" record a reviewer writes with no
        # explicit status field.
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
    workspace: Path
    parsed: int
    deduped: int
    verify: VerifyResult | None


def finalize_repository_review(
    target: str | Path,
    workspace: str | Path,
    *,
    verifier: Verifier | None = None,
    confirmers: list[tuple[str, RefutationChecker]] | None = None,
    provider: Provider | None = None,
    model: str = "",
    verify: bool = True,
    votes: int = 1,
    concurrency: int = 6,
    domain: Domain | None = None,
    poc_backend: object | None = None,
    on_verify: Callable[[int, int, float], None] | None = None,
    meter: UsageMeter | None = None,
) -> FinalizeResult:
    """The coded post-fan-out pipeline: dedup, verify, report over the candidates.

    These steps are mechanical, so they are code, not agent prose: it reads the agent's
    `candidates/*.md`, or the coded run's `_union.json` when no agent candidates exist,
    dedups by location and class, adversarially verifies each survivor, resumable and
    skipping any already in `_verified.json`, drops the refuted into `_refuted.md`, and
    writes the confirmed `findings/*.md` and the ranked `findings.json`."""
    domain = domain or default_domain()
    paths = domain.paths
    source_extensions = load_detection(paths.detection_file).source_extensions
    ws = Path(workspace) / Path(target).resolve().name
    root = str(Path(target).resolve())

    by_file = domain.dedup_by_file
    cands = [c for c in (_parse_candidate(p, source_extensions) for p in sorted((ws / "candidates").glob("*.md"))) if c]
    if not cands and (ws / "_union.json").is_file():
        # a coded --run leaves its candidates in _union.json, not candidates/*.md, so finalizing
        # from the empty candidates/ would write an empty report over the run's real findings.
        # Fall back to the run's union so --finalize verifies it again idempotently, never
        # silently erases a completed run. Invariant 4.
        cands = list(_load_union(ws, by_file).values())
    cands = _canonicalize_categories(cands, paths.vulnerabilities_dir)
    sev_votes: dict = {}
    for c in cands:
        sev_votes.setdefault(c.key(by_file), []).append(c.severity)
    pool: dict = {}
    merge(pool, cands, by_file)
    deduped = [
        replace(c, severity=median(sev_votes.get(c.key(by_file), [c.severity])))
        for c in collapse_colocated(list(pool.values()))
    ]

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
    if deduped and domain.poc_backend is not None:
        deduped = _execute_present_pocs(ws, deduped, domain, root)

    _write_findings(ws, deduped, root)
    _write_pocs_report(ws, deduped)
    _save_finalize_status(ws, parsed=len(cands), deduped=len(deduped), verify=vr, meter=meter)
    return FinalizeResult(workspace=ws, parsed=len(cands), deduped=len(deduped), verify=vr)


def _save_finalize_status(
    ws: Path, *, parsed: int, deduped: int, verify: VerifyResult | None, meter: UsageMeter | None
) -> None:
    """Persist what finalize did, which otherwise survives only as the findings it wrote."""
    status: dict[str, object] = {"parsed": parsed, "deduped": deduped}
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
    """Write a PoC for each confirmed finding, and run it where the domain runs its PoC
    automatically and its toolchain is present, then write `pocs/<name>.<ext>` so the reconciliation
    links it. Adds evidence, never drops a finding, invariant 2, so a PoC that fails to reproduce, or
    one a human must run, is recorded and never treated as safe. An executing domain whose toolchain
    is absent degrades to write-only with an install hint, so a missing toolchain never aborts
    finalize and never hides a finding, invariant 4."""
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
                    # recorded not hidden, so a missing toolchain never reads as a clean finding, invariant 4
                    note = f"PoC written, not run, toolchain absent. To run it: {install_hint}. Then: {art.run_hint}"
                else:
                    note = f"PoC written, run it manually: {art.run_hint}"
                if getattr(art, "note", ""):
                    note = f"{note}. {art.note}"
        except Exception as exc:
            # a failed PoC call is not a safe verdict, keep the finding and record the failure, invariant 4
            source = ""
            note = f"PoC failed to run: {exc}"
        if source:
            (pocs / f"{name}.{ext}").write_text(source, encoding="utf-8")
        annotated.append(replace(c, evidence=f"{c.evidence}\n\n[{note}]".strip()))
    return annotated


def _execute_present_pocs(ws: Path, findings: list[Candidate], domain, root: str) -> list[Candidate]:
    """Run any PoC already present in `pocs/` through the domain's runner and record the result, so
    a PoC an agent wrote is proven by the same local run as a coded one. A domain that never runs
    its PoC automatically, such as web, is left to the reconciliation. A PoC that fails to run is
    recorded, never a safe verdict, so the finding is kept, invariant 2. Local only, invariant 6."""
    runner = domain.poc_backend()
    if not getattr(runner, "executes", True):
        return findings
    out: list[Candidate] = []
    for c in findings:
        rel = _poc_for(ws, _finding_name(c))
        # skip when there is no PoC to run, or the write step already ran this one this call
        if not rel or "[PoC" in c.evidence:
            out.append(c)
            continue
        res = runner.execute(source=(ws / rel).read_text(encoding="utf-8"), root=root)
        if res.ok:
            note = f"PoC reproduced: {res.detail}"
        elif res.ran:
            note = f"PoC inconclusive: {res.detail}"
        else:
            # not run here, such as a missing toolchain, surfaced never hidden, invariant 4
            note = f"PoC not executed: {res.detail}"
        out.append(replace(c, evidence=f"{c.evidence}\n\n[{note}]".strip()))
    return out


@dataclass(frozen=True, kw_only=True)
class RunResult:
    scaffold: ScaffoldResult
    accumulator: Accumulator
    units: int
    verify: VerifyResult | None = None


# a cap on the facts text folded into every unit prompt, so a large repository's facts cannot
# crowd out the unit under review. Truncation is marked, never silent, invariant 4. Only the
# fallback global fold uses it, per-file facts are scoped to the unit and need no global cap
_FACTS_CONTEXT_CAP = 16000


def _shared_context(ws: Path) -> str:
    """The shared review context the coded finder gets, the same Phase-1 inventory the agent
    path hands each sub-review, so a `--run` review and the slash-command review read with the
    same knowledge rather than the coded path silently seeing less than its mandate assumes.
    Operator-seeded inventory still at its pristine template counts as unfilled and is skipped,
    so a blank auth model or invariants file adds nothing, matching the blank-seeds-nothing rule
    in the per-unit mandate. Facts are folded by the caller, since they are per-file when a
    backend emits them."""
    parts: list[str] = []

    def add(label: str, rel: str, template: str | None = None) -> None:
        p = ws / rel
        if not p.is_file():
            return
        text = p.read_text(encoding="utf-8").strip()
        if not text or (template is not None and text == template.strip()):
            return
        parts.append(f"## {label}\n{text}")

    add("Stack", "_stack.md")
    add("Authorization model, trust boundaries, sensitive data", "inventory/_auth_model.md", _AUTH_MODEL_TEMPLATE)
    add("Operator-seeded intent invariants", "inventory/_invariants.md", _INVARIANTS_TEMPLATE)
    add("Vulnerability classes", "_vulnerabilities.md")
    add("False-positive traps", "_false_positive_traps.md")
    return "\n\n".join(parts)


def _with_facts(shared: str, ws: Path) -> str:
    """Fold the persisted facts summary into the shared review context, when scaffold wrote
    it but no per-file map exists. The fallback for a backend that emits only a summary, bounded so a
    large repository's facts stay an aid, not a flood, with the cut marked. A backend that emits
    `by_file` grounds each unit per file instead, see `_load_facts_by_file`."""
    facts_md = ws / "_facts.md"
    if not facts_md.is_file():
        return shared
    facts = facts_md.read_text(encoding="utf-8").strip()
    if not facts:
        return shared
    if len(facts) > _FACTS_CONTEXT_CAP:
        facts = facts[:_FACTS_CONTEXT_CAP] + "\n... [facts truncated, see _facts.md]"
    return f"{shared}\n\nTool-extracted facts:\n{facts}\n"


def _corrupt_facts(p: Path, exc: Exception) -> ValueError:
    # a facts artifact that exists but does not parse is corrupt, not absent. Silently treating
    # it as empty makes the review look more grounded than it was, so fail loud and let the
    # operator regenerate it. Invariant 4. A never-generated facts file is still optional.
    return ValueError(f"facts artifact {p} is corrupt: {exc}. Delete it or re-run with --fresh to regenerate.")


def _load_facts_by_file(ws: Path) -> dict[str, str]:
    """The per-file facts map scaffold persisted, so the engine grounds each unit with only
    the facts for the files it owns. Empty when no backend ran or it emits no by_file map, the
    run then falls back to the global fold or its own heuristics."""
    p = ws / "_facts_by_file.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _corrupt_facts(p, exc) from exc
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if v}


def _load_facts_units(ws: Path) -> list:
    """The focused call-path unit specs scaffold persisted, so the engine adds them to the
    worklist. Empty when no backend ran or it emits none, a backend that emits a graph instead
    still reaches the worklist through `_load_facts_graph`."""
    p = ws / "_facts_units.json"
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _corrupt_facts(p, exc) from exc
    return data if isinstance(data, list) else []


def _load_facts_graph(ws: Path) -> dict:
    """The call and import graph scaffold persisted, so the engine expands each candidate
    entrypoint along its real import edges, the call graph supplying each definition's range.
    Empty when no backend ran or it emits no graph, the packing falls back to path globs."""
    p = ws / "_facts_graph.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _corrupt_facts(p, exc) from exc
    return data if isinstance(data, dict) else {}


def run_repository_review(
    target: str | Path,
    workspace: str | Path,
    *,
    provider: Provider | None = None,
    model: str = "",
    reviewer: UnitReviewer | None = None,
    verifier: Verifier | None = None,
    confirmers: list[tuple[str, RefutationChecker]] | None = None,
    verify: bool = True,
    votes: int = 1,
    max_passes: int = 24,
    converge_after: int = 2,
    min_lens_shots: int = 2,
    concurrency: int = 6,
    fresh: bool = False,
    on_pass=None,
    on_verify: Callable[[int, int, float], None] | None = None,
    domain: Domain | None = None,
    facts: bool = False,
    extra_finder_backends: tuple = (),
    max_units: int | None = None,
    invariants: str | Path | None = None,
    meter: UsageMeter | None = None,
) -> RunResult:
    domain = domain or default_domain()
    paths = domain.paths
    root = str(Path(target).resolve())
    res = scaffold(
        target, workspace, fresh=fresh, domain=domain, facts=facts, max_units=max_units, invariants=invariants
    )
    ws = res.workspace
    units = build_units(root, res.candidate_files, res.trace_targets, _load_facts_units(ws), _load_facts_graph(ws))
    if not units:
        # zero units means the stack detection flagged no entrypoint, so a run would
        # review nothing and still look clean. Fail loud, invariant 4: a review that
        # covered nothing is not a clean pass. The operator scaffolds and seeds the
        # candidates by hand, or adds a guide for the stack, then re-runs.
        raise ValueError(
            f"no candidate entrypoints detected under {root}, so there is nothing to "
            "review. Add a guide for this stack or seed inventory/_entrypoints.md, then re-run."
        )

    # reconcile the units worklist to the actual run units, including split windows and call-path
    # units, so resume, marking, and the gate key on the same set
    _seed_run_units(ws, units, paths)
    reviewed = set() if fresh else _reviewed_slugs(ws)
    if reviewed and not (ws / "_union.json").is_file():
        # units are marked reviewed but the union checkpoint is gone, so the prior findings are
        # lost and a run now would re-skip those units and write a zero-finding clean report.
        # Fail loud rather than report lost progress as clean, invariant 4.
        raise ValueError(
            f"resume found reviewed units under {ws} but no _union.json checkpoint, the prior "
            "findings are lost. Re-run with --fresh to discard the markers and start over."
        )
    open_units = [u for u in units if unit_slug(u.name) not in reviewed]
    acc = Accumulator(
        converge_after=converge_after,
        pool=({} if fresh else _load_union(ws, domain.dedup_by_file)),
        dedup_by_file=domain.dedup_by_file,
    )

    facts_by_file = _load_facts_by_file(ws)
    shared = _shared_context(ws)
    if not facts_by_file:
        # no per-file facts, fall back to the global fold for a backend that emits only a summary
        shared = _with_facts(shared, ws)

    def _make_reviewer(p: Provider, m: str) -> UnitReviewer:
        return ModelReviewer(provider=p, model=m, content=paths, facts_by_file=facts_by_file)

    if reviewer is None:
        if provider is None:
            raise ValueError("run_repository_review needs a provider, or an injected reviewer")
        reviewer = _make_reviewer(provider, model)
    # multi-model fanout: a different model finds alongside the main one, so the union takes
    # whatever any model catches and a single model's blind spot no longer caps recall.
    reviewers: list[UnitReviewer] = [reviewer]
    for p, m in extra_finder_backends:
        reviewers.append(_make_reviewer(p, m))

    run_started = perf_counter()
    pass_records: list[dict] = []
    unit_times: list[tuple[str, float]] = []
    last_pass_end = run_started
    last_usage: dict[str, int] = {}

    def _timed_on_pass(pass_no, lens, new, union_size):
        nonlocal last_pass_end, last_usage
        now = perf_counter()
        record = {"pass": pass_no, "lens": lens, "new": new, "seconds": round(now - last_pass_end, 1)}
        usage = meter.snapshot() if meter is not None else None
        if usage is not None:
            record["usage"] = {k: v - last_usage.get(k, 0) for k, v in usage.items()}
            last_usage = usage
        pass_records.append(record)
        last_pass_end = now
        # a snapshot each pass so a kill mid-run leaves progress, state marks it not yet final
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
            on_pass(pass_no, lens, new, union_size)

    run_passes(
        open_units,
        reviewers,
        lenses=domain.lenses,
        converge_after=converge_after,
        min_lens_shots=min_lens_shots,
        max_passes=max_passes,
        shared_context=shared,
        concurrency=concurrency,
        on_pass=_timed_on_pass,
        on_unit=lambda name, secs: unit_times.append((name, secs)),
        persist=lambda f: _save_union(ws, f),
        accumulator=acc,
    )
    _save_union(ws, acc.findings)
    reviewed_slugs = {unit_slug(u.name) for u in open_units if u.name not in acc.failed_units}
    _mark_units_reviewed(ws, reviewed_slugs)

    findings = _canonicalize_categories(acc.findings, paths.vulnerabilities_dir)
    if domain.dedup_by_file:
        # the union keys by endpoint so two functions stay separate, but one defect at one
        # line can survive under several endpoint phrasings. Collapse those by location, as
        # finalize does, so the run path reports it once. Gated on the domains that dedup by
        # file, so the web path that keys by endpoint is unchanged.
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
            by_file=domain.dedup_by_file,
            on_verify=on_verify,
        )

    _write_surface(ws, units, acc.failed_units)
    unit_totals: dict[str, float] = {}
    for name, secs in unit_times:
        unit_totals[name] = round(unit_totals.get(name, 0.0) + secs, 1)
    by_cost = sorted(unit_totals.items(), key=lambda t: t[1], reverse=True)
    timing = {
        "total_seconds": round(perf_counter() - run_started, 1),  # the whole coded run, passes and verify
        "per_pass": pass_records,
        "unit_seconds": [{"unit": name, "seconds": secs} for name, secs in by_cost],
    }
    usage_total = meter.snapshot() if meter is not None else None
    if usage_total is not None:
        usage_total["unit_review_calls"] = len(unit_times)
    state = "converged" if acc.converged and not acc.failed_units else "incomplete"
    _save_run_status(ws, units_total=len(units), acc=acc, verify=vr, timing=timing, usage=usage_total, state=state)
    _write_findings(ws, findings, root)
    _write_pocs_report(ws, findings)
    return RunResult(scaffold=res, accumulator=acc, units=len(units), verify=vr)
