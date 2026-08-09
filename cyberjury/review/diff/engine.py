"""Diff-audit orchestration: run a diff through the engine and clean the result.

The library entry point behind `review diff`. Picks the standard or adversarial engine,
audits a large diff in size-bounded batches so a big PR does not overflow the model
context, normalizes finding categories onto the rule-id set, and applies the false-
positive filter. Kept out of the CLI so it can be called as a library.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from time import perf_counter

from cyberjury.detection import Detection, load_detection
from cyberjury.domains.base import Domain
from cyberjury.domains.registry import default_domain
from cyberjury.finding import Finding
from cyberjury.review.diff.adversarial import AdversarialAuditRunner
from cyberjury.review.diff.audit import AuditRunner, guides_for_diff
from cyberjury.review.diff.context import changed_line_ranges
from cyberjury.review.diff.filter import FindingsFilter
from cyberjury.review.diff.verify import verify_diff_findings
from cyberjury.review.diff.vulnerabilities import allowed_categories, normalize_category
from cyberjury.review.repository.verifier import Confirmer, Verifier

_MAX_DIFF_CHARS = 60_000


def split_diff_by_file(diff: str) -> list[str]:
    """Split a unified diff into one diff per file at `diff --git` boundaries."""
    chunks: list[str] = []
    cur: list[str] = []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git ") and cur:
            chunks.append("".join(cur))
            cur = []
        cur.append(line)
    if cur:
        chunks.append("".join(cur))
    return chunks or ([diff] if diff.strip() else [])


def _chunk_path(chunk: str) -> str:
    """The file path a per-file diff chunk is about.

    preferring the new-side `+++` path and falling back to the old-side `---` path for a
    deletion, then to the `diff --git` header. Empty when no path can be read, so the caller
    keeps the chunk rather than dropping what it cannot classify.
    """
    plus = minus = git = ""
    for line in chunk.splitlines():
        if line.startswith("+++ ") and not plus:
            plus = line[4:].strip()
        elif line.startswith("--- ") and not minus:
            minus = line[4:].strip()
        elif line.startswith("diff --git ") and not git:
            git = line
        if plus and minus and git:
            break
    for cand in (plus, minus):
        if cand and cand != "/dev/null":
            return cand[2:] if cand[:2] in ("a/", "b/") else cand
    tail = git.partition(" b/")[2]
    return tail.strip() if tail else ""


def strip_noise_files(diff: str, detection: Detection | None = None) -> tuple[str, tuple[str, ...]]:
    """Drop the files a reviewer should not read from a unified diff.

    returning the stripped diff and the skipped paths. A file is dropped only when Detection
    flags it as noise, which wastes review budget and, once a diff is chunked one file at a
    time, a whole model call. A chunk whose path cannot be read is kept, recall over cost,
    invariant 2.
    """
    det = detection or load_detection()
    kept: list[str] = []
    skipped: list[str] = []
    for chunk in split_diff_by_file(diff):
        path = _chunk_path(chunk)
        if path and det.is_noise_path(path):
            skipped.append(path)
        else:
            kept.append(chunk)
    return "".join(kept), tuple(skipped)


def pack_diff_chunks(diff: str, max_chars: int = _MAX_DIFF_CHARS) -> list[str]:
    """Greedily pack the per-file chunks of a diff into batches no larger than `max_chars`.

    so a large diff is reviewed in as few calls as possible and the files in one batch keep
    their cross-file context, instead of each file being audited alone. A single file larger
    than `max_chars` is its own batch, since a file is not split mid- hunk.
    """
    batches: list[str] = []
    cur: list[str] = []
    cur_len = 0
    for chunk in split_diff_by_file(diff):
        if cur and cur_len + len(chunk) > max_chars:
            batches.append("".join(cur))
            cur = []
            cur_len = 0
        cur.append(chunk)
        cur_len += len(chunk)
    if cur:
        batches.append("".join(cur))
    return batches


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate diff findings by category and location."""
    seen: set = set()
    out: list[Finding] = []
    for f in findings:
        k = (f.file, f.line, f.category, f.description)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _line_in_ranges(line: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def _diff_path_key(path: str) -> str:
    path = path.removeprefix("./")
    return path[2:] if path[:2] in ("a/", "b/") else path


def _normalize_finding_lines(findings: list[Finding], diff: str, detection: Detection) -> list[Finding]:
    ranges = changed_line_ranges(diff, detection)
    out: list[Finding] = []
    for f in findings:
        if f.line is None:
            out.append(f)
            continue
        file_ranges = ranges.get(_diff_path_key(f.file))
        if not file_ranges or not _line_in_ranges(f.line, file_ranges):
            out.append(dataclasses.replace(f, line=None))
            continue
        out.append(f)
    return out


def audit_diff(
    diff: str,
    *,
    provider,
    model: str,
    mode: str = "standard",
    max_rounds: int = 3,
    finder_model: str | None = None,
    challenger_model: str | None = None,
    judge_model: str | None = None,
    finder_provider=None,
    challenger_provider=None,
    judge_provider=None,
    context: str = "",
    context_for_diff: Callable[[str], str] | None = None,
    verification_root: str | None = None,
    verifier: Verifier | None = None,
    verification_confirmers: list[Confirmer] | None = None,
    verification_votes: int = 1,
    verification_concurrency: int = 8,
    domain: Domain | None = None,
    on_batch: Callable[[int, int, float], None] | None = None,
) -> tuple[list[Finding], list[tuple[Finding, str]], bool]:
    """Audit a diff and return the kept findings, the dropped finding-reason pairs.

    and a degraded flag. A diff over the size budget is audited in size-bounded batches so
    it does not overflow the context. Finding categories are normalized to the rule-id set.
    ``degraded`` is True when a judgment or verification step could not complete, so the
    caller can surface a degraded audit as a failure rather than a clean pass, invariant 4.
    """
    degraded = False
    domain = domain or default_domain()
    content = domain.paths
    focus, do_not_report = domain.diff_focus, domain.diff_do_not_report
    detection = load_detection(content.detection_file)
    diff, _ = strip_noise_files(diff, detection)
    if not diff.strip():
        return [], [], False

    def _run_one(d: str) -> list[Finding]:
        nonlocal degraded
        local_context = context_for_diff(d) if context_for_diff is not None else context
        if mode == "adversarial":
            stack = guides_for_diff(d, content)
            result = AdversarialAuditRunner(
                provider=provider,
                model=model,
                finder_model=finder_model,
                challenger_model=challenger_model,
                judge_model=judge_model,
                finder_provider=finder_provider,
                challenger_provider=challenger_provider,
                judge_provider=judge_provider,
                content=content,
                focus=focus,
                do_not_report=do_not_report,
            ).run(d, context=local_context, stack=stack, max_rounds=max_rounds)
            degraded = degraded or result.degraded
            return result.findings
        return AuditRunner(
            provider=provider, model=model, content=content, focus=focus, do_not_report=do_not_report
        ).run(d, context=local_context)

    if len(diff) > _MAX_DIFF_CHARS:
        batches = pack_diff_chunks(diff, _MAX_DIFF_CHARS)
        collected: list[Finding] = []
        for i, batch in enumerate(batches, 1):
            started = perf_counter()
            batch_findings = _run_one(batch)
            if on_batch is not None:
                on_batch(i, len(batches), round(perf_counter() - started, 1))
            collected.extend(batch_findings)
        findings = dedup_findings(collected)
    else:
        findings = _run_one(diff)

    allowed = set(allowed_categories(content.vulnerabilities_dir))
    findings = [dataclasses.replace(f, category=normalize_category(f.category, allowed)) for f in findings]
    findings = _normalize_finding_lines(findings, diff, detection)

    def _verify(
        items: list[Finding], dropped: list[tuple[Finding, str]]
    ) -> tuple[list[Finding], list[tuple[Finding, str]], bool]:
        if verifier is not None:
            if verification_root is None:
                raise ValueError("verification_root is required when verifier is set")
            verified = verify_diff_findings(
                items,
                verifier,
                verification_root,
                confirmers=verification_confirmers,
                votes=verification_votes,
                concurrency=verification_concurrency,
            )
            return verified.findings, [*dropped, *verified.dropped], degraded or verified.degraded
        return items, dropped, degraded

    kept, dropped = FindingsFilter(detection=detection).filter(findings)
    return _verify(kept, dropped)
