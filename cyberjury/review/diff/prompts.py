"""Render Diff Review prompts and bounded repository evidence.

The focus, do-not-report, and severity-rubric blocks come from the selected profile.
The default profile supplies them when a caller names none. They name the high-value
classes to hunt, the noise to skip, and how to grade what is found. The prompt asks for
findings as a single JSON object.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from cyberjury.numbering import numbered_diff
from cyberjury.profiles.base import ContentPaths
from cyberjury.profiles.registry import default_profile
from cyberjury.review.definitions import DefinitionFragment
from cyberjury.review.prompts import CHALLENGER_SYSTEM as _CHALLENGER_SYSTEM
from cyberjury.review.prompts import FINDER_SYSTEM as _FINDER_SYSTEM
from cyberjury.review.prompts import JUDGE_SYSTEM as _JUDGE_SYSTEM
from cyberjury.review.prompts import (
    REVIEW_SYSTEM,
    PromptPlan,
    challenger_task,
    finder_task,
    judge_task,
    knowledge_judgment,
)
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

type GraphMap = dict[str, object]

_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff

CHALLENGER_SYSTEM = _CHALLENGER_SYSTEM
FINDER_SYSTEM = _FINDER_SYSTEM
JUDGE_SYSTEM = _JUDGE_SYSTEM

SYSTEM = REVIEW_SYSTEM + " The target evidence is a code change."

FOCUS = default_profile().diff_focus
DO_NOT_REPORT = default_profile().diff_do_not_report

_JSON_SHAPE = (
    '{"findings": [{"file": "path", "line": 0, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
    '"category": "<one id from the category set>", "description": "...", '
    '"exploit_scenario": "end to end steps", "recommendation": "...", "confidence": 0.0, '
    '"change_anchor": {"file": "path", "line": 0, "side": "old|new"}, '
    '"evidence_refs": ["seed|ev-id|src-id"]}], '
    '"evidence_requests": ["ev-id|src-id"], "source_queries": []}'
)
_CODE_CHANGE_MARKER = "Code change (unified diff):\n"
_FINDING_FIELDS = (
    '{"file": "path", "line": 0, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
    '"category": "...", "description": "...", "exploit_scenario": "...", '
    '"recommendation": "...", "confidence": 0.0, '
    '"change_anchor": {"file": "path", "line": 0, "side": "old|new"}, '
    '"evidence_refs": ["seed|ev-id|src-id"]}'
)
_DIFF_SCOPE = """Patch scope rules:
- Each numbered patch gutter is `old:new`. A blank side means that line does not exist on that side.
- `file` and `line` identify where the missing control or unsafe operation is implemented. Use a
  numbered post change line from the patch, or an exact repository line read through a cited `src-*`
  or `ev-*` source receipt. A reachability only route, registration, wrapper, or caller belongs in
  `change_anchor` unless that line itself contains the missing control or unsafe exposure.
- `change_anchor` must identify the exact `+` or `-` line responsible for the vulnerability. Use
  `side: new` for a `+` line and `side: old` for a `-` line. Always provide this field.
- Unchanged context and repository grounding may support the analysis, but neither is a change
  anchor. If no exact patch anchor exists, do not report the issue as a diff finding.
- A deletion can be vulnerable when surviving code loses a security control. Locate the finding at
  surviving post change code and anchor the removed control on the old side.
"""


def diff_cache_prefix(prompt: str) -> str:
    """The reusable diff prompt prefix before the changed code body."""
    head, marker, _tail = prompt.partition(_CODE_CHANGE_MARKER)
    return f"{head}{marker}" if marker else ""


def category_block(vulnerabilities_dir: str | Path | None = None) -> str:
    """The closed category set the model must choose from, the vulnerability ids.

    Reads the profile's vulnerability classes, defaulting to the web profile.
    """
    from cyberjury.review.vulnerabilities import allowed_categories

    cats = allowed_categories() if vulnerabilities_dir is None else allowed_categories(vulnerabilities_dir)
    return (
        "Each finding's `category` must be exactly one of these ids "
        "(use `other` only if none fit):\n" + ", ".join(cats) + "\n\n"
        if cats
        else ""
    )


def severity_rubric_text(content: ContentPaths | None = None) -> str:
    """The profile's severity rubric, defaulting to the web profile.

    This keeps a diff finding on the same calibrated levels and firm rules the repository
    path applies.
    """
    from cyberjury.resources import SEVERITY_RUBRIC_FILE

    path = content.severity_rubric_file if content is not None else SEVERITY_RUBRIC_FILE
    return path.read_text(encoding="utf-8")


def rubric_block(severity_rubric: str) -> str:
    """Format the selected profile severity rubric for the diff prompt."""
    return f"Grade each finding's severity on this rubric:\n{severity_rubric}\n\n" if severity_rubric else ""


def standard_audit_prompt(
    diff: str,
    *,
    vulnerabilities: str = "",
    vulnerability_categories: tuple[str, ...] = (),
    selected_vulnerability_categories: tuple[str, ...] = (),
    context: str = "",
    stack: str = "",
    vulnerabilities_dir: str | Path | None = None,
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> str:
    """Keep the string API for callers that do not need cache boundaries."""
    return standard_audit_prompt_plan(
        diff,
        vulnerabilities=vulnerabilities,
        vulnerability_categories=vulnerability_categories,
        selected_vulnerability_categories=selected_vulnerability_categories,
        context=context,
        stack=stack,
        vulnerabilities_dir=vulnerabilities_dir,
        focus=focus,
        do_not_report=do_not_report,
        severity_rubric=severity_rubric,
    ).text


def standard_audit_prompt_plan(
    diff: str,
    *,
    vulnerabilities: str = "",
    vulnerability_categories: tuple[str, ...] = (),
    selected_vulnerability_categories: tuple[str, ...] = (),
    context: str = "",
    context_controls: str = "",
    stack: str = "",
    vulnerabilities_dir: str | Path | None = None,
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> PromptPlan:
    """Keep one diff's evidence stable across bounded knowledge judgments."""
    stable_prefix = _standard_evidence_prefix(
        diff,
        context=context,
        context_controls=context_controls,
        stack=stack,
        vulnerabilities_dir=vulnerabilities_dir,
        focus=focus,
        do_not_report=do_not_report,
        severity_rubric=severity_rubric,
    )
    judgment = knowledge_judgment(
        vulnerability_categories,
        vulnerabilities,
        selected_categories=selected_vulnerability_categories,
    )
    judgment_suffix = (
        judgment + "Report each real vulnerability with a precise file and line, a concrete "
        "exploit scenario, and a calibrated confidence. If there are none, return an "
        "empty findings list. If a controlling fact is missing and the context publishes an "
        "evidence id for it, request that id. Do not infer the missing fact or invent an evidence "
        "id. Use `source_queries` only to search under the published navigation contract. Request every "
        "exact `ev-*` or `src-*` id through `evidence_requests`.\n\n"
        "Respond with a single JSON object exactly like:\n" + _JSON_SHAPE
    )
    return PromptPlan(stable_prefix=stable_prefix, judgment_suffix=judgment_suffix)


def _standard_evidence_prefix(
    diff: str,
    *,
    context: str,
    context_controls: str,
    stack: str,
    vulnerabilities_dir: str | Path | None,
    focus: str,
    do_not_report: str,
    severity_rubric: str,
) -> str:
    """Render the source prefix shared by navigation and formal judgments."""
    stack_block = f"Conventions of the target's language/framework:\n{stack}\n\n" if stack else ""
    context_block = (
        f"Surrounding code for tracing where values come from (not under review):\n```\n{context}\n```\n\n"
        if context
        else ""
    )
    controls_block = f"Repository grounding controls:\n{context_controls}\n\n" if context_controls else ""
    return (
        "Review the following code change for security vulnerabilities.\n\n"
        f"{_DIFF_SCOPE}\n"
        f"{focus}\n{do_not_report}\n"
        f"{category_block(vulnerabilities_dir)}"
        f"{stack_block}"
        f"{_CODE_CHANGE_MARKER}```diff\n{numbered_diff(diff)}\n```\n\n"
        f"{context_block}{controls_block}"
        f"{rubric_block(severity_rubric)}"
    )


def _diff_block(
    diff: str,
    vulnerabilities: str,
    context: str,
    stack: str = "",
    context_controls: str = "",
) -> str:
    stack_block = f"Conventions of the target's language/framework:\n{stack}\n\n" if stack else ""
    vulnerabilities_block = (
        f"Relevant vulnerability classes for reference:\n{vulnerabilities}\n\n" if vulnerabilities else ""
    )
    context_block = (
        f"Surrounding code for tracing where values come from (not under review):\n```\n{context}\n```\n\n"
        if context
        else ""
    )
    controls_block = f"Repository grounding controls:\n{context_controls}\n\n" if context_controls else ""
    return (
        f"{_DIFF_SCOPE}\n{stack_block}{vulnerabilities_block}"
        f"Code change (unified diff):\n```diff\n{numbered_diff(diff)}\n```\n\n"
        f"{context_block}{controls_block}"
    )


def finder_prompt(
    diff: str,
    *,
    vulnerabilities: str = "",
    context: str = "",
    context_controls: str = "",
    prior: list[dict[str, object]] | None = None,
    vulnerabilities_dir: str | Path | None = None,
    stack: str = "",
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> str:
    """Build the adversarial Finder prompt for one diff round."""
    prior_block = ""
    if prior:
        prior_block = (
            "Findings carried from the previous round. Reassess them against the current code and evidence, "
            "keep the valid ones, and add anything still missed:\n"
            f"{json.dumps(prior, ensure_ascii=False)}\n\n"
        )
    return (
        finder_task("diff unit") + f"{focus}\n{do_not_report}\n{category_block(vulnerabilities_dir)}"
        f"{_diff_block(diff, vulnerabilities, context, stack, context_controls)}{prior_block}"
        f"{rubric_block(severity_rubric)}"
        "If a controlling fact is missing and the context publishes an evidence id for it, "
        "request that id. Do not infer the missing fact.\n\n"
        'Respond with a single JSON object exactly like: {"findings": ['
        + _FINDING_FIELDS
        + '], "evidence_requests": ["ev-id|src-id"], "source_queries": []}'
    )


def challenger_prompt(
    diff: str,
    finder_findings: list[dict[str, object]],
    *,
    vulnerabilities: str = "",
    context: str = "",
    context_controls: str = "",
    vulnerabilities_dir: str | Path | None = None,
    stack: str = "",
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> str:
    """Build the adversarial Challenger prompt for one Finder result."""
    return (
        challenger_task("diff unit") + f"{focus}\n{do_not_report}\n{category_block(vulnerabilities_dir)}"
        f"{_diff_block(diff, vulnerabilities, context, stack, context_controls)}"
        f"Reported findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        f"{rubric_block(severity_rubric)}"
        "Respond with a single JSON object exactly like: "
        '{"rebuttals": [{"target": "finding description or file:line", "verdict": "dismiss|downgrade", '
        '"reason": "..."}], "new_findings": [' + _FINDING_FIELDS + "]}"
    )


def judge_prompt(
    diff: str,
    finder_findings: list[dict[str, object]],
    rebuttals: list[dict[str, object]],
    new_findings: list[dict[str, object]],
    *,
    vulnerabilities: str = "",
    context: str = "",
    context_controls: str = "",
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
    pending: list[dict[str, object]] | None = None,
) -> str:
    """Build the adversarial Judge prompt for challenged findings."""
    context_block = (
        f"Surrounding code for tracing where values come from (not under review):\n```\n{context}\n```\n\n"
        if context
        else ""
    )
    controls_block = f"Repository grounding controls:\n{context_controls}\n\n" if context_controls else ""
    policy_block = f"{do_not_report}\n" if do_not_report else ""
    vulnerabilities_block = (
        f"Relevant vulnerability classes for reference:\n{vulnerabilities}\n\n" if vulnerabilities else ""
    )
    pending_block = (
        "Previously unresolved work. Preserve each item in `unresolved` or `investigate` with its `id`, "
        "or put its id in `resolved_pending` only when current code or evidence resolves it:\n"
        f"{json.dumps(pending, ensure_ascii=False)}\n\n"
        if pending
        else ""
    )
    return (
        judge_task("diff unit") + "- CONFIRMED: real and exploitable -> put it in `findings` at its severity.\n"
        "- DOWNGRADED: real but lower impact than claimed -> put it in `findings` at the lower severity, "
        "and record it in `downgraded`.\n"
        "- DISMISSED: the diff shows a controlling fact that makes the reported path unexploitable. "
        "Do not assume an off-file control or dismiss a dangerous operation merely because the input's "
        "origin is not shown.\n"
        "- UNRESOLVED: cannot decide from the code shown -> put it in `unresolved`.\n"
        "- INVESTIGATE: needs a dynamic/runtime check to confirm -> put it in `investigate`.\n\n"
        f"{policy_block}{vulnerabilities_block}"
        f"{_DIFF_SCOPE}\n"
        f"Code change (unified diff):\n```diff\n{numbered_diff(diff)}\n```\n\n{context_block}{controls_block}"
        f"{pending_block}Finder findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        f"Challenger rebuttals:\n{json.dumps(rebuttals, ensure_ascii=False)}\n\n"
        f"Challenger independent findings:\n{json.dumps(new_findings, ensure_ascii=False)}\n\n"
        f"{rubric_block(severity_rubric)}"
        'Respond with a single JSON object exactly like: {"findings": [' + _FINDING_FIELDS + "], "
        '"downgraded": [{"target": "...", "from": "HIGH", "to": "MEDIUM", "reason": "..."}], '
        '"dismissed": [{"target": "...", "reason": "..."}], '
        '"unresolved": [{"target": "...", "reason": "..."}], '
        '"investigate": [{"id": "pending id when retained", "target": "...", "reason": "..."}], '
        '"resolved_pending": ["pending-id"], "evidence_requests": ["ev-id|src-id"], '
        '"source_queries": []}'
    )


def file_context(
    root: Path,
    rel: str,
    facts: str,
    ranges: tuple[tuple[int, int], ...],
    defs_by_name: GraphMap,
) -> str:
    """Render current source, related definitions, and facts for one changed file."""
    source = _read_source(root, rel)
    if source is None:
        return ""
    source_block, prefix_block, definition_block = _source_blocks(source, ranges, defs_by_name)
    pieces = [f"File: {rel}"]
    facts_block = _facts_block(facts)
    if ranges:
        if definition_block:
            pieces.append(f"Related definitions:\n{definition_block}")
        pieces.append(source_block)
        if prefix_block:
            pieces.append(prefix_block)
        if facts_block:
            pieces.append(facts_block)
    else:
        if facts_block:
            pieces.append(facts_block)
        pieces.append(source_block)
    return "\n".join(pieces)


def _read_source(root: Path, rel: str) -> str | None:
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
        return path.read_text(encoding="utf-8") if path.is_file() else None
    except (OSError, UnicodeDecodeError, ValueError):
        return None


def _source_blocks(
    source: str,
    ranges: tuple[tuple[int, int], ...],
    defs_by_name: GraphMap,
) -> tuple[str, str, str]:
    if ranges:
        source_prefix = _bounded_prefix(
            source,
            _SETTINGS.max_changed_source_prefix_chars,
            "... [source truncated]",
        )
        rendered_source = _source_windows(source, ranges)
        return (
            f"Current source around changed lines:\n{rendered_source}",
            f"Current file source prefix:\n{_numbered_source(source_prefix)}",
            _definition_snippets(source, defs_by_name, rendered_source, ranges),
        )
    bounded = _bounded_prefix(
        source,
        _SETTINGS.max_full_source_chars_per_context_file,
        "... [source truncated]",
    )
    return (f"Current source:\n{_numbered_source(bounded)}", "", "")


def _facts_block(facts: str) -> str:
    if not facts:
        return ""
    bounded = _bounded_prefix(
        facts,
        _SETTINGS.max_facts_chars_per_context_file,
        "... [facts truncated]",
    )
    return f"Facts:\n{bounded}"


def _bounded_prefix(text: str, limit: int, marker: str) -> str:
    return text if len(text) <= limit else f"{text[:limit]}\n{marker}"


def related_file_context(
    root: Path,
    rel: str,
    facts: str,
    defs_by_name: GraphMap,
    focus_names: set[str],
    seed_text: str,
    required_fragments: tuple[DefinitionFragment, ...] = (),
    max_chars: int = _SETTINGS.target_definition_context_chars_per_file,
    allow_required_overflow: bool = False,
) -> tuple[str, tuple[str, ...]]:
    """Render related source while preserving required evidence identities."""
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return "", ()
    if not path.is_file():
        return "", ()
    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return "", ()
    header = f"File: {rel}"
    available = max(0, max_chars - len(header) - len("\nRelated definitions:\n"))
    snippets, included = _caller_definition_snippets(
        source,
        rel,
        defs_by_name,
        focus_names,
        seed_text,
        required_fragments=required_fragments,
        max_chars=available,
        allow_required_overflow=allow_required_overflow,
    )
    pieces = [header]
    if snippets:
        pieces.append(f"Related definitions:\n{snippets}")
    else:
        source_block = f"Current source:\n{_numbered_source(source)}"
        if len(source_block) <= available:
            pieces.append(source_block)
            included = tuple(fragment.identity for fragment in required_fragments)
        elif not required_fragments:
            pieces.append(_clip_block(source_block, available))
    if facts:
        if len(facts) > _SETTINGS.max_facts_chars_per_context_file:
            facts = facts[: _SETTINGS.max_facts_chars_per_context_file] + "\n... [facts truncated]"
        facts_block = f"Facts:\n{facts}"
        remaining = max_chars - len("\n".join(pieces)) - 1
        if remaining > 0:
            pieces.append(_clip_block(facts_block, remaining))
    return "\n".join(pieces), included


def required_definition_chars(
    root: Path,
    rel: str,
    required_fragments: tuple[DefinitionFragment, ...],
) -> int:
    """Reserve enough of the total budget for indivisible required definitions."""
    source = _source_for_rendering(root, rel)
    snippets = [
        _definition_fragment_snippet(source, fragment) for fragment in _outer_definition_fragments(required_fragments)
    ]
    body = sum(len(snippet) + 2 for snippet in snippets if snippet)
    return len(f"File: {rel}\nRelated definitions:\n") + body


def _source_for_rendering(root: Path, rel: str) -> str:
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError):
        return ""


def _numbered_source(source: str) -> str:
    return "\n".join(f"{i:4}: {line}" for i, line in enumerate(source.splitlines(), 1))


def _source_windows(source: str, ranges: tuple[tuple[int, int], ...]) -> str:
    lines = source.splitlines()
    chunks: list[str] = []
    for start, end in ranges:
        if chunks:
            chunks.append("... [source gap]")
        if start > len(lines) + 1:
            chunks.append(f"Changed lines {start}-{end} are outside current source length {len(lines)}.")
            continue
        before_start = max(1, start - _SETTINGS.hunk_context_lines_per_side)
        before_end = min(len(lines), start - 1)
        after_start = end + 1
        after_end = min(len(lines), end + _SETTINGS.hunk_context_lines_per_side)
        chunks.append(f"Before changed lines {start}-{end}:")
        if before_start <= before_end:
            chunks.extend(f"{i:4}: {lines[i - 1]}" for i in range(before_start, before_end + 1))
        else:
            chunks.append("... [start of file]")
        chunks.append("... [changed lines are in the diff]")
        chunks.append(f"After changed lines {start}-{end}:")
        if after_start <= after_end:
            chunks.extend(f"{i:4}: {lines[i - 1]}" for i in range(after_start, after_end + 1))
        else:
            chunks.append("... [end of file]")
    return "\n".join(chunks)


def _definition_snippets(
    source: str,
    defs_by_name: GraphMap,
    seed_text: str,
    changed_ranges: tuple[tuple[int, int], ...],
) -> str:
    if not defs_by_name:
        return ""
    names = _referenced_names(seed_text, defs_by_name)
    snippets: list[tuple[int, str]] = []
    seen: set[str] = set()
    for _ in range(2):
        pending = [name for name in names if name not in seen]
        if not pending:
            break
        names = []
        for name in pending:
            seen.add(name)
            for item in defs_by_name.get(name) or ():
                if _definition_overlaps_changed(source, item, changed_ranges):
                    continue
                snippet = _definition_snippet(source, name, item)
                if not snippet:
                    continue
                snippets.append((_definition_start(item), snippet))
                names.extend(_referenced_names(snippet, defs_by_name))
    out: list[str] = []
    total = 0
    for _start, snippet in snippets:
        add = len(snippet) + 2
        if out and total + add > _SETTINGS.target_definition_context_chars_per_file:
            out.append("... [definitions truncated]")
            break
        out.append(snippet)
        total += add
    return "\n\n".join(out)


def _caller_definition_snippets(
    source: str,
    rel: str,
    defs_by_name: GraphMap,
    focus_names: set[str],
    seed_text: str = "",
    *,
    required_fragments: tuple[DefinitionFragment, ...] = (),
    max_chars: int = _SETTINGS.target_definition_context_chars_per_file,
    allow_required_overflow: bool = False,
) -> tuple[str, tuple[str, ...]]:
    if not defs_by_name or not (focus_names or seed_text or required_fragments):
        return "", ()
    snippets: list[tuple[bool, int, int, str, tuple[str, ...]]] = []
    outer_required = _outer_definition_fragments(required_fragments)
    required = {
        (fragment.name, fragment.start, fragment.end): (
            fragment,
            tuple(
                candidate.identity
                for candidate in required_fragments
                if candidate.file == fragment.file
                and fragment.start <= candidate.start
                and fragment.end >= candidate.end
            ),
        )
        for fragment in outer_required
    }
    for name, entries in defs_by_name.items():
        lexical_hit = bool(re.search(rf"\b{re.escape(str(name))}\b", seed_text))
        for item in entries or ():
            start, end = _definition_range(item)
            required_entry = required.get((str(name), start, end))
            required_hit = required_entry is not None
            calls = {str(call) for call in item.get("calls") or ()} if isinstance(item, dict) else set()
            if not required_hit and not lexical_hit and not calls.intersection(focus_names):
                continue
            snippet = _definition_snippet(source, str(name), item)
            if snippet:
                snippets.append(
                    (
                        required_hit,
                        len(snippet),
                        _definition_start(item),
                        snippet,
                        required_entry[1] if required_entry is not None else (),
                    )
                )
    out: list[str] = []
    included: list[str] = []
    total = 0
    for required_hit, size, _start, snippet, identities in sorted(
        snippets,
        key=lambda item: (not item[0], item[1], item[2]),
    ):
        if not required_hit and size > _SETTINGS.max_caller_definition_chars:
            continue
        add = size + 2
        if total + add > max_chars and (not required_hit or not allow_required_overflow):
            continue
        out.append(snippet)
        total += add
        if required_hit:
            included.extend(identities)
    return "\n\n".join(out), tuple(included)


def _outer_definition_fragments(
    fragments: tuple[DefinitionFragment, ...],
) -> tuple[DefinitionFragment, ...]:
    """Return source ranges not contained by another required definition."""
    return tuple(
        fragment
        for index, fragment in enumerate(fragments)
        if not any(
            other_index != index
            and other.file == fragment.file
            and other.start <= fragment.start
            and other.end >= fragment.end
            and (other.start < fragment.start or other.end > fragment.end or other_index < index)
            for other_index, other in enumerate(fragments)
        )
    )


def _referenced_names(text: str, defs_by_name: GraphMap) -> list[str]:
    found: list[str] = []
    for name in defs_by_name:
        if name in found:
            continue
        if re.search(rf"\b{re.escape(str(name))}\b", text):
            found.append(str(name))
    return found


def _definition_snippet(source: str, name: str, item: object) -> str:
    start, end = _definition_range(item)
    if start < 0 or end <= start:
        return ""
    start_line, end_line = _definition_line_span(source, item)
    if start_line < 0 or end_line < start_line:
        return ""
    lines = source.splitlines()
    rendered = "\n".join(f"{i:4}: {lines[i - 1]}" for i in range(start_line, end_line + 1))
    return f"Definition {name}:\n{rendered}"


def _definition_fragment_snippet(source: str, fragment: DefinitionFragment) -> str:
    return _definition_snippet(source, fragment.name, {"range": [fragment.start, fragment.end]})


def _definition_range(item: object) -> tuple[int, int]:
    if not isinstance(item, dict):
        return (-1, -1)
    raw = item.get("range")
    if not isinstance(raw, list | tuple) or len(raw) < 2:
        return (-1, -1)
    start = raw[0]
    end = raw[1]
    if not isinstance(start, int) or not isinstance(end, int):
        return (-1, -1)
    return (start, end)


def _definition_start(item: object) -> int:
    return _definition_range(item)[0]


def _definition_line_span(source: str, item: object) -> tuple[int, int]:
    start, end = _definition_range(item)
    if start < 0 or end <= start:
        return (-1, -1)
    lines = source.splitlines()
    start_line = max(1, source[:start].count("\n") + 1)
    end_line = min(len(lines), source[:end].count("\n") + 1)
    return (start_line, end_line)


def _definition_overlaps_changed(
    source: str,
    item: object,
    changed_ranges: tuple[tuple[int, int], ...],
) -> bool:
    start_line, end_line = _definition_line_span(source, item)
    if start_line < 0:
        return False
    return any(start_line <= changed_end and end_line >= changed_start for changed_start, changed_end in changed_ranges)


def _merge_ranges(ranges) -> list[tuple[int, int]]:
    ordered = sorted((int(a), int(b)) for a, b in ranges)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def render_context(
    changed: list[tuple[str, str]],
    related: list[tuple[str, str]],
    *,
    related_first: bool,
    preserve_required: bool = False,
) -> str:
    """Assemble changed and related blocks within the prompt context budget."""
    if preserve_required:
        ordered_blocks = (*related, *changed) if related_first else (*changed, *related)
        return "\n\n".join(block for _rel, block in ordered_blocks)
    if not related:
        return _join_capped([block for _rel, block in changed], _SETTINGS.target_repository_context_chars_per_unit)
    related_text = "\n\n".join(block for _rel, block in related)
    separator = 2 if changed and related_text else 0
    changed_limit = _SETTINGS.target_repository_context_chars_per_unit - len(related_text) - separator
    changed_text = _join_capped([block for _rel, block in changed], changed_limit)
    ordered = (related_text, changed_text) if related_first else (changed_text, related_text)
    return _truncate(
        "\n\n".join(text for text in ordered if text),
        _SETTINGS.target_repository_context_chars_per_unit,
        "... [diff context truncated]",
    )


def _join_capped(blocks: list[str], limit: int) -> str:
    if len(blocks) > 1:
        separator_budget = 2 * (len(blocks) - 1)
        budget = max(1, (limit - separator_budget) // len(blocks))
        joined = "\n\n".join(_clip_block(block, budget) for block in blocks)
        if len(joined) <= limit:
            return joined
        return _truncate(joined, limit, "... [diff context truncated]")
    out: list[str] = []
    total = 0
    for block in blocks:
        add = len(block) + 2
        if out and total + add > limit:
            out.append("... [diff context truncated]")
            break
        if not out and add > limit:
            return _truncate(block, limit, "... [diff context truncated]")
        out.append(block)
        total += add
    return "\n\n".join(out)


def _clip_block(block: str, limit: int) -> str:
    if len(block) <= limit:
        return block
    return _truncate(block, limit, "... [file context truncated]")


def _truncate(text: str, limit: int, marker: str) -> str:
    if len(text) <= limit:
        return text
    if limit <= len(marker) + 1:
        return text[:limit]
    return text[: limit - len(marker) - 1] + "\n" + marker
