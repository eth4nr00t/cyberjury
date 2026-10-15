"""Render bounded diff evidence and the diff finder contract."""

from __future__ import annotations

import re
from itertools import takewhile
from pathlib import Path

from cyberjury.numbering import numbered_diff
from cyberjury.review.definitions import DefinitionFragment
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.prompts import (
    CATEGORY_FIELD,
    SEVERITY_FIELD,
    PromptPlan,
    fenced_source,
    finder_system,
)
from cyberjury.review.schemas import (
    closed_object,
    finder_response_schema,
    string_array,
)
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

type GraphMap = dict[str, object]

_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff

DIFF_FINDING_SCHEMA = closed_object(
    {
        "file": {"type": "string"},
        "line": {"type": "integer"},
        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "category": {"type": "string"},
        "entrypoint": {"type": "string"},
        "description": {"type": "string"},
        "exploit_scenario": {"type": "string"},
        "recommendation": {"type": "string"},
        "confidence": {"type": "number"},
        "change_anchor": closed_object(
            {
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "side": {"type": "string", "enum": ["old", "new"]},
            }
        ),
        "evidence_refs": string_array(),
    }
)
FINDER_RESPONSE_SCHEMA = finder_response_schema("diff_finder_reply", DIFF_FINDING_SCHEMA)

_DIFF_SCOPE = """The user message contains one code change as a numbered unified diff, followed by repository \
source for tracing inputs, controls, and effects.
- Each patch gutter is `old:new`. A blank side means the line does not exist on that side.
- Report a vulnerability only when an exact changed line introduces it, exposes it, or removes the control behind \
it. Unchanged context and repository source support the analysis but are never change anchors.
- A deletion is vulnerable when surviving code loses a security control. Locate the finding in surviving code and \
anchor it on the removed line."""

_DIFF_FIELDS = f"""- `findings`: one entry per reported vulnerability; empty when there is none.
- `file`, `line`: where the fix must be applied: a post-change patch line, or a line inside source delivered under \
a cited evidence id.
- `change_anchor`: the exact changed line that introduces, exposes, or removes the control behind the \
vulnerability. `side` is `new` with the new line number for a `+` line and `old` with the old line number for a \
`-` line.
{SEVERITY_FIELD}
{CATEGORY_FIELD}
- `entrypoint`: the attacker-reachable operation where the exploit path starts.
- `description`: the missing or broken control and the implementation flaw.
- `exploit_scenario`: the concrete steps from attacker input to impact.
- `recommendation`: the fix to apply at `file` and `line`.
- `confidence`: the probability, from 0 to 1, that the delivered evidence establishes the exploit.
- `evidence_refs`: the evidence ids that establish the exploit path."""


def diff_finder_system(*, review_brief: str, severity_rubric: str, navigation: str) -> str:
    """Render the diff finder contract shared by every unit of one run."""
    return finder_system(
        target="a code change",
        scope=_DIFF_SCOPE,
        output_fields=_DIFF_FIELDS,
        review_brief=review_brief,
        severity_rubric=severity_rubric,
        navigation=navigation,
    )


def diff_prompt_plan(diff: str, *, context: str = "", catalog: str = "", followup: str = "") -> PromptPlan:
    """Keep one diff unit's evidence ahead of the controls that change between calls."""
    blocks = [f"Code change (unified diff):\n{fenced_source(numbered_diff(diff), 'diff')}"]
    if context:
        blocks.append(f"Repository source:\n{fenced_source(context)}")
    if catalog:
        blocks.append(catalog)
    stable_prefix = "\n\n".join(blocks) + "\n\n"
    return PromptPlan(stable_prefix=stable_prefix, dynamic_suffix=followup)


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
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8")
    except ValueError as exc:
        raise BackendUnavailable(f"diff context source path escapes the repository: {rel}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise BackendUnavailable(f"diff context could not read source {rel}: {exc}") from exc


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
    return f"Syntax hints (unverified; cite only delivered source):\n{bounded}"


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
    linked_names: tuple[str, ...] = (),
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
        linked_names=linked_names,
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
        facts_block = f"Syntax hints (unverified; cite only delivered source):\n{facts}"
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
    linked_names: tuple[str, ...] = (),
    max_chars: int = _SETTINGS.target_definition_context_chars_per_file,
    allow_required_overflow: bool = False,
) -> tuple[str, tuple[str, ...]]:
    if not defs_by_name or not (focus_names or seed_text or required_fragments):
        return "", ()
    snippets: list[tuple[bool, tuple[str, ...], int, int, int, str, tuple[str, ...]]] = []
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
            if str(name) == "<file>" and linked_names and not required_hit:
                continue
            calls = {str(call) for call in item.get("calls") or ()} if isinstance(item, dict) else set()
            linked = tuple(
                linked for linked in linked_names if re.search(rf"\b{re.escape(linked)}\b", source[start:end])
            )
            name_affinity = max(
                (_common_prefix_length(str(name).casefold(), value.casefold()) for value in linked),
                default=0,
            )
            if not required_hit and not lexical_hit and not linked and not calls.intersection(focus_names):
                continue
            snippet = _definition_snippet(source, str(name), item)
            if snippet:
                original_size = len(snippet)
                if linked and not required_hit:
                    if max_chars <= 4:
                        continue
                    linked_limit = max_chars // 2 - 2 if name_affinity else max_chars - 2
                    snippet = _clip_block(snippet, min(_SETTINGS.max_caller_definition_chars, linked_limit))
                snippets.append(
                    (
                        required_hit,
                        linked,
                        name_affinity,
                        original_size if linked else len(snippet),
                        _definition_start(item),
                        snippet,
                        required_entry[1] if required_entry is not None else (),
                    )
                )
    out: list[str] = []
    included: list[str] = []
    total = 0
    required_items = sorted((item for item in snippets if item[0]), key=lambda item: (item[3], item[4]))
    linked_items = [item for item in snippets if item[1] and not item[0]]
    other_items = sorted(
        (item for item in snippets if not item[0] and not item[1]), key=lambda item: (item[3], item[4])
    )
    covered_names: set[str] = set()
    ordered = list(required_items)
    while linked_items:
        item = max(
            linked_items,
            key=lambda candidate: (
                candidate[2],
                len(set(candidate[1]) - covered_names),
                len(candidate[1]),
                candidate[3],
                -candidate[4],
            ),
        )
        ordered.append(item)
        covered_names.update(item[1])
        linked_items.remove(item)
    ordered.extend(other_items)
    for required_hit, _linked, _affinity, _size, _start, snippet, identities in ordered:
        size = len(snippet)
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


def _common_prefix_length(left: str, right: str) -> int:
    return sum(1 for _ in takewhile(lambda pair: pair[0] == pair[1], zip(left, right, strict=False)))
