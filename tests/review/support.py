"""Shared builders for review tests."""

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from cyberjury.review.detection import load_detection
from cyberjury.review.facts import Facts
from cyberjury.review.issues import LinkDecision
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.prepare import SharedGrounding
from cyberjury.review.relationships import (
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
)
from cyberjury.review.selection import select_files
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot


def definition(path: str, name: str, start: int, end: int, *, source: str | None = None) -> DefinitionEvidence:
    """Build one definition record over exact source text, or placeholder text when no source is given."""
    content = source[start:end] if source is not None else "x" * (end - start)
    return DefinitionEvidence.create(
        source=SourceReference.create(path=path, start=start, end=end, content=content),
        kind="file" if name == "<file>" else "function",
        name=name,
    )


def _whole_file_definition(root: Path, path: str, text: str, name: str, signature: str = "") -> DefinitionEvidence:
    (root / path).write_text(text, encoding="utf-8")
    return DefinitionEvidence.create(
        source=SourceReference.create(path=path, start=0, end=len(text), content=text),
        kind="function",
        name=name,
        signature=signature,
    )


def route_call(
    root: Path,
    caller_text: str,
    callees: dict[str, str],
    *,
    call_text: str = "load(value)",
    receiver: str = "",
    signature: str = "",
) -> SimpleNamespace:
    """Write `route.py` calling `load` once and every `load` callee file, and return their evidence bundle."""
    caller = _whole_file_definition(root, "route.py", caller_text, "route", signature)
    loads = tuple(_whole_file_definition(root, path, text, "load") for path, text in callees.items())
    start = caller_text.index(call_text)
    callsite = CallsiteEvidence.create(
        caller_definition_id=caller.id,
        source=SourceReference.create(path="route.py", start=start, end=start + len(call_text), content=call_text),
        expression=call_text,
        callee_spelling="load",
        receiver_expression=receiver,
    )
    return SimpleNamespace(
        caller=caller,
        callees=loads,
        callsite=callsite,
        relationships=RelationshipEvidenceBundle(definitions=(caller, *loads), callsites=(callsite,)),
    )


def callgraph_relationships(
    root: Path, callgraph: dict[str, dict[str, list[dict[str, object]]]]
) -> RelationshipEvidenceBundle:
    """Build definition evidence from a compact file, name, and range table over real source files."""
    definitions = []
    for path, names in callgraph.items():
        source = (root / path).read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        for name, entries in names.items():
            for entry in entries:
                start, end = entry["range"]
                definitions.append(definition(path, name, start, end, source=source))
    return RelationshipEvidenceBundle(definitions=tuple(definitions))


def navigator_from_callgraph(root: Path, graph: dict[str, object], **values: object) -> SourceNavigator | None:
    """Build a navigator whose definitions come from the graph's compact callgraph table."""
    relationships = callgraph_relationships(root, graph.get("callgraph", {}))
    return SourceNavigator.from_facts(
        root,
        import_files=tuple(graph.get("syntax_imports", {})),
        relationship_evidence=relationships,
        **values,
    )


def shared_grounding(
    root: Path,
    *,
    facts: Facts | None = None,
    navigator: SourceNavigator | None = None,
    snapshot: SourceSnapshot | None = None,
) -> SharedGrounding:
    """Build the shared prepare context over one source root with explicit facts and navigation."""
    snapshot = snapshot or capture_source_snapshot(root)
    return SharedGrounding(
        snapshot=snapshot,
        detection=load_detection(),
        selection=select_files(snapshot.root, snapshot.files, load_detection()),
        facts=facts or Facts(),
        navigator=navigator,
    )


@dataclass(frozen=True, kw_only=True)
class _GroundedWork:
    shared: SharedGrounding
    units: tuple
    skipped_files: tuple = ()


def prepared_units(units, root: Path, *, facts: Facts | None = None) -> _GroundedWork:
    """Wrap already grounded units as review work over an empty manifest of one source root."""
    return _GroundedWork(
        shared=shared_grounding(root, facts=facts, snapshot=SourceSnapshot.capture(root, ())),
        units=tuple(units),
    )


class StubIssueJudge:
    """Answer every issue link question from a pair predicate, or raise `error`, recording each pair."""

    fingerprint = "stub-issue-judge"

    def __init__(self, same_fix=lambda pair: True, *, error: Exception | None = None) -> None:
        """Bind the same-fix predicate and the optional failure."""
        self.same_fix = same_fix
        self.error = error
        self.pairs: list[tuple[str, str]] = []

    def judge(self, prompt, *, pair):
        """Link, separate, or fail one candidate pair."""
        self.pairs.append(pair)
        if self.error is not None:
            raise self.error
        return LinkDecision(same_fix=self.same_fix(pair), reason="one change decides both findings")
