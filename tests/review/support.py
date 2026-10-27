"""Shared builders for review tests."""

import tempfile
from pathlib import Path
from types import SimpleNamespace

from cyberjury.providers.metering import UsageMeter
from cyberjury.review.detection import load_detection
from cyberjury.review.facts import Facts
from cyberjury.review.finding import Finding
from cyberjury.review.issues import LinkDecision
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.prepare import PreparedReview, SharedGrounding
from cyberjury.review.recorder import Recorder
from cyberjury.review.relationships import (
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
)
from cyberjury.review.run import ReviewRun, run_review
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


def navigator_from_definitions(
    root: Path, ranges: dict[str, dict[str, list[tuple[int, int]]]], **values: object
) -> SourceNavigator | None:
    """Build a navigator over definitions given as character ranges per file and name of real source files."""
    definitions = []
    for path, names in ranges.items():
        source = (root / path).read_text(encoding="utf-8")
        for name, spans in names.items():
            definitions.extend(definition(path, name, start, end, source=source) for start, end in spans)
    return SourceNavigator.from_facts(
        root, relationship_evidence=RelationshipEvidenceBundle(definitions=tuple(definitions)), **values
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


def prepared_units(units, root: Path, *, facts: Facts | None = None) -> PreparedReview:
    """Wrap already grounded units as review work over an empty manifest of one source root."""
    return PreparedReview(
        shared=shared_grounding(root, facts=facts, snapshot=SourceSnapshot.capture(root, ())),
        units=tuple(units),
    )


def recorder() -> Recorder:
    """Return a recorder that meters model calls and writes nothing."""
    return Recorder(meter=UsageMeter())


def bound_artifacts(recorder: Recorder) -> dict[type, object]:
    """Collect the artifact each stage of the recorder binds, keyed by its type."""
    artifacts: dict[type, object] = {}

    def bind(value: object) -> str:
        artifacts[type(value)] = value
        return type(value).__name__

    recorder.attach(bind=bind, sink=lambda _record: None)
    return artifacts


def run_prepared(
    prepared: PreparedReview, *, review: Path | None = None, stages: Recorder | None = None, **values
) -> ReviewRun:
    """Run one review of prepared units, recording into the review directory or a temporary one."""
    stages = stages or recorder()
    if review is not None:
        return run_review(prepared, review=review, recorder=stages, **values)
    with tempfile.TemporaryDirectory() as directory:
        return run_review(prepared, review=Path(directory), recorder=stages, **values)


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
        return LinkDecision(same_fix=self.same_fix(pair), rationale="one change decides both findings")


def stub_finding(title: str, location: str, *, evidence_refs: tuple[str, ...] = ()) -> Finding:
    """Build one finding at a file:line location for scheduler and evidence exchange tests."""
    file, line = location.rsplit(":", 1)
    return Finding(
        title=title,
        category="c",
        severity="HIGH",
        entrypoint="e",
        file=file,
        line=int(line),
        evidence="evidence",
        attack_path="path",
        evidence_refs=evidence_refs,
    )
