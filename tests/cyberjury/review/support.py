"""Shared builders for review tests."""

from pathlib import Path

from cyberjury.detection import load_detection
from cyberjury.review.facts import Facts
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.prepare import PreparedReview, SharedGrounding
from cyberjury.review.relationships import DefinitionEvidence, RelationshipEvidenceBundle, SourceReference
from cyberjury.review.verification import (
    RefutationCheck,
    RefutationChecker,
    Verdict,
    VerificationActorFingerprint,
    Verifier,
)
from cyberjury.selection import select_files
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot


def definition(path: str, name: str, start: int, end: int, *, source: str | None = None) -> DefinitionEvidence:
    """Build one definition record over exact source text, or placeholder text when no source is given."""
    content = source[start:end] if source is not None else "x" * (end - start)
    return DefinitionEvidence.create(
        source=SourceReference.create(path=path, start=start, end=end, content=content),
        kind="file" if name == "<file>" else "function",
        name=name,
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
    return RelationshipEvidenceBundle.create(definitions=tuple(definitions))


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


def prepared_units(units, root: Path, *, facts: Facts | None = None) -> PreparedReview:
    """Wrap already grounded units in a prepared review over an empty manifest of one source root."""
    return PreparedReview(
        shared=shared_grounding(root, facts=facts, snapshot=SourceSnapshot.capture(root, ())),
        facts=None,
        unit_plan=None,
        grounding=None,
        units=tuple(units),
        skipped_files=(),
    )


class StubVerifier(Verifier):
    """Refute the candidates `refute` selects at their own line, or raise `error`, counting calls."""

    def __init__(self, refute=lambda candidate: False, *, error: Exception | None = None) -> None:
        """Bind the refutation predicate and the optional failure."""
        self.refute = refute
        self.error = error
        self.calls = 0

    def verify(self, candidate, root):
        """Refute, retain, or fail one candidate."""
        self.calls += 1
        if self.error is not None:
            raise self.error
        if self.refute(candidate):
            return Verdict(
                real=False,
                reason="controlling fact holds",
                control_file=candidate.file,
                control_line=candidate.line,
            )
        return Verdict(real=True, reason="candidate remains exploitable")


class StubChecker(RefutationChecker):
    """Uphold the refutations of candidates `holds` selects, on one named seat."""

    def __init__(self, holds=lambda candidate: False, *, seat: str = "checker") -> None:
        """Bind the uphold predicate and the seat identity."""
        self.predicate = holds
        self.seat = seat

    def checkpoint_fingerprint(self):
        """Identify the checker seat."""
        return VerificationActorFingerprint(actor="test checker", settings=(("model", self.seat),))

    def holds(self, candidate, refutation, root):
        """Uphold or reject one refutation."""
        held = self.predicate(candidate)
        return RefutationCheck(holds=held, reason="control covers path" if held else "control misses path")
