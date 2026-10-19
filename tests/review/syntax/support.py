"""Extract syntax facts the way the shared prepare stage does."""

from cyberjury.review.detection import load_detection
from cyberjury.review.facts import Facts
from cyberjury.review.prepare import extract_facts
from cyberjury.review.selection import select_files
from cyberjury.review.syntax.analyzer import analyze_repository, load_specs
from cyberjury.review.syntax.sources import reviewable_sources
from cyberjury.sources.snapshot import capture_source_snapshot


def syntax_facts(root) -> Facts:
    """Extract the syntax facts of every selected source under the root."""
    snapshot = capture_source_snapshot(root)
    facts, _receipt = extract_facts(snapshot, select_files(snapshot.root, snapshot.files, load_detection()))
    return facts


def callgraph(root) -> dict[str, dict[str, list[dict[str, object]]]]:
    """Map each analyzed file to its definitions' character ranges and bare callee names."""
    snapshot = capture_source_snapshot(root)
    analyzed = analyze_repository(reviewable_sources(snapshot.root, snapshot.files, load_detection(), load_specs()))
    graph: dict[str, dict[str, list[dict[str, object]]]] = {}
    for definition in analyzed.definitions:
        entry = {"range": [definition.start, definition.end], "calls": list(definition.calls)}
        graph.setdefault(definition.file, {}).setdefault(definition.name, []).append(entry)
    return graph
