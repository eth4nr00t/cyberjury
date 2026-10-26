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
    facts, _receipt = extract_facts(
        snapshot, select_files(snapshot.root, snapshot.files, load_detection()), load_detection()
    )
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


def write_call_chain(root):
    """Write app/routes.py calling handle_request, which calls load_order, which calls run_query."""
    (root / "app").mkdir(parents=True)
    (root / "app" / "routes.py").write_text(
        "from app.handler import handle_request\n\n\ndef get_order(oid):\n    return handle_request(oid)\n"
    )
    (root / "app" / "handler.py").write_text(
        "from app.repository import load_order\n\n\ndef handle_request(oid):\n    return load_order(oid)\n"
    )
    (root / "app" / "repository.py").write_text("def load_order(oid):\n    return run_query(oid)\n")
    return root
