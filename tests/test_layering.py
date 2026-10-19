"""Import layering keeps lower packages below the review package and review stages one-way."""

import ast
from importlib.util import resolve_name
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "cyberjury"

_REVIEW_ROOT = _PACKAGE_ROOT / "review"

_SYNTAX_ROOT = _REVIEW_ROOT / "syntax"

_TARGET_MODULES = ("cyberjury.review.diff", "cyberjury.review.repository")

_REVIEW_CALLERS = {"cli.py"}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module_path = path.relative_to(_PACKAGE_ROOT.parent).with_suffix("")
    package_parts = module_path.parts if path.name == "__init__.py" else module_path.parts[:-1]
    package = ".".join(package_parts)
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            modules.add(resolve_name(f"{'.' * node.level}{module}", package) if node.level else module)
    return modules


def test_only_the_cli_depends_on_the_review_package():
    """Shared utilities, sources, and providers sit below review and never import it."""
    violations = {
        str(path.relative_to(_PACKAGE_ROOT)): sorted(
            module
            for module in _imports(path)
            if module == "cyberjury.review" or module.startswith("cyberjury.review.")
        )
        for path in _PACKAGE_ROOT.rglob("*.py")
        if _REVIEW_ROOT not in path.parents and path.name not in _REVIEW_CALLERS
    }

    assert not {path: modules for path, modules in violations.items() if modules}


def test_syntax_facts_use_one_way_stage_dependencies():
    """Syntax extraction coordinates analyzer, source selection, and graph work only in its facts module."""
    allowed = {
        "analyzer.py": set(),
        "sources.py": {"analyzer"},
        "graph.py": {"analyzer", "sources"},
        "facts.py": {"analyzer", "sources", "graph"},
    }
    for module, expected in allowed.items():
        imported = {
            name.rsplit(".", 1)[-1]
            for name in _imports(_SYNTAX_ROOT / module)
            if name.startswith("cyberjury.review.syntax.")
        }
        assert imported <= expected


def test_native_tool_imports_stop_at_the_analyzer_boundary():
    analyzer_imports = _imports(_SYNTAX_ROOT / "analyzer.py")
    assert any(name == "tree_sitter" or name.startswith("tree_sitter.") for name in analyzer_imports)

    for module in ("sources.py", "graph.py"):
        imports = _imports(_SYNTAX_ROOT / module)
        assert not any(name == "tree_sitter" or name.startswith("tree_sitter.") for name in imports)


def test_shared_review_modules_do_not_depend_on_target_implementations():
    """A shared primitive cannot acquire a Diff Review or Repository Review dependency."""
    violations = {
        str(path.relative_to(_REVIEW_ROOT)): sorted(
            module for module in _imports(path) if module.startswith(_TARGET_MODULES)
        )
        for path in _REVIEW_ROOT.rglob("*.py")
        if path.relative_to(_REVIEW_ROOT).parts[0] not in {"diff", "repository"}
    }

    assert not {path: modules for path, modules in violations.items() if modules}


def test_review_targets_do_not_depend_on_each_other():
    """Target adapters meet only through modules owned by the shared review layer."""
    violations: dict[str, list[str]] = {}
    for target, forbidden in (("diff", _TARGET_MODULES[1]), ("repository", _TARGET_MODULES[0])):
        for path in (_REVIEW_ROOT / target).rglob("*.py"):
            imports = sorted(module for module in _imports(path) if module.startswith(forbidden))
            if imports:
                violations[str(path.relative_to(_REVIEW_ROOT))] = imports

    assert not violations
