"""Review targets depend on the shared engine without depending on each other."""

import ast
from importlib.util import resolve_name
from pathlib import Path

_REVIEW_ROOT = Path(__file__).parents[1] / "cyberjury" / "review"
_TARGET_MODULES = ("cyberjury.review.diff", "cyberjury.review.repository")
_COMMON_ADAPTERS = {
    "__init__.py",
    "context.py",
    "engine.py",
    "model.py",
    "prompts.py",
    "reviewer.py",
    "runner.py",
    "union.py",
    "verify.py",
}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module_path = path.relative_to(_REVIEW_ROOT.parents[1]).with_suffix("")
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


def _names_imported_from(path: Path, module: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == module
        for alias in node.names
    }


def test_review_targets_use_the_same_stage_modules():
    """Only repository workspace setup and gating justify target-only modules."""
    diff_modules = {path.name for path in (_REVIEW_ROOT / "diff").glob("*.py")}
    repository_modules = {path.name for path in (_REVIEW_ROOT / "repository").glob("*.py")}

    assert diff_modules == _COMMON_ADAPTERS
    assert repository_modules == _COMMON_ADAPTERS | {"gate.py", "scaffold.py"}


def test_target_runners_delegate_fanout_to_the_shared_engine():
    """Runners own worklists without taking back role execution."""
    for target in ("diff", "repository"):
        imported = _names_imported_from(_REVIEW_ROOT / target / "runner.py", "cyberjury.review.engine")
        assert "run_review_units" in imported
        assert "run_role_round" not in imported


def test_target_reviewers_delegate_role_contracts_to_the_shared_engine():
    """Both reviewer adapters must use one parsing and role execution contract."""
    for target in ("diff", "repository"):
        imported = _names_imported_from(_REVIEW_ROOT / target / "reviewer.py", "cyberjury.review.engine")
        assert {"RoleChallenge", "RoleJudgment", "parse_role_response", "run_role_round"} <= imported


def test_target_unions_and_verifiers_delegate_their_common_mechanics():
    """Target identity policies cannot duplicate accumulation or verification mechanics."""
    for target in ("diff", "repository"):
        union_imports = _names_imported_from(_REVIEW_ROOT / target / "union.py", "cyberjury.review.engine")
        verify_imports = _names_imported_from(
            _REVIEW_ROOT / target / "verify.py",
            "cyberjury.review.verification",
        )
        assert "FindingAccumulator" in union_imports
        assert "verify_findings" in verify_imports


def test_shared_review_modules_do_not_depend_on_target_implementations():
    """A shared primitive cannot acquire a Diff Review or Repository Review dependency."""
    violations = {
        path.name: sorted(module for module in _imports(path) if module.startswith(_TARGET_MODULES))
        for path in _REVIEW_ROOT.glob("*.py")
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
