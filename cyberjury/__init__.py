"""AI-assisted security review for code diffs and repositories.

Diff Review is a coded audit engine. Standard mode makes one pass through every unit and
knowledge pack, while adversarial mode adds Finder, Challenger, and Judge judgments.
Repository Review fans out across focused units. Code owns deterministic orchestration,
and agents or model calls provide per-unit judgment. Security knowledge lives in rich
markdown vulnerability classes under knowledge/vulnerabilities, injected into the audit
prompt, not in a rendered schema.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cyberjury")
except PackageNotFoundError:
    __version__ = "0.0.0"
