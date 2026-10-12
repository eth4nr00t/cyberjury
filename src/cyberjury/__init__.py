"""AI-assisted security review for code diffs and repositories.

Diff Review is a coded audit engine. Standard mode makes one Finder pass through every unit,
while adversarial mode adds Challenger and Judge judgments.
Repository Review fans out across focused units. Code owns deterministic orchestration,
and agents or model calls provide per-unit judgment. Security knowledge lives in profile
content. A compact kernel and behavior index drive discovery, then exact candidate rules
drive later judgment.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cyberjury")
except PackageNotFoundError:
    __version__ = "0.0.0"
