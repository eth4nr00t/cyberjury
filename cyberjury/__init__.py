"""AI-assisted security review for code diffs and whole repositories.

Two paths matched to their nature: a coded diff audit engine, a standard single
call or an adversarial Finder/Challenger/Judge pass, and a fan-out whole-repository
review where code owns the deterministic orchestration and agents or model calls
provide per-unit judgment. Security knowledge lives in rich
markdown vulnerability classes under knowledge/vulnerabilities, injected into the
audit prompt, not in a rendered schema.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cyberjury")
except PackageNotFoundError:
    __version__ = "0.0.0"
