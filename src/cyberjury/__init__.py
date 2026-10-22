"""AI-assisted security review for code diffs and repositories."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cyberjury")
except PackageNotFoundError:
    __version__ = "0.0.0"
