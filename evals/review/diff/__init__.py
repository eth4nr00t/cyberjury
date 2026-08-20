"""Diff Review benchmark execution and scoring adapters."""

from .execution import DiffRunOptions, run, run_diff_cases
from .results import score

__all__ = ["DiffRunOptions", "run", "run_diff_cases", "score"]
