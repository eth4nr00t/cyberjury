"""Review profiles: each bundles a body of security knowledge under its own content root.

`web` is the default. The engine selects a profile, the knowledge swaps, the
orchestration is unchanged.
"""

from cyberjury.profiles.base import ContentPaths, ReviewProfile, content_paths

__all__ = ["ContentPaths", "ReviewProfile", "content_paths"]
