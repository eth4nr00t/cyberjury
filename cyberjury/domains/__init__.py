"""Review domains: each bundles a body of security knowledge under its own content root.

`web` is the default. The engine selects a domain, the knowledge swaps, the
orchestration is unchanged.
"""

from cyberjury.domains.base import ContentPaths, Domain, content_paths

__all__ = ["ContentPaths", "Domain", "content_paths"]
