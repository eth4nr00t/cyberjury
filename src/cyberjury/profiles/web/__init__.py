"""The default review backend with optional Tree-sitter facts and HTTP proofs."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury.profiles.base import PoCBackend, ReviewProfile
from cyberjury.profiles.web.facts import TreeSitterFacts

if TYPE_CHECKING:
    from cyberjury.providers.base import Provider


def _web_poc(*, provider: Provider, model: str) -> PoCBackend:
    """Build the web PoC writer lazily so profile imports do not pull a provider."""
    from cyberjury.profiles.web.poc import WebPoC

    return WebPoC(provider=provider, model=model)


WEB_PROFILE = ReviewProfile(
    name="web",
    content_root=Path(__file__).resolve().parent,
    poc_backend=_web_poc,
    facts_backend=TreeSitterFacts(),
)


__all__ = ["WEB_PROFILE", "TreeSitterFacts"]
