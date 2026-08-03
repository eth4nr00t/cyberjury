"""Source acquisition: fetch and reconstruct third-party source trees for review.

Network code lives here and in the CLI, never in the review engine, so a review
never reaches out on its own.
"""

from cyberjury.sources.metadata import SourceError, SourceMeta, source_meta_from_dict
from cyberjury.sources.reconstruct import parse_getsourcecode, parse_source_code

__all__ = [
    "SourceError",
    "SourceMeta",
    "parse_getsourcecode",
    "parse_source_code",
    "source_meta_from_dict",
]
