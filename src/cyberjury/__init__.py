"""AI-assisted security review for code diffs and repositories.

Code owns source acquisition, bounded review units, evidence navigation and receipts,
scheduling, response validation, and reporting. Model calls own the security reasoning
for each unit. Diff Review makes one Finder judgment per diff unit. Repository Review fans
the same judgment out across bounded source units, and verification drops a finding only
when independent seats agree.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cyberjury")
except PackageNotFoundError:
    __version__ = "0.0.0"
