"""Profile selection: resolve a name to a `ReviewProfile`, or detect one from a file list.

The registry is the one place that knows which profiles exist. `get_profile` fails loud on
an unknown or not-yet-available name rather than silently falling back, so a target the
tool cannot review is an error, not an empty clean result. `detect_profile` is a pure
extension heuristic returning a name, kept independent of registration so it can name a
profile that exists as a heuristic before its knowledge set ships.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from cyberjury.profiles.base import ReviewProfile
from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.profiles.web import WEB_PROFILE

_PROFILES: dict[str, ReviewProfile] = {WEB_PROFILE.name: WEB_PROFILE, EVM_PROFILE.name: EVM_PROFILE}

DEFAULT_PROFILE = WEB_PROFILE


def default_profile() -> ReviewProfile:
    """Return the registry default used when no profile is selected."""
    return DEFAULT_PROFILE


def available_profiles() -> tuple[str, ...]:
    """Return the registered profile names."""
    return tuple(_PROFILES)


def get_profile(name: str) -> ReviewProfile:
    """Resolve a registered profile name or fail loud on an unknown one."""
    try:
        return _PROFILES[name]
    except KeyError:
        raise ValueError(
            f"unknown or unavailable review profile {name!r}, available: {', '.join(available_profiles())}"
        ) from None


def detect_profile(files: Iterable[str | Path]) -> str:
    """Name the profile a file list most looks like, by extension.

    Solidity sources name the evm profile, everything else names web. A pure heuristic, it
    does not require the named profile to be registered, the caller resolves and fails loud
    if it is not.
    """
    paths = list(files)
    sol = sum(1 for f in paths if Path(f).suffix.lower() == ".sol")
    return "evm" if sol else "web"


def resolve_profile(name: str, files: Iterable[str | Path] = ()) -> ReviewProfile:
    """Resolve a `--profile` choice.

    `auto` detects from the files, anything else is a direct lookup. The single entry the
    CLI uses so detection and lookup cannot drift.
    """
    chosen = detect_profile(files) if name == "auto" else name
    return get_profile(chosen)
