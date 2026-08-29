"""Profile selection: resolve a name to a `ReviewProfile`, or detect one from a file list.

The registry is the one place that knows which profiles exist. `get_profile` fails loud on
an unknown or unavailable name rather than silently falling back, so a target the tool
cannot review is an error, not an empty clean result. `detect_profile` reads each registered
profile's extension signals and rejects a target that matches more than one profile.
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
    """Resolve one profile from profile-owned extension signals or fail on ambiguity."""
    from cyberjury.detection import load_detection

    paths = tuple(Path(file) for file in files)
    matched: dict[str, tuple[str, ...]] = {}
    for profile in _PROFILES.values():
        extensions = load_detection(profile.paths.detection_file).auto_select_extensions
        representatives = tuple(str(path) for path in paths if path.suffix.lower() in extensions)
        if representatives:
            matched[profile.name] = representatives
    if len(matched) > 1:
        evidence = ", ".join(f"{name}: {paths[0]}" for name, paths in matched.items())
        raise ValueError(
            f"target matches multiple review profiles: {evidence}. "
            "Select --profile explicitly or review narrower scopes."
        )
    return next(iter(matched), DEFAULT_PROFILE.name)


def resolve_profile(name: str, files: Iterable[str | Path] = ()) -> ReviewProfile:
    """Resolve a `--profile` choice.

    `auto` detects from the files, anything else is a direct lookup. The single entry the
    CLI uses so detection and lookup cannot drift.
    """
    chosen = detect_profile(files) if name == "auto" else name
    return get_profile(chosen)
