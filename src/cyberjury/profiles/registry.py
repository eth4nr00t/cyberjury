"""Resolve the review profile by name or select the default for a reviewable target."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from cyberjury.profiles.base import (
    ProfileBinding,
    ReviewProfile,
    bind_profile_content,
    profile_binding,
    profile_content_snapshot,
)
from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.sources.snapshot import SourceSnapshot

_PROFILES: dict[str, ReviewProfile] = {WEB_PROFILE.name: WEB_PROFILE}

DEFAULT_PROFILE = WEB_PROFILE


@dataclass(frozen=True, kw_only=True)
class ProfileResolution:
    """Runtime profile plus the exact behavior receipt persisted by the session."""

    profile: ReviewProfile
    binding: ProfileBinding
    content_snapshot: SourceSnapshot


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
    """Select the default profile when the target has at least one reviewable source file."""
    from cyberjury.detection import load_detection

    detection = load_detection(DEFAULT_PROFILE.paths.detection_file)
    if any(not detection.is_noise_path(Path(file).as_posix()) for file in files):
        return DEFAULT_PROFILE.name
    raise ValueError("target has no reviewable source files")


def resolve_profile_binding(name: str, files: Iterable[str | Path] = ()) -> ProfileResolution:
    """Resolve and validate one profile together with its persistent behavior receipt."""
    chosen = detect_profile(files) if name == "auto" else name
    profile = bind_profile_content(get_profile(chosen))
    content_snapshot = profile_content_snapshot(profile)
    return ProfileResolution(
        profile=profile,
        binding=profile_binding(profile, content_snapshot=content_snapshot),
        content_snapshot=content_snapshot,
    )
