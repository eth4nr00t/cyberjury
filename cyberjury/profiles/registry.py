"""Profile selection: resolve a name to a `ReviewProfile`, or detect one from a file list.

The registry is the one place that knows which profiles exist. `get_profile` fails loud on
an unknown or unavailable name rather than silently falling back, so a target the tool
cannot review is an error, not an empty clean result. `detect_profile` reads each registered
profile's extension signals and rejects a target that matches more than one profile.
"""

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
from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.profiles.web import WEB_PROFILE
from cyberjury.sources.snapshot import SourceSnapshot

_PROFILES: dict[str, ReviewProfile] = {WEB_PROFILE.name: WEB_PROFILE, EVM_PROFILE.name: EVM_PROFILE}

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
    """Resolve one profile from profile-owned extension signals or fail on ambiguity."""
    from cyberjury.detection import load_detection

    paths = tuple(sorted({Path(file) for file in files}, key=lambda path: path.as_posix()))
    matched: dict[str, tuple[str, ...]] = {}
    detections = {profile.name: load_detection(profile.paths.detection_file) for profile in _PROFILES.values()}
    for profile in _PROFILES.values():
        detection = detections[profile.name]
        representatives = tuple(
            path.as_posix()
            for path in paths
            if path.suffix.lower() in detection.auto_select_extensions and not detection.is_skipped_dir(path.parts[:-1])
        )
        if representatives:
            matched[profile.name] = representatives
    if not matched:
        raise ValueError(
            "target does not match any available review profile. "
            "Select --profile explicitly only when the target is supported by that profile."
        )
    if len(matched) > 1:
        manifest_owners: dict[str, set[str]] = {}
        for profile_name, detection in detections.items():
            for manifest in detection.manifests:
                manifest_owners.setdefault(manifest.casefold(), set()).add(profile_name)
        distinguished = {
            profile_name
            for profile_name in matched
            if any(
                owners == {profile_name}
                and any(
                    path.name.casefold() == manifest and not detections[profile_name].is_skipped_dir(path.parts[:-1])
                    for path in paths
                )
                for manifest, owners in manifest_owners.items()
            )
        }
        if len(distinguished) == 1:
            return next(iter(distinguished))
        evidence = ", ".join(f"{name}: {paths[0]}" for name, paths in matched.items())
        raise ValueError(
            f"target matches multiple review profiles: {evidence}. "
            "Select --profile explicitly or review narrower scopes."
        )
    return next(iter(matched))


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


def resolve_profile(name: str, files: Iterable[str | Path] = ()) -> ReviewProfile:
    """Resolve a `--profile` choice.

    `auto` detects from the files, anything else is a direct lookup. The single entry the
    CLI uses so detection and lookup cannot drift.
    """
    return resolve_profile_binding(name, files).profile
