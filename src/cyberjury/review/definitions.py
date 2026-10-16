"""Order repository definitions and describe the seed definitions of one review unit."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from cyberjury.canonical import normalized_repository_path
from cyberjury.review.relationships import DefinitionEvidence


def definitions_by_name(definitions: Iterable[DefinitionEvidence]) -> tuple[DefinitionEvidence, ...]:
    """Group definitions by name in first-seen source order, keeping each name's definitions in source order."""
    ordered = sorted(
        definitions,
        key=lambda definition: (
            definition.source.path,
            definition.kind == "file",
            definition.source.start,
            definition.source.end,
        ),
    )
    by_name: dict[str, list[DefinitionEvidence]] = {}
    for definition in ordered:
        by_name.setdefault(definition.name, []).append(definition)
    return tuple(definition for group in by_name.values() for definition in group)


@dataclass(frozen=True, kw_only=True)
class DefinitionUnitPlan:
    """One review surface with its seed definitions and seed files."""

    seeds: tuple[DefinitionEvidence, ...] = ()
    seed_files: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject duplicate or noncanonical worklist inputs."""
        for file in self.seed_files:
            normalized_repository_path(file, "definition source path")
        for label, values in (
            ("seed", self.seeds),
            ("seed file", self.seed_files),
        ):
            if not isinstance(values, tuple) or len(values) != len(set(values)):
                raise ValueError(f"definition unit plan {label} values must be a unique tuple")
