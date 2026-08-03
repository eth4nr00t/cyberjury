"""FindingsFilter: hard-rule false-positive suppression after the model returns.

The model is told what not to report, but a second deterministic pass drops the
common noise it still emits: findings below a confidence floor, and findings in
test code. Test detection is conservative, a real test directory segment or a
test-file naming convention, not a bare ``sample_``/``mock_`` prefix, so a
production file like ``sample_rate.py`` is not silently suppressed. Operators can
add their own excluded path segments. Returns the kept set and the dropped set, so the dropped set
stays auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cyberjury.detection import Detection, load_detection


@dataclass(frozen=True, kw_only=True)
class FindingsFilter:
    min_confidence: float = 0.5
    drop_test_paths: bool = True
    exclude_paths: tuple[str, ...] = field(default_factory=tuple)
    detection: Detection | None = None

    def filter(self, findings: list) -> tuple[list, list[tuple[object, str]]]:
        kept: list = []
        dropped: list[tuple[object, str]] = []
        for f in findings:
            reason = self._drop_reason(f)
            if reason:
                dropped.append((f, reason))
            else:
                kept.append(f)
        return kept, dropped

    def _drop_reason(self, f) -> str:
        if f.confidence < self.min_confidence:
            return f"confidence {f.confidence:.2f} below floor {self.min_confidence:.2f}"
        path = f.file or ""
        if self.drop_test_paths and (self.detection or load_detection()).is_test_path(path):
            return "test path (test/mock/fixture directory or test-file naming)"
        match = next((e for e in self.exclude_paths if e and e in path), None)
        if match:
            return f"excluded path ({match})"
        return ""
