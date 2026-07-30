from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from statistics import fmean


@dataclass(frozen=True)
class DriftEvent:
    signal: str
    detection_time: datetime
    reference_window: int
    recent_window: int
    magnitude: float
    model_version: str
    recommended_action: str = (
        "Review data quality and evaluate a candidate model; do not auto-retrain."
    )


class WindowDriftDetector:
    """Bounded, deterministic two-window mean-shift detector.

    This is an intentionally small ADWIN-equivalent baseline for environments where
    River is unavailable. It raises an event only after both windows are full and
    never mutates the training baseline or promotes a model.
    """

    def __init__(
        self,
        signal: str,
        model_version: str,
        *,
        window_size: int = 64,
        threshold: float = 0.20,
    ) -> None:
        if window_size < 8:
            raise ValueError("window_size must be at least 8")
        self.signal = signal
        self.model_version = model_version
        self.window_size = window_size
        self.threshold = threshold
        self.values: deque[float] = deque(maxlen=window_size * 2)
        self._in_drift = False

    def update(self, value: float) -> DriftEvent | None:
        self.values.append(float(value))
        if len(self.values) < self.window_size * 2:
            return None
        snapshot = list(self.values)
        before = fmean(snapshot[: self.window_size])
        after = fmean(snapshot[self.window_size :])
        magnitude = abs(after - before)
        if magnitude >= self.threshold and not self._in_drift:
            self._in_drift = True
            return DriftEvent(
                signal=self.signal,
                detection_time=datetime.now(UTC),
                reference_window=self.window_size,
                recent_window=self.window_size,
                magnitude=magnitude,
                model_version=self.model_version,
            )
        if magnitude < self.threshold * 0.6:
            self._in_drift = False
        return None
