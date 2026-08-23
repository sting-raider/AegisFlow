from __future__ import annotations

import math
from collections import OrderedDict, deque
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from statistics import fmean
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from packages.contracts import DetectionResult, FlowEvent, Verdict


@dataclass(frozen=True)
class DriftEvent:
    signal: str
    detection_time: datetime
    reference_window: int
    recent_window: int
    magnitude: float
    reference_mean: float
    recent_mean: float
    model_version: str
    event_id: UUID = field(default_factory=uuid4)
    trigger_detection_id: UUID | None = None
    recommended_action: str = (
        "Review data quality and evaluate a candidate model; do not auto-retrain."
    )
    automatic_action_allowed: bool = False
    eligible_for_retraining: bool = False


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
        if not 0 < threshold <= 1:
            raise ValueError("threshold must be in (0, 1]")
        self.signal = signal
        self.model_version = model_version
        self.window_size = window_size
        self.threshold = threshold
        self.values: deque[float] = deque(maxlen=window_size * 2)
        self._in_drift = False

    def update(self, value: float, *, detection_time: datetime | None = None) -> DriftEvent | None:
        if not math.isfinite(value):
            raise ValueError("drift signal must be finite")
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
                detection_time=detection_time or datetime.now(UTC),
                reference_window=self.window_size,
                recent_window=self.window_size,
                magnitude=magnitude,
                reference_mean=before,
                recent_mean=after,
                model_version=self.model_version,
            )
        if magnitude < self.threshold * 0.6:
            self._in_drift = False
        return None


class RuntimeDriftMonitor:
    """Observe bounded runtime distributions without mutating a training baseline."""

    def __init__(
        self,
        model_version: str,
        *,
        window_size: int = 64,
        seen_capacity: int = 100_000,
    ) -> None:
        if seen_capacity < window_size * 2:
            raise ValueError("seen_capacity must cover both drift windows")
        thresholds = {
            "anomaly_score": 0.20,
            "known_class_confidence": 0.20,
            "flow_rate": 0.15,
            "feature_duration": 0.15,
            "feature_bytes_total": 0.15,
            "feature_packet_length_mean": 0.15,
            "alert_rate": 0.25,
        }
        self.detectors = {
            signal: WindowDriftDetector(
                signal, model_version, window_size=window_size, threshold=threshold
            )
            for signal, threshold in thresholds.items()
        }
        self.seen_capacity = seen_capacity
        self._seen: OrderedDict[UUID, None] = OrderedDict()
        self._flow_times: deque[datetime] = deque(maxlen=256)
        self._alert_window: deque[float] = deque(maxlen=window_size)

    def _flow_rate(self, timestamp: datetime) -> float:
        if timestamp.tzinfo is None:
            raise ValueError("drift timestamps must include a timezone")
        if self._flow_times and timestamp < self._flow_times[-1]:
            self._flow_times.clear()
        self._flow_times.append(timestamp)
        cutoff = timestamp - timedelta(seconds=60)
        while self._flow_times and self._flow_times[0] < cutoff:
            self._flow_times.popleft()
        if len(self._flow_times) < 2:
            rate = float(len(self._flow_times))
        else:
            span = max((self._flow_times[-1] - self._flow_times[0]).total_seconds(), 0.001)
            rate = (len(self._flow_times) - 1) / span
        return math.log1p(min(rate, 10_000.0)) / math.log1p(10_000.0)

    def observe(self, flow: FlowEvent, detection: DetectionResult) -> tuple[DriftEvent, ...]:
        if detection.event_id in self._seen:
            self._seen.move_to_end(detection.event_id)
            return ()
        self._seen[detection.event_id] = None
        if len(self._seen) > self.seen_capacity:
            self._seen.popitem(last=False)
        self._alert_window.append(float(detection.verdict != Verdict.BENIGN))
        signals = {
            "anomaly_score": detection.anomaly_score,
            "known_class_confidence": detection.classifier_confidence,
            "flow_rate": self._flow_rate(detection.timestamp),
            "feature_duration": math.log1p(flow.duration_ms) / math.log1p(86_400_000),
            "feature_bytes_total": math.log1p(flow.bytes_forward + flow.bytes_reverse)
            / math.log1p(2e15),
            "feature_packet_length_mean": flow.packet_length_mean / 65_535,
            "alert_rate": fmean(self._alert_window),
        }
        events: list[DriftEvent] = []
        for signal, value in signals.items():
            event = self.detectors[signal].update(value, detection_time=detection.timestamp)
            if event is None:
                continue
            deterministic_id = uuid5(
                NAMESPACE_URL,
                f"aegisflow-drift:{detection.event_id}:{signal}:{event.magnitude:.12f}",
            )
            events.append(
                replace(
                    event,
                    event_id=deterministic_id,
                    trigger_detection_id=detection.event_id,
                )
            )
        return tuple(events)
