from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from packages.contracts import Severity, Verdict


@dataclass(frozen=True)
class FusionConfig:
    version: str = "1.0.0"
    known_weight: float = 0.43
    anomaly_weight: float = 0.27
    signature_weight: float = 0.20
    context_weight: float = 0.10
    known_threshold: float = 0.72
    anomaly_threshold: float = 0.70
    benign_max_risk: float = 30.0
    review_max_risk: float = 54.0
    high_risk: float = 72.0
    critical_risk: float = 90.0

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("fusion version cannot be empty")
        unit_values = (
            self.known_weight,
            self.anomaly_weight,
            self.signature_weight,
            self.context_weight,
            self.known_threshold,
            self.anomaly_threshold,
        )
        if any(value < 0 or value > 1 for value in unit_values):
            raise ValueError("fusion weights and signal thresholds must be in [0, 1]")
        if abs(sum(unit_values[:4]) - 1.0) > 1e-9:
            raise ValueError("fusion weights must sum to one")
        if not (
            0
            <= self.benign_max_risk
            < self.review_max_risk
            < self.high_risk
            < self.critical_risk
            <= 100
        ):
            raise ValueError("fusion risk thresholds must be strictly ordered in [0, 100]")

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> FusionConfig:
        defaults = cls()
        return cls(
            version=str(value.get("version", defaults.version)),
            known_weight=float(value.get("known_weight", defaults.known_weight)),
            anomaly_weight=float(value.get("anomaly_weight", defaults.anomaly_weight)),
            signature_weight=float(value.get("signature_weight", defaults.signature_weight)),
            context_weight=float(value.get("context_weight", defaults.context_weight)),
            known_threshold=float(value.get("known_threshold", defaults.known_threshold)),
            anomaly_threshold=float(value.get("anomaly_threshold", defaults.anomaly_threshold)),
            benign_max_risk=float(value.get("benign_max_risk", defaults.benign_max_risk)),
            review_max_risk=float(value.get("review_max_risk", defaults.review_max_risk)),
            high_risk=float(value.get("high_risk", defaults.high_risk)),
            critical_risk=float(value.get("critical_risk", defaults.critical_risk)),
        )

    def to_dict(self) -> dict[str, str | float]:
        return {
            "version": self.version,
            "known_weight": self.known_weight,
            "anomaly_weight": self.anomaly_weight,
            "signature_weight": self.signature_weight,
            "context_weight": self.context_weight,
            "known_threshold": self.known_threshold,
            "anomaly_threshold": self.anomaly_threshold,
            "benign_max_risk": self.benign_max_risk,
            "review_max_risk": self.review_max_risk,
            "high_risk": self.high_risk,
            "critical_risk": self.critical_risk,
        }


@dataclass(frozen=True)
class FusionInput:
    known_attack_probability: float
    classifier_confidence: float
    anomaly_score: float
    signature_score: float = 0.0
    contextual_score: float = 0.0
    model_disagreement: float = 0.0
    reconstruction_score: float = 0.0


@dataclass(frozen=True)
class FusionOutcome:
    risk: float
    verdict: Verdict
    severity: Severity
    reasons: tuple[str, ...]
    explanation: str


def _severity(risk: float, config: FusionConfig) -> Severity:
    if risk >= config.critical_risk:
        return Severity.CRITICAL
    if risk >= config.high_risk:
        return Severity.HIGH
    if risk >= config.review_max_risk:
        return Severity.MEDIUM
    if risk >= config.benign_max_risk:
        return Severity.LOW
    return Severity.INFORMATIONAL


def fuse_risk(signals: FusionInput, config: FusionConfig | None = None) -> FusionOutcome:
    config = config or FusionConfig()
    values = (
        signals.known_attack_probability,
        signals.classifier_confidence,
        signals.anomaly_score,
        signals.signature_score,
        signals.contextual_score,
        signals.model_disagreement,
        signals.reconstruction_score,
    )
    if any(v < 0 or v > 1 for v in values):
        raise ValueError("fusion signals must be in [0, 1]")

    open_set_signal = max(signals.anomaly_score, signals.reconstruction_score)
    risk = 100 * (
        config.known_weight * signals.known_attack_probability
        + config.anomaly_weight * open_set_signal
        + config.signature_weight * signals.signature_score
        + config.context_weight * signals.contextual_score
    )
    risk += 8 * signals.model_disagreement
    risk = round(min(risk, 100.0), 2)
    reasons: list[str] = []
    if signals.signature_score >= 0.5:
        reasons.append("SURICATA_SIGNATURE_MATCH")
    if signals.known_attack_probability >= config.known_threshold:
        reasons.append("HIGH_KNOWN_ATTACK_PROBABILITY")
    if signals.anomaly_score >= config.anomaly_threshold:
        reasons.append("ISOLATION_OUTLIER")
    if signals.reconstruction_score >= config.anomaly_threshold:
        reasons.append("HIGH_RECONSTRUCTION_ERROR")
    if signals.classifier_confidence < 0.58:
        reasons.append("LOW_CLASSIFIER_CONFIDENCE")
    if signals.contextual_score >= 0.65:
        reasons.append("UNUSUAL_DESTINATION_FANOUT")
    if signals.model_disagreement >= 0.5:
        reasons.append("MODEL_DISAGREEMENT")

    if signals.signature_score >= 0.5 or (
        signals.known_attack_probability >= config.known_threshold
        and signals.classifier_confidence >= 0.58
    ):
        verdict = Verdict.KNOWN_ATTACK
    elif (
        open_set_signal >= config.anomaly_threshold
        and signals.known_attack_probability < config.known_threshold
    ):
        verdict = Verdict.SUSPICIOUS_UNKNOWN
    elif risk <= config.benign_max_risk and open_set_signal < config.anomaly_threshold:
        verdict = Verdict.BENIGN
    else:
        verdict = Verdict.NEEDS_REVIEW

    severity = _severity(risk, config)
    if verdict == Verdict.BENIGN:
        explanation = "The flow matches the learned benign baseline and has no signature evidence."
    elif verdict == Verdict.KNOWN_ATTACK:
        explanation = "Known-threat evidence dominated the fused score: " + ", ".join(reasons)
    elif verdict == Verdict.SUSPICIOUS_UNKNOWN:
        explanation = (
            "The flow is statistically unusual without a confident known-attack match; "
            "investigate it as suspicious, not as a confirmed zero-day."
        )
    else:
        explanation = (
            "Detection signals conflict or sit near a decision threshold; analyst review is needed."
        )
    return FusionOutcome(risk, verdict, severity, tuple(reasons), explanation)
