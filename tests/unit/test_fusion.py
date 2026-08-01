import pytest

from packages.contracts import Severity, Verdict
from packages.detection.fusion import FusionConfig, FusionInput, fuse_risk


def test_fusion_configuration_loads_every_weight_and_threshold() -> None:
    config = FusionConfig.from_mapping(
        {
            "version": "test",
            "known_weight": 0.4,
            "anomaly_weight": 0.3,
            "signature_weight": 0.2,
            "context_weight": 0.1,
            "known_threshold": 0.8,
            "anomaly_threshold": 0.75,
            "benign_max_risk": 25,
            "review_max_risk": 50,
            "high_risk": 70,
            "critical_risk": 90,
        }
    )
    assert config.to_dict()["known_weight"] == 0.4
    assert config.known_threshold == 0.8
    with pytest.raises(ValueError, match="sum to one"):
        FusionConfig(known_weight=0.5)


def test_known_attack_requires_strong_known_or_signature_evidence() -> None:
    outcome = fuse_risk(
        FusionInput(
            known_attack_probability=0.91,
            classifier_confidence=0.93,
            anomaly_score=0.30,
        )
    )
    assert outcome.verdict == Verdict.KNOWN_ATTACK
    assert "HIGH_KNOWN_ATTACK_PROBABILITY" in outcome.reasons


def test_anomaly_without_known_match_is_suspicious_unknown() -> None:
    outcome = fuse_risk(
        FusionInput(
            known_attack_probability=0.12,
            classifier_confidence=0.51,
            anomaly_score=0.94,
        )
    )
    assert outcome.verdict == Verdict.SUSPICIOUS_UNKNOWN
    assert "ISOLATION_OUTLIER" in outcome.reasons
    assert "zero-day" in outcome.explanation


def test_weak_signal_cannot_create_critical_alert() -> None:
    outcome = fuse_risk(
        FusionInput(
            known_attack_probability=0.30,
            classifier_confidence=0.55,
            anomaly_score=0.25,
            contextual_score=0.25,
        )
    )
    assert outcome.severity != Severity.CRITICAL
    assert outcome.risk < 50


def test_reconstruction_anomaly_can_trigger_unknown_without_isolation_outlier() -> None:
    outcome = fuse_risk(
        FusionInput(
            known_attack_probability=0.10,
            classifier_confidence=0.48,
            anomaly_score=0.25,
            reconstruction_score=0.91,
        )
    )
    assert outcome.verdict == Verdict.SUSPICIOUS_UNKNOWN
    assert "HIGH_RECONSTRUCTION_ERROR" in outcome.reasons
    assert "ISOLATION_OUTLIER" not in outcome.reasons


def test_invalid_signal_is_rejected() -> None:
    with pytest.raises(ValueError):
        fuse_risk(
            FusionInput(
                known_attack_probability=1.1,
                classifier_confidence=0.5,
                anomaly_score=0.2,
            )
        )
