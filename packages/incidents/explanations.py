from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

ALLOWED_FIELDS = {
    "verdict",
    "severity",
    "reason_codes",
    "known_attack_probability",
    "anomaly_score",
    "signature_score",
    "contextual_score",
    "final_risk_score",
    "timeline",
    "signature_names",
}


def sanitize_explanation_input(payload: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key in ALLOWED_FIELDS:
        value = payload.get(key)
        if isinstance(value, str):
            sanitized[key] = value[:500]
        elif isinstance(value, int | float | bool) or value is None:
            sanitized[key] = value
        elif isinstance(value, list):
            sanitized[key] = [
                item[:200] if isinstance(item, str) else item
                for item in value[:50]
                if isinstance(item, str | int | float | bool)
            ]
    return sanitized


class ExplanationProvider(ABC):
    @abstractmethod
    def explain(self, payload: dict[str, Any]) -> str:
        pass


class TemplateExplanationProvider(ExplanationProvider):
    def explain(self, payload: dict[str, Any]) -> str:
        data = sanitize_explanation_input(payload)
        verdict = str(data.get("verdict", "needs_review")).replace("_", " ")
        reasons = ", ".join(map(str, data.get("reason_codes", []))) or "no dominant signal"
        return (
            f"Verdict: {verdict}. Evidence: {reasons}. "
            "Validate endpoint ownership, compare adjacent flows, and review signature context. "
            "Anomaly evidence is statistical and is not proof of a previously unknown exploit."
        )
