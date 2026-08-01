from __future__ import annotations

from dataclasses import dataclass

SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_GENERIC_STAGES = {"known_threat_activity", "unclassified_anomaly", "needs_review"}


@dataclass(frozen=True)
class AlertGroupingContext:
    source_host: str
    destination_host: str
    signature_ids: frozenset[str]
    reason_codes: frozenset[str]
    attack_stage: str
    severity: str
    risk: float


@dataclass(frozen=True)
class IncidentGroupingContext:
    source_hosts: frozenset[str]
    destination_hosts: frozenset[str]
    signature_ids: frozenset[str]
    reason_codes: frozenset[str]
    attack_stages: frozenset[str]
    severities: tuple[str, ...]
    risks: tuple[float, ...]


def attack_stage(
    reason_codes: set[str] | frozenset[str] = frozenset(),
    *,
    signature_name: str = "",
    signature_category: str = "",
    verdict: str = "needs_review",
) -> str:
    evidence = " ".join([*sorted(reason_codes), signature_name, signature_category]).upper()
    stage_terms = (
        ("exfiltration", ("EXFIL", "EGRESS", "DATA TRANSFER", "LARGE_OUTBOUND")),
        ("credential_access", ("BRUTE", "AUTH", "LOGIN", "CREDENTIAL")),
        ("reconnaissance", ("SCAN", "PROBE", "RECON", "DISCOVERY", "PORT_SWEEP")),
        ("command_and_control", ("COMMAND AND CONTROL", "C2", "BEACON")),
        ("execution", ("EXECUTION", "EXPLOIT", "SHELL", "MALWARE")),
        ("impact", ("DENIAL", "DOS", "IMPACT", "DESTRUCT")),
    )
    for stage, terms in stage_terms:
        if any(term in evidence for term in terms):
            return stage
    if verdict == "known_attack":
        return "known_threat_activity"
    if verdict == "suspicious_unknown":
        return "unclassified_anomaly"
    return "needs_review"


def grouping_reasons(
    existing: IncidentGroupingContext, new: AlertGroupingContext
) -> tuple[str, ...]:
    reasons = ["time proximity"]
    if new.source_host in existing.source_hosts:
        reasons.append("same source host")
    if new.destination_host in existing.destination_hosts:
        reasons.append("shared destination")
    if new.signature_ids and new.signature_ids & existing.signature_ids:
        reasons.append("common signature")
    if new.reason_codes and new.reason_codes & existing.reason_codes:
        reasons.append("common reason")
    if new.attack_stage not in _GENERIC_STAGES and new.attack_stage in existing.attack_stages:
        reasons.append(f"similar attack stage ({new.attack_stage})")
    if _is_repeated_escalation(existing, new):
        reasons.append("repeated escalation")
    return tuple(reasons)


def should_group(reasons: tuple[str, ...]) -> bool:
    """Time proximity is mandatory but never sufficient by itself."""

    return any(reason != "time proximity" for reason in reasons)


def _is_repeated_escalation(
    existing: IncidentGroupingContext, new: AlertGroupingContext
) -> bool:
    if len(existing.risks) < 2 or len(existing.severities) < 2:
        return False
    risk_rising = existing.risks[-2] < existing.risks[-1] < new.risk
    ranks = tuple(SEVERITY_ORDER.get(value, -1) for value in existing.severities[-2:])
    new_rank = SEVERITY_ORDER.get(new.severity, -1)
    severity_rising = ranks[0] < ranks[1] < new_rank
    return risk_rising or severity_rising
