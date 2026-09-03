from __future__ import annotations

import math
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"
FEATURE_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"

NonNegativeFloat = Annotated[float, Field(ge=0)]
NonNegativeInt = Annotated[int, Field(ge=0)]
Port = Annotated[int, Field(ge=0, le=65535)]


class CaptureMode(StrEnum):
    DEMO = "demo"
    PCAP = "pcap"
    LIVE = "live"


class Verdict(StrEnum):
    BENIGN = "benign"
    KNOWN_ATTACK = "known_attack"
    SUSPICIOUS_UNKNOWN = "suspicious_unknown"
    NEEDS_REVIEW = "needs_review"
    PROCESSING_ERROR = "processing_error"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FeedbackDisposition(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_NEW_BEHAVIOUR = "benign_new_behaviour"
    DUPLICATE = "duplicate"
    REQUIRES_INVESTIGATION = "requires_investigation"


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_assignment=True)


class FlowEvent(ContractModel):
    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    event_id: UUID = Field(default_factory=uuid4)
    sensor_id: str = Field(min_length=1, max_length=128)
    capture_mode: CaptureMode = CaptureMode.DEMO
    timestamp_start: datetime
    timestamp_end: datetime
    duration_ms: NonNegativeFloat

    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    src_port: Port
    dst_port: Port
    ip_version: Literal[4, 6]
    protocol: str = Field(min_length=1, max_length=32)
    application_protocol: str | None = Field(default=None, max_length=64)
    direction: Literal["outbound", "inbound", "lateral", "unknown"] = "unknown"

    packets_forward: NonNegativeInt
    packets_reverse: NonNegativeInt
    bytes_forward: NonNegativeInt
    bytes_reverse: NonNegativeInt
    packet_rate: NonNegativeFloat
    byte_rate: NonNegativeFloat

    packet_length_min: NonNegativeFloat
    packet_length_max: NonNegativeFloat
    packet_length_mean: NonNegativeFloat
    packet_length_std: NonNegativeFloat
    iat_min: NonNegativeFloat
    iat_max: NonNegativeFloat
    iat_mean: NonNegativeFloat
    iat_std: NonNegativeFloat

    tcp_syn_count: NonNegativeInt = 0
    tcp_ack_count: NonNegativeInt = 0
    tcp_fin_count: NonNegativeInt = 0
    tcp_rst_count: NonNegativeInt = 0
    tcp_psh_count: NonNegativeInt = 0

    first_packet_sizes: list[int] = Field(default_factory=list, max_length=20)
    first_packet_directions: list[Literal[-1, 1]] = Field(default_factory=list, max_length=20)
    first_packet_interarrival_times: list[float] = Field(default_factory=list, max_length=20)

    community_flow_id: str = Field(min_length=1, max_length=160)
    source_adapter: str = Field(min_length=1, max_length=64)
    feature_extractor_version: Literal["1.0.0"] = "1.0.0"
    protocol_metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @field_validator("timestamp_start", "timestamp_end")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_consistency(self) -> FlowEvent:
        if self.timestamp_end < self.timestamp_start:
            raise ValueError("timestamp_end cannot precede timestamp_start")
        if self.src_ip.version != self.ip_version or self.dst_ip.version != self.ip_version:
            raise ValueError("ip_version must match both endpoints")
        if self.packet_length_min > self.packet_length_max:
            raise ValueError("packet_length_min cannot exceed packet_length_max")
        if self.iat_min > self.iat_max:
            raise ValueError("iat_min cannot exceed iat_max")
        if any(v < 0 for v in self.first_packet_sizes):
            raise ValueError("packet sizes cannot be negative")
        if any(not math.isfinite(v) or v < 0 for v in self.first_packet_interarrival_times):
            raise ValueError("interarrival times must be finite and nonnegative")
        return self


class SignatureEvent(ContractModel):
    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    community_flow_id: str
    signature_id: str
    signature_name: str
    category: str
    severity: Severity
    source: Literal["suricata", "fixture"]
    raw_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)


class DetectionResult(ContractModel):
    schema_version: Literal["1.0.0"] = SCHEMA_VERSION
    event_id: UUID = Field(default_factory=uuid4)
    flow_event_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    known_attack_label: str | None
    known_attack_probability: Annotated[float, Field(ge=0, le=1)]
    class_probabilities: dict[str, float]
    classifier_confidence: Annotated[float, Field(ge=0, le=1)]

    anomaly_score: Annotated[float, Field(ge=0, le=1)]
    anomaly_percentile: Annotated[float, Field(ge=0, le=1)]
    open_set_score: Annotated[float, Field(ge=0, le=1)]
    reconstruction_error: NonNegativeFloat = 0.0
    reconstruction_score: Annotated[float, Field(ge=0, le=1)] = 0.0
    signature_score: Annotated[float, Field(ge=0, le=1)]
    contextual_score: Annotated[float, Field(ge=0, le=1)]
    final_risk_score: Annotated[float, Field(ge=0, le=100)]

    verdict: Verdict
    severity: Severity
    reason_codes: list[str]
    explanation: str

    classifier_model_version: str
    anomaly_model_version: str
    feature_schema_version: Literal["1.0.0"] = FEATURE_SCHEMA_VERSION
    threshold_version: str
    inference_latency_ms: NonNegativeFloat
    processing_latency_ms: NonNegativeFloat

    @field_validator("class_probabilities")
    @classmethod
    def validate_probabilities(cls, value: dict[str, float]) -> dict[str, float]:
        if any(v < 0 or v > 1 for v in value.values()):
            raise ValueError("class probabilities must be in [0, 1]")
        if value and abs(sum(value.values()) - 1.0) > 1e-5:
            raise ValueError("class probabilities must sum to 1")
        return value


class AnalystFeedback(ContractModel):
    feedback_id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    actor: str = Field(min_length=1, max_length=128)
    disposition: FeedbackDisposition
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    comment: str = Field(default="", max_length=2000)
    original_model_result: dict[str, Any]
    model_version: str
    eligible_for_retraining: bool = False

    @model_validator(mode="after")
    def gate_retraining(self) -> AnalystFeedback:
        allowed = self.disposition == FeedbackDisposition.BENIGN_NEW_BEHAVIOUR
        if self.eligible_for_retraining and not allowed:
            raise ValueError("only analyst-approved benign new behaviour is retraining-eligible")
        return self


class Incident(ContractModel):
    incident_id: UUID = Field(default_factory=uuid4)
    title: str
    status: Literal["open", "investigating", "contained", "closed"] = "open"
    severity: Severity
    alert_ids: list[UUID]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    grouping_reasons: list[str]
