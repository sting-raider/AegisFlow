from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    delete,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from packages.contracts import AnalystFeedback, DetectionResult, FlowEvent, SignatureEvent, Verdict
from packages.features.registry import flow_to_mapping
from packages.incidents import (
    AlertGroupingContext,
    DriftEvent,
    IncidentGroupingContext,
    attack_stage,
    grouping_reasons,
    should_group,
)


def _as_utc(value: datetime) -> datetime:
    """Restore the UTC marker that SQLite drops from timezone-aware columns."""

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def database_url_from_env(default: str = "sqlite:///aegisflow-demo.db") -> str:
    secret_path = os.getenv("AEGISFLOW_DATABASE_URL_FILE", "").strip()
    if not secret_path:
        return os.getenv("AEGISFLOW_DATABASE_URL", default)
    try:
        path = Path(secret_path)
        if path.stat().st_size > 4096:
            raise ValueError
        value = path.read_text(encoding="utf-8").strip()
        if not value or any(character in value for character in "\r\n\x00"):
            raise ValueError
        return value
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("database URL secret file is invalid") from exc


class Base(DeclarativeBase):
    pass


class SensorRow(Base):
    __tablename__ = "sensors"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    mode: Mapped[str] = mapped_column(String(32))


class FlowRow(Base):
    __tablename__ = "flows"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sensor_id: Mapped[str] = mapped_column(ForeignKey("sensors.id"), index=True)
    timestamp_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    timestamp_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), index=True)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(32), index=True)
    community_flow_id: Mapped[str] = mapped_column(String(160), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)

    __table_args__ = (Index("ix_flows_endpoints_time", "src_ip", "dst_ip", "timestamp_start"),)


class SignatureRow(Base):
    __tablename__ = "signature_events"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    community_flow_id: Mapped[str] = mapped_column(String(160), index=True)
    signature_id: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class DetectionRow(Base):
    __tablename__ = "detection_results"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    flow_event_id: Mapped[str] = mapped_column(ForeignKey("flows.event_id"), unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    risk: Mapped[float] = mapped_column(Float)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class AlertRow(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    detection_id: Mapped[str] = mapped_column(
        ForeignKey("detection_results.event_id"), unique=True, index=True
    )
    flow_event_id: Mapped[str] = mapped_column(ForeignKey("flows.event_id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    risk: Mapped[float] = mapped_column(Float)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)


class IncidentRow(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(32))
    source_host: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    alert_ids: Mapped[list[str]] = mapped_column(JSON)
    grouping_reasons: Mapped[list[str]] = mapped_column(JSON)
    grouping_context: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class IncidentAlertRow(Base):
    __tablename__ = "incident_alerts"
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )


class FeedbackRow(Base):
    __tablename__ = "analyst_feedback"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), index=True)
    actor: Mapped[str] = mapped_column(String(128))
    disposition: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    comment: Mapped[str] = mapped_column(Text)
    original_result: Mapped[dict[str, Any]] = mapped_column(JSON)
    model_version: Mapped[str] = mapped_column(String(64))
    eligible_for_retraining: Mapped[bool] = mapped_column(Boolean, default=False)


class DriftEventRow(Base):
    __tablename__ = "drift_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    signal: Mapped[str] = mapped_column(String(128), index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    magnitude: Mapped[float] = mapped_column(Float)
    model_version: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class ModelVersionRow(Base):
    __tablename__ = "model_versions"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    model_name: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(64), index=True)
    production: Mapped[bool] = mapped_column(Boolean)
    loaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON)


class ModelCandidateRow(Base):
    __tablename__ = "model_candidates"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    model_name: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[str] = mapped_column(String(64), index=True)
    bundle_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(128))
    required_modes: Mapped[list[str]] = mapped_column(JSON)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    blockers: Mapped[list[str]] = mapped_column(JSON)


class ModelReviewRow(Base):
    __tablename__ = "model_reviews"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("model_candidates.id"), index=True)
    actor: Mapped[str] = mapped_column(String(128))
    decision: Mapped[str] = mapped_column(String(32))
    comment: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    __table_args__ = (UniqueConstraint("candidate_id", "actor", name="uq_model_review_actor"),)


class SystemHealthRow(Base):
    __tablename__ = "system_health_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    service: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON)


class AuditLogRow(Base):
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    target_id: Mapped[str] = mapped_column(String(128))
    details: Mapped[dict[str, Any]] = mapped_column(JSON)


def _serialize_incident_context(context: IncidentGroupingContext) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "source_hosts": sorted(context.source_hosts),
        "destination_hosts": sorted(context.destination_hosts),
        "signature_ids": sorted(context.signature_ids),
        "reason_codes": sorted(context.reason_codes),
        "attack_stages": sorted(context.attack_stages),
        "recent_severities": list(context.severities[-2:]),
        "recent_risks": list(context.risks[-2:]),
    }


def _deserialize_incident_context(payload: object) -> IncidentGroupingContext | None:
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0.0":
        return None
    try:
        return IncidentGroupingContext(
            source_hosts=frozenset(str(item) for item in payload["source_hosts"]),
            destination_hosts=frozenset(
                str(item) for item in payload["destination_hosts"]
            ),
            signature_ids=frozenset(str(item) for item in payload["signature_ids"]),
            reason_codes=frozenset(str(item) for item in payload["reason_codes"]),
            attack_stages=frozenset(str(item) for item in payload["attack_stages"]),
            severities=tuple(str(item) for item in payload["recent_severities"]),
            risks=tuple(float(item) for item in payload["recent_risks"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


@dataclass(frozen=True)
class IngestOutcome:
    alert_id: str | None
    is_new_detection: bool


class Repository:
    def __init__(self, url: str | None = None) -> None:
        database_url = url if url is not None else database_url_from_env()
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, pool_pre_ping=True, connect_args=connect_args)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self.sessions() as session:
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise

    def ingest(
        self,
        flow: FlowEvent,
        detection: DetectionResult,
        signature: SignatureEvent | None = None,
    ) -> str | None:
        with self.session() as session:
            return self._ingest(session, flow, detection, signature, {}).alert_id

    def ingest_batch(
        self,
        items: Sequence[tuple[FlowEvent, DetectionResult, SignatureEvent | None]],
    ) -> list[IngestOutcome]:
        """Persist a bounded group in one transaction while retaining row outcomes."""
        if not items:
            return []
        incident_context_cache: dict[str, IncidentGroupingContext] = {}
        with self.session() as session:
            return [
                self._ingest(
                    session,
                    flow,
                    detection,
                    signature,
                    incident_context_cache,
                )
                for flow, detection, signature in items
            ]

    def _ingest(
        self,
        session: Session,
        flow: FlowEvent,
        detection: DetectionResult,
        signature: SignatureEvent | None,
        incident_context_cache: dict[str, IncidentGroupingContext],
    ) -> IngestOutcome:
        flow_id = str(flow.event_id)
        detection_id = str(detection.event_id)
        if session.get(DetectionRow, detection_id) is not None:
            existing = session.scalar(
                select(AlertRow).where(AlertRow.detection_id == detection_id)
            )
            return IngestOutcome(existing.id if existing else None, False)
        sensor = session.get(SensorRow, flow.sensor_id)
        if sensor is None:
            session.add(
                SensorRow(
                    id=flow.sensor_id,
                    last_seen=flow.timestamp_end,
                    mode=flow.capture_mode.value,
                )
            )
            session.flush()
        else:
            sensor.last_seen = flow.timestamp_end
        if session.get(FlowRow, flow_id) is None:
            session.add(
                FlowRow(
                    event_id=flow_id,
                    sensor_id=flow.sensor_id,
                    timestamp_start=flow.timestamp_start,
                    timestamp_end=flow.timestamp_end,
                    src_ip=str(flow.src_ip),
                    dst_ip=str(flow.dst_ip),
                    src_port=flow.src_port,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    community_flow_id=flow.community_flow_id,
                    payload=flow.model_dump(mode="json"),
                )
            )
            session.flush()
        if signature and session.get(SignatureRow, str(signature.event_id)) is None:
            session.add(
                SignatureRow(
                    event_id=str(signature.event_id),
                    timestamp=signature.timestamp,
                    community_flow_id=signature.community_flow_id,
                    signature_id=signature.signature_id,
                    payload=signature.model_dump(mode="json"),
                )
            )
        session.add(
            DetectionRow(
                event_id=detection_id,
                flow_event_id=flow_id,
                timestamp=detection.timestamp,
                verdict=detection.verdict.value,
                severity=detection.severity.value,
                risk=detection.final_risk_score,
                payload=detection.model_dump(mode="json"),
            )
        )
        session.flush()
        if detection.verdict == Verdict.BENIGN:
            return IngestOutcome(None, True)
        alert_id = str(uuid4())
        session.add(
            AlertRow(
                id=alert_id,
                detection_id=detection_id,
                flow_event_id=flow_id,
                created_at=detection.timestamp,
                verdict=detection.verdict.value,
                severity=detection.severity.value,
                risk=detection.final_risk_score,
            )
        )
        self._group_incident(
            session,
            alert_id,
            flow,
            detection,
            signature,
            incident_context_cache,
        )
        return IngestOutcome(alert_id, True)

    def _group_incident(
        self,
        session: Session,
        alert_id: str,
        flow: FlowEvent,
        detection: DetectionResult,
        signature: SignatureEvent | None,
        incident_context_cache: dict[str, IncidentGroupingContext],
    ) -> None:
        cutoff = detection.timestamp - timedelta(minutes=10)
        candidates = session.scalars(
            select(IncidentRow)
            .where(
                IncidentRow.status.in_(["open", "investigating"]),
                IncidentRow.updated_at >= cutoff,
            )
            .order_by(IncidentRow.updated_at.desc())
        ).all()
        new_signature_ids = frozenset({signature.signature_id}) if signature else frozenset()
        new_stage = attack_stage(
            frozenset(detection.reason_codes),
            signature_name=signature.signature_name if signature else "",
            signature_category=signature.category if signature else "",
            verdict=detection.verdict.value,
        )
        new_context = AlertGroupingContext(
            source_host=str(flow.src_ip),
            destination_host=str(flow.dst_ip),
            signature_ids=new_signature_ids,
            reason_codes=frozenset(detection.reason_codes),
            attack_stage=new_stage,
            severity=detection.severity.value,
            risk=detection.final_risk_score,
        )
        incident: IncidentRow | None = None
        selected_reasons: tuple[str, ...] = ()
        selected_sources: frozenset[str] = frozenset()
        for candidate in candidates:
            existing = incident_context_cache.get(candidate.id)
            if existing is None:
                existing = self._incident_grouping_context(session, candidate)
                incident_context_cache[candidate.id] = existing
            reasons = grouping_reasons(existing, new_context)
            if not should_group(reasons):
                continue
            if incident is None or len(reasons) > len(selected_reasons):
                incident = candidate
                selected_reasons = reasons
                selected_sources = existing.source_hosts
        if incident is None:
            incident_id = str(uuid4())
            context = IncidentGroupingContext(
                source_hosts=frozenset({str(flow.src_ip)}),
                destination_hosts=frozenset({str(flow.dst_ip)}),
                signature_ids=new_signature_ids,
                reason_codes=frozenset(detection.reason_codes),
                attack_stages=frozenset({new_stage}),
                severities=(detection.severity.value,),
                risks=(detection.final_risk_score,),
            )
            session.add(
                IncidentRow(
                    id=incident_id,
                    title=f"Activity from {flow.src_ip}",
                    status="open",
                    severity=detection.severity.value,
                    source_host=str(flow.src_ip),
                    created_at=detection.timestamp,
                    updated_at=detection.timestamp,
                    alert_ids=[],
                    grouping_reasons=["initial alert"],
                    grouping_context=_serialize_incident_context(context),
                )
            )
            session.flush()
            session.add(IncidentAlertRow(alert_id=alert_id, incident_id=incident_id))
            incident_context_cache[incident_id] = context
        else:
            session.add(IncidentAlertRow(alert_id=alert_id, incident_id=incident.id))
            incident.updated_at = detection.timestamp
            incident.grouping_reasons = list(
                dict.fromkeys([*incident.grouping_reasons, *selected_reasons])
            )
            if str(flow.src_ip) not in selected_sources:
                incident.title = "Correlated network activity"
            severities = ["informational", "low", "medium", "high", "critical"]
            if severities.index(detection.severity.value) > severities.index(incident.severity):
                incident.severity = detection.severity.value
            existing = incident_context_cache[incident.id]
            updated_context = IncidentGroupingContext(
                source_hosts=existing.source_hosts | {str(flow.src_ip)},
                destination_hosts=existing.destination_hosts | {str(flow.dst_ip)},
                signature_ids=existing.signature_ids | new_signature_ids,
                reason_codes=existing.reason_codes | frozenset(detection.reason_codes),
                attack_stages=existing.attack_stages | {new_stage},
                severities=(*existing.severities[-1:], detection.severity.value),
                risks=(*existing.risks[-1:], detection.final_risk_score),
            )
            incident.grouping_context = _serialize_incident_context(updated_context)
            incident_context_cache[incident.id] = updated_context

    @staticmethod
    def _incident_grouping_context(
        session: Session, incident: IncidentRow
    ) -> IncidentGroupingContext:
        stored = _deserialize_incident_context(incident.grouping_context)
        if stored is not None:
            return stored
        rows = session.execute(
            select(AlertRow, DetectionRow, FlowRow)
            .join(IncidentAlertRow, IncidentAlertRow.alert_id == AlertRow.id)
            .join(DetectionRow, DetectionRow.event_id == AlertRow.detection_id)
            .join(FlowRow, FlowRow.event_id == AlertRow.flow_event_id)
            .where(IncidentAlertRow.incident_id == incident.id)
            .order_by(AlertRow.created_at.asc())
        ).all()
        community_ids = {flow.community_flow_id for _, _, flow in rows}
        signature_rows = (
            session.scalars(
                select(SignatureRow).where(SignatureRow.community_flow_id.in_(community_ids))
            ).all()
            if community_ids
            else []
        )
        signatures_by_community: dict[str, list[SignatureRow]] = {}
        for signature in signature_rows:
            signatures_by_community.setdefault(signature.community_flow_id, []).append(signature)
        stages: set[str] = set()
        for _, detection, flow in rows:
            related = signatures_by_community.get(flow.community_flow_id, [])
            stages.add(
                attack_stage(
                    frozenset(
                        reason
                        for reason in detection.payload.get("reason_codes", [])
                        if isinstance(reason, str)
                    ),
                    signature_name=" ".join(
                        str(item.payload.get("signature_name", "")) for item in related
                    ),
                    signature_category=" ".join(
                        str(item.payload.get("category", "")) for item in related
                    ),
                    verdict=detection.verdict,
                )
            )
        context = IncidentGroupingContext(
            source_hosts=frozenset(flow.src_ip for _, _, flow in rows),
            destination_hosts=frozenset(flow.dst_ip for _, _, flow in rows),
            signature_ids=frozenset(item.signature_id for item in signature_rows),
            reason_codes=frozenset(
                reason
                for _, detection, _ in rows
                for reason in detection.payload.get("reason_codes", [])
                if isinstance(reason, str)
            ),
            attack_stages=frozenset(stages),
            severities=tuple(alert.severity for alert, _, _ in rows[-2:]),
            risks=tuple(alert.risk for alert, _, _ in rows[-2:]),
        )
        incident.grouping_context = _serialize_incident_context(context)
        return context

    def alerts(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        severity: str | None = None,
        verdict: str | None = None,
        host: str | None = None,
        protocol: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[dict[str, Any]]:
        with self.session() as session:
            statement = (
                select(AlertRow, DetectionRow, FlowRow)
                .join(DetectionRow, DetectionRow.event_id == AlertRow.detection_id)
                .join(FlowRow, FlowRow.event_id == AlertRow.flow_event_id)
                .order_by(AlertRow.created_at.desc())
                .offset(offset)
                .limit(min(limit, 200))
            )
            if severity:
                statement = statement.where(AlertRow.severity == severity)
            if verdict:
                statement = statement.where(AlertRow.verdict == verdict)
            if host:
                statement = statement.where((FlowRow.src_ip == host) | (FlowRow.dst_ip == host))
            if protocol:
                statement = statement.where(FlowRow.protocol == protocol)
            if start:
                statement = statement.where(AlertRow.created_at >= start)
            if end:
                statement = statement.where(AlertRow.created_at <= end)
            return [self._alert_dict(*row) for row in session.execute(statement).all()]

    def alert_count(
        self,
        *,
        severity: str | None = None,
        verdict: str | None = None,
        host: str | None = None,
        protocol: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> int:
        with self.session() as session:
            statement = (
                select(func.count(AlertRow.id))
                .select_from(AlertRow)
                .join(FlowRow, FlowRow.event_id == AlertRow.flow_event_id)
            )
            if severity:
                statement = statement.where(AlertRow.severity == severity)
            if verdict:
                statement = statement.where(AlertRow.verdict == verdict)
            if host:
                statement = statement.where((FlowRow.src_ip == host) | (FlowRow.dst_ip == host))
            if protocol:
                statement = statement.where(FlowRow.protocol == protocol)
            if start:
                statement = statement.where(AlertRow.created_at >= start)
            if end:
                statement = statement.where(AlertRow.created_at <= end)
            return int(session.scalar(statement) or 0)

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.session() as session:
            row = session.execute(
                select(AlertRow, DetectionRow, FlowRow)
                .join(DetectionRow, DetectionRow.event_id == AlertRow.detection_id)
                .join(FlowRow, FlowRow.event_id == AlertRow.flow_event_id)
                .where(AlertRow.id == alert_id)
            ).first()
            return self._alert_dict(*row) if row else None

    def acknowledge_alert(self, alert_id: str, actor: str) -> bool:
        with self.session() as session:
            row = session.get(AlertRow, alert_id)
            if row is None:
                return False
            if not row.acknowledged:
                row.acknowledged = True
                session.add(
                    AuditLogRow(
                        id=str(uuid4()),
                        actor=actor,
                        action="alert_acknowledged",
                        timestamp=datetime.now(UTC),
                        target_id=alert_id,
                        details={},
                    )
                )
            return True

    @staticmethod
    def _alert_dict(alert: AlertRow, detection: DetectionRow, flow: FlowRow) -> dict[str, Any]:
        return {
            "id": alert.id,
            "created_at": _as_utc(alert.created_at),
            "verdict": alert.verdict,
            "severity": alert.severity,
            "risk": alert.risk,
            "acknowledged": alert.acknowledged,
            "flow": {
                "event_id": flow.event_id,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "timestamp_start": _as_utc(flow.timestamp_start),
            },
            "detection": detection.payload,
        }

    def flows(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        host: str | None = None,
        protocol: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        event_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        with self.session() as session:
            statement = select(FlowRow).order_by(FlowRow.timestamp_start.desc())
            if host:
                statement = statement.where((FlowRow.src_ip == host) | (FlowRow.dst_ip == host))
            if protocol:
                statement = statement.where(FlowRow.protocol == protocol)
            if start:
                statement = statement.where(FlowRow.timestamp_start >= start)
            if end:
                statement = statement.where(FlowRow.timestamp_start <= end)
            if event_ids is not None:
                statement = statement.where(FlowRow.event_id.in_(event_ids))
            rows = session.scalars(statement.offset(offset).limit(min(limit, 200)))
            return [row.payload for row in rows]

    def flow_count(
        self,
        *,
        host: str | None = None,
        protocol: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> int:
        with self.session() as session:
            statement = select(func.count(FlowRow.event_id))
            if host:
                statement = statement.where((FlowRow.src_ip == host) | (FlowRow.dst_ip == host))
            if protocol:
                statement = statement.where(FlowRow.protocol == protocol)
            if start:
                statement = statement.where(FlowRow.timestamp_start >= start)
            if end:
                statement = statement.where(FlowRow.timestamp_start <= end)
            return int(session.scalar(statement) or 0)

    def flow(self, event_id: str) -> dict[str, Any] | None:
        with self.session() as session:
            row = session.get(FlowRow, event_id)
            if row is None:
                return None
            detection = session.scalar(
                select(DetectionRow).where(DetectionRow.flow_event_id == event_id)
            )
            alert = session.scalar(select(AlertRow).where(AlertRow.flow_event_id == event_id))
            signatures = session.scalars(
                select(SignatureRow).where(
                    SignatureRow.community_flow_id == row.community_flow_id
                )
            ).all()
            return {
                **row.payload,
                "detection": detection.payload if detection else None,
                "alert_id": alert.id if alert else None,
                "signatures": [signature.payload for signature in signatures],
            }

    def incidents(self) -> list[dict[str, Any]]:
        with self.session() as session:
            rows = session.scalars(select(IncidentRow).order_by(IncidentRow.updated_at.desc()))
            return [self._incident_dict(session, row, include_alerts=False) for row in rows]

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.session() as session:
            row = session.get(IncidentRow, incident_id)
            return self._incident_dict(session, row, include_alerts=True) if row else None

    def _incident_dict(
        self, session: Session, incident: IncidentRow, *, include_alerts: bool
    ) -> dict[str, Any]:
        rows = session.execute(
            select(AlertRow, DetectionRow, FlowRow)
            .join(IncidentAlertRow, IncidentAlertRow.alert_id == AlertRow.id)
            .join(DetectionRow, DetectionRow.event_id == AlertRow.detection_id)
            .join(FlowRow, FlowRow.event_id == AlertRow.flow_event_id)
            .where(IncidentAlertRow.incident_id == incident.id)
            .order_by(AlertRow.created_at.asc())
        ).all()
        community_ids = {flow.community_flow_id for _, _, flow in rows}
        signature_rows = (
            session.scalars(
                select(SignatureRow).where(SignatureRow.community_flow_id.in_(community_ids))
            ).all()
            if community_ids
            else []
        )
        signatures_by_community: dict[str, list[SignatureRow]] = {}
        for signature in signature_rows:
            signatures_by_community.setdefault(signature.community_flow_id, []).append(signature)
        timeline: list[dict[str, Any]] = []
        stages: set[str] = set()
        reason_codes: set[str] = set()
        for alert, detection, flow in rows:
            reasons = {
                reason
                for reason in detection.payload.get("reason_codes", [])
                if isinstance(reason, str)
            }
            reason_codes.update(reasons)
            related = signatures_by_community.get(flow.community_flow_id, [])
            stage = attack_stage(
                frozenset(reasons),
                signature_name=" ".join(
                    str(item.payload.get("signature_name", "")) for item in related
                ),
                signature_category=" ".join(
                    str(item.payload.get("category", "")) for item in related
                ),
                verdict=detection.verdict,
            )
            stages.add(stage)
            timeline.append(
                {
                    "alert_id": alert.id,
                    "timestamp": _as_utc(alert.created_at),
                    "verdict": alert.verdict,
                    "severity": alert.severity,
                    "risk": alert.risk,
                    "attack_stage": stage,
                    "source_host": flow.src_ip,
                    "destination_host": flow.dst_ip,
                    "acknowledged": alert.acknowledged,
                }
            )
        risks = [alert.risk for alert, _, _ in rows]
        severity_ranks = [
            ["informational", "low", "medium", "high", "critical"].index(alert.severity)
            for alert, _, _ in rows
        ]
        escalation_count = sum(
            1
            for index in range(2, len(rows))
            if risks[index - 2] < risks[index - 1] < risks[index]
            or severity_ranks[index - 2] < severity_ranks[index - 1] < severity_ranks[index]
        )
        result: dict[str, Any] = {
            "id": incident.id,
            "title": incident.title,
            "status": incident.status,
            "severity": incident.severity,
            "source_host": incident.source_host,
            "source_hosts": sorted({flow.src_ip for _, _, flow in rows}),
            "destination_hosts": sorted({flow.dst_ip for _, _, flow in rows}),
            "created_at": _as_utc(incident.created_at),
            "updated_at": _as_utc(incident.updated_at),
            "alert_ids": [alert.id for alert, _, _ in rows],
            "alert_count": len(rows),
            "acknowledged_alerts": sum(alert.acknowledged for alert, _, _ in rows),
            "max_risk": max(risks, default=0.0),
            "grouping_reasons": incident.grouping_reasons,
            "reason_codes": sorted(reason_codes),
            "signature_names": sorted(
                {
                    str(signature.payload["signature_name"])
                    for signature in signature_rows
                    if isinstance(signature.payload.get("signature_name"), str)
                }
            ),
            "attack_stages": sorted(stages),
            "escalation_count": escalation_count,
            "timeline": timeline,
        }
        if include_alerts:
            result["alerts"] = [self._alert_dict(*row) for row in rows]
            result["analyst_notes"] = self._incident_notes(session, incident.id)
        return result

    def incident_explanation_context(self, incident_id: str) -> dict[str, Any] | None:
        """Build an endpoint-free, allow-list-ready incident evidence envelope."""

        with self.session() as session:
            incident = session.get(IncidentRow, incident_id)
            if incident is None:
                return None
            rows = session.execute(
                select(AlertRow, DetectionRow, FlowRow)
                .join(IncidentAlertRow, IncidentAlertRow.alert_id == AlertRow.id)
                .join(DetectionRow, DetectionRow.event_id == AlertRow.detection_id)
                .join(FlowRow, FlowRow.event_id == AlertRow.flow_event_id)
                .where(IncidentAlertRow.incident_id == incident.id)
                .order_by(AlertRow.created_at.asc())
            ).all()
            detections = [detection.payload for _, detection, _ in rows]
            flows = [flow.payload for _, _, flow in rows]
            community_ids = {flow.community_flow_id for _, _, flow in rows}
            signatures = (
                session.scalars(
                    select(SignatureRow).where(SignatureRow.community_flow_id.in_(community_ids))
                ).all()
                if community_ids
                else []
            )

            highest = max(rows, key=lambda row: row[0].risk, default=None)
            verdict = highest[0].verdict if highest is not None else "needs_review"
            reason_codes = sorted(
                {
                    str(reason)
                    for detection in detections
                    for reason in detection.get("reason_codes", [])
                    if isinstance(reason, str)
                }
            )
            payload = {
                "verdict": verdict,
                "severity": incident.severity,
                "reason_codes": reason_codes,
                "aggregated_features": self._aggregate_explanation_features(flows),
                "known_attack_probability": self._maximum(
                    detections, "known_attack_probability"
                ),
                "anomaly_score": self._maximum(detections, "anomaly_score"),
                "signature_score": self._maximum(detections, "signature_score"),
                "contextual_score": self._maximum(detections, "contextual_score"),
                "final_risk_score": max((alert.risk for alert, _, _ in rows), default=0.0),
                "signature_names": sorted(
                    {
                        str(signature.payload["signature_name"])
                        for signature in signatures
                        if isinstance(signature.payload.get("signature_name"), str)
                    }
                ),
                "timeline": [
                    {
                        "timestamp": alert.created_at.isoformat(),
                        "verdict": alert.verdict,
                        "severity": alert.severity,
                        "risk": alert.risk,
                    }
                    for alert, _, _ in rows
                ],
            }
            return {
                "incident_id": incident.id,
                "incident_version": _as_utc(incident.updated_at).isoformat(),
                "payload": payload,
            }

    @staticmethod
    def _maximum(items: list[dict[str, Any]], key: str) -> float:
        values = [
            float(item[key])
            for item in items
            if isinstance(item.get(key), int | float) and not isinstance(item.get(key), bool)
        ]
        return max(values, default=0.0)

    @staticmethod
    def _aggregate_explanation_features(flows: list[dict[str, Any]]) -> dict[str, float | int]:
        def mean(key: str) -> float:
            values = [
                float(flow[key])
                for flow in flows
                if isinstance(flow.get(key), int | float) and not isinstance(flow.get(key), bool)
            ]
            return sum(values) / len(values) if values else 0.0

        def total(*keys: str) -> int:
            return sum(
                int(flow.get(key, 0))
                for flow in flows
                for key in keys
                if isinstance(flow.get(key, 0), int) and not isinstance(flow.get(key, 0), bool)
            )

        return {
            "flow_count": len(flows),
            "duration_ms_mean": mean("duration_ms"),
            "packets_total": total("packets_forward", "packets_reverse"),
            "bytes_total": total("bytes_forward", "bytes_reverse"),
            "packet_rate_mean": mean("packet_rate"),
            "byte_rate_mean": mean("byte_rate"),
            "packet_length_mean": mean("packet_length_mean"),
            "iat_mean": mean("iat_mean"),
        }

    def set_incident_status(self, incident_id: str, status: str, actor: str) -> bool:
        with self.session() as session:
            row = session.get(IncidentRow, incident_id)
            if row is None:
                return False
            if row.status != status:
                previous_status = row.status
                timestamp = datetime.now(UTC)
                row.status = status
                row.updated_at = timestamp
                session.add(
                    AuditLogRow(
                        id=str(uuid4()),
                        actor=actor,
                        action="incident_status_changed",
                        timestamp=timestamp,
                        target_id=incident_id,
                        details={"from": previous_status, "to": status},
                    )
                )
            return True

    def add_incident_note(self, incident_id: str, actor: str, note: str) -> dict[str, Any] | None:
        timestamp = datetime.now(UTC)
        note_id = str(uuid4())
        with self.session() as session:
            incident = session.get(IncidentRow, incident_id)
            if incident is None:
                return None
            session.add(
                AuditLogRow(
                    id=note_id,
                    actor=actor,
                    action="incident_note_added",
                    timestamp=timestamp,
                    target_id=incident_id,
                    details={"note": note},
                )
            )
            incident.updated_at = timestamp
        return {"id": note_id, "actor": actor, "note": note, "timestamp": timestamp}

    @staticmethod
    def _incident_notes(session: Session, incident_id: str) -> list[dict[str, Any]]:
        rows = session.scalars(
            select(AuditLogRow)
            .where(
                AuditLogRow.action == "incident_note_added",
                AuditLogRow.target_id == incident_id,
            )
            .order_by(AuditLogRow.timestamp.asc())
        )
        return [
            {
                "id": row.id,
                "actor": row.actor,
                "note": str(row.details.get("note", "")),
                "timestamp": _as_utc(row.timestamp),
            }
            for row in rows
        ]

    def add_feedback(self, feedback: AnalystFeedback) -> None:
        with self.session() as session:
            if session.get(AlertRow, str(feedback.alert_id)) is None:
                raise KeyError("alert not found")
            session.add(
                FeedbackRow(
                    id=str(feedback.feedback_id),
                    alert_id=str(feedback.alert_id),
                    actor=feedback.actor,
                    disposition=feedback.disposition.value,
                    timestamp=feedback.timestamp,
                    comment=feedback.comment,
                    original_result=feedback.original_model_result,
                    model_version=feedback.model_version,
                    eligible_for_retraining=feedback.eligible_for_retraining,
                )
            )
            session.add(
                AuditLogRow(
                    id=str(uuid4()),
                    actor=feedback.actor,
                    action="alert_feedback_created",
                    timestamp=feedback.timestamp,
                    target_id=str(feedback.alert_id),
                    details={"disposition": feedback.disposition.value},
                )
            )

    def retraining_candidates(
        self, *, offset: int = 0, limit: int = 200
    ) -> list[dict[str, Any]]:
        """Return eligible benign candidates without endpoints or analyst comments."""

        with self.session() as session:
            rows = session.execute(
                select(FeedbackRow, AlertRow, DetectionRow, FlowRow)
                .join(AlertRow, AlertRow.id == FeedbackRow.alert_id)
                .join(DetectionRow, DetectionRow.event_id == AlertRow.detection_id)
                .join(FlowRow, FlowRow.event_id == AlertRow.flow_event_id)
                .where(
                    FeedbackRow.eligible_for_retraining.is_(True),
                    FeedbackRow.disposition == "benign_new_behaviour",
                )
                .order_by(FeedbackRow.timestamp.asc())
                .offset(offset)
                .limit(min(limit, 500))
            ).all()
            candidates: list[dict[str, Any]] = []
            for feedback, alert, detection, flow in rows:
                validated_flow = FlowEvent.model_validate(flow.payload)
                candidates.append(
                    {
                        "feedback_id": feedback.id,
                        "alert_id": alert.id,
                        "timestamp": feedback.timestamp,
                        "disposition": feedback.disposition,
                        "model_version": feedback.model_version,
                        "feature_schema_version": detection.payload.get(
                            "feature_schema_version"
                        ),
                        "original_verdict": detection.verdict,
                        "original_risk": detection.risk,
                        "features": flow_to_mapping(validated_flow),
                    }
                )
            return candidates

    def record_health_event(
        self, service: str, status: str, details: dict[str, Any] | None = None
    ) -> str:
        event_id = str(uuid4())
        with self.session() as session:
            session.add(
                SystemHealthRow(
                    id=event_id,
                    service=service[:64],
                    status=status[:32],
                    timestamp=datetime.now(UTC),
                    details=details or {},
                )
            )
        return event_id

    def record_audit_event(
        self,
        *,
        actor: str,
        action: str,
        target_id: str,
        details: dict[str, Any] | None = None,
    ) -> str:
        event_id = str(uuid4())
        with self.session() as session:
            session.add(
                AuditLogRow(
                    id=event_id,
                    actor=actor[:128],
                    action=action[:128],
                    timestamp=datetime.now(UTC),
                    target_id=target_id[:128],
                    details=details or {},
                )
            )
        return event_id

    def health_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.session() as session:
            rows = session.scalars(
                select(SystemHealthRow)
                .order_by(SystemHealthRow.timestamp.desc())
                .limit(min(limit, 200))
            )
            return [
                {
                    "id": row.id,
                    "service": row.service,
                    "status": row.status,
                    "timestamp": _as_utc(row.timestamp),
                    "details": row.details,
                }
                for row in rows
            ]

    def audit_events(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        actor: str | None = None,
        action: str | None = None,
    ) -> list[dict[str, Any]]:
        with self.session() as session:
            statement = select(AuditLogRow)
            if actor is not None:
                statement = statement.where(AuditLogRow.actor == actor)
            if action is not None:
                statement = statement.where(AuditLogRow.action == action)
            rows = session.scalars(
                statement.order_by(AuditLogRow.timestamp.desc())
                .offset(max(0, offset))
                .limit(min(max(1, limit), 200))
            )
            return [
                {
                    "id": row.id,
                    "actor": row.actor,
                    "action": row.action,
                    "timestamp": _as_utc(row.timestamp),
                    "target_id": row.target_id,
                    "details": row.details,
                }
                for row in rows
            ]
    def hosts(self) -> list[dict[str, Any]]:
        with self.session() as session:
            flows = session.scalars(select(FlowRow)).all()
            alerts = {item["flow"]["src_ip"] for item in self.alerts(limit=200)}
            summary: dict[str, dict[str, Any]] = {}
            for flow in flows:
                host = summary.setdefault(
                    flow.src_ip,
                    {"host": flow.src_ip, "flows": 0, "destinations": set(), "alerting": False},
                )
                host["flows"] += 1
                host["destinations"].add(flow.dst_ip)
                host["alerting"] = flow.src_ip in alerts
            return [
                {**value, "destinations": len(value["destinations"])} for value in summary.values()
            ]

    def status(self) -> dict[str, Any]:
        with self.session() as session:
            return {
                "database": "ready",
                "sensors": len(session.scalars(select(SensorRow)).all()),
                "flows": len(session.scalars(select(FlowRow)).all()),
                "signature_events": len(session.scalars(select(SignatureRow)).all()),
                "alerts": len(session.scalars(select(AlertRow)).all()),
                "incidents": len(session.scalars(select(IncidentRow)).all()),
                "mode": "demo" if os.getenv("AEGISFLOW_DEMO", "1") == "1" else "production",
            }

    def drift_events(self) -> list[dict[str, Any]]:
        with self.session() as session:
            rows = session.scalars(
                select(DriftEventRow).order_by(DriftEventRow.detected_at.desc()).limit(200)
            )
            return [
                {
                    "id": row.id,
                    "signal": row.signal,
                    "detected_at": _as_utc(row.detected_at),
                    "magnitude": row.magnitude,
                    "model_version": row.model_version,
                    **row.payload,
                }
                for row in rows
            ]

    def record_drift_event(self, event: DriftEvent) -> bool:
        event_id = str(event.event_id)
        with self.session() as session:
            if session.get(DriftEventRow, event_id) is not None:
                return False
            session.add(
                DriftEventRow(
                    id=event_id,
                    signal=event.signal,
                    detected_at=event.detection_time,
                    magnitude=event.magnitude,
                    model_version=event.model_version,
                    payload={
                        "reference_window": event.reference_window,
                        "recent_window": event.recent_window,
                        "reference_mean": event.reference_mean,
                        "recent_mean": event.recent_mean,
                        "trigger_detection_id": (
                            str(event.trigger_detection_id)
                            if event.trigger_detection_id is not None
                            else None
                        ),
                        "recommended_action": event.recommended_action,
                        "automatic_action_allowed": event.automatic_action_allowed,
                        "eligible_for_retraining": event.eligible_for_retraining,
                    },
                )
            )
            return True

    def models(self) -> list[dict[str, Any]]:
        with self.session() as session:
            rows = session.scalars(
                select(ModelVersionRow).order_by(ModelVersionRow.loaded_at.desc())
            )
            return [
                {
                    "id": row.id,
                    "model_name": row.model_name,
                    "version": row.version,
                    "production": row.production,
                    "loaded_at": _as_utc(row.loaded_at),
                    "metadata": row.metadata_json,
                }
                for row in rows
            ]

    def model_candidates(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.session() as session:
            rows = session.scalars(
                select(ModelCandidateRow)
                .order_by(ModelCandidateRow.updated_at.desc())
                .limit(min(max(1, limit), 200))
            )
            return [self._model_candidate_dict(session, row) for row in rows]

    def model_candidate(self, candidate_id: str) -> dict[str, Any] | None:
        with self.session() as session:
            row = session.get(ModelCandidateRow, candidate_id)
            return self._model_candidate_dict(session, row) if row is not None else None

    @staticmethod
    def _model_candidate_dict(
        session: Session, row: ModelCandidateRow
    ) -> dict[str, Any]:
        reviews = session.scalars(
            select(ModelReviewRow)
            .where(ModelReviewRow.candidate_id == row.id)
            .order_by(ModelReviewRow.timestamp.asc())
        )
        return {
            "id": row.id,
            "model_name": row.model_name,
            "version": row.version,
            "bundle_digest": row.bundle_digest,
            "status": row.status,
            "created_at": _as_utc(row.created_at),
            "updated_at": _as_utc(row.updated_at),
            "created_by": row.created_by,
            "required_modes": row.required_modes,
            "evidence": row.evidence,
            "blockers": row.blockers,
            "reviews": [
                {
                    "id": review.id,
                    "actor": review.actor,
                    "decision": review.decision,
                    "comment": review.comment,
                    "timestamp": _as_utc(review.timestamp),
                }
                for review in reviews
            ],
        }

    def register_model_candidate(
        self, assessment: dict[str, Any], *, actor: str
    ) -> dict[str, Any]:
        candidate_id = f"{assessment['model_name']}:{assessment['version']}"
        now = datetime.now(UTC)
        with self.session() as session:
            existing = session.get(ModelCandidateRow, candidate_id)
            if existing is not None:
                if (
                    existing.bundle_digest != assessment["bundle_digest"]
                    or existing.evidence != assessment["evidence"]
                    or existing.required_modes != assessment["required_modes"]
                ):
                    raise ValueError("candidate evidence is immutable")
                return self._model_candidate_dict(session, existing)
            status = "review_pending" if assessment["eligible_for_review"] else "rejected"
            row = ModelCandidateRow(
                id=candidate_id,
                model_name=str(assessment["model_name"]),
                version=str(assessment["version"]),
                bundle_digest=str(assessment["bundle_digest"]),
                status=status,
                created_at=now,
                updated_at=now,
                created_by=actor,
                required_modes=list(assessment["required_modes"]),
                evidence=list(assessment["evidence"]),
                blockers=list(assessment["blockers"]),
            )
            session.add(row)
            session.add(
                AuditLogRow(
                    id=str(uuid4()),
                    actor=actor,
                    action="model_candidate_registered",
                    timestamp=now,
                    target_id=candidate_id,
                    details={"status": status, "blockers": list(assessment["blockers"])},
                )
            )
            session.flush()
            return self._model_candidate_dict(session, row)

    def review_model_candidate(
        self,
        candidate_id: str,
        *,
        actor: str,
        decision: str,
        comment: str,
    ) -> dict[str, Any]:
        if decision not in {"approve", "reject"}:
            raise ValueError("invalid review decision")
        now = datetime.now(UTC)
        with self.session() as session:
            row = session.scalar(
                select(ModelCandidateRow)
                .where(ModelCandidateRow.id == candidate_id)
                .with_for_update()
            )
            if row is None:
                raise KeyError("candidate not found")
            if row.status != "review_pending":
                raise ValueError("candidate is not awaiting review")
            if row.created_by == actor:
                raise ValueError("candidate creator cannot review the same candidate")
            previous = session.scalar(
                select(ModelReviewRow).where(
                    ModelReviewRow.candidate_id == candidate_id,
                    ModelReviewRow.actor == actor,
                )
            )
            if previous is not None:
                raise ValueError("review is immutable")
            session.add(
                ModelReviewRow(
                    id=str(uuid4()),
                    candidate_id=candidate_id,
                    actor=actor,
                    decision=decision,
                    comment=comment,
                    timestamp=now,
                )
            )
            row.status = "approved" if decision == "approve" else "rejected"
            row.updated_at = now
            session.add(
                AuditLogRow(
                    id=str(uuid4()),
                    actor=actor,
                    action="model_candidate_reviewed",
                    timestamp=now,
                    target_id=candidate_id,
                    details={"decision": decision},
                )
            )
            session.flush()
            return self._model_candidate_dict(session, row)

    def begin_model_promotion(self, candidate_id: str, *, actor: str) -> dict[str, Any]:
        now = datetime.now(UTC)
        with self.session() as session:
            row = session.scalar(
                select(ModelCandidateRow)
                .where(ModelCandidateRow.id == candidate_id)
                .with_for_update()
            )
            if row is None:
                raise KeyError("candidate not found")
            if row.status != "approved":
                raise ValueError("candidate is not approved")
            approval = session.scalar(
                select(ModelReviewRow).where(
                    ModelReviewRow.candidate_id == candidate_id,
                    ModelReviewRow.decision == "approve",
                    ModelReviewRow.actor != actor,
                )
            )
            if approval is None:
                raise ValueError("promotion requires approval from a different identity")
            row.status = "promotion_pending"
            row.updated_at = now
            session.add(
                AuditLogRow(
                    id=str(uuid4()),
                    actor=actor,
                    action="model_promotion_started",
                    timestamp=now,
                    target_id=candidate_id,
                    details={"bundle_digest": row.bundle_digest},
                )
            )
            session.flush()
            return self._model_candidate_dict(session, row)

    def finish_model_promotion(
        self,
        candidate_id: str,
        *,
        actor: str,
        manifest: dict[str, Any] | None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        with self.session() as session:
            row = session.scalar(
                select(ModelCandidateRow)
                .where(ModelCandidateRow.id == candidate_id)
                .with_for_update()
            )
            if row is None:
                raise KeyError("candidate not found")
            if row.status != "promotion_pending":
                raise ValueError("candidate promotion is not pending")
            success = manifest is not None and error_code is None
            row.status = "promoted" if success else "approved"
            row.updated_at = now
            session.add(
                AuditLogRow(
                    id=str(uuid4()),
                    actor=actor,
                    action="model_promoted" if success else "model_promotion_failed",
                    timestamp=now,
                    target_id=candidate_id,
                    details={} if success else {"error_code": error_code or "unknown"},
                )
            )
            session.flush()
            return self._model_candidate_dict(session, row)

    def record_model_rollback(
        self,
        *,
        model_name: str,
        from_version: str,
        to_version: str,
        actor: str,
    ) -> None:
        now = datetime.now(UTC)
        with self.session() as session:
            candidate = session.get(ModelCandidateRow, f"{model_name}:{from_version}")
            if candidate is not None and candidate.status == "promoted":
                candidate.status = "rolled_back"
                candidate.updated_at = now
            session.add(
                AuditLogRow(
                    id=str(uuid4()),
                    actor=actor,
                    action="model_rollback_requested",
                    timestamp=now,
                    target_id=model_name,
                    details={"from": from_version, "to": to_version},
                )
            )

    def reconcile_pending_model_promotions(
        self,
        *,
        active_model_name: str,
        active_version: str,
        active_bundle_digest: str,
    ) -> int:
        now = datetime.now(UTC)
        reconciled = 0
        with self.session() as session:
            rows = session.scalars(
                select(ModelCandidateRow)
                .where(ModelCandidateRow.status == "promotion_pending")
                .with_for_update()
            )
            for row in rows:
                success = (
                    row.model_name == active_model_name
                    and row.version == active_version
                    and row.bundle_digest == active_bundle_digest
                )
                row.status = "promoted" if success else "approved"
                row.updated_at = now
                session.add(
                    AuditLogRow(
                        id=str(uuid4()),
                        actor="system:startup",
                        action="model_promotion_reconciled",
                        timestamp=now,
                        target_id=row.id,
                        details={"outcome": "completed" if success else "released_for_retry"},
                    )
                )
                reconciled += 1
        return reconciled

    def record_model(self, manifest: dict[str, Any]) -> None:
        key = f"{manifest['model_name']}:{manifest['version']}"
        with self.session() as session:
            loaded_at = datetime.now(UTC)
            for candidate in session.scalars(
                select(ModelVersionRow).where(
                    ModelVersionRow.model_name == str(manifest["model_name"])
                )
            ):
                candidate.production = candidate.id == key
            row = session.get(ModelVersionRow, key)
            if row is None:
                session.add(
                    ModelVersionRow(
                        id=key,
                        model_name=str(manifest["model_name"]),
                        version=str(manifest["version"]),
                        production=True,
                        loaded_at=loaded_at,
                        metadata_json=manifest,
                    )
                )
            else:
                row.production = True
                row.loaded_at = loaded_at
                row.metadata_json = manifest

    def cleanup_before(
        self, cutoff: datetime, *, audit_cutoff: datetime | None = None
    ) -> dict[str, int]:
        """Delete expired operational records in foreign-key-safe order."""
        counts: dict[str, int] = {}
        effective_audit_cutoff = audit_cutoff or cutoff
        with self.session() as session:
            old_flows = list(
                session.scalars(select(FlowRow.event_id).where(FlowRow.timestamp_end < cutoff))
            )
            old_detections = list(
                session.scalars(
                    select(DetectionRow.event_id).where(DetectionRow.flow_event_id.in_(old_flows))
                )
            )
            old_alerts = list(
                session.scalars(
                    select(AlertRow.id).where(AlertRow.detection_id.in_(old_detections))
                )
            )
            counts["feedback"] = (
                session.execute(
                    delete(FeedbackRow).where(FeedbackRow.alert_id.in_(old_alerts))
                ).rowcount
                or 0
            )
            session.execute(
                delete(IncidentAlertRow).where(IncidentAlertRow.alert_id.in_(old_alerts))
            )
            empty_incidents = list(
                session.scalars(
                    select(IncidentRow.id).where(
                        ~select(IncidentAlertRow.alert_id)
                        .where(IncidentAlertRow.incident_id == IncidentRow.id)
                        .exists()
                    )
                )
            )
            counts["incidents"] = (
                session.execute(
                    delete(IncidentRow).where(IncidentRow.id.in_(empty_incidents))
                ).rowcount
                or 0
            )
            counts["alerts"] = (
                session.execute(
                    delete(AlertRow).where(AlertRow.detection_id.in_(old_detections))
                ).rowcount
                or 0
            )
            counts["detections"] = (
                session.execute(
                    delete(DetectionRow).where(DetectionRow.event_id.in_(old_detections))
                ).rowcount
                or 0
            )
            counts["flows"] = (
                session.execute(delete(FlowRow).where(FlowRow.event_id.in_(old_flows))).rowcount
                or 0
            )
            counts["signatures"] = (
                session.execute(
                    delete(SignatureRow).where(SignatureRow.timestamp < cutoff)
                ).rowcount
                or 0
            )
            counts["drift_events"] = (
                session.execute(
                    delete(DriftEventRow).where(DriftEventRow.detected_at < cutoff)
                ).rowcount
                or 0
            )
            counts["health_events"] = (
                session.execute(
                    delete(SystemHealthRow).where(SystemHealthRow.timestamp < cutoff)
                ).rowcount
                or 0
            )
            counts["audit_events"] = (
                session.execute(
                    delete(AuditLogRow).where(AuditLogRow.timestamp < effective_audit_cutoff)
                ).rowcount
                or 0
            )
        return counts
