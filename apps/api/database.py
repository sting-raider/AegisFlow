from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
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
    create_engine,
    delete,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from packages.contracts import AnalystFeedback, DetectionResult, FlowEvent, SignatureEvent, Verdict
from packages.incidents import DriftEvent


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


class Repository:
    def __init__(self, url: str | None = None) -> None:
        database_url = (
            url
            if url is not None
            else os.getenv("AEGISFLOW_DATABASE_URL", "sqlite:///aegisflow-demo.db")
        )
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
        flow_id = str(flow.event_id)
        detection_id = str(detection.event_id)
        with self.session() as session:
            if session.get(DetectionRow, detection_id) is not None:
                existing = session.scalar(
                    select(AlertRow).where(AlertRow.detection_id == detection_id)
                )
                return existing.id if existing else None
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
                return None
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
            self._group_incident(session, alert_id, flow, detection)
            return alert_id

    @staticmethod
    def _group_incident(
        session: Session, alert_id: str, flow: FlowEvent, detection: DetectionResult
    ) -> None:
        cutoff = detection.timestamp - timedelta(minutes=10)
        incident = session.scalar(
            select(IncidentRow)
            .where(
                IncidentRow.source_host == str(flow.src_ip),
                IncidentRow.status.in_(["open", "investigating"]),
                IncidentRow.updated_at >= cutoff,
            )
            .order_by(IncidentRow.updated_at.desc())
        )
        if incident is None:
            session.add(
                IncidentRow(
                    id=str(uuid4()),
                    title=f"Activity from {flow.src_ip}",
                    status="open",
                    severity=detection.severity.value,
                    source_host=str(flow.src_ip),
                    created_at=detection.timestamp,
                    updated_at=detection.timestamp,
                    alert_ids=[alert_id],
                    grouping_reasons=["same source host", "ten-minute proximity"],
                )
            )
        else:
            incident.alert_ids = [*incident.alert_ids, alert_id]
            incident.updated_at = detection.timestamp
            severities = ["informational", "low", "medium", "high", "critical"]
            if severities.index(detection.severity.value) > severities.index(incident.severity):
                incident.severity = detection.severity.value

    def alerts(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        severity: str | None = None,
        verdict: str | None = None,
        host: str | None = None,
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
            return [self._alert_dict(*row) for row in session.execute(statement).all()]

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.session() as session:
            row = session.execute(
                select(AlertRow, DetectionRow, FlowRow)
                .join(DetectionRow, DetectionRow.event_id == AlertRow.detection_id)
                .join(FlowRow, FlowRow.event_id == AlertRow.flow_event_id)
                .where(AlertRow.id == alert_id)
            ).first()
            return self._alert_dict(*row) if row else None

    @staticmethod
    def _alert_dict(alert: AlertRow, detection: DetectionRow, flow: FlowRow) -> dict[str, Any]:
        return {
            "id": alert.id,
            "created_at": alert.created_at,
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
                "timestamp_start": flow.timestamp_start,
            },
            "detection": detection.payload,
        }

    def flows(self, *, offset: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        with self.session() as session:
            rows = session.scalars(
                select(FlowRow)
                .order_by(FlowRow.timestamp_start.desc())
                .offset(offset)
                .limit(min(limit, 200))
            )
            return [row.payload for row in rows]

    def flow(self, event_id: str) -> dict[str, Any] | None:
        with self.session() as session:
            row = session.get(FlowRow, event_id)
            return row.payload if row else None

    def incidents(self) -> list[dict[str, Any]]:
        with self.session() as session:
            rows = session.scalars(select(IncidentRow).order_by(IncidentRow.updated_at.desc()))
            return [
                {
                    "id": row.id,
                    "title": row.title,
                    "status": row.status,
                    "severity": row.severity,
                    "source_host": row.source_host,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                    "alert_ids": row.alert_ids,
                    "grouping_reasons": row.grouping_reasons,
                }
                for row in rows
            ]

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        return next((item for item in self.incidents() if item["id"] == incident_id), None)

    def incident_explanation_context(self, incident_id: str) -> dict[str, Any] | None:
        """Build an endpoint-free, allow-list-ready incident evidence envelope."""

        with self.session() as session:
            incident = session.get(IncidentRow, incident_id)
            if incident is None:
                return None
            rows = session.execute(
                select(AlertRow, DetectionRow, FlowRow)
                .join(DetectionRow, DetectionRow.event_id == AlertRow.detection_id)
                .join(FlowRow, FlowRow.event_id == AlertRow.flow_event_id)
                .where(AlertRow.id.in_(incident.alert_ids))
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
                "incident_version": incident.updated_at.isoformat(),
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

    def set_incident_status(self, incident_id: str, status: str) -> bool:
        with self.session() as session:
            row = session.get(IncidentRow, incident_id)
            if row is None:
                return False
            row.status = status
            row.updated_at = datetime.now(UTC)
            return True

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
                    "detected_at": row.detected_at,
                    "magnitude": row.magnitude,
                    "model_version": row.model_version,
                    **row.payload,
                }
                for row in rows
            ]

    def detection_exists(self, event_id: str) -> bool:
        with self.session() as session:
            return session.get(DetectionRow, event_id) is not None

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
                    "loaded_at": row.loaded_at,
                    "metadata": row.metadata_json,
                }
                for row in rows
            ]

    def record_model(self, manifest: dict[str, Any]) -> None:
        key = f"{manifest['model_name']}:{manifest['version']}"
        with self.session() as session:
            loaded_at = datetime.now(UTC)
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

    def cleanup_before(self, cutoff: datetime) -> dict[str, int]:
        """Delete expired operational records in foreign-key-safe order."""
        counts: dict[str, int] = {}
        with self.session() as session:
            old_flows = list(
                session.scalars(select(FlowRow.event_id).where(FlowRow.timestamp_end < cutoff))
            )
            old_detections = list(
                session.scalars(
                    select(DetectionRow.event_id).where(DetectionRow.flow_event_id.in_(old_flows))
                )
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
            session.execute(delete(SystemHealthRow).where(SystemHealthRow.timestamp < cutoff))
            session.execute(delete(AuditLogRow).where(AuditLogRow.timestamp < cutoff))
        return counts
