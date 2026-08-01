from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import uvicorn
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field

from apps.api.consumer import DetectionConsumer
from apps.api.database import Repository
from apps.api.retention import RetentionWorker, retention_status, retention_worker_from_env
from packages.common import FLOW_EXPORT_FIELDS, anonymize_ip, sanitize_flow_export
from packages.contracts import (
    AnalystFeedback,
    FeedbackDisposition,
    Severity,
    SignatureEvent,
    Verdict,
)
from packages.detection import DetectionEngine
from packages.features import FEATURE_NAMES
from packages.incidents import (
    DriftEvent,
    ExplanationService,
    RuntimeDriftMonitor,
    explanation_service_from_env,
)
from packages.model_bundle import BundleError, load_production_bundle
from services.sensor import DemoAdapter
from training.cli.train_smoke import train

DETECTIONS = Counter("detections_total", "Detection results", ["verdict"])
ALERTS = Counter("alerts_total", "Alerts created", ["severity"])
UNKNOWN_ALERTS = Counter("unknown_alerts_total", "Suspicious unknown alerts")
INFERENCE = Histogram("inference_latency_seconds", "Single-flow inference latency")
WEBSOCKETS = Gauge("websocket_connections", "Current WebSocket connections")
DATABASE_ERRORS = Counter("database_errors_total", "Database errors")
MODEL_LOAD_FAILURES = Counter("model_load_failures_total", "Model bundle load failures")
QUEUE_LAG = Gauge("queue_lag", "Undelivered Redis stream entries", ["stream", "group"])
QUEUE_PENDING = Gauge(
    "queue_pending", "Delivered but unacknowledged stream entries", ["stream", "group"]
)
DRIFT_EVENTS = Counter("drift_events_total", "Detected runtime distribution shifts", ["signal"])
DRIFT_MAGNITUDE = Gauge("drift_magnitude", "Most recent drift magnitude", ["signal"])
EXPLANATIONS = Counter(
    "incident_explanations_total",
    "On-demand incident explanations",
    ["provider", "outcome"],
)


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor: str = Field(min_length=1, max_length=128)
    disposition: FeedbackDisposition
    comment: str = Field(default="", max_length=2000)
    eligible_for_retraining: bool = False


class IncidentStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "investigating", "contained", "closed"]


class IncidentNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor: str = Field(min_length=1, max_length=128)
    note: str = Field(min_length=1, max_length=2000)


class AcknowledgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor: str = Field(min_length=1, max_length=128)


def _record_drift_metric(event: DriftEvent) -> None:
    DRIFT_EVENTS.labels(event.signal).inc()
    DRIFT_MAGNITUDE.labels(event.signal).set(event.magnitude)


def _seed_demo(
    repository: Repository, engine: DetectionEngine, drift_monitor: RuntimeDriftMonitor
) -> None:
    for flow in DemoAdapter().flows():
        signature = None
        if flow.protocol_metadata.get("scenario") == "known-signature":
            raw = b"aegisflow-safe-demo-signature"
            signature = SignatureEvent(
                event_id=uuid5(NAMESPACE_URL, "aegisflow-demo-signature"),
                timestamp=flow.timestamp_start,
                community_flow_id=flow.community_flow_id,
                signature_id="9000001",
                signature_name="AEGISFLOW DEMO repeated authentication pattern",
                category="Attempted Administrator Privilege Gain",
                severity=Severity.HIGH,
                source="fixture",
                raw_event_hash=hashlib.sha256(raw).hexdigest(),
                metadata={"fixture": True},
            )
        detection = engine.detect(flow, signature)
        try:
            alert_id = repository.ingest(flow, detection, signature)
        except Exception:
            DATABASE_ERRORS.inc()
            raise
        DETECTIONS.labels(detection.verdict.value).inc()
        INFERENCE.observe(detection.inference_latency_ms / 1000)
        if alert_id:
            ALERTS.labels(detection.severity.value).inc()
            if detection.verdict.value == "suspicious_unknown":
                UNKNOWN_ALERTS.inc()
        for event in drift_monitor.observe(flow, detection):
            if repository.record_drift_event(event):
                _record_drift_metric(event)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    repository = Repository()
    repository.create_schema()
    registry = Path(os.getenv("AEGISFLOW_MODEL_REGISTRY", "models/registry"))
    try:
        bundle = load_production_bundle(registry)
    except BundleError:
        MODEL_LOAD_FAILURES.inc()
        if os.getenv("AEGISFLOW_DEMO", "1") != "1":
            raise
        train(registry)
        bundle = load_production_bundle(registry)
    engine = DetectionEngine(bundle)
    drift_monitor = RuntimeDriftMonitor(
        str(bundle.manifest["version"]),
        window_size=int(os.getenv("AEGISFLOW_DRIFT_WINDOW", "64")),
    )
    repository.record_model(bundle.manifest)
    app.state.repository = repository
    app.state.engine = engine
    app.state.drift_monitor = drift_monitor
    app.state.explanation_service = explanation_service_from_env()
    repository.record_health_event(
        "api",
        "ready",
        {"mode": "demo" if os.getenv("AEGISFLOW_DEMO", "1") == "1" else "production"},
    )
    retention_worker = retention_worker_from_env(repository)
    app.state.retention_worker = retention_worker
    if retention_worker is not None:
        retention_worker.start()
    consumer: DetectionConsumer | None = None
    app.state.consumer = None
    if os.getenv("AEGISFLOW_CONSUME_REDIS", "0") == "1":
        consumer = DetectionConsumer(
            repository,
            os.getenv("AEGISFLOW_REDIS_URL", "redis://redis:6379/0"),
            on_database_error=DATABASE_ERRORS.inc,
            drift_monitor=drift_monitor,
            on_drift_event=_record_drift_metric,
        )
        app.state.consumer = consumer
        consumer.start()
    if os.getenv("AEGISFLOW_DEMO_SEED", "1") == "1":
        _seed_demo(repository, engine, drift_monitor)
    yield
    if consumer is not None:
        consumer.stop()
    if retention_worker is not None:
        retention_worker.stop()
    repository.record_health_event("api", "stopped")


app = FastAPI(
    title="AegisFlow API",
    version="1.0.0",
    description=(
        "Known-threat detection plus statistically unusual behaviour. "
        "An anomaly is not proof of a zero-day."
    ),
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        value.strip()
        for value in os.getenv(
            "AEGISFLOW_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key", "X-Correlation-ID"],
)


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
    detail: dict[str, Any] = exc.detail if isinstance(exc.detail, dict) else {}
    code = str(detail.get("code", "http_error"))
    message = str(detail.get("message", "Request could not be completed"))
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "correlation_id": getattr(request.state, "correlation_id", None),
            }
        },
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        {"location": list(item["loc"]), "type": item["type"], "message": item["msg"]}
        for item in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request validation failed",
                "correlation_id": getattr(request.state, "correlation_id", None),
                "details": details,
            }
        },
    )


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    del exc
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_error",
                "message": "An internal processing error occurred",
                "correlation_id": getattr(request.state, "correlation_id", None),
            }
        },
    )


@app.middleware("http")
async def correlation_id(request: Request, call_next: Any) -> Response:
    correlation = request.headers.get("X-Correlation-ID", str(uuid4()))[:128]
    request.state.correlation_id = correlation
    response: Response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def repository(request: Request) -> Repository:
    return cast(Repository, request.app.state.repository)


def explanation_service(request: Request) -> ExplanationService:
    return cast(ExplanationService, request.app.state.explanation_service)


def mutation_auth(x_api_key: Annotated[str | None, Header()] = None) -> None:
    expected = os.getenv("AEGISFLOW_API_KEY")
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail={"code": "invalid_api_key"})


def _utc_range(
    start: datetime | None, end: datetime | None
) -> tuple[datetime | None, datetime | None]:
    for name, value in (("start", start), ("end", end)):
        if value is not None and value.tzinfo is None:
            raise HTTPException(
                status_code=422,
                detail={"code": "timezone_required", "message": f"{name} must include a timezone"},
            )
    normalized_start = start.astimezone(UTC) if start else None
    normalized_end = end.astimezone(UTC) if end else None
    if normalized_start and normalized_end and normalized_start > normalized_end:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_date_range", "message": "start must not follow end"},
        )
    return normalized_start, normalized_end


def _protocol(value: str | None) -> str | None:
    return value.upper() if value else None


def _csv_response(
    rows: list[dict[str, Any]], fieldnames: list[str], filename: str
) -> Response:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _safe_csv_value(row.get(key)) for key in fieldnames})
    return Response(
        output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _safe_csv_value(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, list | tuple | dict):
        value = json.dumps(jsonable_encoder(value), sort_keys=True, separators=(",", ":"))
    if isinstance(value, str):
        value = " ".join(value.replace("\x00", " ").split())
        return f"'{value}" if value.startswith(("=", "+", "-", "@")) else value
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int | float):
        return value
    return str(value)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
def ready(repo: Annotated[Repository, Depends(repository)]) -> dict[str, str]:
    repo.status()
    return {"status": "ready"}


@app.get("/metrics")
def metrics(request: Request) -> Response:
    consumer = cast(DetectionConsumer | None, getattr(request.app.state, "consumer", None))
    if consumer is not None:
        _record_queue_metrics(consumer.queue_status)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/v1/alerts")
def list_alerts(
    repo: Annotated[Repository, Depends(repository)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    severity: Severity | None = None,
    verdict: Verdict | None = None,
    protocol: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    host: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, Any]:
    start, end = _utc_range(start, end)
    severity_value = severity.value if severity else None
    verdict_value = verdict.value if verdict else None
    protocol_value = _protocol(protocol)
    items = repo.alerts(
        offset=offset,
        limit=limit,
        severity=severity_value,
        verdict=verdict_value,
        protocol=protocol_value,
        host=host,
        start=start,
        end=end,
    )
    return {
        "items": items,
        "offset": offset,
        "limit": limit,
        "count": len(items),
        "total": repo.alert_count(
            severity=severity_value,
            verdict=verdict_value,
            protocol=protocol_value,
            host=host,
            start=start,
            end=end,
        ),
    }


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: UUID, repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    item = repo.alert(str(alert_id))
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "alert_not_found"})
    return item


@app.post("/api/v1/alerts/{alert_id}/acknowledge", dependencies=[Depends(mutation_auth)])
def acknowledge_alert(
    alert_id: UUID,
    body: AcknowledgeRequest,
    repo: Annotated[Repository, Depends(repository)],
) -> dict[str, Any]:
    if not repo.acknowledge_alert(str(alert_id), body.actor):
        raise HTTPException(status_code=404, detail={"code": "alert_not_found"})
    return {"id": str(alert_id), "acknowledged": True, "actor": body.actor}


@app.post("/api/v1/alerts/{alert_id}/feedback", dependencies=[Depends(mutation_auth)])
def submit_feedback(
    alert_id: UUID,
    body: FeedbackRequest,
    repo: Annotated[Repository, Depends(repository)],
) -> dict[str, Any]:
    alert = repo.alert(str(alert_id))
    if alert is None:
        raise HTTPException(status_code=404, detail={"code": "alert_not_found"})
    feedback = AnalystFeedback(
        alert_id=alert_id,
        actor=body.actor,
        disposition=body.disposition,
        comment=body.comment,
        original_model_result=alert["detection"],
        model_version=alert["detection"]["classifier_model_version"],
        eligible_for_retraining=body.eligible_for_retraining,
    )
    repo.add_feedback(feedback)
    return feedback.model_dump(mode="json")


@app.get("/api/v1/incidents")
def list_incidents(repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    items = repo.incidents()
    return {"items": items, "count": len(items)}


@app.get("/api/v1/incidents/{incident_id}")
def get_incident(
    incident_id: UUID, repo: Annotated[Repository, Depends(repository)]
) -> dict[str, Any]:
    item = repo.incident(str(incident_id))
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "incident_not_found"})
    return item


@app.get("/api/v1/incidents/{incident_id}/explanation")
def get_incident_explanation(
    incident_id: UUID,
    repo: Annotated[Repository, Depends(repository)],
    service: Annotated[ExplanationService, Depends(explanation_service)],
) -> dict[str, Any]:
    context = repo.incident_explanation_context(str(incident_id))
    if context is None:
        raise HTTPException(status_code=404, detail={"code": "incident_not_found"})
    result = service.generate(
        incident_id=context["incident_id"],
        incident_version=context["incident_version"],
        payload=context["payload"],
    )
    outcome = "cached" if result.cached else "fallback" if result.fallback else "generated"
    EXPLANATIONS.labels(result.provider, outcome).inc()
    return result.as_dict()


@app.post("/api/v1/incidents/{incident_id}/status", dependencies=[Depends(mutation_auth)])
def set_incident_status(
    incident_id: UUID,
    body: IncidentStatusRequest,
    repo: Annotated[Repository, Depends(repository)],
) -> dict[str, str]:
    if not repo.set_incident_status(str(incident_id), body.status):
        raise HTTPException(status_code=404, detail={"code": "incident_not_found"})
    return {"id": str(incident_id), "status": body.status}


@app.post("/api/v1/incidents/{incident_id}/notes", dependencies=[Depends(mutation_auth)])
def add_incident_note(
    incident_id: UUID,
    body: IncidentNoteRequest,
    repo: Annotated[Repository, Depends(repository)],
) -> dict[str, Any]:
    note = repo.add_incident_note(str(incident_id), body.actor, body.note)
    if note is None:
        raise HTTPException(status_code=404, detail={"code": "incident_not_found"})
    return note


@app.get("/api/v1/flows")
def list_flows(
    repo: Annotated[Repository, Depends(repository)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    protocol: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    host: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, Any]:
    start, end = _utc_range(start, end)
    protocol_value = _protocol(protocol)
    items = repo.flows(
        offset=offset,
        limit=limit,
        protocol=protocol_value,
        host=host,
        start=start,
        end=end,
    )
    return {
        "items": items,
        "offset": offset,
        "limit": limit,
        "count": len(items),
        "total": repo.flow_count(
            protocol=protocol_value, host=host, start=start, end=end
        ),
    }


@app.get("/api/v1/flows/{event_id}")
def get_flow(event_id: UUID, repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    item = repo.flow(str(event_id))
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "flow_not_found"})
    return item


@app.get("/api/v1/retraining-candidates")
def list_retraining_candidates(
    repo: Annotated[Repository, Depends(repository)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> dict[str, Any]:
    items = repo.retraining_candidates(offset=offset, limit=limit)
    return {"items": items, "offset": offset, "limit": limit, "count": len(items)}


@app.get("/api/v1/exports/flows.csv")
def export_flows(
    repo: Annotated[Repository, Depends(repository)],
    event_id: Annotated[list[UUID] | None, Query(max_length=200)] = None,
    anonymize_ips: bool = True,
    x_api_key: Annotated[str | None, Header()] = None,
    protocol: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    host: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> Response:
    if not anonymize_ips:
        mutation_auth(x_api_key)
    start, end = _utc_range(start, end)
    payloads = repo.flows(
        limit=200,
        event_ids=[str(value) for value in event_id] if event_id is not None else None,
        protocol=_protocol(protocol),
        host=host,
        start=start,
        end=end,
    )
    salt = secrets.token_bytes(32)
    rows = [
        sanitize_flow_export(payload, anonymize_ips=anonymize_ips, salt=salt)
        for payload in payloads
    ]
    return _csv_response(rows, list(FLOW_EXPORT_FIELDS), "aegisflow-flows.csv")


@app.get("/api/v1/exports/alerts.csv")
def export_alerts(
    repo: Annotated[Repository, Depends(repository)],
    alert_id: Annotated[list[UUID] | None, Query(max_length=200)] = None,
    anonymize_ips: bool = True,
    x_api_key: Annotated[str | None, Header()] = None,
    severity: Severity | None = None,
    verdict: Verdict | None = None,
    protocol: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    host: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> Response:
    if not anonymize_ips:
        mutation_auth(x_api_key)
    start, end = _utc_range(start, end)
    items = (
        [item for value in alert_id if (item := repo.alert(str(value))) is not None]
        if alert_id is not None
        else repo.alerts(
            limit=200,
            severity=severity.value if severity else None,
            verdict=verdict.value if verdict else None,
            protocol=_protocol(protocol),
            host=host,
            start=start,
            end=end,
        )
    )
    salt = secrets.token_bytes(32)
    rows: list[dict[str, Any]] = []
    for item in items:
        detection = item["detection"]
        flow = item["flow"]
        rows.append(
            {
                "alert_id": item["id"],
                "created_at": item["created_at"],
                "verdict": item["verdict"],
                "severity": item["severity"],
                "risk": item["risk"],
                "acknowledged": item["acknowledged"],
                "src_ip": (
                    anonymize_ip(flow["src_ip"], salt)
                    if anonymize_ips
                    else flow["src_ip"]
                ),
                "dst_ip": (
                    anonymize_ip(flow["dst_ip"], salt)
                    if anonymize_ips
                    else flow["dst_ip"]
                ),
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "protocol": flow["protocol"],
                "reason_codes": detection.get("reason_codes", []),
                "known_attack_probability": detection.get("known_attack_probability"),
                "anomaly_score": detection.get("anomaly_score"),
                "signature_score": detection.get("signature_score"),
                "model_version": detection.get("classifier_model_version"),
            }
        )
    fields = [
        "alert_id",
        "created_at",
        "verdict",
        "severity",
        "risk",
        "acknowledged",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "reason_codes",
        "known_attack_probability",
        "anomaly_score",
        "signature_score",
        "model_version",
    ]
    return _csv_response(rows, fields, "aegisflow-alerts.csv")


@app.get("/api/v1/exports/retraining-candidates.csv")
def export_retraining_candidates(
    repo: Annotated[Repository, Depends(repository)],
) -> Response:
    candidates = repo.retraining_candidates(limit=500)
    feature_names = list(FEATURE_NAMES)
    rows = [
        {
            **{key: value for key, value in candidate.items() if key != "features"},
            **candidate["features"],
        }
        for candidate in candidates
    ]
    fields = [
        "feedback_id",
        "alert_id",
        "timestamp",
        "disposition",
        "model_version",
        "feature_schema_version",
        "original_verdict",
        "original_risk",
        *feature_names,
    ]
    return _csv_response(rows, fields, "aegisflow-retraining-candidates.csv")


@app.get("/api/v1/hosts")
def list_hosts(repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    items = repo.hosts()
    return {"items": items, "count": len(items)}


@app.get("/api/v1/hosts/{host}")
def get_host(host: str, repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    item = next((value for value in repo.hosts() if value["host"] == host), None)
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "host_not_found"})
    return item


@app.get("/api/v1/models")
def list_models(repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    items = repo.models()
    return {"items": items, "count": len(items)}


@app.get("/api/v1/models/current")
def current_model(repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    items = repo.models()
    if not items:
        raise HTTPException(status_code=503, detail={"code": "model_unavailable"})
    return items[0]


@app.get("/api/v1/drift-events")
def drift_events(repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    items = repo.drift_events()
    return {"items": items, "count": len(items)}


@app.get("/api/v1/system/status")
def system_status(
    request: Request, repo: Annotated[Repository, Depends(repository)]
) -> dict[str, Any]:
    return _system_status(request.app, repo)


def _system_status(app: FastAPI, repo: Repository) -> dict[str, Any]:
    status = repo.status()
    consumer = cast(DetectionConsumer | None, getattr(app.state, "consumer", None))
    queue = (
        consumer.queue_status if consumer is not None else {"pending": 0, "lag": 0, "consumers": 0}
    )
    _record_queue_metrics(queue)
    worker = cast(
        RetentionWorker | None, getattr(app.state, "retention_worker", None)
    )
    return {
        **status,
        "queue": queue,
        "retention": retention_status(worker),
        "recent_health_events": repo.health_events(limit=10),
    }


def _record_queue_metrics(queue: dict[str, int]) -> None:
    QUEUE_LAG.labels("aegisflow:detections", "api-core").set(queue["lag"])
    QUEUE_PENDING.labels("aegisflow:detections", "api-core").set(queue["pending"])


async def _stream(websocket: WebSocket, kind: Literal["alerts", "system"]) -> None:
    await websocket.accept()
    WEBSOCKETS.inc()
    try:
        last_payload: str | None = None
        while True:
            repo: Repository = websocket.app.state.repository
            payload: Any = (
                {"type": "alerts", "items": repo.alerts(limit=20)}
                if kind == "alerts"
                else {"type": "system", **_system_status(websocket.app, repo)}
            )
            payload = jsonable_encoder(payload)
            serialized = str(payload)
            if serialized != last_payload:
                await websocket.send_json(payload)
                last_payload = serialized
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    finally:
        WEBSOCKETS.dec()


@app.websocket("/api/v1/stream/alerts")
async def alert_stream(websocket: WebSocket) -> None:
    await _stream(websocket, "alerts")


@app.websocket("/api/v1/stream/system")
async def system_stream(websocket: WebSocket) -> None:
    await _stream(websocket, "system")


def run() -> None:
    uvicorn.run("apps.api.main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    run()
