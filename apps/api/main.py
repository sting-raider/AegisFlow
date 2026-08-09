from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import os
import re
import secrets
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, cast
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import uvicorn
from fastapi import (
    Depends,
    FastAPI,
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
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field

from apps.api.auth import (
    AuthConfigurationError,
    AuthenticationError,
    Authenticator,
    Principal,
    PrincipalRateLimiter,
    Role,
)
from apps.api.consumer import DetectionConsumer
from apps.api.database import Repository
from apps.api.retention import RetentionWorker, retention_status, retention_worker_from_env
from packages.common import (
    FLOW_EXPORT_FIELDS,
    anonymize_ip,
    configure_json_logger,
    log_event,
    sanitize_flow_export,
    service_logger,
)
from packages.contracts import (
    AnalystFeedback,
    DetectionResult,
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
from packages.model_bundle import (
    BundleError,
    assess_candidate,
    load_production_bundle,
    promote_bundle,
    revalidate_candidate,
    rollback_production_bundle,
)
from packages.model_bundle.bundle import sha256_file
from services.sensor import DemoAdapter
from training.cli.train_smoke import train

DETECTIONS = Counter("detections_total", "Detection results", ["verdict"])
FLOWS_RECEIVED = Counter("flows_received_total", "Flow envelopes received")
FLOWS_VALIDATED = Counter("flows_validated_total", "Flow envelopes validated")
FLOWS_REJECTED = Counter("flows_rejected_total", "Invalid flow envelopes", ["error_code"])
FLOWS_DROPPED = Counter("flows_dropped_total", "Explicitly dropped flows", ["reason"])
ALERTS = Counter("alerts_total", "Alerts created", ["severity"])
UNKNOWN_ALERTS = Counter("unknown_alerts_total", "Suspicious unknown alerts")
INFERENCE = Histogram("inference_latency_seconds", "Single-flow inference latency")
PROCESSING = Histogram("processing_latency_seconds", "End-to-end event processing latency")
SIGNATURE_EVENTS = Counter("signature_events_total", "Validated signature events")
WEBSOCKETS = Gauge("websocket_connections", "Current WebSocket connections")
DATABASE_ERRORS = Counter("database_errors_total", "Database errors")
MODEL_LOAD_FAILURES = Counter("model_load_failures_total", "Model bundle load failures")
QUEUE_LAG = Gauge("queue_lag", "Undelivered Redis stream entries", ["stream", "group"])
QUEUE_PENDING = Gauge(
    "queue_pending", "Delivered but unacknowledged stream entries", ["stream", "group"]
)
QUEUE_CAPACITY = Gauge("queue_capacity_utilization", "Queue capacity used", ["stream"])
QUEUE_BACKPRESSURE = Counter(
    "queue_backpressure_events_total", "Queue capacity pressure events", ["stream"]
)
DRIFT_EVENTS = Counter("drift_events_total", "Detected runtime distribution shifts", ["signal"])
DRIFT_MAGNITUDE = Gauge("drift_magnitude", "Most recent drift magnitude", ["signal"])
EXPLANATIONS = Counter(
    "incident_explanations_total",
    "On-demand incident explanations",
    ["provider", "outcome"],
)
HTTP_BODY_REJECTIONS = Counter(
    "http_body_rejections_total", "HTTP requests rejected by body limits", ["reason"]
)
WEBSOCKET_REJECTIONS = Counter(
    "websocket_rejections_total", "WebSocket connections or payloads rejected", ["reason"]
)
AUTHENTICATION_FAILURES = Counter(
    "authentication_failures_total", "Rejected API authentication attempts", ["reason"]
)
AUTHORIZATION_DENIALS = Counter(
    "authorization_denials_total", "Authenticated requests denied by RBAC", ["required_role"]
)
RATE_LIMIT_REJECTIONS = Counter(
    "rate_limit_rejections_total", "Per-principal requests rejected", ["scope"]
)
LOGGER = service_logger("api")
_CORRELATION_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_websocket_connections = 0
_explicit_dropped_records = 0


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disposition: FeedbackDisposition
    comment: str = Field(default="", max_length=2000)
    eligible_for_retraining: bool = False


class IncidentStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "investigating", "contained", "closed"]


class IncidentNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(min_length=1, max_length=2000)


class ModelCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    evaluation_reports: list[str] = Field(min_length=1, max_length=20)


class ModelReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=2000)


def _record_drift_metric(event: DriftEvent) -> None:
    DRIFT_EVENTS.labels(event.signal).inc()
    DRIFT_MAGNITUDE.labels(event.signal).set(event.magnitude)


def _record_detection_metric(detection: DetectionResult, alert_created: bool) -> None:
    DETECTIONS.labels(detection.verdict.value).inc()
    INFERENCE.observe(detection.inference_latency_ms / 1000)
    if alert_created:
        ALERTS.labels(detection.severity.value).inc()
        if detection.verdict.value == "suspicious_unknown":
            UNKNOWN_ALERTS.inc()


def _record_flow_drop(reason: str) -> None:
    global _explicit_dropped_records
    _explicit_dropped_records += 1
    FLOWS_DROPPED.labels(reason).inc()


def _seed_demo(
    repository: Repository, engine: DetectionEngine, drift_monitor: RuntimeDriftMonitor
) -> None:
    for flow in DemoAdapter().flows():
        FLOWS_RECEIVED.inc()
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
        FLOWS_VALIDATED.inc()
        if signature is not None:
            SIGNATURE_EVENTS.inc()
        try:
            alert_id = repository.ingest(flow, detection, signature)
        except Exception:
            DATABASE_ERRORS.inc()
            raise
        _record_detection_metric(detection, alert_id is not None)
        for event in drift_monitor.observe(flow, detection):
            if repository.record_drift_event(event):
                _record_drift_metric(event)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_json_logger("uvicorn.access", "api-access", replace_handlers=True)
    configure_json_logger("uvicorn.error", "api-runtime", replace_handlers=True)
    authenticator = Authenticator.from_env()
    rate_limiter = PrincipalRateLimiter.from_env()
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
    repository.reconcile_pending_model_promotions(
        active_model_name=str(bundle.manifest["model_name"]),
        active_version=bundle.version,
        active_bundle_digest=sha256_file(bundle.root / "checksums.sha256"),
    )
    app.state.repository = repository
    app.state.authenticator = authenticator
    app.state.rate_limiter = rate_limiter
    app.state.model_registry = registry
    app.state.evaluation_root = Path(
        os.getenv("AEGISFLOW_EVALUATION_REPORT_DIR", "docs/evaluation")
    )
    app.state.model_version = bundle.version
    app.state.engine = engine
    app.state.drift_monitor = drift_monitor
    app.state.explanation_service = explanation_service_from_env()
    repository.record_health_event(
        "api",
        "ready",
        {
            "mode": "demo" if os.getenv("AEGISFLOW_DEMO", "1") == "1" else "production",
            "auth_mode": authenticator.settings.mode,
        },
    )
    log_event(
        LOGGER,
        "api_ready",
        model_version=str(bundle.manifest["version"]),
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
            on_flow_received=FLOWS_RECEIVED.inc,
            on_flow_validated=FLOWS_VALIDATED.inc,
            on_flow_rejected=lambda code: FLOWS_REJECTED.labels(code).inc(),
            on_flow_dropped=_record_flow_drop,
            on_signature_event=SIGNATURE_EVENTS.inc,
            on_processing_latency=PROCESSING.observe,
            on_detection_result=_record_detection_metric,
            on_backpressure=lambda: QUEUE_BACKPRESSURE.labels(
                "aegisflow:detections"
            ).inc(),
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
    log_event(LOGGER, "api_stopped", model_version=str(bundle.manifest["version"]))


class AegisFlowAPI(FastAPI):
    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is not None:
            return self.openapi_schema
        schema = get_openapi(
            title=self.title,
            version=self.version,
            description=self.description,
            routes=self.routes,
        )
        components = schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})
        security_schemes.update(
            {
                "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            }
        )
        for path, path_item in schema.get("paths", {}).items():
            if not isinstance(path_item, dict) or not (
                path.startswith("/api/v1/") or path == "/metrics"
            ):
                continue
            for operation in path_item.values():
                if isinstance(operation, dict) and "responses" in operation:
                    operation["security"] = [{"BearerAuth": []}, {"ApiKeyAuth": []}]
        self.openapi_schema = schema
        return schema


def _cors_origins_from_env() -> tuple[str, ...]:
    origins = tuple(
        dict.fromkeys(
            value.strip()
            for value in os.getenv(
                "AEGISFLOW_CORS_ORIGINS",
                "http://localhost:5173,http://127.0.0.1:5173",
            ).split(",")
            if value.strip()
        )
    )
    if not origins or len(origins) > 32:
        raise AuthConfigurationError("CORS origins must contain between 1 and 32 values")
    for origin in origins:
        parsed = urlsplit(origin)
        host = (parsed.hostname or "").lower()
        loopback = host in {"localhost", "127.0.0.1", "::1"}
        try:
            _ = parsed.port
        except ValueError as exc:
            raise AuthConfigurationError("CORS origin contains an invalid port") from exc
        if (
            origin == "*"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))
        ):
            raise AuthConfigurationError(
                "CORS origins must be exact HTTPS origins or loopback HTTP origins"
            )
    return origins


_CORS_ORIGINS = _cors_origins_from_env()


app = AegisFlowAPI(
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
    allow_origins=list(_CORS_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Correlation-ID"],
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
    log_event(
        LOGGER,
        "http_internal_error",
        level="error",
        correlation_id=getattr(request.state, "correlation_id", None),
        error_code=type(exc).__name__,
    )
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
    supplied_correlation = request.headers.get("X-Correlation-ID")
    correlation = (
        supplied_correlation
        if supplied_correlation is not None and _CORRELATION_ID.fullmatch(supplied_correlation)
        else str(uuid4())
    )
    request.state.correlation_id = correlation
    if request.url.path.startswith("/api/v1/") or request.url.path == "/metrics":
        authenticator = cast(Authenticator, request.app.state.authenticator)
        try:
            principal = authenticator.authenticate_headers(request.headers)
        except AuthenticationError as exc:
            AUTHENTICATION_FAILURES.labels(exc.code).inc()
            log_event(
                LOGGER,
                "authentication_rejected",
                level="warning" if exc.status_code < 500 else "error",
                correlation_id=correlation,
                error_code=exc.code,
            )
            auth_response = _middleware_error(exc.status_code, exc.code, correlation)
            auth_response.headers["WWW-Authenticate"] = exc.challenge
            return auth_response
        if not principal.allows(Role.VIEWER):
            AUTHORIZATION_DENIALS.labels(Role.VIEWER.value).inc()
            return _middleware_error(403, "insufficient_role", correlation)
        scope: Literal["read", "mutation"] = (
            "read" if request.method in {"GET", "HEAD", "OPTIONS"} else "mutation"
        )
        limiter = cast(PrincipalRateLimiter, request.app.state.rate_limiter)
        if not limiter.allow(principal, scope):
            RATE_LIMIT_REJECTIONS.labels(scope).inc()
            limited_response = _middleware_error(429, "rate_limit_exceeded", correlation)
            limited_response.headers["Retry-After"] = "60"
            return limited_response
        request.state.principal = principal
    if request.method in {"POST", "PUT", "PATCH"}:
        maximum = _bounded_environment_int(
            "AEGISFLOW_HTTP_MAX_BODY_BYTES", 65_536, 1_024, 1_048_576
        )
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                HTTP_BODY_REJECTIONS.labels("invalid_content_length").inc()
                return _middleware_error(400, "invalid_content_length", correlation)
            if declared_length < 0 or declared_length > maximum:
                HTTP_BODY_REJECTIONS.labels("declared_too_large").inc()
                return _middleware_error(413, "request_body_too_large", correlation)
        body = await request.body()
        if len(body) > maximum:
            HTTP_BODY_REJECTIONS.labels("actual_too_large").inc()
            return _middleware_error(413, "request_body_too_large", correlation)
    response: Response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def _middleware_error(status: int, code: str, correlation: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": "Request could not be completed",
                "correlation_id": correlation,
            }
        },
        headers={"X-Correlation-ID": correlation, "Cache-Control": "no-store"},
    )


def _bounded_environment_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def repository(request: Request) -> Repository:
    return cast(Repository, request.app.state.repository)


def explanation_service(request: Request) -> ExplanationService:
    return cast(ExplanationService, request.app.state.explanation_service)


def current_principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, Principal):
        raise HTTPException(status_code=401, detail={"code": "credentials_required"})
    return principal


def _authorize(principal: Principal, required: Role) -> Principal:
    if not principal.allows(required):
        AUTHORIZATION_DENIALS.labels(required.value).inc()
        raise HTTPException(status_code=403, detail={"code": "insufficient_role"})
    return principal


def analyst_principal(
    principal: Annotated[Principal, Depends(current_principal)],
) -> Principal:
    return _authorize(principal, Role.ANALYST)


def admin_principal(
    principal: Annotated[Principal, Depends(current_principal)],
) -> Principal:
    return _authorize(principal, Role.ADMIN)


def _governance_enabled() -> bool:
    return os.getenv("AEGISFLOW_MODEL_GOVERNANCE_ENABLED", "0") == "1"


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


@app.get("/api/v1/auth/me")
def auth_me(
    principal: Annotated[Principal, Depends(current_principal)],
) -> dict[str, Any]:
    return principal.as_dict()


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


@app.post("/api/v1/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: UUID,
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(analyst_principal)],
) -> dict[str, Any]:
    if not repo.acknowledge_alert(str(alert_id), principal.subject):
        raise HTTPException(status_code=404, detail={"code": "alert_not_found"})
    return {"id": str(alert_id), "acknowledged": True, "actor": principal.subject}


@app.post("/api/v1/alerts/{alert_id}/feedback")
def submit_feedback(
    alert_id: UUID,
    body: FeedbackRequest,
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(analyst_principal)],
) -> dict[str, Any]:
    alert = repo.alert(str(alert_id))
    if alert is None:
        raise HTTPException(status_code=404, detail={"code": "alert_not_found"})
    feedback = AnalystFeedback(
        alert_id=alert_id,
        actor=principal.subject,
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
    principal: Annotated[Principal, Depends(analyst_principal)],
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
    repo.record_audit_event(
        actor=principal.subject,
        action="incident_explanation_requested",
        target_id=str(incident_id),
        details={"provider": result.provider, "outcome": outcome},
    )
    return result.as_dict()


@app.post("/api/v1/incidents/{incident_id}/status")
def set_incident_status(
    incident_id: UUID,
    body: IncidentStatusRequest,
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(analyst_principal)],
) -> dict[str, str]:
    if not repo.set_incident_status(str(incident_id), body.status, principal.subject):
        raise HTTPException(status_code=404, detail={"code": "incident_not_found"})
    return {"id": str(incident_id), "status": body.status}


@app.post("/api/v1/incidents/{incident_id}/notes")
def add_incident_note(
    incident_id: UUID,
    body: IncidentNoteRequest,
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(analyst_principal)],
) -> dict[str, Any]:
    note = repo.add_incident_note(str(incident_id), principal.subject, body.note)
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
    principal: Annotated[Principal, Depends(analyst_principal)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> dict[str, Any]:
    items = repo.retraining_candidates(offset=offset, limit=limit)
    repo.record_audit_event(
        actor=principal.subject,
        action="retraining_candidates_viewed",
        target_id="retraining-candidates",
        details={"count": len(items), "offset": offset, "limit": limit},
    )
    return {"items": items, "offset": offset, "limit": limit, "count": len(items)}


@app.get("/api/v1/exports/flows.csv")
def export_flows(
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(current_principal)],
    event_id: Annotated[list[UUID] | None, Query(max_length=200)] = None,
    anonymize_ips: bool = True,
    protocol: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    host: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> Response:
    if not anonymize_ips:
        _authorize(principal, Role.ADMIN)
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
    if not anonymize_ips:
        repo.record_audit_event(
            actor=principal.subject,
            action="raw_flow_export_created",
            target_id="flow-export",
            details={"row_count": len(rows)},
        )
    return _csv_response(rows, list(FLOW_EXPORT_FIELDS), "aegisflow-flows.csv")


@app.get("/api/v1/exports/alerts.csv")
def export_alerts(
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(current_principal)],
    alert_id: Annotated[list[UUID] | None, Query(max_length=200)] = None,
    anonymize_ips: bool = True,
    severity: Severity | None = None,
    verdict: Verdict | None = None,
    protocol: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    host: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> Response:
    if not anonymize_ips:
        _authorize(principal, Role.ADMIN)
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
    if not anonymize_ips:
        repo.record_audit_event(
            actor=principal.subject,
            action="raw_alert_export_created",
            target_id="alert-export",
            details={"row_count": len(rows)},
        )
    return _csv_response(rows, fields, "aegisflow-alerts.csv")


@app.get("/api/v1/exports/retraining-candidates.csv")
def export_retraining_candidates(
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(analyst_principal)],
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
    repo.record_audit_event(
        actor=principal.subject,
        action="retraining_candidates_exported",
        target_id="retraining-candidate-export",
        details={"row_count": len(rows)},
    )
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


@app.get("/api/v1/model-candidates")
def list_model_candidates(
    repo: Annotated[Repository, Depends(repository)],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> dict[str, Any]:
    items = repo.model_candidates(limit=limit)
    return {"items": items, "count": len(items)}


@app.get("/api/v1/model-candidates/{candidate_id}")
def get_model_candidate(
    candidate_id: str,
    repo: Annotated[Repository, Depends(repository)],
) -> dict[str, Any]:
    candidate = repo.model_candidate(candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail={"code": "model_candidate_not_found"})
    return candidate


@app.post("/api/v1/model-candidates/{model_name}")
def register_model_candidate(
    model_name: str,
    body: ModelCandidateRequest,
    request: Request,
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(admin_principal)],
) -> dict[str, Any]:
    registry = cast(Path, request.app.state.model_registry)
    evaluation_root = cast(Path, request.app.state.evaluation_root)
    try:
        assessment = assess_candidate(
            registry,
            evaluation_root,
            model_name,
            body.version,
            body.evaluation_reports,
        )
        return repo.register_model_candidate(assessment.as_dict(), actor=principal.subject)
    except BundleError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_model_candidate"},
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=409, detail={"code": "candidate_evidence_conflict"}
        ) from exc


@app.post("/api/v1/model-candidates/{candidate_id}/reviews")
def review_model_candidate(
    candidate_id: str,
    body: ModelReviewRequest,
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(analyst_principal)],
) -> dict[str, Any]:
    try:
        return repo.review_model_candidate(
            candidate_id,
            actor=principal.subject,
            decision=body.decision,
            comment=body.comment,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404, detail={"code": "model_candidate_not_found"}
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=409, detail={"code": "model_candidate_review_conflict"}
        ) from exc


@app.post("/api/v1/model-candidates/{candidate_id}/promote")
def promote_model_candidate(
    candidate_id: str,
    request: Request,
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(admin_principal)],
) -> dict[str, Any]:
    if not _governance_enabled():
        raise HTTPException(status_code=503, detail={"code": "model_governance_disabled"})
    candidate = repo.model_candidate(candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail={"code": "model_candidate_not_found"})
    registry = cast(Path, request.app.state.model_registry)
    evaluation_root = cast(Path, request.app.state.evaluation_root)
    try:
        revalidate_candidate(registry, evaluation_root, candidate)
        repo.begin_model_promotion(candidate_id, actor=principal.subject)
        promote_bundle(
            registry,
            str(candidate["model_name"]),
            str(candidate["version"]),
        )
        promoted = load_production_bundle(registry, str(candidate["model_name"]))
        if promoted.version != candidate["version"]:
            raise BundleError("promoted model could not be loaded exactly")
    except (BundleError, KeyError, OSError, ValueError) as exc:
        pending = repo.model_candidate(candidate_id)
        if pending is not None and pending["status"] == "promotion_pending":
            repo.finish_model_promotion(
                candidate_id,
                actor=principal.subject,
                manifest=None,
                error_code=type(exc).__name__,
            )
        raise HTTPException(status_code=409, detail={"code": "model_promotion_rejected"}) from exc
    result = repo.finish_model_promotion(
        candidate_id,
        actor=principal.subject,
        manifest=promoted.manifest,
    )
    return {
        **result,
        "restart_required": True,
        "loaded_runtime_version": str(request.app.state.model_version),
    }


@app.post("/api/v1/models/{model_name}/rollback")
def rollback_model(
    model_name: str,
    request: Request,
    repo: Annotated[Repository, Depends(repository)],
    principal: Annotated[Principal, Depends(admin_principal)],
) -> dict[str, Any]:
    if not _governance_enabled():
        raise HTTPException(status_code=503, detail={"code": "model_governance_disabled"})
    registry = cast(Path, request.app.state.model_registry)
    try:
        previous = load_production_bundle(registry, model_name)
        rolled_back = rollback_production_bundle(registry, model_name)
    except (BundleError, OSError) as exc:
        repo.record_audit_event(
            actor=principal.subject,
            action="model_rollback_failed",
            target_id=model_name,
            details={"error_code": type(exc).__name__},
        )
        raise HTTPException(status_code=409, detail={"code": "model_rollback_rejected"}) from exc
    repo.record_model_rollback(
        model_name=model_name,
        from_version=previous.version,
        to_version=rolled_back.version,
        actor=principal.subject,
    )
    return {
        "model_name": model_name,
        "version": rolled_back.version,
        "previous_version": previous.version,
        "restart_required": True,
        "loaded_runtime_version": str(request.app.state.model_version),
    }


@app.get("/api/v1/audit-events")
def list_audit_events(
    repo: Annotated[Repository, Depends(repository)],
    _principal: Annotated[Principal, Depends(admin_principal)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    actor: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    action: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
) -> dict[str, Any]:
    items = repo.audit_events(offset=offset, limit=limit, actor=actor, action=action)
    return {"items": items, "offset": offset, "limit": limit, "count": len(items)}


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
    global _explicit_dropped_records
    status = repo.status()
    consumer = cast(DetectionConsumer | None, getattr(app.state, "consumer", None))
    queue = (
        consumer.queue_status
        if consumer is not None
        else {
            "pending": 0,
            "lag": 0,
            "consumers": 0,
            "capacity": 100_000,
            "utilization": 0.0,
            "backpressure": False,
            "backpressure_events": 0,
        }
    )
    _record_queue_metrics(queue)
    worker = cast(
        RetentionWorker | None, getattr(app.state, "retention_worker", None)
    )
    telemetry = consumer.telemetry() if consumer is not None else {
        "dropped_total": 0,
        "throughput_per_second": 0.0,
        "processing_latency_ms": None,
    }
    return {
        **status,
        "queue": queue,
        "throughput_per_second": telemetry["throughput_per_second"],
        "dropped_records": _explicit_dropped_records,
        "worker_latency_ms": telemetry["processing_latency_ms"],
        "suricata_status": (
            "fixture"
            if status["mode"] == "demo" and status["signature_events"]
            else "observed"
            if status["signature_events"]
            else "not_configured"
        ),
        "auth_mode": cast(Authenticator, app.state.authenticator).settings.mode,
        "model_governance_enabled": _governance_enabled(),
        "loaded_runtime_version": str(app.state.model_version),
        "retention": retention_status(worker),
        "recent_health_events": repo.health_events(limit=10),
    }


def _record_queue_metrics(queue: Mapping[str, int | float | bool]) -> None:
    QUEUE_LAG.labels("aegisflow:detections", "api-core").set(float(queue["lag"]))
    QUEUE_PENDING.labels("aegisflow:detections", "api-core").set(
        float(queue["pending"])
    )
    QUEUE_CAPACITY.labels("aegisflow:detections").set(float(queue.get("utilization", 0)))


async def _stream(websocket: WebSocket, kind: Literal["alerts", "system"]) -> None:
    global _websocket_connections
    allowed_origins = set(_CORS_ORIGINS)
    origin = websocket.headers.get("origin")
    if origin is not None and origin not in allowed_origins:
        WEBSOCKET_REJECTIONS.labels("origin").inc()
        await websocket.close(code=1008, reason="origin not allowed")
        return
    authenticator = cast(Authenticator, websocket.app.state.authenticator)
    try:
        principal, subprotocol = authenticator.authenticate_websocket(websocket.headers)
    except AuthenticationError as exc:
        AUTHENTICATION_FAILURES.labels(exc.code).inc()
        WEBSOCKET_REJECTIONS.labels("authentication").inc()
        await websocket.close(
            code=1013 if exc.status_code >= 500 else 1008,
            reason=(
                "authentication unavailable"
                if exc.status_code >= 500
                else "authentication required"
            ),
        )
        return
    if not principal.allows(Role.VIEWER):
        AUTHORIZATION_DENIALS.labels(Role.VIEWER.value).inc()
        WEBSOCKET_REJECTIONS.labels("authorization").inc()
        await websocket.close(code=1008, reason="insufficient role")
        return
    limiter = cast(PrincipalRateLimiter, websocket.app.state.rate_limiter)
    if not limiter.allow(principal, "websocket"):
        RATE_LIMIT_REJECTIONS.labels("websocket").inc()
        WEBSOCKET_REJECTIONS.labels("rate_limit").inc()
        await websocket.close(code=1013, reason="connection rate limit reached")
        return
    maximum_connections = _bounded_environment_int(
        "AEGISFLOW_WEBSOCKET_MAX_CONNECTIONS", 32, 1, 1024
    )
    if _websocket_connections >= maximum_connections:
        WEBSOCKET_REJECTIONS.labels("connection_limit").inc()
        await websocket.close(code=1013, reason="connection limit reached")
        return
    _websocket_connections += 1
    accepted = False
    try:
        await websocket.accept(subprotocol=subprotocol)
        accepted = True
        WEBSOCKETS.inc()
        last_payload: str | None = None
        while True:
            repo: Repository = websocket.app.state.repository
            payload: Any = (
                {"type": "alerts", "items": repo.alerts(limit=20)}
                if kind == "alerts"
                else {"type": "system", **_system_status(websocket.app, repo)}
            )
            payload = jsonable_encoder(payload)
            serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
            maximum_payload = _bounded_environment_int(
                "AEGISFLOW_WEBSOCKET_MAX_PAYLOAD_BYTES", 262_144, 4096, 1_048_576
            )
            if len(serialized.encode()) > maximum_payload:
                WEBSOCKET_REJECTIONS.labels("payload_limit").inc()
                _record_flow_drop("websocket_payload_limit")
                log_event(
                    LOGGER,
                    "websocket_payload_rejected",
                    level="error",
                    error_code="payload_limit",
                )
                serialized = json.dumps(
                    {
                        "type": "processing_error",
                        "error": {"code": "websocket_payload_too_large"},
                    },
                    separators=(",", ":"),
                )
            if serialized != last_payload:
                await websocket.send_text(serialized)
                last_payload = serialized
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    finally:
        _websocket_connections = max(0, _websocket_connections - 1)
        if accepted:
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
