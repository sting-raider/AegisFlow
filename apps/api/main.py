from __future__ import annotations

import asyncio
import hashlib
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
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
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field

from apps.api.consumer import DetectionConsumer
from apps.api.database import Repository
from packages.contracts import (
    AnalystFeedback,
    FeedbackDisposition,
    Severity,
    SignatureEvent,
)
from packages.detection import DetectionEngine
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


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor: str = Field(min_length=1, max_length=128)
    disposition: FeedbackDisposition
    comment: str = Field(default="", max_length=2000)
    eligible_for_retraining: bool = False


class IncidentStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "investigating", "contained", "closed"]


def _seed_demo(repository: Repository, engine: DetectionEngine) -> None:
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
    repository.record_model(bundle.manifest)
    app.state.repository = repository
    app.state.engine = engine
    consumer: DetectionConsumer | None = None
    app.state.consumer = None
    if os.getenv("AEGISFLOW_CONSUME_REDIS", "0") == "1":
        consumer = DetectionConsumer(
            repository,
            os.getenv("AEGISFLOW_REDIS_URL", "redis://redis:6379/0"),
            on_database_error=DATABASE_ERRORS.inc,
        )
        app.state.consumer = consumer
        consumer.start()
    if os.getenv("AEGISFLOW_DEMO_SEED", "1") == "1":
        _seed_demo(repository, engine)
    yield
    if consumer is not None:
        consumer.stop()


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


@app.middleware("http")
async def correlation_id(request: Request, call_next: Any) -> Response:
    correlation = request.headers.get("X-Correlation-ID", str(uuid4()))[:128]
    response: Response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


def repository(request: Request) -> Repository:
    return cast(Repository, request.app.state.repository)


def mutation_auth(x_api_key: Annotated[str | None, Header()] = None) -> None:
    expected = os.getenv("AEGISFLOW_API_KEY")
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail={"code": "invalid_api_key"})


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
    severity: str | None = None,
    verdict: str | None = None,
    host: str | None = None,
) -> dict[str, Any]:
    items = repo.alerts(offset=offset, limit=limit, severity=severity, verdict=verdict, host=host)
    return {"items": items, "offset": offset, "limit": limit, "count": len(items)}


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: UUID, repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    item = repo.alert(str(alert_id))
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "alert_not_found"})
    return item


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


@app.post("/api/v1/incidents/{incident_id}/status", dependencies=[Depends(mutation_auth)])
def set_incident_status(
    incident_id: UUID,
    body: IncidentStatusRequest,
    repo: Annotated[Repository, Depends(repository)],
) -> dict[str, str]:
    if not repo.set_incident_status(str(incident_id), body.status):
        raise HTTPException(status_code=404, detail={"code": "incident_not_found"})
    return {"id": str(incident_id), "status": body.status}


@app.get("/api/v1/flows")
def list_flows(
    repo: Annotated[Repository, Depends(repository)],
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    items = repo.flows(offset=offset, limit=limit)
    return {"items": items, "offset": offset, "limit": limit, "count": len(items)}


@app.get("/api/v1/flows/{event_id}")
def get_flow(event_id: UUID, repo: Annotated[Repository, Depends(repository)]) -> dict[str, Any]:
    item = repo.flow(str(event_id))
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "flow_not_found"})
    return item


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
    return {**status, "queue": queue}


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
