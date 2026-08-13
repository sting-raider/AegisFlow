from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import MetaData, Table, func, inspect, select

from apps.api.database import Repository, database_url_from_env
from packages.contracts import (
    AnalystFeedback,
    FeedbackDisposition,
    Severity,
    SignatureEvent,
)
from packages.detection import DetectionEngine
from packages.model_bundle import load_production_bundle
from services.sensor import DemoAdapter

SNAPSHOT_PREFIX = "AEGISFLOW_RESTORE_SNAPSHOT="
SMOKE_PREFIX = "AEGISFLOW_RESTORE_API_SMOKE="


def seed_fixture() -> dict[str, int]:
    repository = Repository(database_url_from_env())
    registry = Path(os.getenv("AEGISFLOW_MODEL_REGISTRY", "models/registry"))
    bundle = load_production_bundle(registry)
    engine = DetectionEngine(bundle)
    for flow in DemoAdapter().flows():
        signature = None
        if flow.protocol_metadata.get("scenario") == "known-signature":
            raw = b"aegisflow-safe-restore-signature"
            signature = SignatureEvent(
                event_id=uuid5(NAMESPACE_URL, "aegisflow-restore-signature"),
                timestamp=flow.timestamp_start,
                community_flow_id=flow.community_flow_id,
                signature_id="9000099",
                signature_name="AEGISFLOW RESTORE fixture authentication pattern",
                category="Attempted Administrator Privilege Gain",
                severity=Severity.HIGH,
                source="fixture",
                raw_event_hash=hashlib.sha256(raw).hexdigest(),
                metadata={"fixture": True},
            )
        repository.ingest(flow, engine.detect(flow, signature), signature)

    alerts = repository.alerts(limit=200)
    incidents = repository.incidents()
    if not alerts or not incidents:
        raise RuntimeError("restore fixture did not create required alert and incident rows")
    first_alert = alerts[0]
    alert_id = str(first_alert["id"])
    repository.acknowledge_alert(alert_id, "restore-analyst")
    repository.add_feedback(
        AnalystFeedback(
            alert_id=alert_id,
            actor="restore-analyst",
            disposition=FeedbackDisposition.TRUE_POSITIVE,
            comment="deterministic restore acceptance fixture",
            original_model_result=dict(first_alert["detection"]),
            model_version=bundle.version,
        )
    )
    incident_id = str(incidents[0]["id"])
    repository.set_incident_status(incident_id, "investigating", "restore-analyst")
    repository.add_incident_note(
        incident_id,
        "restore-analyst",
        "deterministic restore acceptance note",
    )
    repository.record_health_event(
        "restore-acceptance",
        "seeded",
        {"fixture_schema": "1.0.0"},
    )
    repository.record_audit_event(
        actor="restore-operator",
        action="restore_fixture_seeded",
        target_id="disposable-database",
        details={"fixture_schema": "1.0.0"},
    )
    repository.record_model(bundle.manifest)
    return {
        "flows": repository.flow_count(),
        "alerts": repository.alert_count(),
        "incidents": len(repository.incidents()),
    }


def database_snapshot() -> dict[str, object]:
    repository = Repository(database_url_from_env())
    inspector = inspect(repository.engine)
    metadata = MetaData()
    tables: dict[str, dict[str, object]] = {}
    migration_version = ""
    with repository.engine.connect() as connection:
        for table_name in sorted(inspector.get_table_names()):
            table = Table(table_name, metadata, autoload_with=repository.engine)
            count = int(connection.scalar(select(func.count()).select_from(table)) or 0)
            primary_columns = [column.name for column in table.primary_key.columns]
            statement = select(*(table.c[name] for name in primary_columns))
            if primary_columns:
                statement = statement.order_by(*(table.c[name] for name in primary_columns))
            identity_rows = [
                [str(value) for value in row]
                for row in connection.execute(statement)
            ]
            encoded = json.dumps(identity_rows, separators=(",", ":"), ensure_ascii=True)
            tables[table_name] = {
                "count": count,
                "identity_columns": primary_columns,
                "identity_sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
            }
            if table_name == "alembic_version" and identity_rows:
                migration_version = identity_rows[0][0]
    required = {
        "flows": 1,
        "detection_results": 1,
        "alerts": 1,
        "incidents": 1,
        "incident_alerts": 1,
        "analyst_feedback": 1,
        "audit_log": 1,
    }
    missing = []
    for name, minimum in required.items():
        table_snapshot = tables.get(name)
        count_value = (
            table_snapshot.get("count", 0) if isinstance(table_snapshot, dict) else 0
        )
        if not isinstance(count_value, int) or count_value < minimum:
            missing.append(name)
    if missing:
        raise RuntimeError(
            "restore snapshot is missing required entity tables: " + ",".join(missing)
        )
    return {
        "schema_version": "1.0.0",
        "captured_at": datetime.now(UTC).isoformat(),
        "migration_version": migration_version,
        "tables": tables,
        "required_entity_tables": sorted(required),
    }


def _get_json(url: str) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            if response.status != 200:
                raise RuntimeError(f"API returned status {response.status}")
            payload = json.loads(response.read(1_048_576))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError("restored API endpoint was unavailable or invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("restored API endpoint did not return a JSON object")
    return payload


def api_smoke(base_url: str = "http://127.0.0.1:8000") -> dict[str, object]:
    if base_url != "http://127.0.0.1:8000":
        raise ValueError("restore API smoke is restricted to container loopback")
    ready = _get_json(f"{base_url}/health/ready")
    flows = _get_json(f"{base_url}/api/v1/flows?limit=200")
    alerts = _get_json(f"{base_url}/api/v1/alerts?limit=200")
    incidents = _get_json(f"{base_url}/api/v1/incidents")
    status = _get_json(f"{base_url}/api/v1/system/status")
    counts = {
        "flows": int(flows.get("total", -1)),
        "alerts": int(alerts.get("total", -1)),
        "incidents": len(incidents.get("items", [])),
    }
    if ready != {"status": "ready"} or min(counts.values()) < 1:
        raise RuntimeError("restored API smoke did not expose required durable entities")
    if status.get("database") != "ready":
        raise RuntimeError("restored API system status did not report database readiness")
    return {
        "passed": True,
        "readiness": "ready",
        "database": "ready",
        "counts": counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed and inspect a disposable restore fixture")
    parser.add_argument("command", choices=("seed", "snapshot", "api-smoke"))
    args = parser.parse_args()
    if args.command == "seed":
        result: dict[str, object] = {"seeded": seed_fixture()}
        prefix = SNAPSHOT_PREFIX
    elif args.command == "snapshot":
        result = database_snapshot()
        prefix = SNAPSHOT_PREFIX
    else:
        result = api_smoke()
        prefix = SMOKE_PREFIX
    print(prefix + json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
