from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from apps.api.auth import AuthConfigurationError
from apps.api.main import _cors_origins_from_env, app
from services.sensor import DemoAdapter


def test_cors_origins_reject_wildcards_and_non_tls_remote_origins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISFLOW_CORS_ORIGINS", "*")
    with pytest.raises(AuthConfigurationError, match="exact HTTPS"):
        _cors_origins_from_env()
    monkeypatch.setenv("AEGISFLOW_CORS_ORIGINS", "http://dashboard.example.test")
    with pytest.raises(AuthConfigurationError, match="exact HTTPS"):
        _cors_origins_from_env()
    monkeypatch.setenv(
        "AEGISFLOW_CORS_ORIGINS",
        "https://dashboard.example.test,http://127.0.0.1:5173",
    )
    assert _cors_origins_from_env() == (
        "https://dashboard.example.test",
        "http://127.0.0.1:5173",
    )


def test_api_vertical_slice(
    monkeypatch: pytest.MonkeyPatch, registry: Path, tmp_path: Path
) -> None:
    monkeypatch.setenv("AEGISFLOW_DATABASE_URL", f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    monkeypatch.setenv("AEGISFLOW_MODEL_REGISTRY", str(registry))
    monkeypatch.setenv("AEGISFLOW_DEMO", "1")
    monkeypatch.setenv("AEGISFLOW_DEMO_SEED", "1")
    monkeypatch.setenv("AEGISFLOW_EXPLANATION_PROVIDER", "disabled")
    monkeypatch.setenv("AEGISFLOW_RETENTION_ENABLED", "0")
    monkeypatch.setenv("AEGISFLOW_AUTH_MODE", "demo")
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/health/ready").json() == {"status": "ready"}
        security_schemes = client.get("/openapi.json").json()["components"]["securitySchemes"]
        assert set(security_schemes) >= {"BearerAuth", "ApiKeyAuth"}
        initial_queue = client.get("/api/v1/system/status").json()["queue"]
        assert {key: initial_queue[key] for key in ("pending", "lag", "consumers")} == {
            "pending": 0,
            "lag": 0,
            "consumers": 0,
        }
        assert initial_queue["capacity"] == 100_000
        assert initial_queue["backpressure"] is False
        metrics = client.get("/metrics").text
        for metric_name in (
            "flows_received_total",
            "flows_validated_total",
            "flows_rejected_total",
            "flows_dropped_total",
            "detections_total",
            "alerts_total",
            "unknown_alerts_total",
            "signature_events_total",
            "inference_latency_seconds",
            "processing_latency_seconds",
            "queue_lag",
            "model_load_failures_total",
            "websocket_connections",
            "drift_events_total",
            "database_errors_total",
            "queue_backpressure_events_total",
            "authentication_failures_total",
            "authorization_denials_total",
            "rate_limit_rejections_total",
        ):
            assert metric_name in metrics
        assert client.get("/api/v1/drift-events").status_code == 200
        alerts = client.get("/api/v1/alerts").json()["items"]
        assert alerts
        assert {item["verdict"] for item in alerts} >= {"known_attack", "suspicious_unknown"}
        first_alert = alerts[0]
        filtered = client.get(
            "/api/v1/alerts",
            params={
                "host": first_alert["flow"]["src_ip"],
                "protocol": first_alert["flow"]["protocol"].lower(),
                "verdict": first_alert["verdict"],
                "start": "2020-01-01T00:00:00Z",
                "end": "2030-01-01T00:00:00Z",
            },
        ).json()
        assert filtered["total"] >= 1
        assert filtered["count"] == len(filtered["items"])
        assert all(
            item["flow"]["protocol"] == first_alert["flow"]["protocol"]
            for item in filtered["items"]
        )
        invalid_range = client.get(
            "/api/v1/alerts",
            params={"start": "2030-01-01T00:00:00Z", "end": "2020-01-01T00:00:00Z"},
            headers={"X-Correlation-ID": "api-test-correlation"},
        )
        assert invalid_range.status_code == 422
        assert invalid_range.json() == {
            "error": {
                "code": "invalid_date_range",
                "message": "start must not follow end",
                "correlation_id": "api-test-correlation",
            }
        }
        naive_date = client.get("/api/v1/flows", params={"start": "2026-08-01T00:00:00"})
        assert naive_date.status_code == 422
        assert naive_date.json()["error"]["code"] == "timezone_required"
        detail = client.get(f"/api/v1/alerts/{alerts[0]['id']}")
        assert detail.status_code == 200
        acknowledged = client.post(
            f"/api/v1/alerts/{alerts[0]['id']}/acknowledge",
        )
        assert acknowledged.status_code == 200
        assert client.get(f"/api/v1/alerts/{alerts[0]['id']}").json()["acknowledged"] is True
        feedback = client.post(
            f"/api/v1/alerts/{alerts[0]['id']}/feedback",
            json={
                "disposition": "requires_investigation",
                "comment": "check adjacent flows",
            },
        )
        assert feedback.status_code == 200
        retraining_feedback = client.post(
            f"/api/v1/alerts/{alerts[0]['id']}/feedback",
            json={
                "disposition": "benign_new_behaviour",
                "comment": "approved pattern from private host",
                "eligible_for_retraining": True,
            },
        )
        assert retraining_feedback.status_code == 200
        candidates = client.get("/api/v1/retraining-candidates").json()["items"]
        assert len(candidates) == 1
        assert "src_ip" not in str(candidates)
        assert "private host" not in str(candidates)
        assert "actor" not in str(candidates)
        assert candidates[0]["disposition"] == "benign_new_behaviour"
        candidate_csv = client.get("/api/v1/exports/retraining-candidates.csv")
        assert candidate_csv.status_code == 200
        assert "duration_ms" in candidate_csv.text
        assert first_alert["flow"]["src_ip"] not in candidate_csv.text
        flow_id = first_alert["flow"]["event_id"]
        flow_detail = client.get(f"/api/v1/flows/{flow_id}").json()
        assert flow_detail["detection"] is not None
        assert flow_detail["alert_id"] == first_alert["id"]
        exported_flows = client.get(
            "/api/v1/exports/flows.csv", params={"event_id": flow_id}
        )
        assert exported_flows.status_code == 200
        assert "attachment" in exported_flows.headers["content-disposition"]
        assert first_alert["flow"]["src_ip"] not in exported_flows.text
        assert "ip_" in exported_flows.text
        allowed_raw_export = client.get(
            "/api/v1/exports/flows.csv",
            params={"event_id": flow_id, "anonymize_ips": "false"},
        )
        assert first_alert["flow"]["src_ip"] in allowed_raw_export.text
        exported_alerts = client.get(
            "/api/v1/exports/alerts.csv",
            params={
                "host": first_alert["flow"]["src_ip"],
                "protocol": first_alert["flow"]["protocol"],
                "verdict": first_alert["verdict"],
            },
        )
        assert exported_alerts.status_code == 200
        assert first_alert["flow"]["src_ip"] not in exported_alerts.text
        missing = client.get(
            "/api/v1/alerts/00000000-0000-0000-0000-000000000000",
            headers={"X-Correlation-ID": "missing-test"},
        )
        assert missing.status_code == 404
        assert missing.json()["error"] == {
            "code": "alert_not_found",
            "message": "Request could not be completed",
            "correlation_id": "missing-test",
        }
        incidents = client.get("/api/v1/incidents").json()["items"]
        assert incidents
        incident_detail = client.get(f"/api/v1/incidents/{incidents[0]['id']}").json()
        assert incident_detail["timeline"]
        assert incident_detail["alerts"]
        assert incident_detail["attack_stages"]
        assert incident_detail["alert_count"] == len(incident_detail["alert_ids"])
        note = client.post(
            f"/api/v1/incidents/{incidents[0]['id']}/notes",
            json={"note": "Review authentication sequence"},
        )
        assert note.status_code == 200
        noted_incident = client.get(f"/api/v1/incidents/{incidents[0]['id']}").json()
        assert noted_incident["analyst_notes"] == [
            {
                "id": note.json()["id"],
                "actor": "demo-analyst",
                "note": "Review authentication sequence",
                "timestamp": note.json()["timestamp"],
            }
        ]
        with monkeypatch.context() as body_limit:
            body_limit.setenv("AEGISFLOW_HTTP_MAX_BODY_BYTES", "1024")
            oversized = client.post(
                f"/api/v1/incidents/{incidents[0]['id']}/notes",
                json={"note": "x" * 1500},
                headers={"X-Correlation-ID": "body-limit-test"},
            )
        assert oversized.status_code == 413
        assert oversized.json()["error"] == {
            "code": "request_body_too_large",
            "message": "Request could not be completed",
            "correlation_id": "body-limit-test",
        }
        replaced_correlation = client.get(
            "/health/live", headers={"X-Correlation-ID": "invalid correlation value"}
        ).headers["X-Correlation-ID"]
        assert replaced_correlation != "invalid correlation value"
        status_update = client.post(
            f"/api/v1/incidents/{incidents[0]['id']}/status",
            json={"status": "investigating"},
        )
        assert status_update.json()["status"] == "investigating"
        explanation = client.get(
            f"/api/v1/incidents/{incidents[0]['id']}/explanation"
        ).json()
        assert explanation["provider"] == "template"
        assert explanation["requested_provider"] == "disabled"
        assert explanation["ai_generated"] is False
        assert explanation["fallback"] is False
        assert len(explanation["incident_version_hash"]) == 64
        assert incidents[0]["source_host"] not in explanation["text"]
        assert "cannot authorize" in explanation["text"]
        assert "incident_explanations_total" in client.get("/metrics").text
        assert client.get("/api/v1/models/current").status_code == 200
        system = client.get("/api/v1/system/status").json()
        assert system["retention"] == {"enabled": False}
        assert system["suricata_status"] == "fixture"
        assert system["dropped_records"] == 0
        assert system["throughput_per_second"] == 0.0
        assert system["worker_latency_ms"] is None
        with monkeypatch.context() as failure:
            failure.setattr(
                app.state.repository,
                "status",
                lambda: (_ for _ in ()).throw(RuntimeError("secret database detail")),
            )
            internal_error = client.get(
                "/health/ready", headers={"X-Correlation-ID": "internal-test"}
            )
        assert internal_error.status_code == 500
        assert internal_error.json()["error"] == {
            "code": "internal_error",
            "message": "An internal processing error occurred",
            "correlation_id": "internal-test",
        }
        assert "secret database detail" not in internal_error.text
        with client.websocket_connect("/api/v1/stream/alerts") as websocket:
            message = websocket.receive_json()
            assert message["type"] == "alerts"
            assert message["items"]
        with pytest.raises(WebSocketDisconnect) as rejected_origin:
            with client.websocket_connect(
                "/api/v1/stream/alerts", headers={"origin": "https://untrusted.example"}
            ):
                pass
        assert rejected_origin.value.code == 1008
        with monkeypatch.context() as connection_limit:
            connection_limit.setenv("AEGISFLOW_WEBSOCKET_MAX_CONNECTIONS", "1")
            with client.websocket_connect("/api/v1/stream/alerts"):
                with pytest.raises(WebSocketDisconnect) as rejected_connection:
                    with client.websocket_connect("/api/v1/stream/alerts"):
                        pass
        assert rejected_connection.value.code == 1013
        with monkeypatch.context() as payload_limit:
            payload_limit.setenv("AEGISFLOW_WEBSOCKET_MAX_PAYLOAD_BYTES", "4096")
            with client.websocket_connect("/api/v1/stream/alerts") as websocket:
                limited_message = websocket.receive_json()
        assert limited_message == {
            "type": "processing_error",
            "error": {"code": "websocket_payload_too_large"},
        }


def test_static_identity_rbac_and_server_side_audit_attribution(
    monkeypatch: pytest.MonkeyPatch, registry: Path, tmp_path: Path
) -> None:
    keys = {"viewer": "v" * 32, "analyst": "a" * 32, "admin": "z" * 32}
    keys_file = tmp_path / "api-keys.json"
    keys_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "keys": [
                    {
                        "id": role,
                        "subject": f"{role}-user",
                        "display_name": f"{role.title()} user",
                        "sha256": hashlib.sha256(secret.encode()).hexdigest(),
                        "roles": [role],
                    }
                    for role, secret in keys.items()
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AEGISFLOW_DATABASE_URL", f"sqlite:///{(tmp_path / 'rbac.db').as_posix()}")
    monkeypatch.setenv("AEGISFLOW_MODEL_REGISTRY", str(registry))
    monkeypatch.setenv("AEGISFLOW_DEMO", "0")
    monkeypatch.setenv("AEGISFLOW_DEMO_SEED", "0")
    monkeypatch.setenv("AEGISFLOW_CONSUME_REDIS", "0")
    monkeypatch.setenv("AEGISFLOW_AUTH_MODE", "api_key")
    monkeypatch.setenv("AEGISFLOW_API_KEYS_FILE", str(keys_file))
    monkeypatch.setenv("AEGISFLOW_RETENTION_ENABLED", "0")
    monkeypatch.setenv("AEGISFLOW_EVALUATION_REPORT_DIR", str(Path("docs/evaluation").resolve()))
    monkeypatch.setenv("AEGISFLOW_MODEL_GOVERNANCE_ENABLED", "0")

    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/health/ready").status_code == 200
        assert client.get("/api/v1/alerts").status_code == 401
        viewer_headers = {"X-API-Key": keys["viewer"]}
        analyst_headers = {"X-API-Key": keys["analyst"]}
        admin_headers = {"X-API-Key": keys["admin"]}
        assert client.get("/api/v1/auth/me", headers=viewer_headers).json() == {
            "subject": "viewer-user",
            "display_name": "Viewer user",
            "roles": ["viewer"],
            "auth_method": "api_key",
        }
        assert client.get("/api/v1/alerts", headers=viewer_headers).status_code == 200
        forbidden_mutation = client.post(
            "/api/v1/alerts/00000000-0000-0000-0000-000000000000/acknowledge",
            headers=viewer_headers,
        )
        assert forbidden_mutation.status_code == 403
        assert forbidden_mutation.json()["error"]["code"] == "insufficient_role"
        assert (
            client.get(
                "/api/v1/exports/flows.csv",
                params={"anonymize_ips": "false"},
                headers=analyst_headers,
            ).status_code
            == 403
        )
        assert client.get("/api/v1/audit-events", headers=analyst_headers).status_code == 403
        candidate_request = {
            "version": "0.3.0",
            "evaluation_reports": [
                "unsw-nb15-official-split.json",
                "unsw-nb15-held-exploits.json",
                "cse-cic-ids2018-thursday-time.json",
                "unsw-to-cse-cic-ids2018-thursday.json",
            ],
        }
        assert (
            client.post(
                "/api/v1/model-candidates/aegisflow-smoke",
                json=candidate_request,
                headers=analyst_headers,
            ).status_code
            == 403
        )
        rejected_candidate = client.post(
            "/api/v1/model-candidates/aegisflow-smoke",
            json=candidate_request,
            headers=admin_headers,
        )
        assert rejected_candidate.status_code == 200
        assert rejected_candidate.json()["status"] == "rejected"
        assert "synthetic_training_bundle" in rejected_candidate.json()["blockers"]
        assert (
            client.post(
                "/api/v1/model-candidates/aegisflow-smoke:0.3.0/reviews",
                json={"decision": "approve", "comment": "must not bypass failed gates"},
                headers=analyst_headers,
            ).status_code
            == 409
        )
        disabled_promotion = client.post(
            "/api/v1/model-candidates/aegisflow-smoke:0.3.0/promote",
            headers=admin_headers,
        )
        assert disabled_promotion.status_code == 503
        assert disabled_promotion.json()["error"]["code"] == "model_governance_disabled"

        app.state.repository.record_health_event("test", "rbac")
        flow = list(DemoAdapter().flows())[2]
        seeded = app.state.engine.detect(flow)
        app.state.repository.ingest(flow, seeded)
        alerts = client.get("/api/v1/alerts", headers=analyst_headers).json()["items"]
        if alerts:
            acknowledged = client.post(
                f"/api/v1/alerts/{alerts[0]['id']}/acknowledge",
                headers=analyst_headers,
            )
            assert acknowledged.status_code == 200
            assert acknowledged.json()["actor"] == "analyst-user"
        audit = client.get("/api/v1/audit-events", headers=admin_headers)
        assert audit.status_code == 200
        if alerts:
            assert audit.json()["items"][0]["actor"] == "analyst-user"
        with client.websocket_connect(
            "/api/v1/stream/system", headers=viewer_headers
        ) as websocket:
            assert websocket.receive_json()["type"] == "system"
