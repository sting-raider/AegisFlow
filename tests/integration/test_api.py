from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from apps.api.main import app


def test_api_vertical_slice(monkeypatch, registry: Path, tmp_path: Path) -> None:
    monkeypatch.setenv("AEGISFLOW_DATABASE_URL", f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    monkeypatch.setenv("AEGISFLOW_MODEL_REGISTRY", str(registry))
    monkeypatch.setenv("AEGISFLOW_DEMO", "1")
    monkeypatch.setenv("AEGISFLOW_DEMO_SEED", "1")
    monkeypatch.setenv("AEGISFLOW_EXPLANATION_PROVIDER", "disabled")
    monkeypatch.delenv("AEGISFLOW_API_KEY", raising=False)
    with TestClient(app) as client:
        assert client.get("/health/ready").json() == {"status": "ready"}
        assert client.get("/api/v1/system/status").json()["queue"] == {
            "pending": 0,
            "lag": 0,
            "consumers": 0,
        }
        metrics = client.get("/metrics").text
        assert "queue_lag" in metrics
        assert "drift_events_total" in metrics
        assert client.get("/api/v1/drift-events").status_code == 200
        alerts = client.get("/api/v1/alerts").json()["items"]
        assert alerts
        assert {item["verdict"] for item in alerts} >= {"known_attack", "suspicious_unknown"}
        detail = client.get(f"/api/v1/alerts/{alerts[0]['id']}")
        assert detail.status_code == 200
        feedback = client.post(
            f"/api/v1/alerts/{alerts[0]['id']}/feedback",
            json={
                "actor": "test-analyst",
                "disposition": "requires_investigation",
                "comment": "check adjacent flows",
            },
        )
        assert feedback.status_code == 200
        incidents = client.get("/api/v1/incidents").json()["items"]
        assert incidents
        incident_detail = client.get(f"/api/v1/incidents/{incidents[0]['id']}").json()
        assert incident_detail["timeline"]
        assert incident_detail["alerts"]
        assert incident_detail["attack_stages"]
        assert incident_detail["alert_count"] == len(incident_detail["alert_ids"])
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
        with client.websocket_connect("/api/v1/stream/alerts") as websocket:
            message = websocket.receive_json()
            assert message["type"] == "alerts"
            assert message["items"]
