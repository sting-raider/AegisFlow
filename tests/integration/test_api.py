from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from apps.api.main import app


def test_api_vertical_slice(monkeypatch, registry: Path, tmp_path: Path) -> None:
    monkeypatch.setenv("AEGISFLOW_DATABASE_URL", f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    monkeypatch.setenv("AEGISFLOW_MODEL_REGISTRY", str(registry))
    monkeypatch.setenv("AEGISFLOW_DEMO", "1")
    monkeypatch.setenv("AEGISFLOW_DEMO_SEED", "1")
    monkeypatch.delenv("AEGISFLOW_API_KEY", raising=False)
    with TestClient(app) as client:
        assert client.get("/health/ready").json() == {"status": "ready"}
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
        assert client.get("/api/v1/incidents").json()["count"] >= 1
        assert client.get("/api/v1/models/current").status_code == 200
        with client.websocket_connect("/api/v1/stream/alerts") as websocket:
            message = websocket.receive_json()
            assert message["type"] == "alerts"
            assert message["items"]
