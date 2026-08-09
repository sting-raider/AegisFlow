from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from packages.model_bundle.bundle import sha256_file


def test_governed_candidate_review_promotion_and_rollback(
    monkeypatch: pytest.MonkeyPatch,
    registry: Path,
    tmp_path: Path,
) -> None:
    candidate_registry, version = _candidate_registry(registry, tmp_path)
    reports = tmp_path / "reports"
    report_names = _passing_reports(reports, candidate_registry, version)
    secrets = {
        "creator": "c" * 32,
        "reviewer": "r" * 32,
        "promoter": "p" * 32,
    }
    roles = {"creator": "admin", "reviewer": "analyst", "promoter": "admin"}
    key_file = tmp_path / "governance-keys.json"
    key_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "keys": [
                    {
                        "id": name,
                        "subject": name,
                        "sha256": hashlib.sha256(secret.encode()).hexdigest(),
                        "roles": [roles[name]],
                    }
                    for name, secret in secrets.items()
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv(
        "AEGISFLOW_DATABASE_URL", f"sqlite:///{(tmp_path / 'governance-api.db').as_posix()}"
    )
    monkeypatch.setenv("AEGISFLOW_MODEL_REGISTRY", str(candidate_registry))
    monkeypatch.setenv("AEGISFLOW_EVALUATION_REPORT_DIR", str(reports))
    monkeypatch.setenv("AEGISFLOW_MODEL_GOVERNANCE_ENABLED", "1")
    monkeypatch.setenv("AEGISFLOW_DEMO", "0")
    monkeypatch.setenv("AEGISFLOW_DEMO_SEED", "0")
    monkeypatch.setenv("AEGISFLOW_CONSUME_REDIS", "0")
    monkeypatch.setenv("AEGISFLOW_RETENTION_ENABLED", "0")
    monkeypatch.setenv("AEGISFLOW_AUTH_MODE", "api_key")
    monkeypatch.setenv("AEGISFLOW_API_KEYS_FILE", str(key_file))

    headers = {name: {"X-API-Key": secret} for name, secret in secrets.items()}
    candidate_id = f"aegisflow-smoke:{version}"
    with TestClient(app, raise_server_exceptions=False) as client:
        registered = client.post(
            "/api/v1/model-candidates/aegisflow-smoke",
            headers=headers["creator"],
            json={"version": version, "evaluation_reports": report_names},
        )
        assert registered.status_code == 200
        assert registered.json()["status"] == "review_pending"
        self_review = client.post(
            f"/api/v1/model-candidates/{candidate_id}/reviews",
            headers=headers["creator"],
            json={"decision": "approve", "comment": "self review must fail"},
        )
        assert self_review.status_code == 409
        reviewed = client.post(
            f"/api/v1/model-candidates/{candidate_id}/reviews",
            headers=headers["reviewer"],
            json={"decision": "approve", "comment": "independent evidence review"},
        )
        assert reviewed.status_code == 200
        assert reviewed.json()["status"] == "approved"
        promoted = client.post(
            f"/api/v1/model-candidates/{candidate_id}/promote",
            headers=headers["promoter"],
        )
        assert promoted.status_code == 200
        assert promoted.json()["status"] == "promoted"
        assert promoted.json()["restart_required"] is True
        assert promoted.json()["loaded_runtime_version"] == "0.3.0"
        pointer = json.loads(
            (candidate_registry / "aegisflow-smoke" / "production.json").read_text(
                encoding="utf-8"
            )
        )
        assert pointer["version"] == version

        rolled_back = client.post(
            "/api/v1/models/aegisflow-smoke/rollback",
            headers=headers["promoter"],
        )
        assert rolled_back.status_code == 200
        assert rolled_back.json()["version"] == "0.3.0"
        candidate = client.get(
            f"/api/v1/model-candidates/{candidate_id}",
            headers=headers["reviewer"],
        )
        assert candidate.json()["status"] == "rolled_back"
        audit = client.get("/api/v1/audit-events", headers=headers["promoter"]).json()[
            "items"
        ]
        actions = [item["action"] for item in audit]
        assert "model_promoted" in actions
        assert "model_rollback_requested" in actions


def _candidate_registry(registry: Path, tmp_path: Path) -> tuple[Path, str]:
    target_registry = tmp_path / "registry"
    shutil.copytree(registry, target_registry)
    version = "0.4.0"
    target = target_registry / "aegisflow-smoke" / version
    shutil.copytree(target_registry / "aegisflow-smoke" / "0.3.0", target)
    manifest_path = target / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = version
    manifest["dataset_fingerprints"] = ["reviewed-public-fit-" + "a" * 44]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    files = sorted(path for path in target.iterdir() if path.name != "checksums.sha256")
    (target / "checksums.sha256").write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in files),
        encoding="utf-8",
        newline="\n",
    )
    return target_registry, version


def _passing_reports(root: Path, registry: Path, version: str) -> list[str]:
    root.mkdir(parents=True, exist_ok=True)
    bundle_digest = sha256_file(
        registry / "aegisflow-smoke" / version / "checksums.sha256"
    )
    names: list[str] = []
    for mode in ("source_file", "time", "leave_family_out", "cross_dataset"):
        name = f"candidate-{mode}.json"
        payload = {
            "schema_version": "1.1.0",
            "dataset": f"fixture-{mode}",
            "fingerprint": "f" * 64,
            "quality": {"blocking_issues": []},
            "evaluation_bundle": {
                "model_name": "aegisflow-smoke",
                "version": version,
                "bundle_schema_version": 3,
                "bundle_digest": bundle_digest,
            },
            "evaluation": {
                "harness": "exact deployed hybrid pipeline",
                "shared_inference_path": "packages.detection.hybrid.HybridPredictor",
                "training_fingerprint": "a" * 64,
                "testing_fingerprint": "b" * 64,
                "readiness_gate": {
                    "status": "pass",
                    "automatic_promotion_allowed": False,
                    "criteria": {"macro_f1": {"status": "pass"}},
                },
            },
        }
        if mode == "cross_dataset":
            payload["evaluation_mode"] = mode
        else:
            payload["split"] = {"strategy": mode, "group_overlap": 0}
        (root / name).write_text(json.dumps(payload), encoding="utf-8")
        names.append(name)
    return names
