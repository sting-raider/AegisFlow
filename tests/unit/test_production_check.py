from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.model_bundle import BundleError
from scripts import production_check


def _safe_env(tmp_path: Path) -> dict[str, str]:
    password = tmp_path / "password"
    password.write_text("strong-unique-database-password", encoding="utf-8")
    database_url = tmp_path / "database-url"
    database_url.write_text(
        "postgresql+psycopg://aegisflow:strong-unique-database-password@postgres/aegisflow",
        encoding="utf-8",
    )
    backup = tmp_path / "backup.json"
    backup.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "owner": "platform-team",
                "schedule": "0 2 * * *",
                "target": "encrypted-object-storage",
                "encrypted": True,
                "restore_tested_at": "2026-08-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return {
        "AEGISFLOW_DEMO": "0",
        "AEGISFLOW_AUTH_MODE": "oidc",
        "AEGISFLOW_OIDC_ISSUER": "https://identity.example.com/",
        "AEGISFLOW_OIDC_AUDIENCE": "aegisflow-api",
        "AEGISFLOW_OIDC_JWKS_URL": "https://identity.example.com/jwks.json",
        "AEGISFLOW_CORS_ORIGINS": "https://aegisflow.example.com",
        "AEGISFLOW_DB_PASSWORD_SECRET_FILE": str(password),
        "AEGISFLOW_DATABASE_URL_SECRET_FILE": str(database_url),
        "AEGISFLOW_RETENTION_OWNER": "api",
        "AEGISFLOW_RETENTION_ENABLED": "1",
        "AEGISFLOW_RETENTION_EXTERNAL": "0",
        "AEGISFLOW_BACKUP_POLICY_FILE": str(backup),
    }


def _safe_compose() -> dict[str, object]:
    hardened = {
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
    }
    return {
        "services": {
            "postgres": {},
            "redis": {},
            "api": {
                **hardened,
                "ports": [{"host_ip": "127.0.0.1", "published": "8000"}],
                "healthcheck": {"test": ["CMD", "true"]},
            },
            "detector": dict(hardened),
            "dashboard": {
                **hardened,
                "ports": [{"host_ip": "127.0.0.1", "published": "5173"}],
            },
            "sensor": dict(hardened),
        }
    }


def test_environment_accepts_explicit_hardened_settings(tmp_path: Path) -> None:
    assert production_check.validate_environment(_safe_env(tmp_path)) == []


def test_environment_fails_closed_without_auth_secrets_retention_and_backup(
    tmp_path: Path,
) -> None:
    env = _safe_env(tmp_path)
    env.update(
        {
            "AEGISFLOW_DEMO": "1",
            "AEGISFLOW_AUTH_MODE": "demo",
            "AEGISFLOW_OIDC_ISSUER": "http://identity.example.com/",
            "AEGISFLOW_CORS_ORIGINS": "https://aegisflow.example.com/path",
            "AEGISFLOW_DB_PASSWORD_SECRET_FILE": "",
            "AEGISFLOW_RETENTION_OWNER": "",
            "AEGISFLOW_BACKUP_POLICY_FILE": "",
        }
    )
    codes = {item["code"] for item in production_check.validate_environment(env)}
    assert {
        "demo_enabled",
        "unsafe_auth_mode",
        "unsafe_oidc_url",
        "unsafe_cors",
        "empty_secret",
        "missing_retention_owner",
        "missing_backup_configuration",
    } <= codes


def test_environment_rejects_insecure_remote_provider_and_backup_policy(
    tmp_path: Path,
) -> None:
    env = _safe_env(tmp_path)
    env.update(
        {
            "AEGISFLOW_EXPLANATION_PROVIDER": "openai",
            "AEGISFLOW_EXPLANATION_BASE_URL": "http://provider.example.com/v1",
        }
    )
    backup = Path(env["AEGISFLOW_BACKUP_POLICY_FILE"])
    payload = json.loads(backup.read_text(encoding="utf-8"))
    payload["encrypted"] = False
    payload["restore_tested_at"] = "2999-01-01T00:00:00Z"
    backup.write_text(json.dumps(payload), encoding="utf-8")
    codes = {item["code"] for item in production_check.validate_environment(env)}
    assert {
        "unsafe_external_provider",
        "empty_provider_secret",
        "unencrypted_backup",
        "invalid_restore_timestamp",
    } <= codes


def test_compose_accepts_internal_datastores_and_hardened_apps() -> None:
    assert production_check.validate_compose(_safe_compose()) == []


def test_compose_rejects_public_datastore_writable_root_and_capabilities() -> None:
    rendered = _safe_compose()
    services = rendered["services"]
    assert isinstance(services, dict)
    services["postgres"] = {"ports": [{"published": "5432"}]}
    api = services["api"]
    assert isinstance(api, dict)
    api["read_only"] = False
    api["cap_add"] = ["NET_ADMIN"]
    codes = {item["code"] for item in production_check.validate_compose(rendered)}
    assert {"public_postgres", "writable_root", "excessive_capabilities"} <= codes


def test_compose_rejects_public_redis_port_privilege_and_missing_readiness() -> None:
    rendered = _safe_compose()
    services = rendered["services"]
    assert isinstance(services, dict)
    services["redis"] = {"network_mode": "host"}
    api = services["api"]
    assert isinstance(api, dict)
    api["ports"] = [{"host_ip": "0.0.0.0", "published": "8000"}]
    api["security_opt"] = []
    api.pop("healthcheck")
    codes = {item["code"] for item in production_check.validate_compose(rendered)}
    assert {
        "public_redis",
        "public_application_port",
        "privilege_escalation",
        "missing_readiness_probe",
    } <= codes


def test_model_approval_must_bind_exact_bundle_with_separate_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = SimpleNamespace(version="1.2.3", load_warning=None)
    assessment = SimpleNamespace(bundle_digest="a" * 64, blockers=())
    monkeypatch.setattr(production_check, "load_production_bundle", lambda *_: bundle)
    monkeypatch.setattr(production_check, "assess_candidate", lambda *_: assessment)
    approval = tmp_path / "approval.json"
    approval.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "decision": "approved",
                "model_name": "aegisflow-smoke",
                "version": "1.2.3",
                "bundle_digest": "a" * 64,
                "approved_by": "reviewer-subject",
                "promoted_by": "promoter-subject",
            }
        ),
        encoding="utf-8",
    )
    env = {
        "AEGISFLOW_PRODUCTION_EVALUATION_REPORTS": "grouped.json,time.json",
        "AEGISFLOW_MODEL_APPROVAL_FILE": str(approval),
    }
    assert production_check.validate_model(env) == []
    payload = json.loads(approval.read_text(encoding="utf-8"))
    payload["promoted_by"] = payload["approved_by"]
    approval.write_text(json.dumps(payload), encoding="utf-8")
    assert production_check.validate_model(env)[0]["code"] == "unapproved_model"


def test_model_check_rejects_missing_bundle_and_blocking_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(*_args: object) -> object:
        raise BundleError("missing")

    monkeypatch.setattr(production_check, "load_production_bundle", missing)
    assert production_check.validate_model({})[0]["code"] == "missing_model_bundle"

    bundle = SimpleNamespace(version="1.2.3", load_warning=None)
    assessment = SimpleNamespace(bundle_digest="a" * 64, blockers=("gate failed",))
    monkeypatch.setattr(production_check, "load_production_bundle", lambda *_: bundle)
    monkeypatch.setattr(production_check, "assess_candidate", lambda *_: assessment)
    errors = production_check.validate_model(
        {"AEGISFLOW_PRODUCTION_EVALUATION_REPORTS": "grouped.json"}
    )
    assert {item["code"] for item in errors} == {
        "failed_readiness_report",
        "missing_model_approval",
    }
