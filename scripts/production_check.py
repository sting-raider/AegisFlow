from __future__ import annotations

import argparse
import json
import os
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict, cast
from urllib.parse import urlsplit

from packages.model_bundle import BundleError, assess_candidate, load_production_bundle


class CheckError(TypedDict):
    code: str
    message: str


def _error(errors: list[CheckError], code: str, message: str) -> None:
    errors.append({"code": code, "message": message})


def _is_https_url(value: str) -> bool:
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    return (
        parsed.scheme == "https"
        and bool(host)
        and parsed.username is None
        and parsed.password is None
        and parsed.fragment == ""
        and not host.endswith(".invalid")
    )


def _is_https_origin(value: str) -> bool:
    parsed = urlsplit(value)
    return _is_https_url(value) and not parsed.path and not parsed.query


def _secret_file(
    env: Mapping[str, str],
    name: str,
    errors: list[CheckError],
) -> str | None:
    raw_path = env.get(name, "").strip()
    if not raw_path:
        _error(errors, "empty_secret", f"{name} must name a nonempty mounted secret file")
        return None
    path = Path(raw_path)
    try:
        if not path.is_file() or path.stat().st_size == 0 or path.stat().st_size > 65_536:
            raise ValueError
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError, ValueError):
        _error(errors, "invalid_secret_file", f"{name} must be a readable nonempty bounded file")
        return None
    if not value:
        _error(errors, "empty_secret", f"{name} must not contain an empty secret")
        return None
    return value


def _validate_backup_policy(env: Mapping[str, str], errors: list[CheckError]) -> None:
    raw_path = env.get("AEGISFLOW_BACKUP_POLICY_FILE", "").strip()
    if not raw_path:
        _error(
            errors,
            "missing_backup_configuration",
            "AEGISFLOW_BACKUP_POLICY_FILE must identify the reviewed backup policy",
        )
        return
    try:
        path = Path(raw_path)
        if not path.is_file() or path.stat().st_size > 65_536:
            raise ValueError
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        _error(
            errors,
            "invalid_backup_configuration",
            "backup policy must be a readable bounded JSON object",
        )
        return
    required_strings = ("owner", "schedule", "target", "restore_tested_at")
    if payload.get("schema_version") != "1.0.0" or any(
        not isinstance(payload.get(field), str) or not str(payload[field]).strip()
        for field in required_strings
    ):
        _error(
            errors,
            "invalid_backup_configuration",
            "backup policy requires schema_version 1.0.0, owner, schedule, target, "
            "and restore_tested_at",
        )
    if payload.get("encrypted") is not True:
        _error(
            errors,
            "unencrypted_backup",
            "backup policy must explicitly require encryption at rest",
        )
    tested_at = payload.get("restore_tested_at")
    if isinstance(tested_at, str):
        try:
            parsed = datetime.fromisoformat(tested_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.astimezone(UTC) > datetime.now(UTC):
                raise ValueError
        except ValueError:
            _error(
                errors,
                "invalid_restore_timestamp",
                "backup restore_tested_at must be a non-future timezone-aware timestamp",
            )


def validate_environment(env: Mapping[str, str]) -> list[CheckError]:
    errors: list[CheckError] = []
    if env.get("AEGISFLOW_DEMO", "").strip() != "0":
        _error(errors, "demo_enabled", "AEGISFLOW_DEMO must be exactly 0")
    if env.get("AEGISFLOW_AUTH_MODE", "").strip().lower() != "oidc":
        _error(errors, "unsafe_auth_mode", "AEGISFLOW_AUTH_MODE must be oidc")
    for name in ("AEGISFLOW_OIDC_ISSUER", "AEGISFLOW_OIDC_JWKS_URL"):
        if not _is_https_url(env.get(name, "").strip()):
            _error(
                errors, "unsafe_oidc_url", f"{name} must be an explicit non-placeholder HTTPS URL"
            )
    if not env.get("AEGISFLOW_OIDC_AUDIENCE", "").strip():
        _error(errors, "empty_oidc_audience", "AEGISFLOW_OIDC_AUDIENCE must be nonempty")

    origins = [item.strip() for item in env.get("AEGISFLOW_CORS_ORIGINS", "").split(",")]
    if not origins or any(not item for item in origins):
        _error(errors, "empty_cors", "AEGISFLOW_CORS_ORIGINS must contain exact HTTPS origins")
    elif any(origin == "*" or not _is_https_origin(origin) for origin in origins):
        _error(
            errors,
            "unsafe_cors",
            "CORS and WebSocket origins must be exact non-placeholder HTTPS origins",
        )

    password = _secret_file(env, "AEGISFLOW_DB_PASSWORD_SECRET_FILE", errors)
    database_url = _secret_file(env, "AEGISFLOW_DATABASE_URL_SECRET_FILE", errors)
    weak_passwords = {"aegisflow-demo-only", "password", "postgres", "aegisflow"}
    if password is not None and password.lower() in weak_passwords:
        _error(
            errors, "default_password", "PostgreSQL secret contains a known demo/default password"
        )
    if database_url is not None:
        parsed_database = urlsplit(database_url.replace("postgresql+psycopg", "postgresql", 1))
        if (
            parsed_database.scheme not in {"postgresql", "postgres"}
            or not parsed_database.hostname
            or not parsed_database.password
            or parsed_database.password.lower() in weak_passwords
        ):
            _error(
                errors,
                "unsafe_database_url",
                "database URL secret must be PostgreSQL and contain a non-default password",
            )

    provider = env.get("AEGISFLOW_EXPLANATION_PROVIDER", "disabled").strip().lower()
    if provider == "openai":
        if not _is_https_url(env.get("AEGISFLOW_EXPLANATION_BASE_URL", "").strip()):
            _error(
                errors,
                "unsafe_external_provider",
                "remote explanation provider requires an explicit HTTPS base URL",
            )
        if not env.get("AEGISFLOW_EXPLANATION_API_KEY", "").strip():
            _error(
                errors,
                "empty_provider_secret",
                "remote explanation provider requires AEGISFLOW_EXPLANATION_API_KEY",
            )

    retention_owner = env.get("AEGISFLOW_RETENTION_OWNER", "").strip().lower()
    enabled = env.get("AEGISFLOW_RETENTION_ENABLED", "").strip() == "1"
    external = env.get("AEGISFLOW_RETENTION_EXTERNAL", "").strip() == "1"
    if retention_owner == "api":
        if not enabled or external:
            _error(
                errors,
                "invalid_retention_owner",
                "api retention owner requires enabled=1 and external=0",
            )
    elif retention_owner == "external":
        if enabled or not external:
            _error(
                errors,
                "invalid_retention_owner",
                "external retention owner requires enabled=0 and external=1",
            )
    else:
        _error(
            errors,
            "missing_retention_owner",
            "AEGISFLOW_RETENTION_OWNER must explicitly be api or external",
        )
    _validate_backup_policy(env, errors)
    return errors


def _published_ports(service: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    ports = service.get("ports", [])
    return [item for item in ports if isinstance(item, dict)] if isinstance(ports, list) else []


def validate_compose(rendered: Mapping[str, Any]) -> list[CheckError]:
    errors: list[CheckError] = []
    services = rendered.get("services")
    if not isinstance(services, dict):
        return [{"code": "invalid_compose", "message": "rendered Compose services are missing"}]
    for name in ("postgres", "redis"):
        service = services.get(name)
        if not isinstance(service, dict):
            _error(errors, "missing_service", f"production Compose service {name} is missing")
            continue
        if _published_ports(service) or service.get("network_mode") == "host":
            _error(
                errors,
                f"public_{name}",
                f"production {name} must not publish ports or use host networking",
            )

    for name in ("api", "detector", "dashboard", "sensor"):
        service = services.get(name)
        if not isinstance(service, dict):
            continue
        if service.get("read_only") is not True:
            _error(
                errors, "writable_root", f"production {name} must use a read-only root filesystem"
            )
        cap_drop = service.get("cap_drop", [])
        cap_add = service.get("cap_add", [])
        if not isinstance(cap_drop, list) or "ALL" not in cap_drop or cap_add:
            _error(
                errors, "excessive_capabilities", f"production {name} must drop ALL capabilities"
            )
        security_opt = service.get("security_opt", [])
        if not isinstance(security_opt, list) or "no-new-privileges:true" not in security_opt:
            _error(errors, "privilege_escalation", f"production {name} must set no-new-privileges")

    for name in ("api", "dashboard"):
        service = services.get(name)
        if not isinstance(service, dict):
            continue
        for port in _published_ports(service):
            host_ip = str(port.get("host_ip", ""))
            if host_ip not in {"127.0.0.1", "::1"}:
                _error(
                    errors, "public_application_port", f"production {name} ports must bind loopback"
                )
    api = services.get("api")
    if isinstance(api, dict) and not isinstance(api.get("healthcheck"), dict):
        _error(errors, "missing_readiness_probe", "production API requires a readiness healthcheck")
    return errors


def _read_json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        if not path.is_file() or path.stat().st_size > 262_144:
            raise ValueError
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{description} must be a readable bounded JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{description} must be a JSON object")
    return payload


def validate_model(env: Mapping[str, str]) -> list[CheckError]:
    errors: list[CheckError] = []
    registry = Path(env.get("AEGISFLOW_MODEL_REGISTRY", "models/registry"))
    evaluation_root = Path(env.get("AEGISFLOW_EVALUATION_REPORT_DIR", "docs/evaluation"))
    model_name = env.get("AEGISFLOW_MODEL_NAME", "aegisflow-smoke").strip()
    report_names = [
        item.strip()
        for item in env.get("AEGISFLOW_PRODUCTION_EVALUATION_REPORTS", "").split(",")
        if item.strip()
    ]
    try:
        bundle = load_production_bundle(registry, model_name)
    except (BundleError, OSError, ValueError):
        _error(
            errors,
            "missing_model_bundle",
            "production model pointer and checksummed bundle must load",
        )
        return errors
    if bundle.load_warning:
        _error(
            errors,
            "model_fallback",
            "production model must load its exact current pointer without fallback",
        )
    if not report_names:
        _error(
            errors,
            "missing_readiness_report",
            "AEGISFLOW_PRODUCTION_EVALUATION_REPORTS must list governed readiness reports",
        )
        return errors
    try:
        assessment = assess_candidate(
            registry,
            evaluation_root,
            model_name,
            bundle.version,
            report_names,
        )
    except (BundleError, OSError, ValueError):
        _error(errors, "failed_readiness_report", "production model readiness evidence is invalid")
        return errors
    if assessment.blockers:
        _error(
            errors,
            "failed_readiness_report",
            "production model has blocking scientific readiness evidence",
        )

    approval_path = env.get("AEGISFLOW_MODEL_APPROVAL_FILE", "").strip()
    if not approval_path:
        _error(
            errors,
            "missing_model_approval",
            "AEGISFLOW_MODEL_APPROVAL_FILE must identify an independent approval attestation",
        )
        return errors
    try:
        approval = _read_json_object(Path(approval_path), "model approval attestation")
        if (
            approval.get("schema_version") != "1.0.0"
            or approval.get("decision") != "approved"
            or approval.get("model_name") != model_name
            or approval.get("version") != bundle.version
            or approval.get("bundle_digest") != assessment.bundle_digest
            or not isinstance(approval.get("approved_by"), str)
            or not approval.get("approved_by")
            or not isinstance(approval.get("promoted_by"), str)
            or not approval.get("promoted_by")
            or approval.get("approved_by") == approval.get("promoted_by")
        ):
            raise ValueError
    except ValueError:
        _error(
            errors,
            "unapproved_model",
            "model approval must bind the exact bundle and use distinct "
            "approver/promoter identities",
        )
    return errors


def render_production_compose() -> tuple[dict[str, Any] | None, CheckError | None]:
    try:
        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                "compose.yml",
                "-f",
                "compose.production.yml",
                "config",
                "--format",
                "json",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, {
            "code": "deployment_render_failed",
            "message": "production Compose render could not be executed within its safe bound",
        }
    if result.returncode != 0:
        return None, {
            "code": "deployment_render_failed",
            "message": "production Compose render failed; verify required variables "
            "and Docker availability",
        }
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, {
            "code": "deployment_render_invalid",
            "message": "production Compose render did not return valid JSON",
        }
    if not isinstance(payload, dict):
        return None, {
            "code": "deployment_render_invalid",
            "message": "production Compose render must be a JSON object",
        }
    return cast(dict[str, Any], payload), None


def run_check(env: Mapping[str, str], rendered: Mapping[str, Any] | None) -> dict[str, object]:
    errors = validate_environment(env)
    errors.extend(validate_model(env))
    if rendered is not None:
        errors.extend(validate_compose(rendered))
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "fail-closed AegisFlow production configuration preflight",
        "passed": not errors,
        "error_count": len(errors),
        "errors": errors,
        "safety": {"secret_values_emitted": False, "external_connections": False},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate AegisFlow production configuration")
    parser.add_argument("--compose-json", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered: Mapping[str, Any] | None = None
    render_error: CheckError | None = None
    if args.compose_json is not None:
        try:
            rendered = _read_json_object(args.compose_json, "rendered Compose configuration")
        except ValueError:
            render_error = {
                "code": "deployment_render_invalid",
                "message": "provided Compose JSON is invalid",
            }
    else:
        rendered, render_error = render_production_compose()
    report = run_check(os.environ, rendered)
    if render_error is not None:
        errors = cast(list[CheckError], report["errors"])
        errors.append(render_error)
        report["error_count"] = len(errors)
        report["passed"] = False
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    if not report["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
