from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict, cast
from uuid import UUID

import httpx
import jwt
from websockets.sync.client import connect
from websockets.typing import Origin, Subprotocol

from scripts.prepare_oidc_acceptance import (
    CLIENT_ID,
    ISSUER,
    SCHEMA_VERSION,
    WRONG_AUDIENCE_CLIENT_ID,
)

API_URL = "http://127.0.0.1:8000"
DEX_IMAGE = "ghcr.io/dexidp/dex:v2.44.0"


class AcceptanceFailure(RuntimeError):
    pass


class CheckResult(TypedDict):
    name: str
    passed: bool
    detail: str


class UserCredential(TypedDict):
    username: str
    password: str
    user_id: str
    expected_role: str


class Credentials(TypedDict):
    schema_version: str
    generated_at: str
    issuer: str
    discovery_url: str
    token_url: str
    client_id: str
    wrong_audience_client_id: str
    ca_file: str
    users: dict[str, UserCredential]


def _load_credentials(path: Path) -> Credentials:
    if not path.is_file() or path.stat().st_size > 65_536:
        raise AcceptanceFailure("OIDC credentials file is missing or oversized")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise AcceptanceFailure("OIDC credentials schema is invalid")
    try:
        users = payload["users"]
        required_users = {
            "viewer",
            "analyst",
            "admin",
            "rate_viewer",
            "expiry_viewer",
            "rotation_viewer",
        }
        if not isinstance(users, dict) or not required_users.issubset(users):
            raise KeyError("users")
        for name in required_users:
            item = users[name]
            if not isinstance(item, dict):
                raise TypeError("user")
            UUID(str(item["user_id"]))
            for field in ("username", "password", "expected_role"):
                if not isinstance(item[field], str) or not item[field]:
                    raise TypeError(field)
        for field in (
            "issuer",
            "discovery_url",
            "token_url",
            "client_id",
            "wrong_audience_client_id",
            "ca_file",
        ):
            if not isinstance(payload[field], str) or not payload[field]:
                raise TypeError(field)
    except (KeyError, TypeError, ValueError) as exc:
        raise AcceptanceFailure("OIDC credentials contents are invalid") from exc
    return cast(Credentials, payload)


def _wait_for(
    client: httpx.Client,
    url: str,
    *,
    expected_status: int = 200,
    timeout_seconds: float = 120.0,
) -> httpx.Response:
    deadline = time.monotonic() + timeout_seconds
    last_status: int | None = None
    while time.monotonic() < deadline:
        try:
            response = client.get(url)
            last_status = response.status_code
            if response.status_code == expected_status:
                return response
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    rendered = "unreachable" if last_status is None else str(last_status)
    raise AcceptanceFailure(f"service readiness timed out with status {rendered}")


def _token(
    client: httpx.Client,
    credentials: Credentials,
    user_name: str,
    *,
    wrong_audience: bool = False,
) -> str:
    user = credentials["users"][user_name]
    client_id = (
        credentials["wrong_audience_client_id"]
        if wrong_audience
        else credentials["client_id"]
    )
    response = client.post(
        credentials["token_url"],
        auth=(client_id, ""),
        data={
            "grant_type": "password",
            "scope": "openid profile email",
            "username": user["username"],
            "password": user["password"],
        },
    )
    if response.status_code != 200:
        raise AcceptanceFailure(
            f"Dex token issuance failed for {user_name} with status {response.status_code}"
        )
    payload = response.json()
    token = payload.get("id_token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or token.count(".") != 2:
        raise AcceptanceFailure(f"Dex did not return an ID token for {user_name}")
    return token


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _expect(
    response: httpx.Response,
    expected_status: int,
    description: str,
) -> httpx.Response:
    if response.status_code != expected_status:
        raise AcceptanceFailure(
            f"{description}: expected {expected_status}, received {response.status_code}"
        )
    return response


def _record(checks: list[CheckResult], name: str, detail: str) -> None:
    checks.append({"name": name, "passed": True, "detail": detail})


def _claims(token: str) -> dict[str, Any]:
    payload = jwt.decode(
        token,
        options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
    )
    if not isinstance(payload, dict):
        raise AcceptanceFailure("Dex token claims are not an object")
    return payload


def _recreate_dex(repository_root: Path) -> float:
    started = time.perf_counter()
    command = [
        "docker",
        "compose",
        "-f",
        "compose.yml",
        "-f",
        "compose.oidc.yml",
        "up",
        "-d",
        "--force-recreate",
        "dex",
    ]
    subprocess.run(
        command,
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return time.perf_counter() - started


def run_acceptance(credentials_path: Path) -> dict[str, object]:
    credentials = _load_credentials(credentials_path)
    if credentials["issuer"] != ISSUER or credentials["client_id"] != CLIENT_ID:
        raise AcceptanceFailure("OIDC acceptance issuer or audience differs from the profile")
    if credentials["wrong_audience_client_id"] != WRONG_AUDIENCE_CLIENT_ID:
        raise AcceptanceFailure("OIDC negative-control audience differs from the profile")
    ca_file = Path(credentials["ca_file"])
    if not ca_file.is_file():
        raise AcceptanceFailure("OIDC acceptance CA is missing")

    checks: list[CheckResult] = []
    started = time.perf_counter()
    repository_root = Path(__file__).resolve().parents[1]
    with (
        httpx.Client(verify=str(ca_file), timeout=10.0, trust_env=False) as dex,
        httpx.Client(base_url=API_URL, timeout=10.0, trust_env=False) as api,
    ):
        discovery_response = _wait_for(dex, credentials["discovery_url"])
        discovery = discovery_response.json()
        if not isinstance(discovery, dict) or discovery.get("issuer") != ISSUER:
            raise AcceptanceFailure("Dex discovery issuer does not match the locked issuer")
        jwks_uri = discovery.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri.endswith("/dex/keys"):
            raise AcceptanceFailure("Dex discovery JWKS URI is invalid")
        keys_response = _expect(dex.get(jwks_uri), 200, "Dex JWKS retrieval")
        keys_payload = keys_response.json()
        if not isinstance(keys_payload, dict) or not keys_payload.get("keys"):
            raise AcceptanceFailure("Dex JWKS contains no signing keys")
        _record(checks, "discovery_and_jwks", "HTTPS discovery and non-empty JWKS passed")

        _wait_for(api, "/health/ready")
        _record(checks, "api_readiness", "API and database readiness passed")

        tokens = {
            name: _token(dex, credentials, name)
            for name in ("viewer", "analyst", "admin", "rate_viewer")
        }
        token_subjects: dict[str, str] = {}
        for name in ("viewer", "analyst", "admin"):
            claims = _claims(tokens[name])
            audience = claims.get("aud")
            audiences = {audience} if isinstance(audience, str) else set(audience or [])
            subject = claims.get("sub")
            if (
                claims.get("iss") != ISSUER
                or CLIENT_ID not in audiences
                or not isinstance(subject, str)
                or not subject
                or not isinstance(claims.get("iat"), int)
                or not isinstance(claims.get("exp"), int)
            ):
                raise AcceptanceFailure(f"Dex claims are invalid for {name}")
            token_subjects[name] = subject
        _record(checks, "token_issuance", "viewer, analyst, and admin ID tokens issued")

        for name in ("viewer", "analyst", "admin"):
            response = _expect(
                api.get("/api/v1/auth/me", headers=_headers(tokens[name])),
                200,
                f"{name} identity",
            )
            principal = response.json()
            expected = credentials["users"][name]
            if (
                principal.get("subject") != token_subjects[name]
                or expected["expected_role"] not in principal.get("roles", [])
                or principal.get("auth_method") != "oidc"
            ):
                raise AcceptanceFailure(f"server-derived identity is invalid for {name}")
        _record(checks, "role_mapping", "server-derived viewer/analyst/admin roles passed")

        _expect(
            api.get("/api/v1/system/status", headers=_headers(tokens["viewer"])),
            200,
            "viewer read",
        )
        fake_id = "00000000-0000-0000-0000-000000000000"
        _expect(
            api.post(
                f"/api/v1/alerts/{fake_id}/acknowledge",
                headers=_headers(tokens["viewer"]),
            ),
            403,
            "viewer mutation denial",
        )
        _expect(
            api.post(
                f"/api/v1/alerts/{fake_id}/acknowledge",
                headers=_headers(tokens["analyst"]),
            ),
            404,
            "analyst mutation authorization",
        )
        _expect(
            api.get("/api/v1/audit-events", headers=_headers(tokens["viewer"])),
            403,
            "viewer admin denial",
        )
        _record(checks, "rbac_boundaries", "viewer denial and analyst/admin boundaries passed")

        _expect(
            api.get(
                "/api/v1/exports/flows.csv?anonymize_ips=false",
                headers=_headers(tokens["viewer"]),
            ),
            403,
            "viewer raw export denial",
        )
        _expect(
            api.get(
                "/api/v1/exports/flows.csv?anonymize_ips=false",
                headers=_headers(tokens["admin"]),
            ),
            200,
            "admin raw export",
        )
        audit_response = _expect(
            api.get(
                "/api/v1/audit-events?action=raw_flow_export_created",
                headers=_headers(tokens["admin"]),
            ),
            200,
            "admin audit read",
        )
        audit_items = audit_response.json().get("items", [])
        admin_subject = token_subjects["admin"]
        if not any(item.get("actor") == admin_subject for item in audit_items):
            raise AcceptanceFailure("OIDC admin subject was not durably attributed")
        _record(checks, "audit_actor", "admin OIDC subject was durably attributed")

        websocket_url = f"ws://{API_URL.removeprefix('http://')}/api/v1/stream/system"
        with connect(
            websocket_url,
            origin=cast(Origin, "http://127.0.0.1:5173"),
            subprotocols=[
                cast(Subprotocol, "aegisflow"),
                cast(Subprotocol, f"aegisflow.bearer.{tokens['viewer']}"),
            ],
            open_timeout=10,
            close_timeout=5,
            proxy=None,
        ) as websocket:
            message = websocket.recv(timeout=5)
        payload = json.loads(message)
        if not isinstance(payload, dict) or payload.get("type") != "system":
            raise AcceptanceFailure("authenticated WebSocket returned an invalid payload")
        _record(checks, "websocket_authentication", "viewer bearer subprotocol passed")

        malformed = _expect(
            api.get("/api/v1/auth/me", headers=_headers("not-a-jwt")),
            401,
            "malformed token denial",
        )
        if malformed.json().get("error", {}).get("code") != "invalid_credentials":
            raise AcceptanceFailure("malformed token did not return the stable error code")
        wrong_audience = _token(dex, credentials, "viewer", wrong_audience=True)
        _expect(
            api.get("/api/v1/auth/me", headers=_headers(wrong_audience)),
            401,
            "wrong audience denial",
        )
        _record(checks, "token_abuse_controls", "malformed and wrong-audience tokens denied")

        rate_headers = _headers(tokens["rate_viewer"])
        for index in range(5):
            _expect(
                api.get("/api/v1/auth/me", headers=rate_headers),
                200,
                f"rate-limit allowed request {index + 1}",
            )
        _expect(
            api.get("/api/v1/auth/me", headers=rate_headers),
            429,
            "rate-limit rejection",
        )
        _record(checks, "principal_rate_limit", "sixth read in one window was rejected")

        rotation_token = _token(dex, credentials, "rotation_viewer")
        rotation_started = time.monotonic()
        recreate_seconds = _recreate_dex(repository_root)
        _wait_for(dex, credentials["discovery_url"])
        remaining_cache = 31.0 - (time.monotonic() - rotation_started)
        if remaining_cache > 0:
            time.sleep(remaining_cache)
        _expect(
            api.get("/api/v1/auth/me", headers=_headers(rotation_token)),
            401,
            "rotated key denial",
        )
        expiry_token = _token(dex, credentials, "expiry_viewer")
        _expect(
            api.get("/api/v1/auth/me", headers=_headers(expiry_token)),
            200,
            "new signing key acceptance",
        )
        _record(
            checks,
            "jwks_key_rotation",
            f"old key denied and new key accepted; Dex recreation {recreate_seconds:.2f}s",
        )

        expiry_claims = _claims(expiry_token)
        expires_at = int(expiry_claims["exp"])
        within_skew_sleep = expires_at + 0.5 - time.time()
        if within_skew_sleep > 0:
            time.sleep(within_skew_sleep)
        _expect(
            api.get("/api/v1/auth/me", headers=_headers(expiry_token)),
            200,
            "token within clock skew",
        )
        expired_sleep = expires_at + 3.0 - time.time()
        if expired_sleep > 0:
            time.sleep(expired_sleep)
        expired = _expect(
            api.get("/api/v1/auth/me", headers=_headers(expiry_token)),
            401,
            "expired token denial",
        )
        if expired.json().get("error", {}).get("code") != "credentials_expired":
            raise AcceptanceFailure("expired token did not return the stable expiry code")
        _record(checks, "expiry_and_clock_skew", "2-second skew accepted then expiry denied")

    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "local Dex-to-AegisFlow OIDC production-acceptance profile",
        "identity_provider": {"name": "Dex", "image": DEX_IMAGE},
        "configuration": {
            "issuer": ISSUER,
            "audience": CLIENT_ID,
            "algorithm": "RS256",
            "roles_claim": "email",
            "clock_skew_seconds": 2,
            "jwks_cache_seconds": 30,
            "id_token_lifetime_seconds": 60,
        },
        "checks": checks,
        "timing": {"total_seconds": time.perf_counter() - started},
        "safety": {
            "loopback_only": True,
            "ephemeral_credentials": True,
            "credentials_or_tokens_recorded": False,
            "production_dependency": False,
        },
        "verdict": {"accepted": True, "failures": []},
        "limitations": [
            "Dex static users exercise the OIDC contract but do not represent an "
            "organizational IdP.",
            "Application rate limits are process-local; multi-replica deployments still "
            "need a gateway-wide limit.",
            "The profile validates deployment mechanics on one local Compose host only.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Exercise AegisFlow OIDC against the optional local Dex profile"
    )
    parser.add_argument(
        "--credentials",
        type=Path,
        default=Path(".runtime/oidc/credentials.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run_acceptance(args.credentials)
        exit_code = 0
    except (AcceptanceFailure, httpx.HTTPError, subprocess.SubprocessError, ValueError) as exc:
        report = {
            "schema_version": "1.0.0",
            "generated_at": datetime.now(UTC).isoformat(),
            "scope": "local Dex-to-AegisFlow OIDC production-acceptance profile",
            "identity_provider": {"name": "Dex", "image": DEX_IMAGE},
            "checks": [],
            "safety": {
                "loopback_only": True,
                "credentials_or_tokens_recorded": False,
                "production_dependency": False,
            },
            "verdict": {
                "accepted": False,
                "failures": [type(exc).__name__],
            },
        }
        exit_code = 2
    serialized = json.dumps(report, indent=2) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
