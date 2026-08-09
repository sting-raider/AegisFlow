from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.api.auth import (
    AuthConfigurationError,
    AuthenticationError,
    Authenticator,
    AuthSettings,
    Principal,
    PrincipalRateLimiter,
    Role,
    _JwksCache,
)


def test_demo_authentication_is_explicitly_local_to_demo_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISFLOW_DEMO", "0")
    monkeypatch.setenv("AEGISFLOW_AUTH_MODE", "demo")
    with pytest.raises(AuthConfigurationError, match="forbidden"):
        AuthSettings.from_env()

    monkeypatch.setenv("AEGISFLOW_DEMO", "1")
    principal = Authenticator.from_env().authenticate_headers({})
    assert principal.subject == "demo-analyst"
    assert principal.allows(Role.ADMIN)


def test_hashed_api_keys_assign_server_controlled_identity_and_role(tmp_path: Path) -> None:
    secret = "viewer-" + "s" * 32
    keys_file = tmp_path / "keys.json"
    keys_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "keys": [
                    {
                        "id": "viewer-key",
                        "subject": "viewer@example.test",
                        "display_name": "Example Viewer",
                        "sha256": hashlib.sha256(secret.encode()).hexdigest(),
                        "roles": ["viewer"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    authenticator = Authenticator(_settings(mode="api_key", keys_file=keys_file))
    principal = authenticator.authenticate_headers({"x-api-key": secret})
    assert principal.as_dict() == {
        "subject": "viewer@example.test",
        "display_name": "Example Viewer",
        "roles": ["viewer"],
        "auth_method": "api_key",
    }
    assert principal.allows(Role.VIEWER)
    assert not principal.allows(Role.ANALYST)
    with pytest.raises(AuthenticationError) as missing:
        authenticator.authenticate_headers({})
    assert missing.value.code == "credentials_required"
    with pytest.raises(AuthenticationError) as invalid:
        authenticator.authenticate_headers({"x-api-key": "x" * 32})
    assert invalid.value.code == "invalid_credentials"


def test_oidc_verifies_signature_issuer_audience_lifetime_and_mapped_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk["kid"] = "test-key"
    public_jwk["alg"] = "RS256"
    settings = _settings(mode="oidc")
    authenticator = Authenticator(settings)
    jwks = authenticator.__dict__["_jwks"]
    monkeypatch.setattr(jwks, "key", lambda key_id: public_jwk)
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "sub": "analyst@example.test",
            "name": "Example Analyst",
            "iat": now,
            "exp": now + 300,
            "groups": ["soc-reviewers", "unmapped"],
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    principal = authenticator.authenticate_headers({"authorization": f"Bearer {token}"})
    assert principal.subject == "analyst@example.test"
    assert principal.roles == (Role.ANALYST,)
    assert principal.allows(Role.VIEWER)
    assert not principal.allows(Role.ADMIN)

    too_long = jwt.encode(
        {
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_audience,
            "sub": "analyst@example.test",
            "iat": now,
            "exp": now + settings.oidc_max_token_lifetime_seconds + 1,
            "groups": ["soc-reviewers"],
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    with pytest.raises(AuthenticationError) as invalid:
        authenticator.authenticate_headers({"authorization": f"Bearer {too_long}"})
    assert invalid.value.code == "invalid_credentials"


def test_websocket_subprotocol_carries_credentials_without_query_parameters(
    tmp_path: Path,
) -> None:
    secret = "api-key-" + "k" * 32
    keys_file = tmp_path / "keys.json"
    keys_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "keys": [
                    {
                        "id": "viewer",
                        "subject": "viewer",
                        "sha256": hashlib.sha256(secret.encode()).hexdigest(),
                        "roles": ["viewer"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    encoded = base64.urlsafe_b64encode(secret.encode()).decode().rstrip("=")
    principal, subprotocol = Authenticator(
        _settings(mode="api_key", keys_file=keys_file)
    ).authenticate_websocket(
        {"sec-websocket-protocol": f"aegisflow, aegisflow.key.{encoded}"}
    )
    assert principal.subject == "viewer"
    assert subprotocol == "aegisflow"


def test_rate_limiter_is_per_principal_and_scope() -> None:
    limiter = PrincipalRateLimiter(
        read_per_minute=2,
        mutation_per_minute=1,
        websocket_per_minute=1,
        maximum_principals=2,
    )
    first = Principal("first", "First", (Role.VIEWER,), "api_key")
    second = Principal("second", "Second", (Role.VIEWER,), "api_key")
    assert limiter.allow(first, "read")
    assert limiter.allow(first, "read")
    assert not limiter.allow(first, "read")
    assert limiter.allow(second, "read")
    assert limiter.allow(first, "mutation")
    assert not limiter.allow(first, "mutation")


def test_unknown_oidc_key_ids_cannot_force_repeated_jwks_refreshes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = _JwksCache("https://identity.example.test/jwks.json", cache_seconds=300)
    cache._keys = {"known-key": {"kid": "known-key"}}
    cache._expires_at = time.monotonic() + 300
    refreshes = 0

    def refresh() -> None:
        nonlocal refreshes
        refreshes += 1

    monkeypatch.setattr(cache, "_refresh", refresh)
    for key_id in ("unknown-one", "unknown-two"):
        with pytest.raises(AuthenticationError, match="invalid_credentials"):
            cache.key(key_id)
    assert refreshes == 1


def _settings(
    *,
    mode: str,
    keys_file: Path | None = None,
) -> AuthSettings:
    values: dict[str, Any] = {
        "mode": mode,
        "static_keys_file": keys_file,
        "oidc_issuer": "https://identity.example.test/",
        "oidc_audience": "aegisflow-api",
        "oidc_jwks_url": "https://identity.example.test/.well-known/jwks.json",
        "oidc_algorithms": ("RS256",),
        "oidc_roles_claim": "groups",
        "oidc_role_map": {"soc-reviewers": Role.ANALYST},
        "oidc_clock_skew_seconds": 0,
        "oidc_max_token_lifetime_seconds": 3600,
        "oidc_jwks_cache_seconds": 300,
    }
    return AuthSettings(**values)
