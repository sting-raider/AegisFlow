from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
import jwt

_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:@/-]{1,128}$")
_SAFE_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"})
_MAX_KEYS = 100
_MAX_KEYS_FILE_BYTES = 65_536
_MAX_JWKS_BYTES = 262_144


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


_ROLE_LEVEL = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}


class AuthConfigurationError(RuntimeError):
    pass


class AuthenticationError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        status_code: int = 401,
        challenge: str = "Bearer",
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.challenge = challenge


@dataclass(frozen=True)
class Principal:
    subject: str
    display_name: str
    roles: tuple[Role, ...]
    auth_method: Literal["demo", "api_key", "oidc"]
    credential_id: str | None = None

    def allows(self, required: Role) -> bool:
        return any(_ROLE_LEVEL[role] >= _ROLE_LEVEL[required] for role in self.roles)

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "display_name": self.display_name,
            "roles": [role.value for role in self.roles],
            "auth_method": self.auth_method,
        }


@dataclass(frozen=True)
class _StaticKey:
    key_id: str
    subject: str
    display_name: str
    digest: str
    roles: tuple[Role, ...]


@dataclass(frozen=True)
class AuthSettings:
    mode: Literal["demo", "api_key", "oidc"]
    static_keys_file: Path | None
    oidc_issuer: str | None
    oidc_audience: str | None
    oidc_jwks_url: str | None
    oidc_algorithms: tuple[str, ...]
    oidc_roles_claim: str
    oidc_role_map: Mapping[str, Role]
    oidc_clock_skew_seconds: int
    oidc_max_token_lifetime_seconds: int
    oidc_jwks_cache_seconds: int

    @classmethod
    def from_env(cls) -> AuthSettings:
        demo_enabled = os.getenv("AEGISFLOW_DEMO", "1") == "1"
        raw_mode = os.getenv("AEGISFLOW_AUTH_MODE", "demo" if demo_enabled else "oidc")
        if raw_mode not in {"demo", "api_key", "oidc"}:
            raise AuthConfigurationError("AEGISFLOW_AUTH_MODE must be demo, api_key, or oidc")
        mode = raw_mode
        if mode == "demo" and not demo_enabled:
            raise AuthConfigurationError(
                "demo authentication is forbidden when demo mode is disabled"
            )

        static_keys_file: Path | None = None
        if mode == "api_key":
            value = os.getenv("AEGISFLOW_API_KEYS_FILE", "").strip()
            if not value:
                raise AuthConfigurationError(
                    "api_key authentication requires AEGISFLOW_API_KEYS_FILE"
                )
            static_keys_file = Path(value)

        issuer = os.getenv("AEGISFLOW_OIDC_ISSUER", "").strip() or None
        audience = os.getenv("AEGISFLOW_OIDC_AUDIENCE", "").strip() or None
        jwks_url = os.getenv("AEGISFLOW_OIDC_JWKS_URL", "").strip() or None
        if mode == "oidc":
            if issuer is None or audience is None or jwks_url is None:
                raise AuthConfigurationError(
                    "oidc authentication requires issuer, audience, and JWKS URL"
                )
            _validate_https_or_loopback_url(issuer, "OIDC issuer")
            _validate_https_or_loopback_url(jwks_url, "OIDC JWKS URL")

        raw_algorithms = os.getenv("AEGISFLOW_OIDC_ALGORITHMS", "RS256")
        algorithms = tuple(
            dict.fromkeys(item.strip() for item in raw_algorithms.split(",") if item.strip())
        )
        if not algorithms or any(item not in _SAFE_ALGORITHMS for item in algorithms):
            raise AuthConfigurationError("OIDC algorithms contain an unsupported value")

        raw_role_map = os.getenv("AEGISFLOW_OIDC_ROLE_MAP", "")
        role_map: dict[str, Role] = {role.value: role for role in Role}
        if raw_role_map:
            try:
                parsed = json.loads(raw_role_map)
                if not isinstance(parsed, dict):
                    raise ValueError
                role_map = {
                    str(source): Role(str(target)) for source, target in parsed.items()
                }
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise AuthConfigurationError(
                    "AEGISFLOW_OIDC_ROLE_MAP must map strings to roles"
                ) from exc
        if not role_map or len(role_map) > 100:
            raise AuthConfigurationError("OIDC role mapping must contain between 1 and 100 entries")

        roles_claim = os.getenv("AEGISFLOW_OIDC_ROLES_CLAIM", "roles").strip()
        if not roles_claim or any(not part for part in roles_claim.split(".")):
            raise AuthConfigurationError("OIDC roles claim path is invalid")

        return cls(
            mode=mode,  # type: ignore[arg-type]
            static_keys_file=static_keys_file,
            oidc_issuer=issuer,
            oidc_audience=audience,
            oidc_jwks_url=jwks_url,
            oidc_algorithms=algorithms,
            oidc_roles_claim=roles_claim,
            oidc_role_map=role_map,
            oidc_clock_skew_seconds=_bounded_env_int(
                "AEGISFLOW_OIDC_CLOCK_SKEW_SECONDS", 30, 0, 300
            ),
            oidc_max_token_lifetime_seconds=_bounded_env_int(
                "AEGISFLOW_OIDC_MAX_TOKEN_LIFETIME_SECONDS", 3600, 60, 86_400
            ),
            oidc_jwks_cache_seconds=_bounded_env_int(
                "AEGISFLOW_OIDC_JWKS_CACHE_SECONDS", 300, 30, 3600
            ),
        )


class _JwksCache:
    def __init__(self, url: str, cache_seconds: int) -> None:
        self._url = url
        self._cache_seconds = cache_seconds
        self._keys: dict[str, Mapping[str, Any]] = {}
        self._expires_at = 0.0
        self._next_refresh_attempt = 0.0
        self._refresh_backoff_seconds = min(30, cache_seconds)
        self._lock = threading.Lock()

    def key(self, key_id: str) -> Mapping[str, Any]:
        with self._lock:
            now = time.monotonic()
            expired = now >= self._expires_at
            missing = key_id not in self._keys
            if (expired or missing) and now >= self._next_refresh_attempt:
                # Unknown key IDs are untrusted input. Bound refresh attempts so they
                # cannot turn token parsing into an outbound request amplifier.
                self._next_refresh_attempt = now + self._refresh_backoff_seconds
                self._refresh()
            elif expired:
                raise AuthenticationError("identity_provider_unavailable", status_code=503)
            key = self._keys.get(key_id)
        if key is None:
            raise AuthenticationError("invalid_credentials")
        return key

    def _refresh(self) -> None:
        try:
            with httpx.Client(timeout=3.0, follow_redirects=False) as client:
                response = client.get(self._url, headers={"Accept": "application/json"})
                response.raise_for_status()
                if len(response.content) > _MAX_JWKS_BYTES:
                    raise ValueError("JWKS response is too large")
                payload = response.json()
            raw_keys = payload.get("keys") if isinstance(payload, dict) else None
            if not isinstance(raw_keys, list) or not raw_keys or len(raw_keys) > _MAX_KEYS:
                raise ValueError("JWKS keys are invalid")
            parsed: dict[str, Mapping[str, Any]] = {}
            for item in raw_keys:
                if not isinstance(item, dict):
                    raise ValueError("JWKS key is invalid")
                key_id = item.get("kid")
                if not isinstance(key_id, str) or not _IDENTIFIER.fullmatch(key_id):
                    raise ValueError("JWKS key id is invalid")
                parsed[key_id] = item
        except (httpx.HTTPError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise AuthenticationError("identity_provider_unavailable", status_code=503) from exc
        self._keys = parsed
        self._expires_at = time.monotonic() + self._cache_seconds


class Authenticator:
    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self._static_keys = (
            _load_static_keys(settings.static_keys_file)
            if settings.mode == "api_key" and settings.static_keys_file is not None
            else ()
        )
        self._jwks = (
            _JwksCache(settings.oidc_jwks_url, settings.oidc_jwks_cache_seconds)
            if settings.mode == "oidc" and settings.oidc_jwks_url is not None
            else None
        )

    @classmethod
    def from_env(cls) -> Authenticator:
        return cls(AuthSettings.from_env())

    def authenticate_headers(self, headers: Mapping[str, str]) -> Principal:
        if self.settings.mode == "demo":
            return Principal(
                subject="demo-analyst",
                display_name="Demo analyst",
                roles=(Role.ADMIN,),
                auth_method="demo",
            )
        if self.settings.mode == "api_key":
            value = headers.get("x-api-key")
            if value is None or not value:
                raise AuthenticationError("credentials_required", challenge="ApiKey")
            return self._authenticate_api_key(value)
        authorization = headers.get("authorization")
        if authorization is None:
            raise AuthenticationError("credentials_required")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token:
            raise AuthenticationError("invalid_credentials")
        return self._authenticate_oidc(token)

    def authenticate_websocket(self, headers: Mapping[str, str]) -> tuple[Principal, str | None]:
        synthetic = {key.lower(): value for key, value in headers.items()}
        offered = [
            value.strip()
            for value in synthetic.get("sec-websocket-protocol", "").split(",")
            if value.strip()
        ]
        for value in offered:
            if value.startswith("aegisflow.bearer."):
                synthetic["authorization"] = f"Bearer {value.removeprefix('aegisflow.bearer.')}"
            elif value.startswith("aegisflow.key."):
                encoded = value.removeprefix("aegisflow.key.")
                try:
                    padding = "=" * (-len(encoded) % 4)
                    synthetic["x-api-key"] = base64.urlsafe_b64decode(encoded + padding).decode()
                except (UnicodeDecodeError, ValueError) as exc:
                    raise AuthenticationError("invalid_credentials") from exc
        principal = self.authenticate_headers(synthetic)
        return principal, "aegisflow" if "aegisflow" in offered else None

    def _authenticate_api_key(self, presented: str) -> Principal:
        if len(presented) < 24 or len(presented) > 512:
            raise AuthenticationError("invalid_credentials", challenge="ApiKey")
        digest = hashlib.sha256(presented.encode()).hexdigest()
        matched: _StaticKey | None = None
        for candidate in self._static_keys:
            if secrets_compare(digest, candidate.digest):
                matched = candidate
        if matched is None:
            raise AuthenticationError("invalid_credentials", challenge="ApiKey")
        return Principal(
            subject=matched.subject,
            display_name=matched.display_name,
            roles=matched.roles,
            auth_method="api_key",
            credential_id=matched.key_id,
        )

    def _authenticate_oidc(self, token: str) -> Principal:
        if len(token) > 16_384 or self._jwks is None:
            raise AuthenticationError("invalid_credentials")
        try:
            header = jwt.get_unverified_header(token)
            key_id = header.get("kid")
            algorithm = header.get("alg")
            if (
                not isinstance(key_id, str)
                or not _IDENTIFIER.fullmatch(key_id)
                or algorithm not in self.settings.oidc_algorithms
            ):
                raise AuthenticationError("invalid_credentials")
            pyjwk = jwt.PyJWK.from_dict(dict(self._jwks.key(key_id)))
            if pyjwk.algorithm_name != algorithm:
                raise AuthenticationError("invalid_credentials")
            claims = jwt.decode(
                token,
                key=pyjwk.key,
                algorithms=[algorithm],
                audience=self.settings.oidc_audience,
                issuer=self.settings.oidc_issuer,
                leeway=self.settings.oidc_clock_skew_seconds,
                options={"require": ["exp", "iat", "sub"]},
            )
            issued_at = int(claims["iat"])
            expires_at = int(claims["exp"])
            if expires_at <= issued_at or (
                expires_at - issued_at > self.settings.oidc_max_token_lifetime_seconds
            ):
                raise AuthenticationError("invalid_credentials")
            subject = str(claims["sub"])
            if not _IDENTIFIER.fullmatch(subject):
                raise AuthenticationError("invalid_credentials")
            roles = self._roles_from_claims(claims)
            display_name = _bounded_display_name(
                claims.get("name") or claims.get("preferred_username") or subject
            )
        except AuthenticationError:
            raise
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError("credentials_expired") from exc
        except (jwt.InvalidTokenError, KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("invalid_credentials") from exc
        return Principal(
            subject=subject,
            display_name=display_name,
            roles=roles,
            auth_method="oidc",
            credential_id=key_id,
        )

    def _roles_from_claims(self, claims: Mapping[str, Any]) -> tuple[Role, ...]:
        value: Any = claims
        for part in self.settings.oidc_roles_claim.split("."):
            value = value.get(part) if isinstance(value, Mapping) else None
        raw_roles = [value] if isinstance(value, str) else value if isinstance(value, list) else []
        roles = {
            mapped
            for item in raw_roles
            if isinstance(item, str)
            if (mapped := self.settings.oidc_role_map.get(item)) is not None
        }
        return tuple(sorted(roles, key=_ROLE_LEVEL.__getitem__))


@dataclass
class _RateWindow:
    minute: int
    count: int


class PrincipalRateLimiter:
    def __init__(
        self,
        *,
        read_per_minute: int,
        mutation_per_minute: int,
        websocket_per_minute: int,
        maximum_principals: int = 10_000,
    ) -> None:
        self._limits = {
            "read": read_per_minute,
            "mutation": mutation_per_minute,
            "websocket": websocket_per_minute,
        }
        if any(value <= 0 for value in self._limits.values()) or maximum_principals <= 0:
            raise ValueError("rate limits must be positive")
        self._maximum_keys = maximum_principals * len(self._limits)
        self._windows: OrderedDict[tuple[str, str], _RateWindow] = OrderedDict()
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> PrincipalRateLimiter:
        return cls(
            read_per_minute=_bounded_env_int(
                "AEGISFLOW_AUTH_READS_PER_MINUTE", 1200, 1, 100_000
            ),
            mutation_per_minute=_bounded_env_int(
                "AEGISFLOW_AUTH_MUTATIONS_PER_MINUTE", 120, 1, 10_000
            ),
            websocket_per_minute=_bounded_env_int(
                "AEGISFLOW_AUTH_WEBSOCKETS_PER_MINUTE", 30, 1, 1000
            ),
        )

    def allow(self, principal: Principal, scope: Literal["read", "mutation", "websocket"]) -> bool:
        now_minute = int(time.monotonic() // 60)
        key = (principal.subject, scope)
        with self._lock:
            window = self._windows.pop(key, None)
            if window is None or window.minute != now_minute:
                window = _RateWindow(now_minute, 0)
            if window.count >= self._limits[scope]:
                self._windows[key] = window
                return False
            window.count += 1
            self._windows[key] = window
            while len(self._windows) > self._maximum_keys:
                self._windows.popitem(last=False)
            return True


def _load_static_keys(path: Path) -> tuple[_StaticKey, ...]:
    try:
        if path.stat().st_size > _MAX_KEYS_FILE_BYTES:
            raise ValueError("key file is too large")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != "1.0.0":
            raise ValueError("key file schema is invalid")
        raw_keys = payload.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys or len(raw_keys) > _MAX_KEYS:
            raise ValueError("key list is invalid")
        keys: list[_StaticKey] = []
        seen_ids: set[str] = set()
        for item in raw_keys:
            if not isinstance(item, dict):
                raise ValueError("key entry is invalid")
            key_id = str(item.get("id", ""))
            subject = str(item.get("subject", ""))
            digest = str(item.get("sha256", "")).lower()
            if (
                not _IDENTIFIER.fullmatch(key_id)
                or not _IDENTIFIER.fullmatch(subject)
                or key_id in seen_ids
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                raise ValueError("key identity or digest is invalid")
            raw_roles = item.get("roles")
            if not isinstance(raw_roles, list) or not raw_roles:
                raise ValueError("key roles are invalid")
            roles = tuple(
                sorted({Role(str(role)) for role in raw_roles}, key=_ROLE_LEVEL.__getitem__)
            )
            keys.append(
                _StaticKey(
                    key_id=key_id,
                    subject=subject,
                    display_name=_bounded_display_name(item.get("display_name") or subject),
                    digest=digest,
                    roles=roles,
                )
            )
            seen_ids.add(key_id)
        return tuple(keys)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise AuthConfigurationError("invalid API key metadata file") from exc


def _bounded_display_name(value: object) -> str:
    normalized = " ".join(str(value).split())[:128]
    return normalized or "Authenticated user"


def _validate_https_or_loopback_url(value: str, label: str) -> None:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    if (
        not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))
    ):
        raise AuthConfigurationError(f"{label} must use HTTPS or loopback HTTP")


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def secrets_compare(left: str, right: str) -> bool:
    # Kept behind a named helper so tests can exercise all key candidates without
    # exposing which digest matched through ordinary string-comparison timing.
    import secrets

    return secrets.compare_digest(left, right)
