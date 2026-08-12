from __future__ import annotations

import argparse
import json
import secrets
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import TypedDict, cast
from uuid import NAMESPACE_URL, uuid5

import bcrypt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SCHEMA_VERSION = "1.1.0"
DEFAULT_RUNTIME_DIR = Path(".runtime/oidc")
ISSUER = "https://localhost:5556/dex"
CLIENT_ID = "aegisflow-api"
WRONG_AUDIENCE_CLIENT_ID = "aegisflow-wrong-audience"
USER_ROLES = {
    "viewer": "viewer",
    "analyst": "analyst",
    "admin": "admin",
    "rate_viewer": "viewer",
    "expiry_viewer": "viewer",
    "rotation_viewer": "viewer",
}
REQUIRED_FILES = {
    "ca.pem",
    "ca-key.pem",
    "server.pem",
    "server-key.pem",
    "dex.yaml",
    "credentials.json",
}


class PreparedUser(TypedDict):
    username: str
    password: str
    user_id: str
    expected_role: str


class PreparedCredentials(TypedDict):
    schema_version: str
    generated_at: str
    issuer: str
    discovery_url: str
    token_url: str
    client_id: str
    wrong_audience_client_id: str
    ca_file: str
    users: dict[str, PreparedUser]


def _private_key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _certificate_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _write(path: Path, content: bytes | str, *, mode: int) -> None:
    payload = content.encode() if isinstance(content, str) else content
    path.write_bytes(payload)
    try:
        path.chmod(mode)
    except OSError:
        pass


def _certificates() -> tuple[bytes, bytes, bytes, bytes]:
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "AegisFlow local acceptance CA")]
    )
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName("dex"),
                    x509.IPAddress(ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        _certificate_pem(ca_certificate),
        _private_key_pem(ca_key),
        _certificate_pem(server_certificate),
        _private_key_pem(server_key),
    )


def _quoted(value: str) -> str:
    return json.dumps(value)


def prepare(runtime_dir: Path, *, force: bool = False) -> PreparedCredentials:
    runtime_dir = runtime_dir.resolve()
    existing = {path.name for path in runtime_dir.iterdir()} if runtime_dir.exists() else set()
    if existing and not force:
        if REQUIRED_FILES.issubset(existing):
            payload = json.loads((runtime_dir / "credentials.json").read_text(encoding="utf-8"))
            if payload.get("schema_version") != SCHEMA_VERSION:
                raise RuntimeError("existing OIDC acceptance credentials have an unknown schema")
            return cast(PreparedCredentials, payload)
        raise RuntimeError(
            "OIDC runtime directory is partial; rerun with --force to replace known files"
        )
    runtime_dir.mkdir(parents=True, exist_ok=True)
    if force:
        for name in REQUIRED_FILES:
            (runtime_dir / name).unlink(missing_ok=True)

    ca_pem, ca_key_pem, server_pem, server_key_pem = _certificates()
    users: dict[str, PreparedUser] = {}
    static_passwords: list[str] = []
    for name, role in USER_ROLES.items():
        email = f"{name.replace('_', '-')}@aegisflow.invalid"
        password = secrets.token_urlsafe(24)
        user_id = str(uuid5(NAMESPACE_URL, f"aegisflow-oidc-acceptance:{name}"))
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()
        users[name] = {
            "username": email,
            "password": password,
            "user_id": user_id,
            "expected_role": role,
        }
        static_passwords.extend(
            [
                f"- email: {_quoted(email)}",
                f"  hash: {_quoted(password_hash)}",
                f"  username: {_quoted(name.replace('_', '-'))}",
                f"  userID: {_quoted(user_id)}",
            ]
        )

    dex_config = "\n".join(
        [
            f"issuer: {_quoted(ISSUER)}",
            "storage:",
            "  type: sqlite3",
            "  config:",
            "    file: /var/dex/dex.db",
            "web:",
            "  https: 0.0.0.0:5556",
            "  tlsCert: /run/aegisflow-oidc/server.pem",
            "  tlsKey: /run/aegisflow-oidc/server-key.pem",
            "  headers:",
            '    X-Frame-Options: "DENY"',
            '    X-Content-Type-Options: "nosniff"',
            '    Content-Security-Policy: "default-src \'self\'"',
            "telemetry:",
            "  http: 0.0.0.0:5558",
            "expiry:",
            '  signingKeys: "24h"',
            '  idTokens: "60s"',
            "oauth2:",
            "  grantTypes:",
            '    - "password"',
            "  passwordConnector: local",
            "enablePasswordDB: true",
            "staticClients:",
            f"- id: {_quoted(CLIENT_ID)}",
            "  public: true",
            '  name: "AegisFlow local acceptance"',
            f"- id: {_quoted(WRONG_AUDIENCE_CLIENT_ID)}",
            "  public: true",
            '  name: "AegisFlow wrong-audience control"',
            "staticPasswords:",
            *static_passwords,
            "logger:",
            '  level: "info"',
            '  format: "json"',
            "",
        ]
    )
    credentials: PreparedCredentials = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "issuer": ISSUER,
        "discovery_url": f"{ISSUER}/.well-known/openid-configuration",
        "token_url": f"{ISSUER}/token",
        "client_id": CLIENT_ID,
        "wrong_audience_client_id": WRONG_AUDIENCE_CLIENT_ID,
        "ca_file": str(runtime_dir / "ca.pem"),
        "users": users,
    }

    _write(runtime_dir / "ca.pem", ca_pem, mode=0o644)
    _write(runtime_dir / "ca-key.pem", ca_key_pem, mode=0o600)
    _write(runtime_dir / "server.pem", server_pem, mode=0o644)
    # The server key is ephemeral, valid for seven days, and exists only under the
    # ignored local runtime directory. Read access is required by Dex's non-root UID.
    _write(runtime_dir / "server-key.pem", server_key_pem, mode=0o644)
    _write(runtime_dir / "dex.yaml", dex_config, mode=0o644)
    _write(
        runtime_dir / "credentials.json",
        json.dumps(credentials, indent=2) + "\n",
        mode=0o600,
    )
    return credentials


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare ephemeral local Dex credentials and TLS for OIDC acceptance"
    )
    parser.add_argument("--runtime-dir", type=Path, default=DEFAULT_RUNTIME_DIR)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    payload = prepare(args.runtime_dir, force=args.force)
    print(
        json.dumps(
            {
                "runtime_dir": str(args.runtime_dir.resolve()),
                "generated_at": payload["generated_at"],
                "reusable": True,
                "secrets_printed": False,
            }
        )
    )


if __name__ == "__main__":
    main()
