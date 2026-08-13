from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import bcrypt
import pytest
import yaml
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from scripts.accept_oidc import _load_credentials
from scripts.prepare_oidc_acceptance import REQUIRED_FILES, prepare


def test_dex_hardening_keeps_only_required_runtime_paths_writable() -> None:
    compose = yaml.safe_load(Path("compose.oidc.yml").read_text(encoding="utf-8"))
    dex = compose["services"]["dex"]

    assert dex["read_only"] is True
    assert dex["cap_drop"] == ["ALL"]
    assert {entry.split(":", 1)[0] for entry in dex["tmpfs"]} == {
        "/tmp",
        "/var/dex",
    }


def test_prepare_oidc_acceptance_keeps_plaintext_out_of_dex_config(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "oidc"
    credentials = prepare(runtime_dir)

    assert REQUIRED_FILES == {item.name for item in runtime_dir.iterdir()}
    parsed = _load_credentials(runtime_dir / "credentials.json")
    assert parsed["issuer"] == credentials["issuer"]
    dex_config = (runtime_dir / "dex.yaml").read_text(encoding="utf-8")
    hashes = re.findall(r'hash: "([^"]+)"', dex_config)
    assert len(hashes) == len(parsed["users"])
    assert dex_config.count("public: true") == 2
    for user in parsed["users"].values():
        assert user["password"] not in dex_config
        assert any(
            bcrypt.checkpw(user["password"].encode(), value.encode())
            for value in hashes
        )

    certificate = x509.load_pem_x509_certificate(
        (runtime_dir / "server.pem").read_bytes()
    )
    names = cast(
        x509.SubjectAlternativeName,
        certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value,
    )
    assert set(names.get_values_for_type(x509.DNSName)) == {"localhost", "dex"}
    assert "127.0.0.1" in {
        str(value) for value in names.get_values_for_type(x509.IPAddress)
    }


def test_prepare_oidc_acceptance_reuses_complete_runtime_and_rotates_explicitly(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "oidc"
    first = prepare(runtime_dir)
    reused = prepare(runtime_dir)

    assert reused["generated_at"] == first["generated_at"]
    rotated = prepare(runtime_dir, force=True)
    first_password = first["users"]["viewer"]["password"]
    rotated_password = rotated["users"]["viewer"]["password"]
    assert rotated_password != first_password


def test_prepare_oidc_acceptance_refuses_partial_runtime(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "oidc"
    runtime_dir.mkdir()
    (runtime_dir / "ca.pem").write_text("partial", encoding="utf-8")

    with pytest.raises(RuntimeError, match="partial"):
        prepare(runtime_dir)
