from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from training.v2.prepare_sequences import flow_join_key, match_row, prepare_scenario
from training.v2.provenance import (
    canonical_digest,
    clean_execution_commit,
    load_verified_preparation,
    partition_provenance,
    prepare_verified_pool,
    verify_capture_pool,
)
from training.v2.tensors import load_records


def test_ambiguous_ground_truth_never_defaults_to_first_benign_label() -> None:
    key = flow_join_key("192.0.2.1", 1234, "192.0.2.2", 80, "TCP")
    rows = [
        {"ts": 10.0, "duration_s": 2.0, "label": "Benign", "family": "benign"},
        {"ts": 10.5, "duration_s": 2.0, "label": "Malicious", "family": "c_and_c"},
    ]
    with pytest.raises(ValueError, match="ambiguous"):
        match_row({key: rows}, key, 10.0, 13.0)


def test_preparation_never_overwrites_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "existing.jsonl"
    output.write_text("retained evidence\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        prepare_scenario("capture", tmp_path, output)
    assert output.read_text(encoding="utf-8") == "retained evidence\n"


def test_equivalent_labels_do_not_create_false_ambiguity() -> None:
    key = flow_join_key("192.0.2.1", 1234, "192.0.2.2", 80, "TCP")
    rows = [
        {"ts": 10.0, "duration_s": 2.0, "label": "Malicious", "family": "c_and_c"},
        {"ts": 10.5, "duration_s": 2.0, "label": "Malicious", "family": "c_and_c"},
    ]
    assert match_row({key: rows}, key, 10.0, 13.0) == rows[0]


def _pool(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    raw = tmp_path / "raw"
    raw.mkdir()
    configs = tmp_path / "configs/research-v2"
    configs.mkdir(parents=True)
    frozen = tmp_path / "configs/evaluation"
    frozen.mkdir()
    (frozen / "frozen-evidence-v1.json").write_text('{"reports": []}', encoding="utf-8")
    scenario = "CTU-Honeypot-Capture-4-1"
    pcap = b"capture fixture"
    labels = b"labels fixture"
    (raw / "fixture.pcap").write_bytes(pcap)
    (raw / f"{scenario}.conn.log.labeled").write_bytes(labels)
    (raw / f"{scenario}.manifest.json").write_text(json.dumps({
        "scenario": scenario, "pcap_filename": "fixture.pcap",
    }), encoding="utf-8")
    pool = {scenario: {
        "pcap_sha256": hashlib.sha256(pcap).hexdigest(),
        "labels_sha256": hashlib.sha256(labels).hexdigest(),
        "pcap_size_bytes": len(pcap),
    }}
    (configs / "pool-hashes.json").write_text(json.dumps(pool), encoding="utf-8")
    return tmp_path, raw, pool


def test_capture_pool_checks_actual_bytes(tmp_path: Path) -> None:
    root, raw, pool = _pool(tmp_path)
    assert verify_capture_pool(root, raw)[0] == pool
    (raw / "fixture.pcap").write_bytes(b"corrupt fixture")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_capture_pool(root, raw)


def test_capture_pool_rejects_frozen_source_before_replay(tmp_path: Path) -> None:
    root, raw, pool = _pool(tmp_path)
    digest = next(iter(pool.values()))["pcap_sha256"]
    (root / "configs/evaluation/frozen-evidence-v1.json").write_text(json.dumps({
        "reports": [{"source_files": [{"sha256": digest}]}],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="frozen-final source refused"):
        verify_capture_pool(root, raw)


def test_capture_pool_rejects_path_traversal(tmp_path: Path) -> None:
    root, raw, pool = _pool(tmp_path)
    scenario = next(iter(pool))
    (raw / f"{scenario}.manifest.json").write_text(json.dumps({
        "scenario": scenario, "pcap_filename": "../private.pcap",
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="basename"):
        verify_capture_pool(root, raw)


def test_verified_preparation_cannot_reuse_output_directory(tmp_path: Path) -> None:
    with pytest.raises(FileExistsError, match="reuse"):
        prepare_verified_pool(tmp_path, tmp_path, tmp_path)


def test_execution_commit_refuses_unrelated_import_tree(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="imported project source"):
        clean_execution_commit(tmp_path)


def _prepared(root: Path, pool: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    directory = root / "prepared"
    directory.mkdir()
    scenario = next(iter(pool))
    record: dict[str, Any] = {
        "event_id": "fixture-id", "scenario": scenario, "family": "benign",
        "detailed_label": "-", "binary_label": "benign", "seq_sizes": [60.0],
        "seq_directions": [1], "seq_iats_ms": [0.0], "total_packets": 1,
        "duration_ms": 0.1, "protocol": "TCP", "tcp_syn_count": 1, "tcp_ack_count": 0,
        "tcp_fin_count": 0, "tcp_rst_count": 0, "tcp_psh_count": 0,
        "bytes_forward": 60, "bytes_reverse": 0, "packets_forward": 1,
        "packets_reverse": 0, "src_port": 1234, "dst_port": 80, "ip_version": 4,
        "observability": "LOW",
    }
    content = (json.dumps(record) + "\n").encode()
    path = directory / f"{scenario}.jsonl"
    path.write_bytes(content)
    entry = {
        **pool[scenario], "scenario": scenario, "prepared_file": path.name,
        "prepared_size_bytes": len(content), "output_sha256": hashlib.sha256(content).hexdigest(),
        "records": 1,
    }
    manifest = {
        "schema_version": "2.0.0", "permitted_use": "development_only",
        "preparation_code_commit": "a" * 40,
        "source_pool_sha256_canonical": canonical_digest(pool), "scenarios": [entry],
    }
    manifest_path = directory / "preparation-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, manifest


def test_prepared_manifest_binds_complete_rows_and_content(tmp_path: Path) -> None:
    root, _, pool = _pool(tmp_path)
    path, manifest = _prepared(root, pool)
    records = load_verified_preparation(root, path)
    assert len(records) == 1
    partition = partition_provenance(records)
    assert partition["rows"] == 1
    assert "fixture-id" not in json.dumps(partition)
    data = path.parent / manifest["scenarios"][0]["prepared_file"]
    data.write_bytes(data.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="hash/size mismatch"):
        load_verified_preparation(root, path)


def test_prepared_manifest_rejects_missing_scenario(tmp_path: Path) -> None:
    root, _, pool = _pool(tmp_path)
    path, manifest = _prepared(root, pool)
    manifest["scenarios"] = []
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="incomplete"):
        load_verified_preparation(root, path)


@pytest.mark.parametrize("row", [[], {}, {"binary_label": "unreviewed"}])
def test_incompatible_prepared_rows_are_visible_errors(tmp_path: Path, row: object) -> None:
    path = tmp_path / "rows.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="incompatible prepared row"):
        load_records([path])
