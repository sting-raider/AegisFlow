"""Immutable registration contract for DEV2-CONTEXT-001."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from packages.features.research import TEMPORAL_FEATURE_NAMES
from training.v2.missingness import CORE_DIM, INPUT_NAMES, observation_inputs
from training.v2.provenance import read_object, sha256_file
from training.v2.registered_family import text_digest
from training.v2.tensors import SequenceRecord
from training.v2.transfer_support import load_registration as load_missingness_registration

REGISTRATION_PATH = "configs/research-v2/registered/DEV2-CONTEXT-001.json"
REGISTRATION_SHA256 = "9715c4acd1ae3aa03ff49f1d6404097d5873c51cff3e0a69ccdad8cba9fc7157"
VIEWS = (
    "causal_context",
    "shuffled_context",
    "no_context",
    "non_causal_reference",
)
_SIDECAR_SCHEMA_VERSION = "1.1.0"
_COLD_INDEX = TEMPORAL_FEATURE_NAMES.index("temporal_cold_start")


@dataclass(frozen=True)
class ContextRow:
    scenario: str
    causal: np.ndarray
    terminal: np.ndarray


def _vector(value: Any, name: str) -> np.ndarray:
    array = np.asarray(value, dtype=np.float64)
    if array.shape != (len(TEMPORAL_FEATURE_NAMES),) or not np.isfinite(array).all():
        raise ValueError(f"invalid {name} context vector")
    return array


def load_context_rows(
    sidecar_directory: Path, manifest: Mapping[str, Any]
) -> dict[str, ContextRow]:
    """Load exact registered sidecars and reject schema/cohort drift."""
    declared = {report["sidecar_file"] for report in manifest["scenarios"]}
    actual = {path.name for path in sidecar_directory.glob("*.context.json")}
    if actual != declared:
        raise ValueError("context sidecar file set differs from registered manifest")
    rows: dict[str, ContextRow] = {}
    for report in manifest["scenarios"]:
        path = sidecar_directory / report["sidecar_file"]
        if (
            not path.is_file()
            or path.stat().st_size != report["sidecar_size_bytes"]
            or sha256_file(path) != report["output_sha256"]
        ):
            raise ValueError(f"context sidecar hash/size mismatch: {path.name}")
        payload = read_object(path)
        if (
            payload["schema_version"] != _SIDECAR_SCHEMA_VERSION
            or payload["scenario"] != report["scenario"]
            or payload["temporal_feature_names"] != list(TEMPORAL_FEATURE_NAMES)
            or payload["source_hashes"] != report["source_hashes"]
            or payload["ledger_sha256"] != report["ledger_sha256"]
            or payload["emitted_count"] != report["emitted_rows"]
            or payload["non_causal_reference"]["deployable"] is not False
        ):
            raise ValueError(f"context sidecar contract mismatch: {path.name}")
        entries = payload["entries"]
        if not isinstance(entries, list) or len(entries) != report["emitted_rows"]:
            raise ValueError(f"context sidecar row count mismatch: {path.name}")
        for entry in entries:
            event_id = entry.get("event_id") if isinstance(entry, dict) else None
            if not isinstance(event_id, str) or not event_id or event_id in rows:
                raise ValueError("context sidecars require globally unique event IDs")
            rows[event_id] = ContextRow(
                scenario=report["scenario"],
                causal=_vector(entry.get("vector"), "causal"),
                terminal=_vector(
                    entry.get("non_causal_terminal_vector"), "terminal"
                ),
            )
    if len(rows) != manifest["totals"]["emitted_rows"]:
        raise ValueError("context sidecar total row count differs from manifest")
    return rows


def _stratum_seed(seed: int, role: str, scenario: str) -> int:
    material = f"{seed}\0{role}\0{scenario}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "little")


def context_views(
    records: Sequence[SequenceRecord],
    context_rows: Mapping[str, ContextRow],
    *,
    role: str,
    seed: int,
) -> dict[str, np.ndarray]:
    """Build registered paired inputs with role- and scenario-local shuffling."""
    if not records:
        raise ValueError("context view construction requires rows")
    event_ids = [record["event_id"] for record in records]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("context view construction requires unique event IDs")
    joined: list[ContextRow] = []
    for record in records:
        row = context_rows.get(record["event_id"])
        if row is None:
            raise ValueError(f"missing context row: {record['event_id']}")
        if row.scenario != record["scenario"]:
            raise ValueError(f"context scenario mismatch: {record['event_id']}")
        joined.append(row)

    portable = np.asarray(observation_inputs(records).values[:, :CORE_DIM], dtype=np.float64)
    causal = np.stack([row.causal for row in joined])
    terminal = np.stack([row.terminal for row in joined])
    shuffled = np.empty_like(causal)
    scenarios = sorted({record["scenario"] for record in records})
    for scenario in scenarios:
        indices = sorted(
            (index for index, record in enumerate(records) if record["scenario"] == scenario),
            key=lambda index: records[index]["event_id"],
        )
        permutation = np.random.default_rng(_stratum_seed(seed, role, scenario)).permutation(
            len(indices)
        )
        for destination, source_position in zip(indices, permutation, strict=True):
            shuffled[destination] = causal[indices[int(source_position)]]
    no_context = np.zeros_like(causal)
    no_context[:, _COLD_INDEX] = 1.0
    contexts = {
        "causal_context": causal,
        "shuffled_context": shuffled,
        "no_context": no_context,
        "non_causal_reference": terminal,
    }
    matrices = {
        view: np.concatenate((portable, contexts[view]), axis=1) for view in VIEWS
    }
    expected_shape = (len(records), CORE_DIM + len(TEMPORAL_FEATURE_NAMES))
    if any(
        matrix.shape != expected_shape or not np.isfinite(matrix).all()
        for matrix in matrices.values()
    ):
        raise ValueError("context view matrix violates the registered contract")
    if any(
        not np.array_equal(matrix[:, :CORE_DIM], portable)
        for matrix in matrices.values()
    ):
        raise RuntimeError("portable inputs changed across context views")
    return matrices


def validate_registration(root: Path, config: Mapping[str, Any]) -> None:
    """Reject registration drift before any model can be fit."""
    if (
        config.get("schema_version") != "1.0.0"
        or config.get("experiment_id") != "DEV2-CONTEXT-001"
        or config.get("status") != "registered_not_run"
        or config.get("permitted_use") != "development_only"
        or config.get("candidate_promotion_authorized") is not False
    ):
        raise ValueError("context registration status or scope changed")
    for field in ("protocol", "prepared_manifest", "context_manifest"):
        binding = config[field]
        if text_digest(root / binding["path"]) != binding["sha256"]:
            raise ValueError(f"context registration {field} binding changed")

    missingness = load_missingness_registration(root)
    if config["cohort"] != missingness["cohort"]:
        raise ValueError("context registration changed the common-support cohort")
    splits = config["splits"]
    for key in (
        "attack_environments",
        "fit_choices_per_target",
        "background_benign",
        "site_orientations",
        "fit_per_binary_class_cap",
        "fit_selection",
        "target_includes_incidental_benign",
        "expected_source_target_choices",
        "site_orientations_reuse_fitted_model",
    ):
        if splits[key] != missingness["splits"][key]:
            raise ValueError(f"context registration changed split field {key}")
    if (
        splits["expected_model_fits"] != 36
        or splits["expected_site_evaluations"] != 72
    ):
        raise ValueError("context registration matrix size changed")

    representation = config["representation"]
    if (
        representation["portable_core_features"] != list(INPUT_NAMES[:CORE_DIM])
        or representation["temporal_features"] != list(TEMPORAL_FEATURE_NAMES)
        or representation["views"] != list(VIEWS)
        or representation["portable_dimension"] != CORE_DIM
        or representation["temporal_dimension"] != len(TEMPORAL_FEATURE_NAMES)
        or representation["dimension"] != CORE_DIM + len(TEMPORAL_FEATURE_NAMES)
        or representation["value_dtype"] != "float64"
        or representation["sequence_consumed"] is not False
        or representation["signatures_consumed"] is not False
    ):
        raise ValueError("context representation contract changed")
    for field in ("model", "ood", "calibration", "fusion"):
        if config[field] != missingness[field]:
            raise ValueError(f"context registration changed shared {field} contract")

    analysis = config["paired_analysis"]
    if (
        analysis["comparisons"]
        != [
            "causal_context_minus_shuffled_context",
            "causal_context_minus_no_context",
        ]
        or analysis["terminal_reference_excluded_from_benefit_rule"] is not True
        or analysis["expected_strata"] != 6
        or analysis["bootstrap_replicates"] != 2000
        or analysis["benefit_minimum_positive_strata_per_control"] != 5
        or analysis["benefit_requires_all_targets_and_orientations"] is not True
        or analysis["benefit_max_safety_upper_delta"] != 0.005
        or analysis["missing_comparison_policy"] != "benefit_rule_fails_visibly"
    ):
        raise ValueError("context paired-analysis rule changed")

    prepared = read_object(root / config["prepared_manifest"]["path"])
    context = read_object(root / config["context_manifest"]["path"])
    context_binding = config["context_manifest"]
    if (
        prepared["permitted_use"] != "development_only"
        or context["permitted_use"] != "development_only"
        or context["source_preparation"]["manifest_sha256"]
        != config["prepared_manifest"]["sha256"]
        or sum(entry["records"] for entry in prepared["scenarios"])
        != config["prepared_manifest"]["expected_rows"]
        or context["totals"]["emitted_rows"] != context_binding["expected_rows"]
        or context["totals"]["history_flows"]
        != context_binding["expected_history_flows"]
        or context["sidecar_schema_version"]
        != context_binding["sidecar_schema_version"]
        or context["totals"]["cold_rows"] != context_binding["causal_cold_rows"]
        or context["totals"]["late_rows"] != context_binding["causal_late_rows"]
        or context["totals"]["non_causal_cold_rows"]
        != context_binding["non_causal_cold_rows"]
        or context["totals"]["non_causal_late_rows"]
        != context_binding["non_causal_late_rows"]
    ):
        raise ValueError("context registration preparation evidence changed")


def load_registration(root: Path) -> dict[str, Any]:
    path = root / REGISTRATION_PATH
    if text_digest(path) != REGISTRATION_SHA256:
        raise ValueError("context registration differs from its immutable digest")
    config = read_object(path)
    validate_registration(root, config)
    return config
