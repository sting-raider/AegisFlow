"""Immutable registration contract for DEV2-CONTEXT-001."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from packages.features.research import TEMPORAL_FEATURE_NAMES
from training.v2.missingness import CORE_DIM, INPUT_NAMES
from training.v2.provenance import read_object
from training.v2.registered_family import text_digest
from training.v2.transfer_support import load_registration as load_missingness_registration

REGISTRATION_PATH = "configs/research-v2/registered/DEV2-CONTEXT-001.json"
REGISTRATION_SHA256 = "9715c4acd1ae3aa03ff49f1d6404097d5873c51cff3e0a69ccdad8cba9fc7157"
VIEWS = (
    "causal_context",
    "shuffled_context",
    "no_context",
    "non_causal_reference",
)


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
