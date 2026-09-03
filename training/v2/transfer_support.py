"""Common-support admission and capture-disjoint splits for representation studies.

This cohort is intentionally a distinct-input development benchmark, not an estimate
of operational traffic prevalence. Exclusions remain counted and content-bound.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from training.v2.missingness import CHANNELS, CORE_DIM, INPUT_NAMES, VIEWS, observation_inputs
from training.v2.origin_probe import KINDS, vector_keys
from training.v2.partitions import assert_disjoint_partitions
from training.v2.provenance import partition_provenance, read_object
from training.v2.registered_family import text_digest
from training.v2.tensors import SequenceRecord, class_capped_subset

REGISTRATION_PATH = "configs/research-v2/registered/DEV2-MISSINGNESS-001.json"
REGISTRATION_SHA256 = "b60ebf4873582e6507d7fa36f8eba8cea615f7af978b647f3bc40b78ce974ef4"


def load_registration(root: Path) -> dict[str, Any]:
    path = root / REGISTRATION_PATH
    if text_digest(path) != REGISTRATION_SHA256:
        raise ValueError("missingness registration differs from the implemented protocol")
    config = read_object(path)
    for field in ("protocol", "prepared_manifest"):
        binding = config[field]
        if text_digest(root / binding["path"]) != binding["sha256"]:
            raise ValueError(f"missingness registration {field} binding changed")
    representation = config["representation"]
    if (
        representation["portable_core_features"] != list(INPUT_NAMES[:CORE_DIM])
        or representation["sequence_channels"] != list(CHANNELS)
        or representation["views"] != list(VIEWS)
        or representation["transforms"] != list(KINDS)
    ):
        raise ValueError("missingness input contract differs from registration")
    return config


def common_support(
    records: Sequence[SequenceRecord],
) -> tuple[list[SequenceRecord], dict[str, Any]]:
    """Use the same portable-core-distinct rows in every representation comparison.

    Remove all cross-capture core groups using features/scenarios only, then retain
    the minimum event ID within each remaining same-capture, same-label group. Never
    select a convenient label when information removal introduces ambiguity.
    """
    event_ids = [r["event_id"] for r in records]
    if len(set(event_ids)) != len(event_ids) or any(not event_id for event_id in event_ids):
        raise ValueError("common-support admission requires unique nonempty event IDs")
    for record in records:
        if (
            record["binary_label"] not in {"benign", "malicious"}
            or (record["binary_label"] == "benign") != (record["family"] == "benign")
            or not record["scenario"]
            or not record["family"]
        ):
            raise ValueError("invalid label or scenario in common-support admission")
    inputs = observation_inputs(records)
    groups: dict[bytes, list[int]] = defaultdict(list)
    for index, key in enumerate(vector_keys(inputs.values[:, :CORE_DIM])):
        groups[key].append(index)
    retained: list[SequenceRecord] = []
    shared: list[SequenceRecord] = []
    duplicates: list[SequenceRecord] = []
    ambiguous: list[SequenceRecord] = []
    shared_groups = 0
    optional_variant_groups = 0
    for indices in groups.values():
        group = sorted((records[i] for i in indices), key=lambda row: row["event_id"])
        optional_variant_groups += int(
            len({(inputs.values[i].tobytes(), inputs.observed[i].tobytes()) for i in indices}) > 1
        )
        if len({row["scenario"] for row in group}) > 1:
            shared.extend(group)
            shared_groups += 1
            continue
        if len({(row["binary_label"], row["family"]) for row in group}) > 1:
            ambiguous.extend(group)
            continue
        retained.append(group[0])
        duplicates.extend(group[1:])
    retained.sort(key=lambda row: row["event_id"])
    if not retained:
        raise ValueError("no independent common-support rows remain")
    return retained, {
        "policy": (
            "core9_cross_capture_and_within_capture_conflicting_label_groups_excluded_"
            "then_min_event_id_per_same_label_group"
        ),
        "input_core_groups": len(groups),
        "cross_capture_groups": shared_groups,
        "groups_with_optional_packet_variants": optional_variant_groups,
        "input": partition_provenance(records),
        "cross_capture_excluded": partition_provenance(shared),
        "within_capture_ambiguous_excluded": partition_provenance(ambiguous),
        "within_capture_duplicate_rows": partition_provenance(duplicates),
        "retained": partition_provenance(retained),
        "limitations": [
            "Excluding cross-capture aliases can remove hard indistinguishable traffic.",
            "Selecting one portable-core representative discards some optional packet variation.",
            "Conflicting labels introduced by the reduced view are excluded, not resolved.",
            "Results apply to this common-support cohort, not all observed traffic or prevalence.",
        ],
    }


def transfer_partitions(
    records: Sequence[SequenceRecord],
    *,
    sources: Sequence[str],
    target: str,
    background_benign: str,
    orientation: Mapping[str, str],
    per_class_cap: int,
    seed: int,
) -> dict[str, list[SequenceRecord]]:
    roles = [
        *sources,
        target,
        background_benign,
        orientation["calibration"],
        orientation["benign_test"],
    ]
    if not sources or len(set(roles)) != len(roles) or per_class_cap < 1:
        raise ValueError("transfer roles must name distinct captures with positive fit cap")
    background = [r for r in records if r["scenario"] == background_benign]
    if not background or any(r["binary_label"] != "benign" for r in background):
        raise ValueError("background capture must be present and benign-only")
    partitions = {
        "fit": class_capped_subset(
            records,
            scenarios={*sources, background_benign},
            per_class_cap=per_class_cap,
            seed=seed,
        ),
        "site_calibration": [r for r in records if r["scenario"] == orientation["calibration"]],
        "benign_test": [r for r in records if r["scenario"] == orientation["benign_test"]],
        "target": [r for r in records if r["scenario"] == target],
    }
    assert_disjoint_partitions(partitions)
    for role in ("site_calibration", "benign_test"):
        if any(r["binary_label"] != "benign" for r in partitions[role]):
            raise ValueError("site calibration/testing must be benign-only")
    if not any(r["binary_label"] == "malicious" for r in partitions["target"]):
        raise ValueError("target capture has no attacks for transfer evaluation")
    return partitions
