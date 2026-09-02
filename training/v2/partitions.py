"""Fail-closed partition checks for Detector-v2 development experiments."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from training.v2.tensors import SequenceRecord, record_fingerprint


def assert_disjoint_partitions(
    partitions: Mapping[str, Sequence[SequenceRecord]],
) -> None:
    """Reject empty, duplicate-ID, or duplicate-observation experiment partitions."""

    seen_ids: dict[str, str] = {}
    seen_vectors: dict[tuple[object, ...], str] = {}
    for name, records in partitions.items():
        if not records:
            raise ValueError(f"partition {name} is empty")
        for record in records:
            event_id = str(record["event_id"])
            previous_id = seen_ids.get(event_id)
            if previous_id is not None:
                raise ValueError(
                    f"event {event_id} overlaps partitions {previous_id} and {name}"
                )
            seen_ids[event_id] = name
            fingerprint = record_fingerprint(record)
            previous_vector = seen_vectors.get(fingerprint)
            if previous_vector is not None:
                raise ValueError(
                    f"observation overlaps partitions {previous_vector} and {name}"
                )
            seen_vectors[fingerprint] = name


def assert_strict_family_rotation(
    *,
    fit: Sequence[SequenceRecord],
    site_calibration: Sequence[SequenceRecord],
    held_attack: Sequence[SequenceRecord],
    benign_test: Sequence[SequenceRecord],
    held_family: str,
) -> None:
    """Prove family exclusion, approved-benign calibration, and row isolation."""

    partitions = {
        "fit": fit,
        "site_calibration": site_calibration,
        "held_attack": held_attack,
        "benign_test": benign_test,
    }
    assert_disjoint_partitions(partitions)
    if held_family == "benign":
        raise ValueError("benign cannot be a held attack family")
    if any(str(record["family"]) == held_family for record in fit):
        raise ValueError(f"held family {held_family} appears in fit")
    if any(
        str(record["binary_label"]) != "malicious"
        or str(record["family"]) != held_family
        for record in held_attack
    ):
        raise ValueError("held-attack partition contains another label or family")
    for name, records in (
        ("site-calibration", site_calibration),
        ("benign-test", benign_test),
    ):
        if any(
            str(record["binary_label"]) != "benign"
            or str(record["family"]) != "benign"
            for record in records
        ):
            raise ValueError(f"{name} partition is not approved benign-only")
    site_scenarios = {str(record["scenario"]) for record in site_calibration}
    other_scenarios = {
        str(record["scenario"])
        for records in (fit, held_attack, benign_test)
        for record in records
    }
    if site_scenarios & other_scenarios:
        raise ValueError("site-calibration scenarios overlap another partition")
