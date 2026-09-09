"""Verify DEV2-CONTEXT-001 registration without fitting a model."""

from __future__ import annotations

from pathlib import Path

from scripts.verify_registered_research_v2 import safe_aggregate
from training.v2.registered_context import VIEWS, load_registration


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    config = load_registration(root)
    safe_aggregate(config)
    splits = config["splits"]
    choices = splits["expected_source_target_choices"]
    fits = choices * len(VIEWS)
    sites = fits * len(splits["site_orientations"])
    if fits != splits["expected_model_fits"]:
        raise ValueError("registered context fit count disagrees")
    if sites != splits["expected_site_evaluations"]:
        raise ValueError("registered context site count disagrees")
    print(
        f"verified DEV2-CONTEXT-001: {fits} fits, {sites} site evaluations, "
        "development only; not run"
    )


if __name__ == "__main__":
    main()

