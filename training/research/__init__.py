"""Evidence-driven challenger research harnesses."""

from training.research.anomaly import run_cross_environment_anomaly_baselines
from training.research.baselines import (
    prepare_research_sources,
    run_cross_environment_supervised,
)

__all__ = [
    "prepare_research_sources",
    "run_cross_environment_anomaly_baselines",
    "run_cross_environment_supervised",
]
