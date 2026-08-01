# ML methodology

## Smoke pipeline

The deterministic smoke generator uses seed 431 and disjoint source-group train,
calibration, and test partitions. No synthetic capture group crosses a partition.
Standard scaling is fitted only on training rows. Logistic regression, a class-weighted
random forest, and a compact MLP are compared using calibration-partition macro F1. The
selected classifier is
sigmoid-calibrated with grouped folds drawn only from the training partition and retains
multiclass attack-family probabilities. Isolation Forest and a compact PyTorch denoising
autoencoder are fitted only on benign training rows.

The benign-only calibration partition selects open-set normalization and persists a
bounded empirical CDF of the combined anomaly score. At runtime, `anomaly_percentile`
is the right-rank CDF estimate against that reference population; it is independent from
the normalized `anomaly_score`. At most 2,049 monotonic knots are retained, with linear
interpolation between knots and the source sample count recorded.

The interpretable fusion rule remains the decision mechanism. All weights and thresholds
load from `thresholds.json`. Smoke training compares the baseline with 81 candidate
weight/threshold configurations on final verdict macro F1 using the calibration partition
plus explicitly synthetic unknown fixtures, then reports both configurations on the
untouched grouped test partition. This validates the selection machinery only; public
held-family and cross-dataset evidence is required before treating the selected values as
operationally justified.

The smoke bundle records
per-class, macro/weighted, PR-AUC, ROC-AUC, calibration, confusion, benign false-positive,
synthetic-novelty, feature-importance, and single/batch CPU latency evidence. Results in
`metrics.json` are explicitly synthetic smoke evidence, not real-world performance.

## Production evaluation gate

A candidate must report per-class precision/recall/F1, macro/weighted F1, PR-AUC,
secondary ROC-AUC, benign false-positive rate, calibration, false alerts per replay
hour, held-out-family unknown detection, known/unknown confusion, single/batch
latency, throughput, resource use, and cross-dataset behavior. Splits must be
time-, capture-day-, or source-file-grouped. Preprocessing fits only the training fold.

Promotion requires schema compatibility, checksum validation, a bounded benign
false-positive target, improvement without material regression on critical classes,
and a rollback pointer. Drift and analyst feedback only create candidates.

`training.cli.evaluate_dataset` is the public-data gate. It first writes a quality and
leakage report, refuses non-finite canonical features or fewer than two normalized
classes, and supports time, capture-day, source-file, held-family, and cross-dataset
evaluation. Its class-weighted logistic model is a transparent evaluation baseline,
not an automatically promoted production candidate. Unknown-confidence selection uses
the three-percent low-confidence validation tail; the final test set never sets that
threshold.

## Runtime drift

`RuntimeDriftMonitor` maintains two bounded windows per signal. The default is 64
reference plus 64 recent observations and can be changed with
`AEGISFLOW_DRIFT_WINDOW` (minimum 8). Signals are anomaly score, classifier confidence,
normalized flow rate, normalized duration, normalized total bytes, normalized packet
length mean, and rolling alert rate. Each event records both means, window sizes,
magnitude, model version, triggering detection ID, and a review-only recommendation.

Drift rows use deterministic IDs and are written before the Redis detection is
acknowledged. `/api/v1/drift-events`, `drift_events_total`, and `drift_magnitude` expose
the result. `automatic_action_allowed` and `eligible_for_retraining` are always false.
The windows include all operational traffic as distribution observations; no traffic,
suspicious or otherwise, is inserted into a benign training baseline by this monitor.
