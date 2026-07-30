# ML methodology

## Smoke pipeline

The deterministic smoke generator uses seed 431 and source groups. A grouped holdout
prevents rows from the same synthetic capture group appearing on both sides. Standard
scaling is fitted only on training rows. Logistic regression and a class-weighted
random forest are compared using macro F1; the selected classifier retains multiclass
attack-family probabilities. Isolation Forest is fitted only on benign training rows.

Threshold metadata explicitly says “smoke baseline.” Results in `metrics.json` are not
published as real-world performance.

## Production evaluation gate

A candidate must report per-class precision/recall/F1, macro/weighted F1, PR-AUC,
secondary ROC-AUC, benign false-positive rate, calibration, false alerts per replay
hour, held-out-family unknown detection, known/unknown confusion, single/batch
latency, throughput, resource use, and cross-dataset behavior. Splits must be
time-, capture-day-, or source-file-grouped. Preprocessing fits only the training fold.

Promotion requires schema compatibility, checksum validation, a bounded benign
false-positive target, improvement without material regression on critical classes,
and a rollback pointer. Drift and analyst feedback only create candidates.
