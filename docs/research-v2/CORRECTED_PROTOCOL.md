# Corrected Detector-v2 experiment protocol

Recorded 2026-09-02, before corrected model execution. This is a development protocol,
not a model lock or authorization to query frozen final data. The historical five
experiments remain archived as unvalidated observations. No model is selected.

## Input and execution boundary

- Verify all six source PCAP/label pairs against `configs/research-v2/pool-hashes.json`
  and reject any frozen-final source hash.
- Prepare in a clean committed checkout using `training.v2.provenance`; reject
  conflicting ground-truth joins instead of choosing the first candidate. Keep
  exclusions visible. Every prepared file, source, count and preparation commit must
  be bound by a complete manifest. Do not relabel old preparation as a new execution.
- Run models from clean code. Record actual execution commit, preparation-manifest
  hash, prepared-file hashes, environment/dependency versions and exact configuration.
- Record each partition's ordered event-ID and content digests, counts, scenarios,
  labels and families. Keep raw IDs, addresses, payloads and per-row predictions out
  of committed reports. Preserve local model artifacts with hashes; do not promote them.
- Reject duplicate observations/IDs across partitions, empty partitions, held-family
  leakage, non-benign calibration, and reuse of site-calibration captures in fitting.
- Deduplicate the actual sequence/mask/aggregate model-input tensors, not a raw-field
  subset that omits service categories. Reject contradictory labels for identical
  tensors. The six verified captures yield 6,674 unique inputs with no such conflicts;
  the old fingerprint yielded 6,671 by collapsing three distinct feature vectors.

## Strict-family matrix (planned DEV2-FAMILY-002)

Repeat whole-label-family exclusion for `c_and_c`, `ddos`, and `port_scan`. Use the
34-1, 8-1 and 42-1 captures as the source pool, removing the held family before any
fitting, preprocessing or class cap. Retain up to 1,500 rows per binary class using
the deterministic seed 20260822. Holdout attack rows come only from the declared
family. Other attack families may share the malware capture with a holdout; this
proves label-family exclusion, not whole-environment exclusion.

For each family, run both hp4-calibrate/hp5-benign-test and
hp5-calibrate/hp4-benign-test orientations. Neither honeypot may enter fitting.
This yields six declared rotations, with every rotation and worst case reported.
The small deduplicated DDoS/port-scan samples must remain visible limitations.

Use the existing sequence MLP plus portable aggregate fusion, 150 epochs,
batch size 256, Adam learning rate 0.001, fit-only mean/std preprocessing, and
Mahalanobis distance from training-benign embeddings with covariance ridge 1e-6.
Seed model initialization and data-loader shuffling explicitly. No TCP-state input
is claimed unless the executed model actually consumes it.

## Thresholds and verdict semantics

Allocate the 1% calibration direct-alert budget equally to the known-score and OOD
channels (0.5% each); allocate the 5% review-inclusive budget equally (2.5% each).
Use tie-aware score cut points with the exact `>=` decision rule, allowing a threshold
above the maximum calibration score when required. These are calibration budgets,
not guarantees on independent benign data. Do not adjust them after test results.

Strong known evidence yields `known_attack`; direct OOD evidence without strong known
evidence yields `suspicious_unknown`; weaker evidence yields `needs_review`; otherwise
the verdict is `benign`. Publish all four counts. Known-channel detection of a held
family must not be called direct suspicious-unknown recall. Report direct unknown,
all detection, detection-or-review and each channel separately.

Report independent benign union FPR and review-inclusive rate, false alerts per
10,000 benign flows, score/distance distributions, sample counts and uncertainty
intervals, binary F1/PR-AUC, Brier/ECE, and the fit/calibration thresholds. A percentile
measured on the calibration pool is not an independent FPR validation. Do not invent
alerts/hour when the evaluated prepared records lack usable chronological timestamps.

## Measured costs and admission

Measure training wall time, process memory and reproducible CPU inference distributions.
Report warm-up, repetitions, batch sizes, thread count and whether tensor construction,
preprocessing and OOD calculation are included. Distinguish model-stage inference from
the durable Redis/PostgreSQL pipeline. Preserve exact artifact checksums and parameters.

Before execution, bind this protocol and the prepared manifest in a machine-readable
experiment registration consumed by the runner. These registered runs may establish a
development result, including a negative result. They cannot establish the original
brief's full stop condition without the remaining research and operational requirements.
The v1 frozen matrix and reserved final environment remain sealed.
