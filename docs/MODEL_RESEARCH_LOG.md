# Model research log

This log is append-only research evidence for the final model-quality phase. Failed and
inconclusive experiments remain visible. Frozen final evidence is never used to select a
representation, model, hyperparameter, calibration method, or threshold.

## Research protocol

- Development evidence must come from newly acquired, provenance-checked datasets not
  listed in `configs/evaluation/frozen-evidence-v1.json`.
- Every experiment will record code commit, dataset fingerprints, split indices/groups,
  schema version, preprocessing fit scope, estimator parameters, seed, calibration scope,
  thresholds, operating costs, artifacts, metrics, and disposition.
- Candidate selection uses repeated grouped/chronological, leave-family-out, and
  cross-environment development evidence. The chosen candidate is locked before final
  evaluation. Frozen final evidence may be run only once for that locked candidate.
- No failed or suspicious sample automatically enters a benign baseline. AI explanations
  remain outside detection and evaluation.

## MR-000 — Freeze-boundary integrity

Date: 2026-08-10

Status: complete

The four previously published reports all reject model `aegisflow-smoke` v0.3.0. They are
now registered as final-only evidence with exact byte, configuration, source-data,
publication commit, and publication date fingerprints. The verifier checks four reports
and eight embedded source fingerprints; tests prove byte tampering, configuration changes,
and development-use policy changes fail closed.

No model decision was made from the contents of these reports. Their previously published
failure values are retained only to explain why the current model cannot be promoted.

## MR-001 — Current-schema portability audit

Date: 2026-08-10

Status: audit complete; replacement schemas not yet implemented

The current 18-feature schema is runtime-consistent but not portable enough to be accepted
as the final representation:

- All features use a standard scaler over raw heavy-tailed counts, rates, durations, and
  ratios. There is no log transform, robust/quantile transform, or training-derived clip.
- `destination_port` is treated as a continuous number even though port ordering is not a
  meaningful distance. The official UNSW partitions omit it and receive the numeric value
  zero, creating a dataset-origin marker that is also a valid protocol value.
- UNSW lacks packet-length standard deviation, IAT standard deviation, SYN count, RST
  count, and sometimes destination port. The adapter substitutes zero without missingness
  indicators, conflating unavailable with observed zero.
- Protocol and bounded port/service categories are absent. Dataset-specific derived fields
  therefore depend heavily on source exporter semantics.
- `packet_rate`, `byte_rate`, packet-size mean, and IAT mean may be supplied directly or
  reconstructed differently by adapter. The derivations are documented but no origin-
  classification diagnostic currently quantifies shortcut leakage.
- Runtime fan-out context is used only in explainable fusion metadata. Training CSV
  evaluation states that it does not synthesize rolling context, so it cannot validate a
  temporal representation end to end.

Decision: retain the schema solely for legacy bundle compatibility. Challenger work must
implement (A) a portable universal flow schema with explicit missingness and semantically
bounded protocol/port encoding, and (B) an optional runtime-enriched bounded temporal
schema with identical training/runtime state semantics. Both require parity tests and an
origin-classifier diagnostic before model comparisons begin.

Detailed availability and risk mapping is in `docs/FEATURE_PORTABILITY_AUDIT.md`.

## MR-002 — Research schemas A/B and train-fit numeric representation

Date: 2026-08-10

Status: implementation complete; empirical selection not started

Schema A (`2.0.0-research-a`) contains 24 current-flow features. Counts, duration, derived
rates, packet-size mean, and byte asymmetry use stable log/fraction representations.
Protocol is one-hot grouped; destination port becomes range and service-family categories
with an explicit missing indicator. Raw IPs, continuous port magnitude, exporter-provided
rates, optional IAT dispersion, and optional TCP flag counts are excluded.

Schema B (`2.0.0-research-b`) adds 16 bounded temporal features computed by AegisFlow over
10/60-second windows keyed by sensor and source. It records flow/unique-peer/unique-port
counts, novelty, protocol/port rarity, fan-out entropy, interval moments/burstiness,
short-flow ratio, cold start, and late-event state. Duplicate IDs return a cached vector
without mutation; state expires and has explicit source/event/cache caps; events beyond
the skew allowance are visible as late and do not corrupt state. Training adapters replay
the same state machine in source-row order only when every row has a valid timestamp and
endpoint. Otherwise Schema B is unavailable rather than imputed.

A separate train-fit preprocessor performs quantile clipping and robust scaling for
continuous fields while passing declared binary categories unchanged. Transforming a test
outlier cannot alter learned bounds. This is implementation/parity evidence only: neither
schema is preferred until fresh development experiments and the dataset-origin diagnostic
are complete.

## MR-003 — Fresh development pool and first origin diagnostic

Date: 2026-08-10

Status: corpus incomplete; full Schema A blocked

Two non-frozen official sources were acquired and reviewed. HIKARI-2021 v1.4.0 contributes
555,278 retained rows (SHA-256
`fddcf2a9fe496ed5a2306df4586f7029e2d4150b0fe7ad70337d5d63e61c645f`); the distinct
CSE-CIC-IDS2018 2018-02-28 object contributes 606,902 retained rows after 33 repeated
headers and 6,169 invalid canonical rows are excluded (SHA-256
`f15e2a12304446058a0186c8ad67de2bd15735a9ba5c70c9a1f4c4242ab06771`). Both pass the
blocking quality gate. Exact provenance and aggregate quality evidence are in
`configs/datasets/development-pool-v1.json` and `docs/development/`. A preparation guard
refuses every source hash registered as frozen-final evidence.

Neither aggregate file can support Schema B: HIKARI lacks trustworthy per-row timestamps
and the processed CSE CSV lacks endpoints. The pool therefore does not yet satisfy the
environment or temporal-evidence requirement.

After exact per-source Schema A deduplication, a deterministic balanced 50,000-row sample
from each source was split 75/25. A train-fit robust-preprocessed logistic classifier
identified corpus origin with 1.000 balanced accuracy. `protocol_other`, `protocol_tcp`,
and `protocol_udp` dominated because HIKARI publishes no protocol column. Full Schema A is
therefore blocked from challenger selection. Removing all protocol, port, service, and
port-missing categorical fields reduced origin balanced accuracy to `0.69772`, below the
`0.90` block threshold. That numerical core is only a research candidate; the two-source,
row-stratified diagnostic cannot substitute for a capture-disjoint, three-environment
result. See `docs/development/dataset-origin-diagnostic.json`.
