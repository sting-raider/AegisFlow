# Model governance

Model evidence may reject automatically but can never promote automatically. AI-generated
explanations do not participate in detection, evaluation, review, or promotion.

## Candidate requirements

A candidate must use the shared runtime feature/inference path, a checksum-valid v3
bundle, train-only transforms, benign-only anomaly fitting, calibrated thresholds, and
sanitized schema-1.1 reports for grouped/source, chronological, held-family, and true
cross-dataset evaluation. Reports bind the exact model version, feature order, training
and test fingerprints, checksum-file digest, and code provenance.

The frozen reports in `configs/evaluation/frozen-evidence-v1.json` are final-only. Never
use their labels, predictions, distributions, or errors to select features, models,
hyperparameters, thresholds, or calibration.

## Review and promotion

1. Register the checksum-valid candidate as an authenticated admin.
2. Treat any failed report as a durable rejection; there is no override.
3. For a passing candidate, obtain immutable review from an identity other than the
   registrant.
4. Promote only through a different admin identity from the approver.
5. Re-hash the bundle and every report immediately before pointer change.
6. Back up the registry and database, promote atomically, restart API then detectors, and
   verify every replica reports the same version before replay.
7. Retain candidate, review, promotion, restart, and smoke evidence in the audit ledger.

Enable `AEGISFLOW_MODEL_GOVERNANCE_ENABLED=1` only after the shared registry is writable
by the control plane, read-only to detectors, access-controlled, backed up, and rollback-
tested. Joblib files are executable content and must never come from an untrusted source.

## Rollback

Use the audited rollback endpoint to select the newest checksum-valid pointer-history
entry, then restart workers and verify convergence. If no compatible v3 history exists,
stop detection visibly; do not load an incompatible or corrupt bundle as fallback. See
[`ROLLBACK.md`](ROLLBACK.md) and [`MODEL_BUNDLES.md`](MODEL_BUNDLES.md).

## Current decision

The current challenger family has a development scientific NO-GO and no candidate is
locked. The synthetic smoke bundle is useful only for installation. Administrators must
not promote it or rerun frozen final evidence to tune around its failures.
