# Model bundles

Every runtime-ready v3 version directory contains:

```text
manifest.json
feature_schema.json
preprocessor.joblib
classifier.joblib
anomaly.joblib
autoencoder.pt
calibration.json
label_mapping.json
thresholds.json
metrics.json
training_config.yaml
training_data_manifest.json
checksums.sha256
```

`production.json` points atomically to one version and retains up to five previous
versions. The loader verifies required files, every SHA-256 checksum, the manifest's
independent artifact hashes, artifact format, schema version, and exact feature order
before loading trusted local joblib objects or the Torch state dictionary. Registry write
access is privileged: pickle/joblib remains unsafe for untrusted artifacts.

`calibration.json` contains a bounded monotonic empirical CDF fitted only to benign rows
from the grouped calibration partition. It is checksum-covered and independently named
in the manifest artifact hashes. Runtime detection requires this v3 calibration rather
than mislabelling a normalized anomaly score as a percentile.

Promotion validates the candidate before an atomic pointer replacement. Startup tries
the current version, pointer history, and then remaining version directories; loading a
previous valid version produces a visible warning. The rollback helper promotes the
newest recorded previous version through the same validated atomic path. Bundle v1/v2
remain inspectable for migration and rollback tooling, but the current detector refuses
to infer with them because they lack empirical anomaly calibration. Until a second v3
candidate is promoted, the older pointer history is not a runtime-capable fallback; a
missing valid v3 bundle therefore fails visibly.

## Governed champion/challenger workflow

The API control plane can register a challenger only from a checksum-valid bundle and
repository-local sanitized evaluation reports. Every report must use schema 1.1, bind to
the exact model name/version/schema and checksum-file digest, include valid train/test
fingerprints, identify the shared
`packages.detection.hybrid.HybridPredictor` path, retain
`automatic_promotion_allowed=false`, and have internally consistent readiness criteria.
The default gate requires grouped/source-file, chronological, leave-family-out, and true
cross-dataset evidence. A source-file split counts as grouped only when its report
records that strategy; an official partition does not silently substitute for missing
grouped evidence.

Failed reports immediately create a durable `rejected` candidate. Passing reports only
make a candidate eligible for human review; they never promote it. Reviews are immutable,
the registering identity cannot review its own candidate, and the admin who promotes
needs approval from a different identity. Immediately before pointer replacement the
control plane re-hashes the bundle and every report. Promotion is atomic but deliberately
requires a controlled API/detector restart, so active processes cannot silently diverge
mid-batch. Emergency rollback selects the newest checksum-valid pointer history entry and
marks the displaced candidate `rolled_back`.

The baked smoke v0.3.0 model is ineligible: its training fingerprint is synthetic and all
published public reports fail at least one readiness criterion. This is intentional
negative evidence, not an obstacle that administrators may override. Governance writes
are disabled by default with `AEGISFLOW_MODEL_GOVERNANCE_ENABLED=0`; enable them only on
a writable, access-controlled shared registry after backup and rollback rehearsal.
