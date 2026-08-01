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
