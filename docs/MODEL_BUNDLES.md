# Model bundles

Every v2 version directory contains:

```text
manifest.json
feature_schema.json
preprocessor.joblib
classifier.joblib
anomaly.joblib
autoencoder.pt
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

Promotion validates the candidate before an atomic pointer replacement. Startup tries
the current version, pointer history, and then remaining version directories; loading a
previous valid version produces a visible warning. The rollback helper promotes the
newest recorded previous version through the same validated atomic path. Bundle v1
remains loadable as a recovery target during the v2 rollout.
