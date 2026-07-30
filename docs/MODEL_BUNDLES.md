# Model bundles

Every version directory contains:

```text
manifest.json
feature_schema.json
preprocessor.joblib
classifier.joblib
anomaly.joblib
label_mapping.json
thresholds.json
metrics.json
training_config.yaml
training_data_manifest.json
checksums.sha256
```

`production.json` points atomically to one version. The loader verifies required files,
every SHA-256 checksum, artifact format, schema version, and exact feature order before
loading trusted local joblib files. Registry write access is privileged: pickle/joblib
is unsafe for untrusted artifacts. Keep a previous valid directory and change the
pointer to roll back.
