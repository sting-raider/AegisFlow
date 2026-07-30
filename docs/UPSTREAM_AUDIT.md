# Upstream audit

## Scope and baseline

Reference: `isaiah-harville/NIDS` commit
`277c4ff12be35e5f855a1aaff75de816f3f10f7a`.

The repository was cloned read-only for the audit. `python -m pytest -q` failed during
collection because `icecream` is imported by `tests/conftest.py` but is absent from
the root dependency declaration. The clone also reported
`data/checkpoints/mlp.ckpt` as a Git LFS pointer mismatch.

## Reusable ideas

- Separate feeder, inference, logger, and UI responsibilities.
- NFStream as one possible PCAP-to-flow adapter.
- gRPC contracts demonstrate the value of typed service boundaries.
- CPU-only inference and health probes are appropriate defaults.
- A dashboard and terminal fallback are useful operational surfaces.

These ideas informed AegisFlow, but no source code was copied.

## Components rewritten

- `src/services/feeder/feeder.py`: live packet capture buffers packets, writes a
  temporary PCAP, then invokes NFStream. AegisFlow adapters emit completed,
  validated `FlowEvent` objects directly and keep demo/PCAP replay deterministic.
- `src/services/ids/ids.py`: returns only an argmax class. AegisFlow returns
  calibrated probabilities, anomaly/open-set scores, reason codes, versions,
  latency, severity, and fused risk.
- `src/ai/DataModule.py` and preprocessing: AegisFlow owns one fixed feature
  registry and serializes the fitted train-only preprocessing pipeline.
- Mongo/gRPC persistence and orchestration: AegisFlow uses idempotent events,
  PostgreSQL/SQLAlchemy, Redis Streams in distributed mode, and an SQLite/in-process
  fallback for the offline demo.
- The UI is a fresh strict TypeScript implementation against `/api/v1`.

## Correctness findings

1. Training calls `StandardScaler.fit_transform` before the train/validation split,
   leaking validation distribution into training.
2. Live inference calls `StandardScaler().fit_transform(x)` for a single flow. A
   single row becomes all zeros, so inference cannot match training.
3. Offline inference fits another scaler over the replay dataset rather than loading
   the training scaler.
4. Both training and inference select columns by the substring `piat`, but there is
   no versioned feature list, fixed order, dtype/range policy, or compatibility check.
5. Rows containing non-finite values are dropped after labels are captured, which can
   misalign `x` and `y`.
6. A random stratified row split is the only implemented split. Capture/day/source
   grouping and cross-dataset testing are absent.
7. Multiclass labels are explicitly collapsed with `np.where(y == 0, 0, 1)`.
8. Hard-coded resampling counts assume one exact dataset/class encoding and can fail
   when a class is absent.
9. The service hard-codes `model.ckpt`; the test hard-codes
   `data/checkpoints/mlp.ckpt`. No manifest, checksum, threshold, label mapping,
   dependency metadata, schema version, or rollback pointer travels with the model.
10. `strict=False` checkpoint loading can mask incompatible model state.
11. Inference exposes only argmax. There is no probability calibration, uncertainty,
    anomaly model, open-set decision, signature correlation, or explainable fusion.

## Test, deployment, and security gaps

- Several critical tests are skipped; one catches every exception without failing.
- The root `pyproject.toml` declares only `rich` and `textual` while runtime imports
  PyTorch, Lightning, pandas, scikit-learn, NFStream, gRPC, dpkt, pcap, Mongo, and
  others.
- Ruff excludes `src/ai` and `tests`, hiding the highest-risk logic.
- Compose exposes Mongo and mongo-express with example credentials and uses
  `network_mode: host` for the web server.
- There is no input size limit, event schema validation, queue backpressure,
  retention policy, artifact integrity verification, audit trail, least-privilege
  capture profile, or malformed-PCAP/EVE handling.
- Images are tagged `latest`, dependencies are mostly unpinned, generated gRPC code
  is committed, and old/new app trees coexist. This increases maintenance risk.

## License finding

The brief described the upstream as MIT licensed, and the upstream README says
“MIT License,” but the audited root license is Apache-2.0. AegisFlow uses the actual
license text and does not claim MIT reuse.
