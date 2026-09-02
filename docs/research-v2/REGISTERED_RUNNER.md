# Corrected registered family runner

`training.v2.registered_family` implements only the hash-bound `DEV2-FAMILY-002`
registration published in commit `9be5306`. The registration's `registered_not_run`
status describes its immutable state when declared; execution status belongs in a
separate result. No dataset selection, budget, or epoch override is accepted by the CLI.

Run from a clean committed checkout, with absolute paths to the ignored local source
pool and verified preparation. Use a new ignored output directory for every attempt:

```text
python -m training.v2.registered_family --prepared-manifest /path/to/preparation-manifest.json --pcap-dir /path/to/pcap_v2 --output-dir /path/to/new-ignored-run
```

The runner verifies raw source pins, prepared bytes, protocol and registration hashes;
checks every partition; and records actual code commit, environment, split digests,
numeric-only local model artifacts, exact thresholds, four-verdict metrics, confidence
intervals, CPU inference distributions and sampled process RSS. The second isolation
check uses actual preprocessed float32 tensors, rejecting any aliasing that appears
after encoding/scaling. This is additional to shared pre-transform deduplication.

Every completed rotation retains an aggregate JSON and a numeric NPZ model locally.
`report.json` is written exclusively only after all six rotations and final source/code
checks succeed. A failed attempt may retain partial outputs but cannot produce a
complete report. Never overwrite it or treat partial output as a completed experiment.
Review and publish only aggregate results; no raw observations or unreviewed weights.

Inference timing starts at already prepared metadata records, includes shared tensor
construction (including the unused state diagnostic), aggregate preprocessing, model
embedding/head and Mahalanobis calculation. It excludes PCAP parsing, streaming,
persistence and verdict fusion. Batch throughput is not service capacity. RSS samples
cover model fit through artifact verification and include already loaded process/data
memory; they are not model-only memory or a guaranteed OS high-water mark.
Benchmark rows are sampled uniformly from the combined test pool with the registered
seed, without replacement unless a batch exceeds the available rows. Record their
aggregate family counts and content digest. The same model fitted twice with the same
family exclusion must produce identical numeric artifact hashes across site orientations.

F1 uses direct known-or-unknown flags; review is reported separately. PR-AUC/Brier/ECE
measure the known-score head, not a fabricated hybrid probability. Wilson intervals
describe row-level sampling uncertainty but do not remove same-capture correlation.
Calibration labels are public research ground truth, not operator approval for a
deployed baseline. No inference, artifact, or result promotes a production model.
