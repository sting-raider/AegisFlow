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

## Independent-benign origin audit

`training.v2.registered_origin` implements the immutable `DEV2-ORIGIN-002` protocol
registered in `df7df95`. It loads the verified local FAMILY-002 numeric artifacts into
evaluation-only encoders, rechecks exact fit exclusion, and evaluates the eight declared
views and four numeric transforms using grouped folds. It does not retrain a detector.

```text
python -m training.v2.registered_origin --prepared-manifest /path/to/preparation-manifest.json --pcap-dir /path/to/pcap_v2 --family-artifact-dir /path/to/FAMILY-002-run --output-dir /path/to/new-ignored-origin-run
```

Run from a clean committed checkout with absolute external evidence paths. All three
selected encoder artifacts and the full family report must pass their original hashes.
The output directory must not exist. Probe/transform numeric NPZ files stay local;
only aggregate reports may be published after review. Ineligible grouping or transformed
input overlap is explicit coverage loss, never a zero or chance-level invented score.
Every view is accounted for before a final report is written, and all input/output
artifact and clean-code checks are repeated. Origin accuracy is not attack detection.

## Packet availability and cross-capture source addition

`DEV2-MISSINGNESS-001` is registered in
`configs/research-v2/registered/DEV2-MISSINGNESS-001.json`; the exact design and known
cohort exclusions are in `MISSINGNESS_001_PROTOCOL.md`. `training.v2.missingness`
implements fixed 9/69/89-dimensional views, observed-fit median/mode replacement,
four numeric transforms and safe numeric reconstruction. `training.v2.transfer_support`
binds registration/protocol/preparation, admits the same core-distinct cohort across
views and constructs capture-disjoint fitting/calibration/test roles.

The execution/report CLI is `training.v2.registered_missingness`:

```text
python -m training.v2.registered_missingness --prepared-manifest /path/to/preparation-manifest.json --pcap-dir /path/to/pcap_v2 --output-dir /path/to/new-ignored-missingness-run
```

Run from clean committed code with a new output directory. The driver accounts for all
108 planned model entries and 216 site evaluations. A post-transform alias or failed
linear/covariance fit remains explicit coverage loss with elapsed cost and sampled RSS;
the report distinguishes planned entries, attempted linear fits and accepted models.
Scoring, integrity and artifact errors stop the attempt; partial files are retained and
no complete report is emitted. Every accepted numeric artifact is safely reloaded and
must reproduce exact scores on each partition. Both site orientations use that same
model. Target incidental benign and independent-site metrics remain separate.

The final report also compares adding the second source only where both single-source
cases and their union all complete on identical evaluation rows. Missing comparisons
remain explicit. Model costs start at preprocessing fit (feature construction is timed
separately); inference benchmarks include record feature construction through supervised
and distance scores, not fusion or streaming. Threadpool limits are enforced and checked.
Source, prepared-data, configuration, code and artifact checks run again before completion.
Do not infer real-data results from synthetic tests. No historical or final report is
an input to model selection; no result automatically promotes a candidate.
