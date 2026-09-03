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

Status: initial corpus complete; full Schema A blocked; numerical core eligible

Three non-frozen official environments were acquired and reviewed. HIKARI-2021 v1.4.0 contributes
555,278 retained rows (SHA-256
`fddcf2a9fe496ed5a2306df4586f7029e2d4150b0fe7ad70337d5d63e61c645f`); the distinct
CSE-CIC-IDS2018 2018-02-28 object contributes 606,902 retained rows after 33 repeated
headers and 6,169 invalid canonical rows are excluded (SHA-256
`f15e2a12304446058a0186c8ad67de2bd15735a9ba5c70c9a1f4c4242ab06771`). Both pass the
blocking quality gate. Exact provenance and aggregate quality evidence are in
`configs/datasets/development-pool-v1.json` and `docs/development/`. A preparation guard
refuses every source hash registered as frozen-final evidence.

The third source is 43,009 IoT-23 rows across four malicious and two real-device benign
capture groups (six reviewed SHA-256 objects). Its labels include command-and-control,
DDoS, file download, and horizontal port scan behavior. Every retained row has timestamps,
endpoints, protocol, port, and directional counts and replays through shared Schema B.
HIKARI still lacks trustworthy per-row timestamps and the processed CSE CSV lacks
endpoints, so those aggregate sources remain Schema A-only.

After exact per-source Schema A deduplication, HIKARI and CSE contribute deterministic
50,000-row samples and IoT-23 contributes all 11,078 unique portable rows. A 75/25
train-fit robust-preprocessed logistic diagnostic identifies corpus origin with 0.95416
balanced accuracy. Protocol categories remain strongest because HIKARI publishes no
protocol column. Full Schema A is therefore blocked from challenger selection. Removing
all protocol, port, service, and port-missing categorical fields reduces origin balanced
accuracy to `0.68428`, below the `0.90` block threshold. That nine-feature numerical core
may proceed to grouped development experiments; it has not yet been selected. See
`docs/development/dataset-origin-diagnostic.json`.

## MR-004 — Cross-environment supervised baselines

Date: 2026-08-10

Experiment: `DEV-SUP-001`

Code commit: `a1e5f933fb29ec55bd2857fe1e7c809eaf059ed3`

Status: complete; no candidate selected

The numerical-core view was evaluated as benign-versus-malicious classification in all
three leave-one-environment-out rotations. Each source contributed at most 10,000 rows per
binary class before exact-vector deduplication and conflicting-label removal. Training
used fold-only quantile clipping and robust scaling. Logistic regression, sigmoid-
calibrated random forest, HistGradientBoosting, and the compact MLP all used an untuned
0.5 threshold.

No model meets the development operating objectives. The compact MLP is strongest on
mean macro F1 (`0.61474`) and mean malicious recall (`0.43945`), but its worst-environment
macro F1 is `0.36329`, malicious recall is `0.03644`, benign FPR is `0.18202`, and mean ECE
is `0.26168`. Its apparently strong IoT-23 result does not transfer to CSE. The other
models have worst malicious recall from zero to `0.00664`; their worst benign FPR ranges
from `0.31460` to `0.55160` except for the MLP. No threshold was tuned, no model was locked,
and no frozen report was run.

Disposition: supervised maliciousness alone is insufficient on this feature view.
Proceed to benign-only anomaly/open-set baselines and repeated held-family evaluation.
Machine-readable evidence is in
`docs/research/experiments/dev-supervised-baselines-v1.json`; its SHA-256 is
`533346ccfaa841e3795fca6a9a386621b732e6db18c73719b247479ea140816a`.

## MR-005 â€” Three-way cross-environment anomaly baselines

Date: 2026-08-10

Experiment: `DEV-ANO-001`

Code commit: `c91aadc678e179d000cc1f549bbff50b703cc99d`

Status: complete; no candidate selected

Isolation Forest, robust covariance, Local Outlier Factor novelty, one-class SVM, and a
CPU denoising autoencoder were each evaluated in six strict three-way rotations. One
environment supplied benign-only fit rows, a second supplied benign-only threshold
calibration, and the third remained completely held out for testing. Both fit/calibration
orientations were run for every held environment, so no malicious sample or test row
entered fitting, preprocessing, or threshold selection.

All five model families fail the development objectives. One-class SVM has the strongest
mean direct unknown recall (`0.06281`) but zero worst-rotation recall and a worst benign
FPR of `0.18817`. Robust covariance has the strongest mean detection-or-review recall
(`0.15814`) but also reaches zero in a rotation and a worst benign FPR of `0.10854`.
Isolation Forest is more restrained but reaches only `0.00479` mean direct recall and
`0.08101` mean detection-or-review. The remaining models are similarly unstable across
source orientation. All 30 runs completed; no threshold was changed after observing a
test environment, no candidate was locked, and no frozen report was run.

Disposition: a universal benign-only detector over the nine-feature numerical core does
not transfer reliably. Proceed to controlled supervised/anomaly fusion, Schema B temporal
contribution, and repeated held-family ablations using development evidence only.
Machine-readable evidence is in
`docs/research/experiments/dev-anomaly-baselines-v1.json`; its SHA-256 is
`0b9bdb7a0235db714849e642a7bf68ca985dcbfe2ceb17a728ad2b8389fb2023`.

## MR-006 - Held-family hybrid and temporal ablations

Date: 2026-08-11

Experiment: `DEV-HYB-001`

Code commit: `0b98eebfc3eb1bf37c24a7a7da68a7928e4c0625`

Status: complete; no candidate selected

The compact MLP was fitted on HIKARI plus the fresh CSE day after removing each held
family. Isolation Forest used one all-benign IoT capture for fit and the other for
threshold calibration, then repeated the reversed orientation. Command-and-control,
DDoS, and port-scan were tested separately on their attack capture groups. Nine ablations
measured supervised, anomaly, temporal context, pairwise fusion, the full hybrid, removal
of temporal context, and removal of port-derived context. Multi-signal calibration budgets
were divided before OR fusion. File-download was excluded because it has only three rows;
signature evidence was marked not evaluable rather than fabricated.

The full hybrid does not meet the objectives. Across six family/orientation runs its mean
direct detection is `0.18586`, but the worst result is `0.00007`. Mean direct
suspicious-unknown recall is `0.02072`, with the same near-zero worst result. Mean
detection-or-review is `0.52139`, but the worst result is `0.00067`; worst benign FPR is
`0.01612`. Context-only evidence reaches higher average recall but transfers with up to
`0.38898` benign FPR. Removing temporal context is more restrained (mean benign FPR
`0.00630`) but worst detection-or-review remains only `0.09016`. Reversing the two benign
device captures materially changes DDoS and port-scan results, demonstrating site/device
calibration sensitivity rather than robust transfer.

Disposition: the current temporal representation sometimes helps within IoT-23, but it
does not provide a stable universal challenger and cannot be locked. Continue with
development-only root-cause/error analysis and an explicit decision on environment-aware
calibration versus a scientific flow-level NO-GO. No frozen report was run.
Machine-readable evidence is in
`docs/research/experiments/dev-hybrid-temporal-held-family-v1.json`; its SHA-256 is
`b7267131af5c6291a1290f5ab89b07aff618b242c5f76f59a3eda5a01fbcc896`.

## MR-007 - Aggregate held-family root-cause analysis

Date: 2026-08-11

Experiment: `DEV-ERR-001`

Code commit: `b4892c53920f3882db8caa10cf1efe6ff08058e2`

Status: complete; no candidate selected

The fixed `DEV-HYB-001` protocol was rerun with aggregate-only error buckets. Categories
below five rows were suppressed; no endpoint, row identifier, individual score, or
per-row output was retained. The run reproduces the earlier metrics and identifies a
large calibration-orientation effect: reversing HUE and Echo moves DDoS direct detection
from `0.00035` to `0.99152` and port-scan detection-or-review from `0.04098` to `0.77049`.

Command-and-control is dominated by zero/one-packet, often zero-duration flows and remains
almost completely missed. Late-event buckets have elevated missed rates for DDoS and port
scan. Benign direct errors concentrate in TCP/web and small high-packet buckets; removing
port context worsens the maximum FPR rather than solving the problem. These patterns point
to limited flow observability plus device-specific benign calibration, not a single
threshold defect.

Disposition: run one predeclared cross-fitted benign-device calibration ensemble using
development evidence only. If it cannot meet repeated held-family objectives, record a
development scientific NO-GO rather than expanding model complexity opportunistically.
Evidence is in `docs/error_analysis/held-family-root-cause-v1.json`; its SHA-256 is
`105d015726ed4886314111f137c93f3bf6a626484ce93218d00e5e33702f6b20`.

## MR-008 - Cross-fitted site calibration and development NO-GO

Date: 2026-08-11

Experiment: `DEV-CAL-001`

Code commit: `020431d5caf5497938adaab97a14076865f95401`

Status: complete; development scientific NO-GO

Two Isolation Forests were fitted independently on the approved HUE and Echo benign
captures. Each benign capture was scored only by the model fitted on the other capture;
the resulting empirical percentiles formed a pooled calibration reference. The mean of
the two test percentiles was the predeclared primary anomaly signal. Minimum and maximum
aggregation were retained only as sensitivity checks. The supervised head and held-family
tests remained unchanged, and no attack row entered preprocessing, CDF construction, or
threshold calibration.

The primary cross-fitted mean hybrid still fails. Direct command-and-control detection is
`0.00000`; port-scan detection-or-review is `0.04098`; worst direct unknown recall is
`0.00000`; and worst benign FPR is `0.01092`. DDoS direct detection is high (`0.99111`),
but one family cannot compensate for the other failures. The max sensitivity rule raises
unknown recall only to a 3.04% mean while worsening maximum benign FPR to 1.61%; it was not
eligible for post-hoc selection.

Disposition: no current challenger meets development objectives. No model, schema,
threshold, or bundle is locked, and the frozen final reports remain sealed. This is a
development scientific NO-GO for a universal detector under the current flow-level
contract, not a universal impossibility claim. Evidence is in
`docs/research/experiments/dev-site-calibration-v1.json`; its SHA-256 is
`076f2ab08abc48deb9fc0d144219ac4875c69f978819b96de74874529b6fc3a4`.

## MR-009 - Detector-v2 evidence audit and correction boundary

2026-09-02. The v1 development NO-GO and frozen-final boundary are unchanged. The v2
audit found mislabelled whole-family tests, fit/site overlap, high learned-embedding
origin predictability, and incomplete execution/cost provenance. See MR2-007 in
`docs/research-v2/RESEARCH_LOG.md` and `docs/REQUIREMENTS_AUDIT.md`. The new archive
verifier establishes historical integrity only. Strict partition checks and seeded
corrected diagnostic runners are implemented; no corrected experiment is registered,
no model selected, and no final dataset unsealed. The broader final-phase goal remains
incomplete, including deployed approved-site baselines and specific failure drills.

## MR-010 - Verified preparation and corrected family preregistration

2026-09-02. All six captures replayed from clean code `cba2329` in 335.003 seconds,
producing 7,145 records with zero ambiguous joins. Source fingerprints were checked
before and after; no frozen-source overlap occurred. Aggregate preparation manifest:
`docs/research-v2/preparation/prepared-pool-cba2329.json`, SHA-256 (UTF-8 LF)
`332939033261e67a41dd15f8c95edf54e4dd4fd1723e636c9e3c53f93c71f86a`.
Actual sequence/mask/aggregate deduplication retains 6,674 inputs, no label conflicts.
The old raw-field fingerprint discarded three distinct service-feature inputs.

`configs/research-v2/registered/DEV2-FAMILY-002.json` binds the protocol, prepared data,
three whole-family exclusions, both independent site orientations, fixed training,
tie-aware channel budgets, four-verdict semantics, and resource measurements before
execution. The dedicated runner and results are pending; registration is not a result.
307 tests, lint, type checking, and all three evidence guards pass locally. Preparation
commit CI `33657593024` is successful. No model selected or final data accessed.

Runner implementation: `training.v2.registered_family` consumes only the immutable
registration (SHA-256 `442ea69203048d4e89e3689fe333cbcb5b3060201ba1dd86d5c7bc3f7bc47705`).
The synthetic execution test covers training, metrics, latency, memory and numeric NPZ
retention; 317 full-suite tests pass. The six real partitions also pass preprocessing-
aware float32 isolation before any model run. Actual held counts are 4,710 C&C, 7 DDoS,
and 4 port scan; site calibration and independent benign tests each contain 181 rows.
The driver, not the registration file, records subsequent execution status separately.
See `docs/research-v2/REGISTERED_RUNNER.md`. Clean model execution remains pending.

## MR-011 - Corrected strict-family matrix completed: development NO-GO

2026-09-02, clean execution `365903128b0db36128e0846960a89b72fe8a7a74`, 51.472 seconds.
All six fixed rotations completed. C&C and DDoS detection/review are zero; port-scan
direct unknown recall is 0/4 or 2/4 depending on site orientation (all four detected).
Independent benign FPR ranges 0–47.51% over 181 inputs per site. Counts, uncertainty,
exact thresholds, four-verdict outputs, config/data/split provenance, measured latency,
sampled RSS and local numeric artifact hashes are retained in
`docs/research-v2/registered-results/DEV2-FAMILY-002.json`; SHA-256 (UTF-8 LF)
`6c1e2d5a576cb7c7afde9968151665f2e3afb64e0d7a737da17cb332dcadde73`.
No site row entered fitting, all post-preprocessing inputs are disjoint, and duplicate
same-family fits have identical model artifact hashes. See the development-only error
analysis `docs/error_analysis/dev2-family-002.md`. No new final evaluation, model lock,
promotion, or blanket project-completion claim is supported.

Publication verification: 325 tests passed in 50.68 seconds, 84% backend coverage,
Ruff passed, MyPy passed 109 sources, and all four evidence guards passed, including
local numeric model arrays/hash checks. Runner commit CI `33661356302` passed ten jobs;
CI for the subsequent aggregate publication will be recorded after it actually finishes.

## MR-012 - Preregistered independent-benign origin audit runner

2026-09-03. FAMILY-002 publication CI `33662571272` and ORIGIN-002 registration CI
`33663241779` both completed successfully. `DEV2-ORIGIN-002` was registered in `df7df95`
before execution; it binds three fixed encoder artifacts and 392 benign rows from
hp4/hp5/20-1, eight views, four numeric transforms, exact-vector-grouped five-fold origin
probes and a fixed 0.90 warning threshold. All three captures are absent from encoder
fitting, verified against exact reconstructed partition hashes and preprocessed inputs.

The driver is implemented and synthetic regression covers transformations, disjoint
groups, missing-origin fold rejection, frozen numeric model loading, view dimensions,
costs and artifact retention. 342 full tests and 16 final focused origin tests pass;
lint and strict types pass. A grouped stratifier is not assumed to guarantee all origins:
one synthetic fold lacked an origin and is explicitly rejected. Clean execution is still
pending. This is a diagnostic only, not a new detector or authorization to use final data.

ORIGIN-002 first execution completed from `53a62eb` in 89.676 seconds: all eight views
accounted for, 123 numeric probe artifacts, 15 convergence failures and two transformed
aliasing exclusions; the missingness-only view cannot form valid grouped folds. Review
found an instrumentation defect: failed folds lacked elapsed fit time. Preserve the
first local report (SHA-256 `0f6f95b72f7b120c7f514a50b468112084df99bc2f63b664a24798067cc017c2`)
as cost-incomplete. A controlled nonconverging regression reproduces the missing field.
Repeat the exact registered study only after the timer fix is committed; no scientific
configuration, solver limit, split, encoder, or cutoff changes are permitted.

## MR-013 - Independent-benign origin audit completed with measured failures

2026-09-03. Cost-complete execution `825efd123b711334e17e5fdc738a50281f8d8f95` took
87.233 seconds. Its exact scientific projection (all input/fold hashes, metrics, statuses
and 123 numeric probe-artifact hashes) matches the preserved cost-incomplete attempt.
The three encoders exceed the fixed origin warning under at least one declared transform
(C&C 0.93908, DDoS 0.90594, scan 0.91344). Full aggregate exceeds 0.90 across transforms;
the numerical core remains near 0.89. Of 32 combinations, 24 are fully evaluable, four
have incomplete folds, and the four mask-only combinations lack valid grouped folds.
Fifteen probe folds fail convergence and two alias after transformation. None is hidden
or assigned an invented score. See `docs/error_analysis/dev2-origin-002.md`.

Complete report SHA-256 (UTF-8 LF):
`cb1d6916868dfa57c685c6d9ec87dd1f0ca8b58845fb03ec087db60a6ea1914c`.
The table regenerates from the report. No detector retraining, model selection, final
evaluation or promotion occurred. Runner CI `33711233961` passed ten jobs; subsequent
publication CI is distinct and must be recorded only after it finishes.
Timer-fix CI `33711842752` also passed. Final local publication checks passed 354 tests
in 48.25 seconds (84% backend coverage), Ruff, MyPy over 112 sources, all five evidence
guards, table regeneration and 123 local numeric probe artifacts. Frozen and historical
FAMILY evidence remain unchanged. Aggregate-publication CI is not yet claimed complete.

## MR-014 - Reject malformed sequence metadata before missingness research

2026-09-03. Origin-publication CI `33712407348` at `b9d58af` completed all ten jobs.
During the next representation study, 15 of 16 focused malformed-metadata cases failed
before the fix: independent filtering could realign packets, fractional directions were
coerced, and the flow contract accepted nonfinite packet timings. The fix rejects these
inputs; worker tests retain visible quarantine and process the valid remainder.
All 7,145 verified development records match the pre-fix encoder's tensor/mask bytes.
372 full tests pass in 47.69 seconds with 84% backend coverage, Ruff and strict MyPy
over 112 sources. This is input-integrity evidence, not a new model result; imputation,
detector ablations and cross-environment attack studies remain open.

## MR-015 - Register packet-availability and source-addition comparisons

2026-09-03. `DEV2-MISSINGNESS-001` registration SHA-256 (UTF-8 LF):
`b60ebf4873582e6507d7fa36f8eba8cea615f7af978b647f3bc40b78ce974ef4`;
protocol SHA-256 `5c76a99dd5c67a12ec9300706661761615b516f620618a29f0c1b0e66707ebd9`.
The pre-registration structural audit fixes 6,195 common-support rows and records why
950 input rows are omitted (284 cross-capture, 249 family-ambiguous, 417 duplicates).
Labels remain public development ground truth, not operator-approved site traffic.

Implemented train-only median/mode imputation, optional fixed missingness indicators,
four numeric transforms with binary passthrough, numeric-array restoration, paired
cohort admission and capture-disjoint splits. Synthetic tests cover malformed input,
empty-column fallback, train-only parameters, scalar/batch parity, serialization,
source aliases, label ambiguity and configuration binding. No registered model has
been fit. The 108-fit/216-site-evaluation matrix still requires its execution/report
driver and a clean run. Safety-fix CI `33713525244` passed; this registration/component
milestone's CI must be recorded independently after publication.

Local verification: 452 tests pass in 50.46 seconds (84% backend coverage), including
80 new missingness/cohort/registration cases; Ruff and strict MyPy over 114 sources
pass. No model performance, artifact cost or clean experiment execution is inferred
from the structural diagnostic or synthetic verification.

## MR-016 - Registered missingness execution driver implemented

The driver now executes the immutable source/target/view/transform matrix, enforces
single-thread numerical pools, records fit/RSS/inference costs and separates planned
entries, actual fit attempts, accepted models and site coverage. Numeric-only LR,
preprocessing and covariance parameters must safely reconstruct identical partition
scores. Transformed aliases and fitting failures remain explicit; integrity/scoring
errors prevent a complete report. Paired source-addition deltas require all three cases.

The synthetic mini-matrix completes, and an otherwise identical controlled attempt
rejects changed prepared inputs at the final check without producing a completion
report. All 91 focused missingness tests pass; registration CI `33714322097` is green.
Real clean-code execution remains pending; these tests are not detector-quality evidence.

Full runner verification passes 463 tests in 126.51 seconds (84% backend coverage),
Ruff, strict MyPy over 116 sources and all five existing historical/registered evidence
guards. The preregistration and its protocol are unchanged. Execute only after this
driver is committed, then retain the actual execution commit and measured outputs.

## MR-017 - Missingness/source-addition execution and paired negative evidence

2026-09-03. The registered run completed from clean `b83f184d583d5d1f719c1be4702968516c3fd5f9`
in 633.044 seconds, with the unchanged 6,195-row common-support fingerprint and
single-thread numerical pools. All 108 planned entries are retained: 84 actual linear
fits, 84 accepted numeric artifacts and 168 site evaluations; 24 entries fail the
pre-fit transformed-alias check (19 clip-robust and five quantile-normal). No solver
failure or retry occurred. All numeric artifacts pass the publication integrity check.

Report SHA-256 (UTF-8 LF):
`c0d7685393ebd76abbdbb78a75ce3ed40a62a925ea5a9e6a8aa19fcca7966961`.
Full aggregate report and deterministic tables: `research-v2/registered-results/DEV2-MISSINGNESS-001.*`.
Analysis: `error_analysis/dev2-missingness-001.md`. The original local report is copied
byte-for-byte; raw rows, packet captures and model weights remain ignored.

No evaluated target-mixture/site entry reaches 50% direct unknown recall. Independent
benign FPR is 0–61.88%, with 114/168 entries meeting 1% alone. Source-addition contrasts
improve detection/review in 30, worsen it in 32 and tie in 42 of 104 contrasts across
52 complete triples; 20 triples are unevaluable. Among 44 complete representation
triples, indicators improve detection/review in nine, worsen it in 12 and tie in 23;
benign FPR increases in 20 and decreases in six. These are correlated descriptive
differences, not independent replicates. Adding packet features changes more than
the imputation method. No single treatment universally fixes transfer.

Runner CI `33715446245` passed. Publication checks add a sixth integrity guard,
semantic mutation tests, checkout-independent text hashing and reproducible paired
tables. An initial table test caught Windows stdout damage to em dashes; regeneration
through ASCII-escaped JSON preserves Unicode exactly without touching any report bytes.
Final local publication verification passes 499 tests in 81.52 seconds (84% backend
coverage), Ruff, strict MyPy over 117 sources, all six evidence guards and all 84 local
numeric artifacts. All 36 evidence regressions pass, including LF/CRLF normalized
hashes and exact generated-table equality. Publication CI is still separate from the
green runner milestone; it subsequently passed all ten jobs in `33717028051` at
`ae350e3`. No candidate selection, final-data access, deployment activation
or completion claim is authorized.

## MR-018 - Repair shared temporal-state isolation before context preparation

2026-09-03. MISSINGNESS-001 publication is `ae350e3ec57e3555da665e3205c894f1fc88a656`;
its CI `33717028051` passed all ten jobs.
During the next context-ablation review, a synthetic regression reproduces cross-sensor
duplicate-cache contamination: warm sensor A and cold sensor B share a replay event ID,
and B incorrectly receives A's cached vector. Shared source windows were sensor-scoped
but the duplicate cache was not. Scope that cache to `(sensor_id, event_id)` and expose
the key in feature-schema metadata. The collision and clear/restart tests pass alongside
all prior focused temporal tests (10 total). Final-source verification passes 501 tests
in 201.77 seconds (84% backend coverage; 91% in the research-feature module), Ruff,
strict MyPy over 117 sources and all six evidence guards. Local JUnit evidence is
retained under ignored `data/verification/temporal-cache-final.xml`. A prior verification
handle disappeared; process inspection confirmed it was absent before this final run.
No success was inferred from that missing handle. Cache-fix CI is not yet claimed.

No model is retrained, no prepared data is overwritten and no historical report changes.
The current v2 prepared contract does not retain timestamp/context, while PcapAdapter
coalesces a canonical five-tuple over a capture. The next context study must explicitly
address that observation/ordering limitation rather than assigning invented temporal
features to already-filtered records. A new dataset/protocol and runtime-parity evidence
remain required; this bug fix alone does not fulfill the context ablations.
