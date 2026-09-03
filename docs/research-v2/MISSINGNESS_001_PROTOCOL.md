# DEV2-MISSINGNESS-001: packet availability and cross-capture transfer

Registered before detector fitting. Development-only; no model selection, production
activation or frozen evaluation is authorized. This study addresses the final brief's
imputation/indicator/intersection comparison and asks whether adding a second attack
environment improves transfer. It is a controlled linear baseline, not a substitute
for the remaining learned-detector, context and signature ablations.

## Inputs and common support

Use only the six captures in the clean `cba2329` preparation manifest (7,145 rows).
Verify raw capture/label hashes, prepared bytes and frozen-source exclusion before and
after execution. Neither source identifiers nor labels enter model features.

Compare the same rows across all representations. Before fitting, group the nine
portable numerical-core features as exact little-endian float64 vectors, normalizing
signed zero. Remove every group spanning captures. Within each remaining capture,
exclude entire groups with different binary **or family** labels; never select one
convenient label. Otherwise retain the smallest event ID in each group. Sort retained
rows by event ID. This policy was fixed after a model-free structural audit, not after
looking at any detector outcome. Record all excluded counts, label/source counts and
content digests as well as retained-row provenance.

The pre-registration structural audit found 6,273 core groups: 77 cross-capture groups
(284 rows), 249 within-capture family-ambiguous rows, and 417 duplicate rows excluded,
leaving 6,195 rows. There are 334 groups with different optional packet observations.
These ambiguities arise after information removal; they do not prove the original
ground truth is wrong. The retained cohort has 1,739 benign, 4,440 C&C, six DDoS,
seven other-attack and three port-scan rows. Clean execution must reproduce the bound
cohort hash; these structural counts are not registered model results.

This deliberately changes prevalence and excludes hard indistinguishable examples.
It may make transfer look better than on unfiltered traffic. One core representative
also discards packet variation. Therefore results apply only to this paired common-
support cohort; they must not be advertised as full-capture or operational performance.

## Three representations, four numeric transforms

All share the nine portable core features, already expressed using runtime log1p,
fractions and log-ratios. No port/protocol/service categories, endpoint identity,
connection-state tensor or sequence-position channel is consumed.

1. `portable_intersection`: nine complete aggregate features.
2. `imputation_only`: those nine plus the first 20 packet slots' signed log1p size,
   log1p interarrival time and binary reverse-direction flag (69 dimensions).
3. `imputation_missingness`: the same 69 plus one binary unobserved flag for each
   packet slot (89 dimensions). All 20 indicators exist even if constant in fitting.

Use shared `sequence_arrays` and `aggregate_matrix`; malformed metadata fails visibly.
Unobserved means no complete metadata for that slot, not inferred packet loss or an
extractor-specific missing CSV column. Short flows are not assumed defective. Their
available prefix remains valid. Scalar and batch paths must match.

Fit continuous replacement medians and binary replacement modes on observed training
values only. Mode ties use zero; a wholly unobserved fitting column uses declared zero
and retains its dimension. Record per-feature observed counts. Then fit each declared
numeric transform on the imputed training matrix: mean/std; median/IQR; training 1st/
99th percentile clipping then median/IQR; or quantile-to-normal (at most 100 quantiles,
no subsampling). Scale below 1e-9 becomes one. Direction bits and missingness indicators
remain binary. No transform is refitted on calibration/test rows. Malformed/nonfinite
values are never converted to missingness. Restore numeric-only parameters and verify
identical inference before accepting artifacts.

## Capture-disjoint experiment matrix

Attack-bearing target/source captures are 20-1, 34-1 and 8-1. For each target, compare
each other source alone and their union, always adding the same benign-only 42-1
background to fitting. Fit caps are 1,500 per binary class using sorted event IDs and
the fixed seeded permutation; both classes are required. Target rows never enter fit.
Two site orientations use hp4 for benign calibration and hp5 for independent benign
testing, then swap them. Neither site enters fitting; target incidental benign rows
are additionally reported separately. Site orientations reuse the exact fitted model.

For each of nine source/target choices, run three views and four transforms: 108 model
fits and 216 site evaluations. Record every planned entry. Raw IDs and evaluated input
vectors must be disjoint across roles. If imputation/transformation introduces exact
cross-role aliases, mark that entry ineligible without dropping rows or changing the
seed. Preserve solver convergence failures with elapsed costs; do not average only a
convenient successful subset. Compare adding a source only where paired entries all
complete, and report the missing comparisons.

Use balanced logistic regression (C=1, lbfgs, tolerance 1e-4, 3,000 iterations, intercept)
for maliciousness and a benign-fit Mahalanobis distance on the **preprocessed input**
(covariance ridge 1e-6). This is not a learned embedding. Both use only fit rows.
Thresholds come from site benign scores using the existing exact tie-aware rule:
direct per-channel FPR budget 0.005 and review-inclusive 0.025; unions at most 0.01
and 0.05 on calibration. These are not independent-test guarantees. Four-verdict
precedence is known, suspicious unknown, review, benign. Known means supervised budget
exceedance, not confident recognition of the target family. Identify whether each test
family was present in fitting; do not call every cross-capture attack an unseen family.

## Evidence, metrics and limits

Record the actual clean execution commit, registration/protocol/preparation hashes,
partition digests, seed 20260903, library versions and single-thread execution. Retain
local numeric-only imputation/scaling, LR and covariance parameters with hashes and
safe-load round trips. Exclusive output creation; retain incomplete attempts.

Report four verdicts, per-family known/unknown/review rates, held-capture and independent
benign FPR, alerts per 10,000 benign rows, PR-AUC, Brier, 10-bin ECE, macro/weighted F1,
score/distance quantiles and Wilson intervals. PR-AUC/Brier/ECE describe the supervised
head, not an invented hybrid probability. No prepared chronological timestamps: false
alerts/hour unavailable. Tiny attack families, coalesced flows and correlated captures
limit statistical claims; Wilson intervals do not remove that correlation.

Measure elapsed fit costs, process RSS sampled every 10 ms, and record-to-score CPU
latency for seeded batches of 1 and 128 with 10 warmups and 100 measured calls. Include
feature construction, imputation/scaling, LR and distance scoring; exclude PCAP parsing,
streaming/persistence and fusion. Report cohort construction separately. No model-stage
throughput claim is durable service capacity. Publish aggregate-only tables/error analysis
after review; leave model parameters, prepared records and raw captures ignored.
