# Packet availability does not uniformly repair cross-capture transfer

Development-only analysis, 2026-09-03. This is not a production acceptance report.
The immutable [registered protocol](../research-v2/MISSINGNESS_001_PROTOCOL.md),
[aggregate JSON](../research-v2/registered-results/DEV2-MISSINGNESS-001.json) and
[reproducible tables](../research-v2/registered-results/DEV2-MISSINGNESS-001.md) bind
the evidence. Execution commit: `b83f184d583d5d1f719c1be4702968516c3fd5f9`.

## Validity and coverage

The clean run completed in 633.044 seconds. All 108 planned entries are present;
84 passed the post-transform isolation check and were fitted/evaluated on both site
orientations (168 evaluations). All 24 ineligible entries failed before fitting:
19 clip-robust and five quantile-normal entries produced exact aliases across roles.
There were no nonconvergent fits. Clipping and quantile saturation can collapse distinct
inputs; those cases were not rescued by dropping rows or replacing seeds. This is lost
coverage, not proof that their unmeasured detector performance would be poor.

The common-support cohort contains 6,195 rows after excluding 284 cross-capture alias,
249 within-capture family-ambiguous and 417 duplicate rows. It is not the original
traffic population. Dropping indistinguishable examples and optional-packet variants
may make results optimistic. These exclusions and the exact cohort digest were fixed
before model scoring, and all treatments use the same raw fitting/evaluation rows.

The 84 numeric-only local artifacts total 3,040,264 bytes and all passed hash, shape,
safe reconstruction and exact partition-score round trips. Summed preprocessing/model
fit time (including failed prechecks) is 16.799 seconds; the full elapsed time also
includes feature construction, repeated record-to-score benchmarks, evaluation,
serialization and verification. Sampled process RSS ranges from 342,196,224 to
367,693,824 bytes and includes already loaded data, not just a model. Neither inference
throughput nor this elapsed run is a durable service-capacity measurement.

## Capture and family findings

None of the 168 evaluated target-mixture/site entries reaches 50% direct unknown
recall. Independent-site benign FPR ranges from 0 to 61.88%; 114 entries meet the
1% FPR budget alone. All calibration entries meet their registered empirical budgets;
this does not guarantee independent-site performance.

- Target 20-1 has seven `other_attack` rows; that label is absent from every fitting
  choice. Direct unknown recall ranges from 0 to 28.57%, while detection/review ranges
  from 14.29% to 100%. The latter can include the supervised channel and must not be
  called direct novelty recognition.
- Target 34-1 has 2,391 C&C and six DDoS rows, plus a port-scan category too small for
  a quantitative error-analysis claim. Target 8-1 has 2,049 C&C rows. Capture-level
  unknown recall is at most 0.42% for 34-1 and is always zero for 8-1. C&C is present
  in some source choices and absent from others; these are not all whole-family tests.
- Across the evaluated per-family entries, C&C direct unknown recall is at most one
  of 2,391 rows (0.0418%). DDoS direct unknown recall spans 0–100% on only six repeated
  inputs. A high rate in that small group does not repair the large C&C failure or
  establish population-level novelty detection. Port-scan rates are suppressed here
  because its category has fewer than five inputs; full required coverage remains
  explicit in the registered report.

## Adding sources and packet features

Only 52/72 source-addition triples fully complete. Their 104 comparisons of combined
versus each individual source show detection/review increasing 30 times, decreasing
32 and tying 42. Independent benign FPR increases 26 times, decreases 35 and ties 43.
More sources do not uniformly improve this baseline. Fit capping is held constant;
the combined choice changes source composition and need not simply contain every
single-source fitting row.

Only 44/72 representation triples complete all three views. On those same triples:

| Change | Detection/review increases / ties / decreases | Benign FPR increases / ties / decreases |
|---|---:|---:|
| Add 60 imputed packet features to portable core | 3 / 11 / 30 | 10 / 13 / 21 |
| Add 20 availability indicators to those same features | 9 / 23 / 12 | 20 / 18 / 6 |

An FPR increase is a regression. The first comparison changes feature content as well
as missingness treatment; it does not isolate an imputation algorithm. The second
holds packet features fixed but changes both the supervised and distance geometry.
These paired counts are descriptive and correlated across reused rows, models and
site orientations. No significance or universal winning treatment is claimed.

## What this does and does not establish

The observed linear/raw-Mahalanobis baseline is highly dependent on representation,
source composition and calibration site. The recorded low unknown recall and mixed
paired changes do not justify selecting it. However, this study does not causally
attribute the errors to a single feature, prove that indicators encode dataset origin,
or prove that packet features cannot generalize. Learned embeddings, nonlinear
supervised models, host temporal context and signatures are not evaluated here.
Comparing this cohort directly to FAMILY-002 as if only model architecture changed
would be invalid: the row selection and fitting tasks differ.

The next defensible work is a preregistered, matched-cohort learned/context/signature
ablation with independent fit/calibration/site roles and measured origin leakage,
alongside improving effective family and benign-environment support. Do not optimize
on frozen acceptance reports, average away the alias failures, or promote the best
looking single capture/site result. The deployed observation/approval/activation/
rollback workflow and operational failure/partitioning drills remain separate work.

## Verification boundary

`python -m scripts.verify_registered_missingness` checks the immutable public hash,
registration, full matrix, cohort conservation, observed-prefix support, role bindings,
metric/confusion accounting, family membership, costs and recomputed source deltas.
`--artifact-dir` additionally checks the ignored local numeric model files.
`--markdown` deterministically regenerates the full paired tables. These guards protect
the evidence; passing them does not turn a negative scientific result into acceptance.
