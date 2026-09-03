# Packet availability and cross-capture transfer

Executed commit: `b83f184d583d5d1f719c1be4702968516c3fd5f9`. Development-only common-support cohort.

Coverage: 84/108 evaluated models; 168/216 evaluated site entries. Failed entries are not assigned zero scores.

Each cell lists the two calibration-site orientations as percentages. Unknown is direct suspicious-unknown recall; review includes any detection/review. FPR uses the independent benign site, not its calibration sample.

| Target | Fit attack source(s) | View | Transform | Unknown | Detection/review | Benign FPR |
|---|---|---|---|---:|---:|---:|
| 20-1 | 34-1 | portable_intersection | standard | 14.29 / 0.00 | 100.00 / 100.00 | 0.55 / 1.42 |
| 20-1 | 34-1 | portable_intersection | robust | 14.29 / 0.00 | 100.00 / 100.00 | 0.55 / 0.71 |
| 20-1 | 34-1 | portable_intersection | clip_robust | ineligible | — | — |
| 20-1 | 34-1 | portable_intersection | quantile_normal | 0.00 / 0.00 | 100.00 / 100.00 | 2.21 / 0.71 |
| 20-1 | 34-1 | imputation_only | standard | 0.00 / 0.00 | 100.00 / 71.43 | 0.00 / 0.71 |
| 20-1 | 34-1 | imputation_only | robust | 0.00 / 0.00 | 42.86 / 14.29 | 0.00 / 0.71 |
| 20-1 | 34-1 | imputation_only | clip_robust | ineligible | — | — |
| 20-1 | 34-1 | imputation_only | quantile_normal | 28.57 / 0.00 | 100.00 / 42.86 | 2.21 / 0.71 |
| 20-1 | 34-1 | imputation_missingness | standard | 14.29 / 0.00 | 100.00 / 71.43 | 0.55 / 0.71 |
| 20-1 | 34-1 | imputation_missingness | robust | 14.29 / 0.00 | 42.86 / 14.29 | 0.55 / 0.71 |
| 20-1 | 34-1 | imputation_missingness | clip_robust | ineligible | — | — |
| 20-1 | 34-1 | imputation_missingness | quantile_normal | 28.57 / 0.00 | 100.00 / 100.00 | 0.55 / 1.42 |
| 20-1 | 8-1 | portable_intersection | standard | 14.29 / 0.00 | 100.00 / 100.00 | 1.10 / 0.71 |
| 20-1 | 8-1 | portable_intersection | robust | 14.29 / 0.00 | 100.00 / 100.00 | 1.10 / 0.71 |
| 20-1 | 8-1 | portable_intersection | clip_robust | ineligible | — | — |
| 20-1 | 8-1 | portable_intersection | quantile_normal | ineligible | — | — |
| 20-1 | 8-1 | imputation_only | standard | 0.00 / 0.00 | 100.00 / 42.86 | 0.00 / 1.42 |
| 20-1 | 8-1 | imputation_only | robust | 0.00 / 0.00 | 100.00 / 100.00 | 0.00 / 0.71 |
| 20-1 | 8-1 | imputation_only | clip_robust | ineligible | — | — |
| 20-1 | 8-1 | imputation_only | quantile_normal | 0.00 / 0.00 | 100.00 / 28.57 | 0.00 / 0.71 |
| 20-1 | 8-1 | imputation_missingness | standard | 0.00 / 0.00 | 100.00 / 100.00 | 0.55 / 1.42 |
| 20-1 | 8-1 | imputation_missingness | robust | 0.00 / 0.00 | 100.00 / 85.71 | 0.55 / 0.71 |
| 20-1 | 8-1 | imputation_missingness | clip_robust | ineligible | — | — |
| 20-1 | 8-1 | imputation_missingness | quantile_normal | 14.29 / 0.00 | 100.00 / 42.86 | 5.52 / 0.71 |
| 20-1 | 34-1+8-1 | portable_intersection | standard | 14.29 / 0.00 | 100.00 / 42.86 | 0.55 / 0.71 |
| 20-1 | 34-1+8-1 | portable_intersection | robust | 14.29 / 0.00 | 100.00 / 100.00 | 0.55 / 0.71 |
| 20-1 | 34-1+8-1 | portable_intersection | clip_robust | ineligible | — | — |
| 20-1 | 34-1+8-1 | portable_intersection | quantile_normal | 0.00 / 0.00 | 85.71 / 100.00 | 2.76 / 0.00 |
| 20-1 | 34-1+8-1 | imputation_only | standard | 0.00 / 0.00 | 100.00 / 57.14 | 0.00 / 0.71 |
| 20-1 | 34-1+8-1 | imputation_only | robust | 0.00 / 0.00 | 42.86 / 14.29 | 0.00 / 0.71 |
| 20-1 | 34-1+8-1 | imputation_only | clip_robust | ineligible | — | — |
| 20-1 | 34-1+8-1 | imputation_only | quantile_normal | 0.00 / 0.00 | 100.00 / 71.43 | 1.66 / 0.71 |
| 20-1 | 34-1+8-1 | imputation_missingness | standard | 14.29 / 0.00 | 100.00 / 71.43 | 0.55 / 0.71 |
| 20-1 | 34-1+8-1 | imputation_missingness | robust | 14.29 / 0.00 | 42.86 / 14.29 | 0.55 / 0.71 |
| 20-1 | 34-1+8-1 | imputation_missingness | clip_robust | ineligible | — | — |
| 20-1 | 34-1+8-1 | imputation_missingness | quantile_normal | 14.29 / 0.00 | 100.00 / 100.00 | 0.55 / 18.44 |
| 34-1 | 20-1 | portable_intersection | standard | 0.21 / 0.08 | 100.00 / 0.42 | 1.10 / 0.71 |
| 34-1 | 20-1 | portable_intersection | robust | 0.21 / 0.04 | 100.00 / 0.42 | 1.10 / 0.71 |
| 34-1 | 20-1 | portable_intersection | clip_robust | ineligible | — | — |
| 34-1 | 20-1 | portable_intersection | quantile_normal | ineligible | — | — |
| 34-1 | 20-1 | imputation_only | standard | 0.21 / 0.21 | 0.50 / 0.38 | 0.00 / 1.42 |
| 34-1 | 20-1 | imputation_only | robust | 0.21 / 0.21 | 0.50 / 0.21 | 0.00 / 18.44 |
| 34-1 | 20-1 | imputation_only | clip_robust | 0.38 / 0.00 | 0.54 / 0.17 | 61.88 / 0.00 |
| 34-1 | 20-1 | imputation_only | quantile_normal | 0.12 / 0.00 | 99.96 / 0.42 | 1.10 / 0.71 |
| 34-1 | 20-1 | imputation_missingness | standard | 0.21 / 0.21 | 0.46 / 0.42 | 0.00 / 1.42 |
| 34-1 | 20-1 | imputation_missingness | robust | 0.25 / 0.21 | 0.46 / 0.25 | 0.55 / 18.44 |
| 34-1 | 20-1 | imputation_missingness | clip_robust | 0.25 / 0.04 | 0.71 / 0.25 | 56.35 / 0.00 |
| 34-1 | 20-1 | imputation_missingness | quantile_normal | 0.08 / 0.04 | 99.96 / 0.50 | 0.55 / 0.71 |
| 34-1 | 8-1 | portable_intersection | standard | 0.42 / 0.08 | 100.00 / 90.92 | 1.10 / 0.71 |
| 34-1 | 8-1 | portable_intersection | robust | 0.42 / 0.08 | 100.00 / 90.92 | 1.10 / 0.71 |
| 34-1 | 8-1 | portable_intersection | clip_robust | ineligible | — | — |
| 34-1 | 8-1 | portable_intersection | quantile_normal | ineligible | — | — |
| 34-1 | 8-1 | imputation_only | standard | 0.21 / 0.21 | 99.88 / 0.46 | 0.00 / 1.42 |
| 34-1 | 8-1 | imputation_only | robust | 0.21 / 0.04 | 89.96 / 89.92 | 0.00 / 0.71 |
| 34-1 | 8-1 | imputation_only | clip_robust | ineligible | — | — |
| 34-1 | 8-1 | imputation_only | quantile_normal | 0.00 / 0.12 | 99.92 / 0.38 | 0.00 / 0.71 |
| 34-1 | 8-1 | imputation_missingness | standard | 0.21 / 0.21 | 98.83 / 0.50 | 0.55 / 1.42 |
| 34-1 | 8-1 | imputation_missingness | robust | 0.25 / 0.04 | 0.50 / 0.46 | 0.55 / 0.71 |
| 34-1 | 8-1 | imputation_missingness | clip_robust | ineligible | — | — |
| 34-1 | 8-1 | imputation_missingness | quantile_normal | 0.08 / 0.04 | 99.96 / 0.25 | 5.52 / 0.71 |
| 34-1 | 20-1+8-1 | portable_intersection | standard | 0.25 / 0.21 | 100.00 / 90.08 | 2.21 / 0.00 |
| 34-1 | 20-1+8-1 | portable_intersection | robust | 0.25 / 0.21 | 100.00 / 90.29 | 2.21 / 0.00 |
| 34-1 | 20-1+8-1 | portable_intersection | clip_robust | ineligible | — | — |
| 34-1 | 20-1+8-1 | portable_intersection | quantile_normal | ineligible | — | — |
| 34-1 | 20-1+8-1 | imputation_only | standard | 0.21 / 0.21 | 99.58 / 0.42 | 0.00 / 1.42 |
| 34-1 | 20-1+8-1 | imputation_only | robust | 0.21 / 0.21 | 90.04 / 89.96 | 0.00 / 0.71 |
| 34-1 | 20-1+8-1 | imputation_only | clip_robust | ineligible | — | — |
| 34-1 | 20-1+8-1 | imputation_only | quantile_normal | 0.12 / 0.00 | 99.92 / 0.29 | 1.66 / 0.00 |
| 34-1 | 20-1+8-1 | imputation_missingness | standard | 0.25 / 0.25 | 94.58 / 0.46 | 0.55 / 0.71 |
| 34-1 | 20-1+8-1 | imputation_missingness | robust | 0.08 / 0.08 | 0.50 / 0.58 | 1.10 / 0.00 |
| 34-1 | 20-1+8-1 | imputation_missingness | clip_robust | ineligible | — | — |
| 34-1 | 20-1+8-1 | imputation_missingness | quantile_normal | 0.12 / 0.04 | 99.71 / 0.42 | 1.10 / 0.00 |
| 8-1 | 20-1 | portable_intersection | standard | 0.00 / 0.00 | 100.00 / 0.00 | 1.10 / 0.71 |
| 8-1 | 20-1 | portable_intersection | robust | 0.00 / 0.00 | 100.00 / 0.00 | 1.10 / 0.71 |
| 8-1 | 20-1 | portable_intersection | clip_robust | ineligible | — | — |
| 8-1 | 20-1 | portable_intersection | quantile_normal | ineligible | — | — |
| 8-1 | 20-1 | imputation_only | standard | 0.00 / 0.00 | 99.95 / 99.95 | 0.00 / 1.42 |
| 8-1 | 20-1 | imputation_only | robust | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 18.44 |
| 8-1 | 20-1 | imputation_only | clip_robust | 0.00 / 0.00 | 99.95 / 99.95 | 61.88 / 0.00 |
| 8-1 | 20-1 | imputation_only | quantile_normal | 0.00 / 0.00 | 100.00 / 99.95 | 1.10 / 0.71 |
| 8-1 | 20-1 | imputation_missingness | standard | 0.00 / 0.00 | 99.95 / 99.95 | 0.00 / 1.42 |
| 8-1 | 20-1 | imputation_missingness | robust | 0.00 / 0.00 | 0.00 / 0.00 | 0.55 / 18.44 |
| 8-1 | 20-1 | imputation_missingness | clip_robust | 0.00 / 0.00 | 99.95 / 0.00 | 56.35 / 0.00 |
| 8-1 | 20-1 | imputation_missingness | quantile_normal | 0.00 / 0.00 | 100.00 / 99.95 | 0.55 / 0.71 |
| 8-1 | 34-1 | portable_intersection | standard | 0.00 / 0.00 | 100.00 / 100.00 | 0.55 / 1.42 |
| 8-1 | 34-1 | portable_intersection | robust | 0.00 / 0.00 | 100.00 / 100.00 | 0.55 / 0.71 |
| 8-1 | 34-1 | portable_intersection | clip_robust | ineligible | — | — |
| 8-1 | 34-1 | portable_intersection | quantile_normal | 0.00 / 0.00 | 100.00 / 100.00 | 2.21 / 0.71 |
| 8-1 | 34-1 | imputation_only | standard | 0.00 / 0.00 | 100.00 / 0.05 | 0.00 / 0.71 |
| 8-1 | 34-1 | imputation_only | robust | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.71 |
| 8-1 | 34-1 | imputation_only | clip_robust | 0.00 / 0.00 | 0.00 / 0.00 | 13.26 / 0.71 |
| 8-1 | 34-1 | imputation_only | quantile_normal | 0.00 / 0.00 | 100.00 / 0.00 | 2.21 / 0.71 |
| 8-1 | 34-1 | imputation_missingness | standard | 0.00 / 0.00 | 0.05 / 0.05 | 0.55 / 0.71 |
| 8-1 | 34-1 | imputation_missingness | robust | 0.00 / 0.00 | 0.00 / 0.00 | 0.55 / 0.71 |
| 8-1 | 34-1 | imputation_missingness | clip_robust | 0.00 / 0.00 | 0.00 / 0.00 | 22.65 / 0.71 |
| 8-1 | 34-1 | imputation_missingness | quantile_normal | 0.00 / 0.00 | 93.02 / 0.05 | 0.55 / 1.42 |
| 8-1 | 20-1+34-1 | portable_intersection | standard | 0.00 / 0.00 | 100.00 / 100.00 | 0.55 / 0.71 |
| 8-1 | 20-1+34-1 | portable_intersection | robust | 0.00 / 0.00 | 100.00 / 100.00 | 0.55 / 0.71 |
| 8-1 | 20-1+34-1 | portable_intersection | clip_robust | ineligible | — | — |
| 8-1 | 20-1+34-1 | portable_intersection | quantile_normal | 0.00 / 0.00 | 100.00 / 100.00 | 2.21 / 0.71 |
| 8-1 | 20-1+34-1 | imputation_only | standard | 0.00 / 0.00 | 100.00 / 0.00 | 0.00 / 0.71 |
| 8-1 | 20-1+34-1 | imputation_only | robust | 0.00 / 0.00 | 0.00 / 0.00 | 0.55 / 0.71 |
| 8-1 | 20-1+34-1 | imputation_only | clip_robust | 0.00 / 0.00 | 0.05 / 0.05 | 12.71 / 0.71 |
| 8-1 | 20-1+34-1 | imputation_only | quantile_normal | 0.00 / 0.00 | 0.05 / 100.00 | 0.00 / 2.13 |
| 8-1 | 20-1+34-1 | imputation_missingness | standard | 0.00 / 0.00 | 0.05 / 0.00 | 0.55 / 0.71 |
| 8-1 | 20-1+34-1 | imputation_missingness | robust | 0.00 / 0.00 | 0.00 / 0.00 | 1.10 / 0.00 |
| 8-1 | 20-1+34-1 | imputation_missingness | clip_robust | 0.00 / 0.00 | 0.05 / 0.05 | 17.13 / 0.71 |
| 8-1 | 20-1+34-1 | imputation_missingness | quantile_normal | 0.00 / 0.00 | 0.05 / 100.00 | 2.21 / 2.13 |

6,195 paired rows remain after disclosed source-alias, ambiguity and duplicate exclusions.
These results do not establish full-capture or operational generalization. The source-addition comparisons, failure reasons, target incidental benign metrics, costs and per-family coverage remain in the machine-readable report.


## Adding an attack source

52/72 target/view/transform/site comparisons are fully paired. Each compares the combined fit to both single-source fits on identical test rows. The remaining comparisons are unevaluable, not zero effect.

| Metric | Increased | Unchanged | Decreased | Min / max change (percentage points) |
|---|---:|---:|---:|---:|
| target_attack_direct | 25 | 54 | 25 | -99.95 / 57.14 |
| target_attack_unknown | 17 | 79 | 8 | -28.57 / 14.29 |
| target_attack_or_review | 30 | 42 | 32 | -99.95 / 100.00 |
| independent_benign_fpr | 26 | 43 | 35 | -49.17 / 17.73 |
| independent_benign_review | 46 | 20 | 38 | -52.49 / 40.88 |

## Packet-feature and indicator comparisons

44/72 source-choice/transform/site triples complete all three views. Only those complete triples enter the paired differences below. Imputation versus portable also adds 60 packet features; it is not a pure imputation-method comparison. Adding indicators holds those packet features fixed.

### imputation_only minus portable_intersection

| Metric | Increased | Unchanged | Decreased | Min / max change (pp) |
|---|---:|---:|---:|---:|
| target: direct_suspicious_unknown | 4 | 29 | 11 | -14.29 / 28.57 |
| target: detection_or_review | 3 | 11 | 30 | -100.00 / 99.95 |
| independent_benign: direct_union_fpr | 10 | 13 | 21 | -2.21 / 17.73 |
| independent_benign: review_inclusive_rate | 15 | 1 | 28 | -58.56 / 43.09 |

### imputation_missingness minus imputation_only

| Metric | Increased | Unchanged | Decreased | Min / max change (pp) |
|---|---:|---:|---:|---:|
| target: direct_suspicious_unknown | 9 | 33 | 2 | -0.12 / 14.29 |
| target: detection_or_review | 9 | 23 | 12 | -99.95 / 57.14 |
| independent_benign: direct_union_fpr | 20 | 18 | 6 | -1.66 / 17.73 |
| independent_benign: review_inclusive_rate | 10 | 15 | 19 | -35.91 / 24.82 |

An increase in benign FPR/review is worse, not an improvement. These repeated fits, source choices and site orientations are correlated; counts are descriptive, not independent replications or significance tests. No missing entry is imputed and no candidate is selected.

Regenerate with `python -m scripts.verify_registered_missingness --markdown`.
