# Development supervised baseline results

Experiment: `DEV-SUP-001`  
Code commit: `a1e5f933fb29ec55bd2857fe1e7c809eaf059ed3`  
Generated: `2026-08-10T08:27:19.050325+00:00`

This is development-only evidence. It does not select, lock, or promote a model,
and it does not use the frozen final reports.

| Model | Mean macro F1 | Worst macro F1 | Mean benign FPR | Worst benign FPR | Mean malicious recall | Worst malicious recall |
|---|---:|---:|---:|---:|---:|---:|
| logistic_regression | 0.46713 | 0.38750 | 0.20108 | 0.31460 | 0.22641 | 0.00664 |
| calibrated_random_forest | 0.33259 | 0.30786 | 0.13361 | 0.39378 | 0.03600 | 0.00000 |
| hist_gradient_boosting | 0.44249 | 0.33643 | 0.21086 | 0.55160 | 0.25774 | 0.00051 |
| compact_mlp | 0.61474 | 0.36329 | 0.10736 | 0.18202 | 0.43945 | 0.03644 |

## Cross-environment rotations

### Test: hikari

Train sources: cse_2018_02_28, iot23. Exact feature-row overlap: 3.

| Model | Macro F1 | Benign FPR | Malicious recall | PR-AUC | ECE | Rows/s |
|---|---:|---:|---:|---:|---:|---:|
| logistic_regression | 0.57829 | 0.31460 | 0.49322 | 0.69348 | 0.04281 | 16264328.8 |
| calibrated_random_forest | 0.30786 | 0.00000 | 0.00000 | 0.62998 | 0.10174 | 92691.5 |
| hist_gradient_boosting | 0.60607 | 0.55160 | 0.76912 | 0.70903 | 0.08530 | 694088.5 |
| compact_mlp | 0.65134 | 0.18202 | 0.52132 | 0.69741 | 0.13617 | 5385563.7 |

### Test: cse_2018_02_28

Train sources: hikari, iot23. Exact feature-row overlap: 0.

| Model | Macro F1 | Benign FPR | Malicious recall | PR-AUC | ECE | Rows/s |
|---|---:|---:|---:|---:|---:|---:|
| logistic_regression | 0.43558 | 0.19896 | 0.17939 | 0.49266 | 0.39696 | 36647161.1 |
| calibrated_random_forest | 0.33977 | 0.00706 | 0.00745 | 0.49923 | 0.21140 | 118645.7 |
| hist_gradient_boosting | 0.33643 | 0.00320 | 0.00359 | 0.48941 | 0.47996 | 1027919.1 |
| compact_mlp | 0.36329 | 0.03529 | 0.03644 | 0.49589 | 0.46974 | 5023229.3 |

### Test: iot23

Train sources: hikari, cse_2018_02_28. Exact feature-row overlap: 3.

| Model | Macro F1 | Benign FPR | Malicious recall | PR-AUC | ECE | Rows/s |
|---|---:|---:|---:|---:|---:|---:|
| logistic_regression | 0.38750 | 0.08969 | 0.00664 | 0.46218 | 0.14398 | 24379763.8 |
| calibrated_random_forest | 0.35014 | 0.39378 | 0.10056 | 0.29166 | 0.09602 | 38543.3 |
| hist_gradient_boosting | 0.38499 | 0.07778 | 0.00051 | 0.58911 | 0.18966 | 567230.8 |
| compact_mlp | 0.82958 | 0.10476 | 0.76059 | 0.69624 | 0.17914 | 4504524.5 |

## Limitations

- This is a supervised maliciousness baseline, not an unknown-behaviour result.
- Random-forest calibration uses stratified development rows because only two source environments remain in each training rotation.
- A fixed 0.5 threshold is reported; operational threshold selection is a later development-only experiment.
