# Cross-fitted environment-aware calibration results

Experiment: `DEV-CAL-001`

Code commit: `020431d5caf5497938adaab97a14076865f95401`

Generated: `2026-08-11T13:45:53.473414+00:00`

The predeclared primary rule is `crossfit_mean_hybrid`. Each approved benign
capture is scored only by an anomaly model fitted on the other capture. Min and
max aggregation are sensitivity checks and cannot replace the primary after the
held-family results are visible.

| Strategy | Runs | Mean direct detection | Worst direct detection | Mean direct unknown | Worst direct unknown | Mean detection/review | Worst detection/review | Mean benign FPR | Worst benign FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| crossfit_min_anomaly_only | 3 | 0.01380 | 0.00000 | 0.01380 | 0.00000 | 0.01380 | 0.00000 | 0.00566 | 0.00780 |
| crossfit_min_hybrid | 3 | 0.34127 | 0.00000 | 0.01104 | 0.00000 | 0.44951 | 0.04098 | 0.00695 | 0.00988 |
| crossfit_mean_anomaly_only | 3 | 0.01380 | 0.00000 | 0.01380 | 0.00000 | 0.01380 | 0.00000 | 0.00566 | 0.00780 |
| crossfit_mean_hybrid | 3 | 0.34403 | 0.00000 | 0.01380 | 0.00000 | 0.44951 | 0.04098 | 0.00770 | 0.01092 |
| crossfit_max_anomaly_only | 3 | 0.03042 | 0.00027 | 0.03042 | 0.00027 | 0.03042 | 0.00027 | 0.01399 | 0.01924 |
| crossfit_max_hybrid | 3 | 0.36063 | 0.00020 | 0.03040 | 0.00020 | 0.46611 | 0.09016 | 0.01174 | 0.01612 |

## Primary held-family results

### command_and_control

Test rows `26664` (14947 held-family, 11717 benign). Direct detection `0.00000`, direct suspicious-unknown `0.00000`, detection-or-review `0.31645`, benign FPR `0.00179`.

### ddos

Test rows `16317` (14394 held-family, 1923 benign). Direct detection `0.99111`, direct suspicious-unknown `0.00042`, detection-or-review `0.99111`, benign FPR `0.01040`.

### port_scan

Test rows `2045` (122 held-family, 1923 benign). Direct detection `0.04098`, direct suspicious-unknown `0.04098`, detection-or-review `0.04098`, benign FPR `0.01092`.

## Limitations

- This is environment-aware calibration inside one CTU environment, not evidence of cross-organization temporal transfer.
- The mean percentile strategy was fixed before test results; min and max are sensitivity analyses and cannot replace it after results are visible.
- File-download remains below the minimum sample count.
- No suspicious or attack-capture traffic enters the approved benign baseline.
- IoT-23 does not provide replay-correlated signature evidence.
