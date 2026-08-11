# Development hybrid temporal held-family results

Experiment: `DEV-HYB-001`

Code commit: `0b98eebfc3eb1bf37c24a7a7da68a7928e4c0625`

Generated: `2026-08-11T13:18:18.674209+00:00`

This is development-only evidence. Every reported attack family is removed from
supervised fitting, anomaly fitting uses an all-benign IoT capture, thresholds use
a second all-benign capture, and testing uses separate attack capture groups.

| Ablation | Runs | Mean direct detection | Worst direct detection | Mean direct unknown | Worst direct unknown | Mean detection/review | Worst detection/review | Mean benign FPR | Worst benign FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| supervised_only | 6 | 0.38554 | 0.00000 | 0.00000 | 0.00000 | 0.44228 | 0.00000 | 0.01457 | 0.05155 |
| anomaly_core_only | 6 | 0.03045 | 0.00033 | 0.03045 | 0.00033 | 0.29144 | 0.00076 | 0.00548 | 0.01040 |
| context_only | 6 | 0.41989 | 0.00007 | 0.41989 | 0.00007 | 0.62614 | 0.00049 | 0.19553 | 0.38898 |
| supervised_plus_anomaly | 6 | 0.19551 | 0.00027 | 0.03039 | 0.00020 | 0.51192 | 0.09016 | 0.00630 | 0.01092 |
| supervised_plus_context | 6 | 0.33799 | 0.00000 | 0.33748 | 0.00000 | 0.79352 | 0.40550 | 0.14473 | 0.38274 |
| anomaly_plus_context | 6 | 0.02211 | 0.00013 | 0.02211 | 0.00013 | 0.41215 | 0.00013 | 0.00982 | 0.01560 |
| full_hybrid | 6 | 0.18586 | 0.00007 | 0.02072 | 0.00007 | 0.52139 | 0.00067 | 0.00935 | 0.01612 |
| without_temporal | 6 | 0.19551 | 0.00027 | 0.03039 | 0.00020 | 0.51192 | 0.09016 | 0.00630 | 0.01092 |
| without_destination_port_information | 6 | 0.20785 | 0.00000 | 0.04369 | 0.00000 | 0.57114 | 0.01438 | 0.02959 | 0.05252 |

## Held-family runs

### command_and_control: fit CTU-Honeypot-Capture-4-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-5-1.conn.log.labeled

Test rows `26664` (14947 held-family, 11717 benign). Full hybrid direct detection `0.00007`, direct suspicious-unknown `0.00007`, detection-or-review `0.00067`, benign FPR `0.00154`.

### command_and_control: fit CTU-Honeypot-Capture-5-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-4-1.conn.log.labeled

Test rows `26664` (14947 held-family, 11717 benign). Full hybrid direct detection `0.00027`, direct suspicious-unknown `0.00013`, detection-or-review `0.33258`, benign FPR `0.00307`.

### ddos: fit CTU-Honeypot-Capture-4-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-5-1.conn.log.labeled

Test rows `16317` (14394 held-family, 1923 benign). Full hybrid direct detection `0.00035`, direct suspicious-unknown `0.00035`, detection-or-review `0.99111`, benign FPR `0.00884`.

### ddos: fit CTU-Honeypot-Capture-5-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-4-1.conn.log.labeled

Test rows `16317` (14394 held-family, 1923 benign). Full hybrid direct detection `0.99152`, direct suspicious-unknown `0.00083`, detection-or-review `0.99250`, benign FPR `0.01612`.

### port_scan: fit CTU-Honeypot-Capture-4-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-5-1.conn.log.labeled

Test rows `2045` (122 held-family, 1923 benign). Full hybrid direct detection `0.03279`, direct suspicious-unknown `0.03279`, detection-or-review `0.04098`, benign FPR `0.01040`.

### port_scan: fit CTU-Honeypot-Capture-5-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-4-1.conn.log.labeled

Test rows `2045` (122 held-family, 1923 benign). Full hybrid direct detection `0.09016`, direct suspicious-unknown `0.09016`, detection-or-review `0.77049`, benign FPR `0.01612`.

## Limitations

- Only IoT-23 provides Schema B, so temporal transfer across organizations is not established.
- The temporal state is replayed over complete captures; other behavior in the same stream can influence context, but no test row enters fitting or threshold calibration.
- The supervised head is binary maliciousness evidence, not an attack-family classifier; anomaly evidence takes precedence for suspicious-unknown verdict accounting.
- File-download has too few rows for an independent quantitative claim.
- IoT-23 has no replay-correlated signature evidence, so signatures-only and signatures-plus-hybrid performance are not evaluated.
- Class sampling in supervised sources prevents representative false-alerts-per-hour estimates.
