# Development hybrid temporal held-family results

Experiment: `DEV-ERR-001`

Code commit: `b4892c53920f3882db8caa10cf1efe6ff08058e2`

Generated: `2026-08-11T13:34:21.137921+00:00`

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

| Error dimension | Highest direct-FP bucket | Highest missed-after-review bucket |
|---|---|---|
| protocol | tcp: 0.00237 (2109 benign) | tcp: 0.99933 (14947 malicious) |
| service | web: 0.02778 (108 benign) | other: 0.99946 (14928 malicious) |
| duration_range | zero: 0.00427 (2808 benign) | 100ms_to_1s: 1.00000 (80 malicious) |
| packet_count_range | more_than_twenty: 0.17391 (23 benign) | zero_or_one: 1.00000 (8586 malicious) |
| direction | mostly_forward: 0.00403 (3718 benign) | mostly_forward: 0.99970 (13302 malicious) |
| host_behavior | fanout_one: 0.00883 (1699 benign) | cold_start: 1.00000 (113 malicious) |
| missing_feature_pattern | late_event: 0.00240 (5844 benign) | cold_start: 1.00000 (113 malicious) |
| score_component | anomaly_only: 1.00000 (15 benign) | neither_direct: 0.99940 (14946 malicious) |

### command_and_control: fit CTU-Honeypot-Capture-5-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-4-1.conn.log.labeled

Test rows `26664` (14947 held-family, 11717 benign). Full hybrid direct detection `0.00027`, direct suspicious-unknown `0.00013`, detection-or-review `0.33258`, benign FPR `0.00307`.

| Error dimension | Highest direct-FP bucket | Highest missed-after-review bucket |
|---|---|---|
| protocol | tcp: 0.01091 (2109 benign) | tcp: 0.66742 (14947 malicious) |
| service | web: 0.13889 (108 benign) | other: 0.66760 (14928 malicious) |
| duration_range | 1s_to_10s: 0.01046 (2007 benign) | zero: 1.00000 (8586 malicious) |
| packet_count_range | more_than_twenty: 0.78261 (23 benign) | zero_or_one: 1.00000 (8586 malicious) |
| direction | mostly_forward: 0.00592 (3718 benign) | bidirectional: 0.84498 (1645 malicious) |
| host_behavior | fanout_one: 0.01413 (1699 benign) | fanout_two_to_four: 0.74258 (8597 malicious) |
| missing_feature_pattern | none: 0.00373 (4555 benign) | late_event: 0.83841 (1609 malicious) |
| score_component | anomaly_only: 1.00000 (27 benign) | neither_direct: 0.66760 (14943 malicious) |

### ddos: fit CTU-Honeypot-Capture-4-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-5-1.conn.log.labeled

Test rows `16317` (14394 held-family, 1923 benign). Full hybrid direct detection `0.00035`, direct suspicious-unknown `0.00035`, detection-or-review `0.99111`, benign FPR `0.00884`.

| Error dimension | Highest direct-FP bucket | Highest missed-after-review bucket |
|---|---|---|
| protocol | tcp: 0.03604 (111 benign) | tcp: 0.00889 (14393 malicious) |
| service | web: 0.04615 (65 benign) | web: 0.00889 (14393 malicious) |
| duration_range | 1s_to_10s: 0.02674 (187 benign) | under_100ms: 1.00000 (2 malicious) |
| packet_count_range | more_than_twenty: 0.19048 (21 benign) | six_to_twenty: 1.00000 (1 malicious) |
| direction | mostly_forward: 0.01304 (1074 benign) | mostly_forward: 0.95522 (134 malicious) |
| host_behavior | fanout_one: 0.01938 (774 benign) | fanout_two_to_four: 0.05821 (2199 malicious) |
| missing_feature_pattern | late_event: 0.01486 (942 benign) | late_event: 0.47716 (197 malicious) |
| score_component | anomaly_only: 1.00000 (14 benign) | neither_direct: 0.00890 (14389 malicious) |

### ddos: fit CTU-Honeypot-Capture-5-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-4-1.conn.log.labeled

Test rows `16317` (14394 held-family, 1923 benign). Full hybrid direct detection `0.99152`, direct suspicious-unknown `0.00083`, detection-or-review `0.99250`, benign FPR `0.01612`.

| Error dimension | Highest direct-FP bucket | Highest missed-after-review bucket |
|---|---|---|
| protocol | tcp: 0.16216 (111 benign) | tcp: 0.00750 (14393 malicious) |
| service | web: 0.18462 (65 benign) | web: 0.00750 (14393 malicious) |
| duration_range | 1s_to_10s: 0.09091 (187 benign) | zero: 0.00751 (14381 malicious) |
| packet_count_range | more_than_twenty: 0.85714 (21 benign) | zero_or_one: 0.00751 (14381 malicious) |
| direction | mostly_forward: 0.01676 (1074 benign) | mostly_forward: 0.80597 (134 malicious) |
| host_behavior | fanout_one: 0.03101 (774 benign) | fanout_two_to_four: 0.04911 (2199 malicious) |
| missing_feature_pattern | none: 0.01997 (601 benign) | late_event: 0.38071 (197 malicious) |
| score_component | anomaly_only: 1.00000 (23 benign) | neither_direct: 0.88525 (122 malicious) |

### port_scan: fit CTU-Honeypot-Capture-4-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-5-1.conn.log.labeled

Test rows `2045` (122 held-family, 1923 benign). Full hybrid direct detection `0.03279`, direct suspicious-unknown `0.03279`, detection-or-review `0.04098`, benign FPR `0.01040`.

| Error dimension | Highest direct-FP bucket | Highest missed-after-review bucket |
|---|---|---|
| protocol | tcp: 0.06306 (111 benign) | udp: 1.00000 (1 malicious) |
| service | web: 0.09231 (65 benign) | other: 0.95902 (122 malicious) |
| duration_range | 1s_to_10s: 0.04278 (187 benign) | 100ms_to_1s: 1.00000 (1 malicious) |
| packet_count_range | more_than_twenty: 0.33333 (21 benign) | zero_or_one: 1.00000 (111 malicious) |
| direction | mostly_forward: 0.01304 (1074 benign) | mostly_forward: 0.95902 (122 malicious) |
| host_behavior | fanout_one: 0.02326 (774 benign) | fanout_two_to_four: 1.00000 (1 malicious) |
| missing_feature_pattern | late_event: 0.01592 (942 benign) | late_event: 0.97872 (94 malicious) |
| score_component | anomaly_only: 1.00000 (14 benign) | neither_direct: 0.99153 (118 malicious) |

### port_scan: fit CTU-Honeypot-Capture-5-1.conn.log.labeled, calibrate CTU-Honeypot-Capture-4-1.conn.log.labeled

Test rows `2045` (122 held-family, 1923 benign). Full hybrid direct detection `0.09016`, direct suspicious-unknown `0.09016`, detection-or-review `0.77049`, benign FPR `0.01612`.

| Error dimension | Highest direct-FP bucket | Highest missed-after-review bucket |
|---|---|---|
| protocol | tcp: 0.17117 (111 benign) | tcp: 0.23140 (121 malicious) |
| service | web: 0.18462 (65 benign) | other: 0.22951 (122 malicious) |
| duration_range | 1s_to_10s: 0.09091 (187 benign) | zero: 0.25225 (111 malicious) |
| packet_count_range | more_than_twenty: 0.90476 (21 benign) | zero_or_one: 0.25225 (111 malicious) |
| direction | mostly_forward: 0.01676 (1074 benign) | mostly_forward: 0.22951 (122 malicious) |
| host_behavior | fanout_one: 0.02972 (774 benign) | fanout_one: 0.23140 (121 malicious) |
| missing_feature_pattern | none: 0.01997 (601 benign) | none: 0.82143 (28 malicious) |
| score_component | anomaly_only: 1.00000 (23 benign) | neither_direct: 0.25225 (111 malicious) |

## Limitations

- Only IoT-23 provides Schema B, so temporal transfer across organizations is not established.
- The temporal state is replayed over complete captures; other behavior in the same stream can influence context, but no test row enters fitting or threshold calibration.
- The supervised head is binary maliciousness evidence, not an attack-family classifier; anomaly evidence takes precedence for suspicious-unknown verdict accounting.
- File-download has too few rows for an independent quantitative claim.
- IoT-23 has no replay-correlated signature evidence, so signatures-only and signatures-plus-hybrid performance are not evaluated.
- Class sampling in supervised sources prevents representative false-alerts-per-hour estimates.
