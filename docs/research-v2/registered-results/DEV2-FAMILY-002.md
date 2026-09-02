# Corrected strict-family development result

Executed commit: `365903128b0db36128e0846960a89b72fe8a7a74`. Development only; no model selected.

| Held family / calibration site | Attacks | Direct unknown | Detection or review | Benign FPR |
|---|---:|---:|---:|---:|
| c_and_c / hp4-1 | 4,710 | 0.00% | 0.00% | 2.21% |
| c_and_c / hp5-1 | 4,710 | 0.00% | 0.00% | 47.51% |
| ddos / hp4-1 | 7 | 0.00% | 0.00% | 14.36% |
| ddos / hp5-1 | 7 | 0.00% | 0.00% | 0.00% |
| port_scan / hp4-1 | 4 | 0.00% | 100.00% | 8.29% |
| port_scan / hp5-1 | 4 | 50.00% | 100.00% | 0.00% |

Benign test is the other honeypot (181 rows). Same attacks are reused across
site orientations; they are not independent additional attack samples.

Regenerate this table with `python -m scripts.verify_registered_research_v2 --markdown`.
