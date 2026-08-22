# Detector v2 results

All evidence is development-only unless marked otherwise. Machine-readable artifacts
live in `docs/research-v2/experiments/`.

## Mandatory mode comparison (DEV2-SEQ-001 + DEV2-SITE-001)

Hard transfer direction (fit Hakai C&C -> target Mirai C&C, hp4 site):

| Mode | Model | Benign FPR | Known recall | Unknown/D-or-R | Source |
|---|---|---:|---:|---:|---|
| Flow v1 (global thr) | aggregate logreg | 0.0% | 0.0% | 0.0% | SITE-001 |
| Sequence (global thr) | seq MLP / CNN / fusion | 0.0-3.5% | 0.0% | 0.0% | SEQ-001 |
| Seq+flow (global thr) | fusion | 0.0% | 0.0% | 0.0% | SEQ-001 |
| + site calibration p990 | aggregate logreg | ~1% nominal | **90.7%** | - | SITE-001 |
| + site calibration p990 | sequence MLP | ~1% nominal | **90.9%** | - | SITE-001 |
| + domain adversary + site p99 | fusion lambda=0.1 | **0% incidental** | **90.6%** | OOD catches held DDoS/scan at 100% | DANN-001/FAMILY-001 |

Easy direction (fit Mirai -> target Hakai, hp5 site): aggregate logreg reaches
recall 100% / FPR 0.5% under the global threshold; some sequence encoders exhibit
score inversion across environments and fail there (CNN pooled ROC-AUC 0.86).

## Dataset-origin leakage (DEV2-ORIGIN-001)

| Representation | Origin balanced accuracy | Binary task BA |
|---|---:|---:|
| v1 aggregate Schema A | 0.779 | 0.869 |
| Connection state only | **0.349** | 0.856 |
| Packet sequence flat | 0.794 | 0.875 |
| Fused (all) | 0.797 | 0.876 |

None crosses the 0.90 block threshold (v1's full Schema A measured 0.954 on CSV pools).
Connection-state semantics are near-environment-blind while retaining task signal.

## Held-family open-set channels (DEV2-FAMILY-001)

| Rotation | Held family | Known channel | OOD channel | Detection-or-review |
|---|---|---:|---:|---:|
| HF1 hold Hakai | c_and_c (2,056) | 0.05% | 0.0% | **0.05%** |
| HF2 hold Mirai | c_and_c (2,654) | 90.88% | 0.38% | **91.26%** |
| HF2 incidental | ddos (6) / port_scan (4) | 0%/25% | **100%/100%** | 100% |
| HF3 no C&C fit | both c_and_c (4,710) | 0.04% | 0.06% | **0.09%** |

## Domain adversary (DEV2-DANN-001)

lambda=0.1 removes environment-artifact false positives entirely (28.26% -> 0.00%)
while preserving unseen-family recall (91.07% -> 90.58%).

## Performance (CPU, PyTorch, recorded dev host)

Single-flow latency 0.066 ms; batched throughput ~749,000 flows/s.

## Objective scorecard (predeclared in MASTER_PLAN.md)

| Objective | Result |
|---|---|
| Benign FPR <= 1% every held env | Partial: nominal on site pool; incidental benign 28% without adversary, 0% with (46-row sample); HF1/HF3 collapse unrelated to FPR |
| Unseen-family direct unknown recall >= 50% mean | Not met as a mean: 91% one direction, 0.05% the other |
| Unknown detection-or-review >= 80% | Met only in HF2 direction |
| Known recall >= 90% (HIGH/MEDIUM observability) | Met per-direction where ranking transfers |
| ECE <= 0.10 | Not met for raw probability heads (up to 0.92); ranking unaffected |
| No catastrophic collapse | **Failed** (HF1, HF3) |
| CPU latency <= 10ms single, >= 500 flows/s batch | **Passed** by wide margins |

Verdict: Outcome B. See `docs/research-v2/FINAL_REPORT.md`.
