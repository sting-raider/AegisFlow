# Detector v2 final report

Date: 2026-08-22. Branch `codex/detector-v2`. Development evidence only; the v1 frozen
reports were never queried and remain sealed.

## 1. Research question

Can packet-sequence representations, protocol/connection-state semantics,
domain-invariant representation learning, and explicitly approved target-site benign
calibration materially improve cross-environment and previously unseen-behaviour
detection while maintaining an operationally acceptable benign false-positive rate?

## 2. Hypothesis

First-N-packet sequence semantics carry discriminative information that survives
environment change better than aggregate-flow statistics (predeclared in
`docs/research-v2/MASTER_PLAN.md` before any experiment).

## 3. Dataset provenance

Eight official Stratosphere IoT-23 scenario PCAPs plus their Zeek per-flow ground truth
(`docs/research-v2/DATASETS.md`), replayed through AegisFlow's own PcapAdapter so
training shares the runtime feature contract. Six scenarios prepared into 6,671
deduplicated labeled flow records spanning three attack families (C&C, DDoS, port scan)
and five benign-leaning environments. Raw data stays outside Git; hashes pinned in
`configs/research-v2/pool-hashes.json`.

## 4. Leakage controls

- Environments partitioned fit/test by capture, never by rows.
- Exact-vector deduplication across the whole pool.
- Fit-side calibration splits for all threshold selection; target attack data never
  touches any selection decision; Mode C uses only approved benign target scores.
- Fail-closed origin diagnostic with a predeclared 0.90 block threshold.
- The reserved final environment (CTU-13 scenario 8) was never touched.

## 5. Sequence representation

Per-packet signed log1p(size), log1p(IAT ms), direction flag, contract-normalized
position; explicit padding masks; shared implementation for training and runtime
(`packages/detection_v2/sequences.py`, 11 unit tests including parity and endpoint-
identity independence). Payload contents are never read.

## 6. Model architecture

Fusion of masked sequence encoder (MLP or temporal CNN) + portable Schema-A aggregate
branch + TCP connection-state vector -> compact embedding -> known-attack head;
Mahalanobis OOD channel in embedding space; site-percentile calibration for both
channels; transparent reason-code fusion. No LLM anywhere in detection.

## 7. Domain-invariance method

Gradient-reversal domain adversary on the fusion encoder. Weak coefficient (lambda=0.1)
is optimal: environment-artifact false positives on target-site incidental benign drop
from 28.26% to 0.00% while unseen-family recall is preserved (91.07% -> 90.58%).

## 8. Site-calibration protocol

Observation-mode analogue: thresholds placed at quantiles of APPROVED BENIGN scores
from the target environment only; operator approval and rollback inherited from the
v1 governance design. Nominal site FPR holds by construction on the calibration pool;
fresh same-environment benign validation remains required at deployment.

## 9. OOD methodology

Mahalanobis distance in the fusion embedding, fit on training-benign embeddings,
calibrated at the target-site p99. Catches structurally distinct held families
(DDoS/port-scan: 100% each) but not cross-family C&C variants.

## 10. Held-family results

See `RESULTS.md`: HF2 recovers 91.26% detection-or-review for held Mirai C&C; HF1 and
HF3 collapse (<0.1%) - transfer is direction- and diversity-dependent.

## 11. Cross-environment results

Global absolute thresholds fail completely in the hard direction (0% recall despite
PR-AUC 0.85-0.98). Site-percentile calibration recovers ~91% recall at nominal 1%
site-FPR. Ranking transfers better than score levels everywhere measured.

## 12. Ablations

Aggregate-only vs sequence-only vs fused vs +site-calibration vs +domain-adversary are
tabulated in `RESULTS.md`; Suricata-without and temporal-window ablations were not
run because no Suricata evidence exists in this pool and temporal context is out of
the current scope boundary - both are recorded as open.

## 13. Error analysis

Dominant limitations (aggregate): environment-indexed score levels (score inversion in
some encoders); tiny benign calibration pools produce degenerate thresholds; repetitive
families collapse under exact deduplication (DDoS 211->6 unique vectors); honeypot
"benign" contains adversarial-looking noise making some fit tasks intrinsically hard
(best calibration macro-F1 ~0.44).

## 14. Performance

Single-flow inference 0.066 ms; batched ~749k flows/s on CPU (gates: <=10 ms, >=500/s).
Training runs complete in minutes on CPU.

## 15. Limitations

IoT-scale captures only; two malware families with one dominant transfer direction;
small benign pools; ECE gates unmet for raw probability heads (ranking unaffected);
no Suricata/DNS/TLS semantics evaluated; single-host CPU measurements only.

## 16. Final verdict

**Outcome B — strong material improvement, production gates not fully met.**

Material improvements over Detector v1:

- Cross-environment unseen-family detection: v1 best direct unknown recall was 6.28%
  (mean) with universal collapse; v2 site-calibrated detection reaches 90.6-90.9% in
  the tested hard direction.
- Dataset-origin leakage: blocked at 0.954 (v1) -> maximum 0.797 across all v2
  representations; connection-state semantics measure 0.349.
- Environment-artifact false positives: eliminated (28% -> 0%) by the weak domain
  adversary without sacrificing recall.
- Unknown-channel behavior: structurally distinct held families surface through the
  Mahalanobis channel at 100%.

Not met: universal held-environment stability (collapse persists in one direction),
ECE <= 0.10 for probability heads, and a mean >=50% unknown-recall gate across all
held families. Because no challenger satisfies every predeclared gate, **no candidate
is locked**, the reserved final environment stays sealed, and Detector v2 is not a
production candidate.

## 17. Claims safe for faculty/project presentation

1. AegisFlow's runtime contract already carries first-20-packet sequences end to end;
   training and inference share one tested implementation.
2. Packet-sequence + connection-state representations rank unseen-family attacks well
   across environments where aggregate-flow ranking already worked, and add an OOD
   channel that surfaces structurally novel families at 100% in our tests.
3. Absolute decision thresholds do not transfer between environments; operator-approved
   site-benign percentile calibration converts non-transferring rankings into ~91%
   detection at nominal 1% site-FPR in the tested hard direction.
4. A weak domain-adversarial objective removes residual environment-artifact false
   positives without losing that recovery.
5. All of this runs at 0.066 ms/flow on CPU inside the existing platform contract.
6. Detector v2 is research evidence, not a validated production detector; the v1 NO-GO
   stands and the reserved final evaluation remains unused.
