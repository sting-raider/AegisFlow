# Detector v2 final report

Audit correction, 2026-09-02: **historical and scientifically unvalidated**. The earlier
Outcome-B conclusion and presentation claims are superseded. FAMILY/DANN contain
fit/calibration overlap; HF1/HF2 are not whole-family holdouts; actual execution
provenance and performance artifacts are incomplete. See `../REQUIREMENTS_AUDIT.md`.
The original JSON/NPZ bytes are retained, not silently replaced by corrected runs.

Corrected evidence is now separate: [DEV2-FAMILY-002](registered-results/DEV2-FAMILY-002.md)
completed six preregistered strict-family/site rotations from clean code `3659031`.
It remains a development NO-GO (zero C&C/DDoS detection-or-review, worst independent
benign FPR 47.51%). This does not rehabilitate the historical experiments below or
establish the full final-phase stop condition.
The separate [ORIGIN-002 audit](registered-results/DEV2-ORIGIN-002.md) confirms retained
benign-origin information in the corrected encoders; it is not a detector-quality result.
The [MISSINGNESS-001 study](registered-results/DEV2-MISSINGNESS-001.md) completed from
`b83f184`: 84 evaluated models, 24 alias-ineligible entries and 168 site evaluations.
Its paired source/representation effects are mixed; no target-mixture site entry reaches
50% direct unknown recall. This is a narrow linear/raw-distance study, not completion
of the learned/context/signature ablations or authorization for frozen evaluation.

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

Eight official Stratosphere IoT-23 scenarios were declared, six acquired/prepared with
their Zeek per-flow ground truth
(`docs/research-v2/DATASETS.md`), replayed through AegisFlow's own PcapAdapter so
training shares the runtime feature contract. Six scenarios prepared into 6,671
deduplicated labeled flow records spanning three attack families (C&C, DDoS, port scan)
and five benign-leaning environments. Raw data stays outside Git; hashes pinned in
`configs/research-v2/pool-hashes.json`.

## 4. Leakage controls

- Intended capture isolation was violated in FAMILY/DANN by reusing site captures in fit.
- Exact-vector deduplication across the whole pool.
- Historical fit-side calibration and site-score quantiles exist, but do not prove
  independent benign validation. They are not a deployed human-approved baseline workflow.
- The 0.90 origin threshold was exceeded by learned embeddings (0.93874--0.94378).
- The reserved final environment (CTU-13 scenario 8) was never touched.

## 5. Sequence representation

Per-packet signed log1p(size), log1p(IAT ms), direction flag, contract-normalized
position; explicit padding masks; shared implementation for training and runtime
(`packages/detection_v2/sequences.py`, 11 unit tests including parity and endpoint-
identity independence). Payload contents are never read.

## 6. Model architecture

Fusion of masked sequence encoder (MLP or temporal CNN) + portable Schema-A aggregate
branch -> compact embedding -> known-attack head. TCP state exists as a separate
diagnostic tensor, but is not concatenated into `FusionNet`;
Mahalanobis OOD channel in embedding space; site-percentile calibration for both
channels; transparent reason-code fusion. No LLM anywhere in detection.

## 7. Domain-invariance method

Gradient-reversal domain adversary on the fusion encoder. The historical lambda=0.1
run reports incidental-benign flags falling from 28.26% to 0.00%, and cross-capture
C&C recall 91.07% -> 90.58%. This is exploratory, not an optimal-coefficient or
unseen-family result; fitting reused site-calibration data and model initialization
was not globally seeded. All learned-embedding origin scores still exceed 0.90.

## 8. Site-calibration protocol

Observation-mode analogue: thresholds placed at quantiles of APPROVED BENIGN scores
from the target environment only. The deployed observation/approval/activation/rollback
workflow remains unimplemented. Nominal calibration FPR is not an independent FPR test;
ties can also exceed the nominal percentile budget with `>=` decision semantics.

## 9. OOD methodology

Mahalanobis distance in the fusion embedding, fit on training-benign embeddings,
calibrated at the target-site p99. The old report flags six DDoS and four port-scan rows,
but those families were allowed in HF2 fitting configuration. This is not proof of
strict-family novelty detection; actual fit-family membership and corrected splits
must be checked in each run.

## 10. Held-family results

See `RESULTS.md` for historical metrics. HF1/HF2 retain C&C in fit and therefore test
cross-capture transfer. HF3 excludes C&C but reuses calibration data in fit and includes
other families in its test partition. The separate corrected FAMILY-002 results linked
above supersede these historical strict-family claims, not the original artifact bytes.

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

Not verified. The earlier 0.066 ms and ~749k flows/s prose figures have no retained
machine-readable benchmark, so they do not establish either CPU gate. Corrected runs
must retain latency distributions, batching conditions, memory and environment metadata.

## 15. Limitations

IoT-scale captures only; two malware families with one dominant transfer direction;
small benign pools; ECE gates unmet for raw probability heads (ranking unaffected);
no Suricata/DNS/TLS semantics evaluated; single-host CPU measurements only.

## 16. Final verdict

**Incomplete research validation; no production candidate.** The archived runs cannot
support a v1-to-v2 improvement claim under a common valid protocol. Raw-feature origin
BA below 0.90 does not clear learned-embedding origin BA above 0.90. Cross-capture C&C
recall is not whole-family unknown recall. Corrected partitioning, deterministic model
initialization, full run provenance and independent benign metrics are required.

No candidate is locked, final data stays sealed, and the v1 model rejection stands.
This does not yet satisfy the full final-phase brief's Outcome-B stop condition.

## 17. Claims safe for faculty/project presentation

1. AegisFlow's runtime contract already carries first-20-packet sequences end to end;
   training and inference share one tested implementation.
2. V2 contains experimental sequence/fusion, site-relative quantile and domain-adversarial
   implementations. Historical metrics are provisional because the audit found defects.
3. The research distinguishes classification and embedding-distance channels; their
   benefit under strict family isolation and independent FPR testing is not established.
4. The archive guard detects byte/content-boundary changes, not scientific validity.
5. V2 CPU performance has not been verified with retained benchmark evidence.
6. Detector v2 is research evidence, not a validated production detector; the v1 NO-GO
   stands and the reserved final evaluation remains unused.
