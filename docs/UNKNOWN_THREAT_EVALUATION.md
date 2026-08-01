# Unknown-behaviour evaluation

The open-set decision combines anomaly score, classifier confidence/margin, signature
evidence, context, and model disagreement. A high anomaly score without a confident
known class becomes `suspicious_unknown`; it is not labeled as a zero-day.

Evaluation should hold out one entire attack family from supervised training, retain
it only for final unknown testing, and report unknown detection rate alongside benign
false-positive rate. Cross-dataset evaluation is required when feature definitions
are compatible. Thresholds are selected on validation data against a documented
false-positive budget, never on the final test set.

## Published evidence

The exact harness uses `packages.detection.hybrid.HybridPredictor`, the same classifier,
Isolation Forest, autoencoder, empirical CDF, and fusion implementation as runtime. CSV
evaluation does not fabricate signature or rolling-context evidence.

- Official UNSW train/test: 64.4% benign false-positive rate and no unknown family.
- UNSW leave-`exploits`-out: 44,525 unknown flows, 2.1% direct suspicious-unknown
  detection and 38.6% detection-or-review.
- UNSW to official CSE-CIC-IDS2018 Thursday: zero canonical overlap, but 100% benign
  false-positive rate, 18.9% direct infiltration unknown detection, 87.7% detection-or-
  review, and about 19,649 false alerts per replay hour. Median anomaly percentile is
  1.0, demonstrating incompatible domain shift rather than confirmed novelty.
- CSE chronological split: 1.15% benign false-positive rate but essentially zero later
  infiltration recall and about 280 false alerts per replay hour.

Every report fails the machine-readable readiness gate. A single report can reject a
candidate but cannot authorize promotion; all required modes and human review remain
mandatory. `suspicious_unknown` remains a review state, never a zero-day claim.
