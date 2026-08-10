# AegisFlow research evidence

## Research question

Can a hybrid system combining signature detection, supervised classification,
anomaly/open-set modelling, and temporal behavioural context improve detection of
previously unseen network behaviour while maintaining an operationally acceptable benign
false-positive rate?

## Hypothesis

A portable, dataset-origin-audited flow representation plus AegisFlow-owned bounded
temporal context will transfer better than the deployed legacy feature contract. A hybrid
known-attack and benign-only anomaly detector may then improve held-family
detection-or-review without exceeding the development benign-FPR budget. This remains a
hypothesis; current evidence has not established it.

## Protocol boundary

- Development choices use only the three fresh sources registered in
  `configs/datasets/development-pool-v1.json`.
- The four reports in `configs/evaluation/frozen-evidence-v1.json` remain final-only.
- Full Schema A is blocked by the dataset-origin diagnostic. Experiments may use only a
  documented ablation that clears the blocking threshold.
- Every experiment binds its clean code commit, dataset fingerprints, split IDs, feature
  order, seed, preprocessing, model/calibration configuration, metrics, resource cost,
  artifact hashes, and disposition under `configs/research/experiments/`.
- A completed development experiment cannot promote a model. Challenger locking and the
  single frozen run are separate governed steps.

## Evidence index

| Experiment | Question | Result | Artifacts |
|---|---|---|---|
| DEV-SUP-001 | Do standard supervised maliciousness models transfer across all three fresh environments on the numerical core? | No. Every model misses development objectives; no candidate selected. | `experiments/dev-supervised-baselines-v1.json`, `supervised-baselines.md` |

## Current conclusion

The compact MLP has the strongest mean supervised baseline, but its worst-environment
malicious recall is 3.64% and worst benign FPR is 18.20%. Logistic regression, calibrated
random forest, and HistGradientBoosting are also unstable. Binary supervised evidence
alone is insufficient. The next experiment must test benign-only anomaly/open-set signals
and repeated held-family detection; it must not tune on frozen evidence.
