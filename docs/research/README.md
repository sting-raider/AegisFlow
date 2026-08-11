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
| DEV-ANO-001 | Do benign-only anomaly models transfer when fit, calibration, and test environments are mutually disjoint? | No. All five model families fail; every model has a zero or near-zero worst-environment unknown recall. | `experiments/dev-anomaly-baselines-v1.json`, `anomaly-baselines.md` |
| DEV-HYB-001 | Does bounded temporal context improve a calibrated hybrid on repeated held-family IoT tests? | Not reliably. Some rotations improve, but the full hybrid has near-zero worst recall and exceeds the transferred 1% benign-FPR target. | `experiments/dev-hybrid-temporal-held-family-v1.json`, `hybrid-temporal-held-family.md` |
| DEV-ERR-001 | Which aggregate flow/context buckets explain held-family errors and calibration instability? | Device calibration orientation and low-observability zero/one-packet behavior dominate; port removal is not a remedy. | `../error_analysis/held-family-root-cause-v1.json`, `../error_analysis/held-family-root-cause-v1.md` |

## Current conclusion

The compact MLP has the strongest mean supervised baseline, but its worst-environment
malicious recall is 3.64% and worst benign FPR is 18.20%. The benign-only anomaly study
also rejects all five model families: mean direct unknown recall is at most 6.28%, and
every family has a zero or near-zero worst-environment result. Neither supervised
maliciousness nor a universal benign-only anomaly score is sufficient on the numerical
core. Controlled hybrid and temporal evidence also fails: the full hybrid reaches 52.14%
mean detection-or-review but only 0.067% in its worst family/orientation, while worst
benign FPR reaches 1.61%. Context-only behavior is even less stable. The evidence now
points to environment calibration and flow-level cross-domain observability as the next
root-cause questions; no model is eligible for locking and frozen evidence remains sealed.
The predeclared final development direction is a cross-fitted environment-aware benign
calibration ensemble. Failure there will support a flow-level scientific NO-GO rather
than further opportunistic model search.
