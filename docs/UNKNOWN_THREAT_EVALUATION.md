# Unknown-behaviour evaluation

The open-set decision combines anomaly score, classifier confidence/margin, signature
evidence, context, and model disagreement. A high anomaly score without a confident
known class becomes `suspicious_unknown`; it is not labeled as a zero-day.

Evaluation should hold out one entire attack family from supervised training, retain
it only for final unknown testing, and report unknown detection rate alongside benign
false-positive rate. Cross-dataset evaluation is required when feature definitions
are compatible. Thresholds are selected on validation data against a documented
false-positive budget, never on the final test set.
