# Independent-benign origin audit (DEV2-ORIGIN-002)

Declared 2026-09-02 before executing this diagnostic. Development only. No detector
training, model selection, threshold retuning, deployment or frozen evaluation is authorized.

## Questions

1. Do the three fixed FAMILY-002 encoders retain benign environment identity on captures
   absent from their fitting data, at mean balanced accuracy >= 0.90?
2. Does numerical-only aggregate input reduce that signal relative to full categorical
   aggregate input? This is a sensitivity comparison, not proof of detector quality.
3. Does train-fold-only numeric transformation materially change the origin diagnostic?
4. Can padding/port-missingness indicators alone identify the environment?

## Admission and fixed representations

Bind the verified preparation manifest and completed FAMILY-002 report. Verify every
numeric encoder artifact before loading, load with `allow_pickle=False`, freeze/evaluate
the encoders, and never fit them on origin-diagnostic data. Verify raw capture hashes and
prepared bytes before and after the run, and execute from a clean committed checkout.

Use only benign records from hp4, hp5, and CTU-IoT-Malware-Capture-20-1. After the shared
full-input deduplication these contribute 181, 181 and 30 records (392 total). Reconstruct
FAMILY-002 fitting partitions and reject any overlap in event identity or encoded inputs.
All three captures are absent from encoder fitting. This controls attack-label prevalence
and seen-encoder rows; it does not turn three captures into broad deployment evidence.

Compare eight fixed views: portable aggregate (24), its numerical core (first 9), packet
sequence values plus explicit mask (100), sequence-plus-aggregate input (124), mask plus
port-missingness indicators (21), and each of the three frozen fusion embeddings (48).
No separate connection-state tensor is attributed to a fusion encoder.

Continuous dimensions are aggregate's first nine, sequence size/IAT channels (indices
0 and 1 per packet), and all learned embedding dimensions. Direction/position/mask and
categorical aggregate indicators retain their original geometry. Compare these four
transformations, fitted exclusively to each probe's training fold:

- standard: mean/std, replacing scales below 1e-9 with 1;
- robust: median/IQR, replacing scales below 1e-9 with 1;
- clip_robust: clip to train 1st/99th percentiles, then median/IQR;
- quantile_normal: sklearn QuantileTransformer, up to 100 train quantiles, normal output,
  no subsampling, fixed seed. No transformation of declared categorical/binary columns.

## Probe isolation and interpretation

Use all 392 admitted records without resampling the class distribution. For each view,
group identical float64 feature vectors; identical vectors with different origin labels
are retained as unavoidable ambiguity, not assigned a convenient origin. Use five-fold
StratifiedGroupKFold with shuffle and seed 20260902. Every fold must contain all three
origin classes in both train and test; groups must be disjoint. If a view cannot satisfy
this fixed split, record it as ineligible rather than changing folds or manufacturing a
score. Use the same folds across the four transformations of a view, and reject any
additional train/test aliasing introduced by transformation. Report view-specific groups,
duplicate/ambiguous groups and fold source counts/digests. Different views may require
different grouped folds, so their scores are not an exact paired statistical comparison.

Probe: sklearn LogisticRegression(C=1, class_weight='balanced', solver='lbfgs',
max_iter=3000, random_state=20260902). Convergence warnings invalidate that fold and
remain visible. Report all outcomes, per-fold confusion and per-source recall, balanced
accuracy mean/std, macro F1, and the fixed >=0.90 origin warning. A score below this cutoff
is not proof of invariance: a linear probe, small samples and within-capture correlation
limit inference. No detector accuracy or unknown-recall result is implied.

## Retention and costs

Record actual execution commit, exact configuration, input/source/artifact hashes, seeds,
fold digests, dependency versions, feature-building wall time, per-fold probe fitting wall
time, sampled process RSS and numeric-only local probe/transform artifacts with checksums.
Measure transform-plus-probe prediction latency on batch sizes 1 and 128, using fixed-seed
uniform test-fold sampling (replacement only when needed), 10 warmups and 100 timed calls.
This excludes encoder/feature generation and is explicitly origin-probe cost, not NIDS
throughput. Retain coefficients/intercepts/classes and all transform parameters as numeric
NPZ arrays; never commit unreviewed weights, row-level features, IDs or predictions.

Write an aggregate completion report only after every declared view is accounted for and
the final clean-code/data/artifact checks pass. Ineligible views/folds are explicit negative
diagnostic coverage, not pass results. Preserve failures and partial attempts without
overwriting old evidence. Historical ORIGIN-001 remains scientifically unvalidated.
