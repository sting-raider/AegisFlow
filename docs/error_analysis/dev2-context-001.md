# DEV2-CONTEXT-001 error analysis

## Scope and outcome

`DEV2-CONTEXT-001` is a development-only paired ablation, not a production evaluation.
It used the pre-registered 6,195-row portable-core common-support cohort, nine
source/target choices, four context views, and two independent benign-site orientations.
All 36 models and 72 site evaluations completed from clean commit `8071496`; report
SHA-256 is `e5bc778271823a5b2bc30d60bb7aa125212fad58863a73e6c81dbeb921540909`.

The registered benefit rule fails. Causal context qualifies in one of six strata against
shuffled context and zero of six against no context; five strata against each control were
required, with all targets and site orientations represented. The result is therefore
NULL for detectable causal benefit here. No candidate is selected and no deployment or
frozen-test access follows.

## Observed failure pattern

- Capture 20: causal direct detection is lower than shuffled in both site orientations
  and lower than no context in both. Detection-or-review is also lower than no context by
  52.38 and 61.90 percentage points. The causal independent-benign FPR penalty reaches
  15.84 points against no context in the 5→4 orientation.
- Capture 34: causal direct detection is 26.94 and 28.31 points below shuffled context.
  Detection-or-review is lower than shuffled by 13.32 and 14.67 points and lower than no
  context by 77.82 and 37.07 points. One tiny direct advantage over no context has a
  positive interval, but the review endpoint and cross-control consistency fail.
- Capture 8: causal direct detection improves by roughly 33.3 points against both
  controls. Only the 5→4 comparison against shuffled also improves detection-or-review
  while reducing benign FPR, so just that stratum qualifies. Against no context, review
  is worse or tied and the 5→4 benign FPR penalty is 7.80 points.
- Across the 18 correlated site entries per view, causal context averages 12.79% direct
  attack detection, 39.34% detection-or-review, 5.72% independent-benign FPR, and 19.23%
  independent-benign review. These means describe this matrix; they are not independent
  population estimates.
- No context averages 83.09% detection-or-review but only 7.22% direct detection. That is
  mostly review escalation, not reliable direct attack recognition, so the high inclusive
  rate is not evidence that the context-free detector is production-ready.
- The deliberately future-leaking terminal view averages 71.43% direct detection and
  97.62% detection-or-review, but also 24.99% direct benign FPR and 62.66% benign review.
  It demonstrates how full-capture leakage can make attack results look impressive while
  destroying site specificity; it is permanently non-deployable.

Exact paired intervals and descriptive means are in
`docs/research-v2/registered-results/DEV2-CONTEXT-001.md`.

## Likely causes and limits

The 16 shipped temporal aggregates are highly capture- and site-specific. Completion
ordering is causal between merged flows, but `PcapAdapter` still coalesces an entire
canonical five-tuple, so within-flow packet chronology cannot be recovered. Sparse
capture-20 attack support (seven retained attacks), correlated source captures, fixed
60/10-second windows, and source-address aggregation further limit what this experiment
can distinguish. The result isolates the registered context treatment on common support;
it does not show that all temporal modelling is useless.

## Permitted follow-up

Do not tune windows, thresholds, row filters, or feature selection against this completed
report and call the result confirmatory. A follow-up needs a new development registration
and fresh evidence. Useful directions are event-time context from non-coalesced flow
exports, independently sourced benign sites, richer attack-environment support, and a
sequence/aggregate learner that preserves portable feature semantics. The frozen final
reports remain sealed until a later challenger is locked by evidence that does not use
them.
