# DEV2-CONTEXT-001 protocol — causal temporal-context ablation

Status: draft for registration. No execution has occurred under this protocol.
No model is selected, no candidate is locked, and frozen final evidence stays
sealed. This study uses development captures only.

## Research question

Does causal temporal context (16 Schema-B features computed from
prior-history-only at each flow's completion) add detectable value over
distribution-matched and context-free controls on identical rows?

## Timing contract

Prepared v2 rows carry no absolute timestamps, addresses, sensor identity, or
capture order: only `duration_ms` and relative `seq_iats_ms` survive
(`training/v2/prepare_sequences.py`, enforced by the `SequenceRecord` schema).
Sorting those rows cannot reconstruct flow-completion order or the pre-filter
observation history, so any context computed over prepared rows is non-causal
(future leakage) and invalid as a context ablation.

The causal rule: a flow's context may depend only on completions at or before
its own end. `PcapAdapter` merges each canonical five-tuple over the whole
capture, so the only observable runtime decision point for a flow is its last
packet. Replay order per scenario is therefore
`(timestamp_end, timestamp_start, event_id)`, computed ephemerally and never
persisted as clock time.

## Replay specification

- One fresh `TemporalFeatureState` (shipped 60 s / 10 s windows, 5 s skew)
  per scenario replay; state is never shared across scenarios or partitions.
- Observations use `FlowObservation.from_completed_flow` (completion
  instant); `TemporalFeatureState` itself is unmodified. Start-timestamped
  replay is rejected: on whole-capture-merged flows it trips late/too-late
  exclusion and silently discards most history.
- Every adapter flow enters the ephemeral history exactly once, including
  unmatched and ambiguous-label flows: the runtime sensor has no label
  oracle. Duplicate `event_id` within a replay fails closed.
- Only unambiguously labeled flows emit sidecar entries; context-only flows
  leave no persisted trace. Per-scenario accounting reports matched,
  unmatched, unlabeled, ambiguous, and non-TCP/UDP/ICMP counts.
- Sidecar payload per emitted row: `event_id`, `completion_index`,
  `prior_completions`, `coalesced_span_ms`, `cold_start`, `late_event`, and
  the 16-vector in `TEMPORAL_FEATURE_NAMES` order. No timestamps, addresses,
  sensor ids, or payloads are persisted. Sealed `SequenceRecord` rows and
  the `cba2329` preparation hashes are never modified; the sidecar joins by
  `event_id` at study runtime.

## Ablation views (identical rows, paired statistics)

1. `causal_context` — sidecar vectors.
2. `shuffled_context` — negative control: causal vectors permuted under seed
   within sensor-by-partition strata (marginals preserved, conditional
   information broken).
3. `no_context` — cold-start sentinel (`temporal_cold_start=1`, else 0).
4. `non_causal_reference` — vectors queried against full-capture terminal
   state; labeled non-deployable; quantifies the leakage being removed.

Portable, sequence, and aggregate inputs are byte-identical across views, so
deltas isolate context causality. The transfer matrix, budgets, seeds, and
four-verdict semantics follow the `DEV2-MISSINGNESS-001` precedent; exact
counts bind in the registration.

## Decision rule

Preregistered NULL: if causal minus shuffled and causal minus no-context
paired intervals cover zero with no consistent direction across targets and
site orientations, causal context adds nothing detectable here. Promotion is
blocked, no deployment claim follows, and follow-ups require new
registration, never post-hoc slicing. A NULL result does not prove context is
useless: within-flow merging, window choice, and cohort limits stay open.

## Declared limitations

- Within-flow non-causality: end-ordered replay cannot un-merge packets from
  whole-capture five-tuple coalescing; report the fraction of labeled rows
  whose span exceeds the 60 s window.
- Tiny effective held-family support and correlated captures, as in prior v2
  studies; paired common-support comparisons only.
- `false_alerts_per_hour` is unavailable without prepared chronological
  timestamps; report `false_alerts_per_10000_benign` instead.
- Late/too-late rates under completion ordering are reported, not hidden;
  they measure the merge artifact, not sensor quality.
