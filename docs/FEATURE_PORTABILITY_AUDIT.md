# Feature portability audit

Date: 2026-08-10

Audited schema: `packages.features.registry` v1.0.0 (18 ordered floats)

## Availability matrix

| Feature group | Runtime flow | CIC 2017/2018 | UNSW-NB15 | NFStream CSV | Portability finding |
|---|---:|---:|---:|---:|---|
| Duration, directional packets/bytes, totals | Native | Native | Native | Native | Broadly portable; heavy-tailed and needs train-fit transformation/clipping |
| Packet and byte rates | Native | Native or derived | Packet native; bytes reconstructed from directional load | Native or derived | Exporter/derivation semantics may differ |
| Packet length mean | Native | Native | Directionally packet-weighted reconstruction | Native | Comparable intent, non-identical source semantics |
| Packet length standard deviation | Native | Native | Missing→0 | Native | Zero substitution leaks source and loses missingness |
| IAT mean | Native | Native | Directionally packet-weighted reconstruction | Native | Comparable intent, non-identical source semantics |
| IAT standard deviation | Native | Native | Missing→0 | Native | Zero substitution leaks source and loses missingness |
| TCP SYN/RST counts and SYN/ACK ratio | Native | Native | Missing→0 | Native | Zero substitution leaks source and protocol applicability |
| Destination port | Native | Native | Sometimes missing→0 | Native | Continuous encoding is semantically invalid; missing value leaks source |
| Forward/reverse byte ratio | Derived | Derived | Derived | Derived | Unbounded and unstable near zero reverse bytes |
| Protocol/service category | Available in contract | Not adapted | Available in source but not adapted | Available in source but not adapted | Useful portable signal is currently discarded |

“Native” means the current adapter/contract exposes a value; it does not assert identical
exporter semantics. Missing values shown as `Missing→0` are indistinguishable from genuine
zero in the current vector.

## Risks requiring closure

1. Dataset-origin shortcuts: missing-field zero patterns, port zero, and exporter-specific
   rate/statistic semantics can identify the corpus instead of behavior.
2. Scale instability: standard scaling of raw long-tailed counts and ratios gives extreme
   environments disproportionate influence.
3. Invalid categorical geometry: numeric port distances imply that 443 is “closer” to 445
   than to 80, which is not a defensible service representation.
4. Protocol ambiguity: TCP-only counters have no explicit applicability indicator.
5. Temporal parity gap: runtime context exists, but dataset evaluation cannot reconstruct
   the same bounded, ordered state transitions.

## Required successor evidence

- Schema A: universal flow-only fields, log/robust or quantile transforms fitted on the
  training fold, training-derived clipping, missing indicators, protocol one-hot/buckets,
  and semantic service/port buckets.
- Schema B: Schema A plus bounded trailing-window counts/rates/fan-out with explicit key,
  window, expiry, cold-start, ordering, and reset semantics shared by replay and runtime.
- Exact raw→vector parity tests for every adapter and runtime flow path.
- An origin-classifier diagnostic evaluated on disjoint source groups. High corpus-origin
  accuracy blocks model selection until ablation identifies and removes shortcut features.
- Per-feature missingness, clipping rate, drift, and ablation results on fresh development
  data. Frozen reports remain excluded from every one of these checks.

## First empirical result

The 2026-08-10 two-source diagnostic sampled 50,000 unique Schema A rows each from fresh
HIKARI-2021 and CSE-CIC-IDS2018 development captures. Full Schema A origin balanced
accuracy was 1.000; the three strongest coefficients were protocol categories because
HIKARI's aggregate CSV has no protocol field. Full Schema A is blocked. Removing protocol,
port, service, and port-missing categories reduced balanced accuracy to 0.69772. This
identifies a concrete shortcut surface, but it does not close the audit: the evidence has
only two environments and lacks capture-disjoint groups.
