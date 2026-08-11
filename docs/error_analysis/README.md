# Development error analysis

This directory contains sanitized aggregate evidence derived only from the fresh
development pool. It never stores endpoints, row identifiers, individual scores, or
per-row outputs. Categories with fewer than five rows are suppressed.

## Current finding

`DEV-ERR-001` reproduces the fixed held-family hybrid protocol and groups errors by
protocol, service, duration, packet count, direction, host behavior, missingness/state,
and score disagreement. The evidence identifies four recurring problems:

- Reversing the HUE and Echo benign fit/calibration roles changes DDoS direct detection
  from effectively zero to 99.15%, and port-scan detection-or-review from 4.10% to 77.05%.
  The current threshold is therefore device-calibration-sensitive rather than portable.
- Zero/one-packet and zero-duration command-and-control rows are almost entirely missed.
  The flow contract carries too little observable behavior for the current models to
  separate them robustly.
- Late-event buckets show elevated missed-attack rates for DDoS and port scan, indicating
  that the bounded temporal signal cannot rescue materially reordered capture behavior.
- Direct benign errors concentrate in small high-packet, TCP/web buckets. Removing port
  context does not solve this and increases worst benign FPR to 5.25%.

The next defensible experiment is a cross-fitted environment-aware calibration ensemble:
use both approved benign device captures without treating attack traffic as benign or
using any frozen evidence. If that remains below the held-family objectives, the current
flow-level representation has strong evidence for a scientific NO-GO.

Exact machine-readable and human-readable evidence is in
`held-family-root-cause-v1.json` and `held-family-root-cause-v1.md`.
