# Feature schema

`packages/features/registry.py` is the single ordered registry. Every feature records
its source, dtype, missing policy, range, transformation, training/inference
availability, introduction version, and privacy class.

Raw IP addresses, event IDs, timestamps, and sensor IDs are excluded. The primary
vector contains durations, packet/byte counts and rates, size/IAT summaries, TCP
counts, destination port, byte/SYN ratios, and totals. Context-window signals such
as destination-port fan-out enter risk fusion separately so their state and expiry
remain explainable.

All missing required values reject the event. Infinity and out-of-range values reject
the vector. The scaler is fitted once on the training fold and serialized; the sensor
never fits preprocessing.

Flow identity and feature direction are intentionally separate. `community_flow_id` is
the unordered standard Community ID v1 correlation key. `src`/`dst`, forward/reverse
counters, first-packet directions, and `destination_port` follow the best available
initiator/responder evidence: TCP SYN without ACK, an unambiguous ephemeral-client to
well-known-service pair, NFStream first-packet semantics, or complete correlated
Suricata `toserver`/`toclient` metadata. The selected basis is recorded in
`protocol_metadata.direction_basis`.
