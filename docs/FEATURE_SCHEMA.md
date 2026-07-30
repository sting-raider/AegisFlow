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
