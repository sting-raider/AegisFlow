# Capacity planning

Capacity is valid only for an exact hardware, deployment, traffic mix, duration, model,
configuration, and failure envelope. Do not convert the repository's synthetic numbers
into a site-wide promise.

## Inputs to measure

Record expected average and peak new flows per second, protocol/host cardinality, alert
rate, incident fan-out, burst duration, replay catch-up requirements, retention volume,
analyst/API/WebSocket concurrency, model batch cost, and database/Redis latency. Include
malformed/error rates without storing packet payloads.

## Acceptance ladder

1. Establish an idle baseline and resource headroom.
2. Run a short burst below the expected rate.
3. Run 10-minute paced points to locate obvious queue/database limits.
4. Predeclare and run 30-minute or longer points below and above the expected rate.
5. Repeat with replica loss, Redis/PostgreSQL interruption, stale work reclaim, API
   rollout, and representative incident correlation.
6. Revalidate after any model, schema, batch, retention, database, or infrastructure
   change.

Use `make benchmark-sustained` with explicit duration, rate, and retained output. A pass
requires at least 98% of requested ingress, exact published/flow/detection conservation,
bounded maximum depth, no positive second-half growth beyond tolerance, P95 durable
latency within budget, and zero final lag/pending. Eventual drain cannot repair a capacity
failure.

## Current boundary

On the recorded contended Windows/Docker host, 50 flows/s passes for 10 minutes but fails
at 30 minutes on latency, queue depth, and growth despite eventual exact conservation.
Therefore 50 flows/s is not a supported sustained rate. PostgreSQL incident persistence
is the observed pipeline boundary. See [`PERFORMANCE.md`](PERFORMANCE.md) for exact
artifacts and limitations.

Keep CPU and memory below the organization's failover headroom, size Redis retention for
the maximum validated outage, alert on queue utilization/growth and database latency, and
scale only after the complete durable path—not publisher or inference alone—passes.
