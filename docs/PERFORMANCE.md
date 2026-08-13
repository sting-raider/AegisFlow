# Runtime performance

The numbers in this document are measured evidence, not deployment capacity promises.
They use repeated deterministic metadata-only demo flows and the checksum-verified smoke
bundle. They do not measure detection accuracy or represent an enterprise traffic mix.

## Exact detector profile

`scripts/benchmark.py` runs the same `DetectionEngine` and `HybridPredictor` used by the
Redis worker. The 2026-08-09 Windows run processed the same 2,000-flow burst once with
single-row inference and once with batches of 64. Queue capacity was 2,000, so neither
run dropped an event.

| Measure | Single-row baseline | Batch 64 |
|---|---:|---:|
| Throughput | 153.50 flows/s | 3,496.81 flows/s |
| Throughput change | 1.00x | 22.78x |
| Inference p50 | 6.00 ms | 12.32 ms per batch |
| Inference p95 | 7.86 ms | 22.82 ms per batch |
| Queue-inclusive processing p50 | 6,403.00 ms | 283.67 ms |
| Dropped events | 0 | 0 |

The baseline profile attributed 66.3% of observed stage time to single-row Isolation
Forest calls and 19.0% to classifier inference. With batching, Isolation Forest fell from
4.238 to 0.093 ms per processed flow. Serialization then represented 17.1% and empirical
calibration/open-set computation 21.4% of observed batch-stage time. The full stage table,
CPU, memory, queue, and machine evidence is stored in
[`runtime-batching-2026-08-09.json`](benchmarks/runtime-batching-2026-08-09.json).

The processing latency above is intentionally a burst-drain measurement: all 2,000
events enter a bounded queue immediately. It is not steady-state network latency.

## Sustained acceptance harness

`scripts/benchmark_sustained.py` paces metadata-only flows through the local Compose
Redis-to-PostgreSQL path and samples both consumer groups throughout ingress and drain.
It fails closed unless the requested input rate is maintained, every published flow and
detection is durable, queue depth and second-half growth stay within explicit budgets,
durable P95 latency stays within its budget, and both queues return to zero pending plus
lag. Reports contain aggregate counts, latencies, queue/resource samples, the configured
budgets, and a machine-readable verdict; they contain no packet payloads or endpoint
identities. Redis and PostgreSQL URLs are restricted to localhost or service names in the
AegisFlow Compose network.

The harness is an acceptance instrument, not evidence by itself. A rate is supportable
only after a committed report records a passing verdict for the required duration and the
failure/recovery scenarios have been exercised.

### Ten-minute 50 flows/s result

The 2026-08-13 local Windows/Docker Desktop run first produced a valid NO-GO. Incident
membership was stored as a growing JSON alert-ID array; one row reached 17,922 IDs and
about 717 KiB, so every alert rewrote an increasingly large row. Docker storage also
filled during the run, causing Redis's RDB safety to stop writes visibly. The published
30,000 messages were preserved and later reached exactly 30,000 flows and detections with
zero duplicate flow IDs, but the original drain-window verdict remains a failure.

Membership is now normalized in `incident_alerts`, grouping uses a compact aggregate
context with only the two recent risk/severity values, and parent-before-membership flush
order is regression-tested. Local Compose uses one durable Redis mechanism (AOF) and
disables redundant automatic RDB snapshots; target deployments retain their own managed
backup policy. Repeating the identical predeclared workload then passed:

| Measure | Before normalization | After normalization |
|---|---:|---:|
| Published / durable flows / durable detections | 30,000 / 20,611 / 20,611 at timeout | 30,000 / 30,000 / 30,000 |
| Achieved input rate | 50.0000 flows/s | 49.9999 flows/s |
| End-to-end durable rate | 38.45 flows/s | 49.89 flows/s |
| Durable P95 latency | 322.51 s | 2.002 s |
| Maximum detection depth | 12,205 | 175 |
| Second-half detection growth | 28.131/s | 0.002/s |
| Final detection depth | 9,389 | 0 |
| Drain time | Timed out at 180.25 s | 1.35 s |
| Verdict | NO-GO | Pass |

Exact reports are
[`sustained-compose-windows-2026-08-13-50fps-10m.json`](benchmarks/sustained-compose-windows-2026-08-13-50fps-10m.json)
and
[`sustained-compose-windows-2026-08-13-50fps-10m-postfix.json`](benchmarks/sustained-compose-windows-2026-08-13-50fps-10m-postfix.json).
The host-memory samples include an unrelated roughly 5 GiB process that ran intermittently;
the passing result is therefore useful contended single-host evidence, not a clean-host or
production capacity promise.

The subsequent 30-minute run at the same 50 flows/s is a NO-GO despite exact eventual
conservation. It published and durably stored 90,000 flows/detections and returned both
queues to zero, but P95 durable latency reached 73.03 seconds, detection depth peaked at
11,475, and the second-half detection slope was +2.538 messages/s. Under the same
intermittent host contention, the API process was killed once without a Docker OOM flag;
`restart: unless-stopped` brought it back and the consumer reclaimed and drained all work.
The exact report is
[`sustained-compose-windows-2026-08-13-50fps-30m.json`](benchmarks/sustained-compose-windows-2026-08-13-50fps-30m.json).

The supported evidence boundary on this host is therefore narrow: 50 flows/s passes for
10 minutes but is not sustainable for 30 minutes under the declared 5-second latency and
10,000-depth budgets. Rate-ladder, lower-rate 30-minute, and clean-host capacity evidence
remain open. Eventual drain after an unplanned restart is recovery evidence, not a
capacity pass.

## Multi-worker persistence recovery

`make multiworker-acceptance` starts an acceptance-only second API replica and runs a
paced, metadata-only local workload. It requires both replicas to durably persist work,
stops the extra replica with SIGKILL while Redis shows it owns pending messages, waits for
the primary to reclaim the abandoned batch after the configured idle boundary, restarts
the replica, and fails unless exact database conservation and zero final queue depth hold.

The retained 120-second run at 50 flows/s passed: 6,000/6,000 flows and detections were
durable; the killed replica owned 25 pending messages; the primary reclaimed them; the
initial, primary, and restarted worker phases logged 50, 3,150, and 2,800 durable writes;
and both queues ended at zero. P95 latency was 1.504 seconds. The workload report contains
all 6,000 latency observations, including the late reclaimed batch. Exact evidence is
[`multiworker-compose-windows-2026-08-13.json`](acceptance/multiworker-compose-windows-2026-08-13.json)
and
[`multiworker-recovery-workload-compose-windows-2026-08-13.json`](benchmarks/multiworker-recovery-workload-compose-windows-2026-08-13.json).

The drill proves local shared-consumer partitioning, acknowledgement-after-durability,
abandoned-work recovery, restart participation, and final idempotent conservation. It is
not a multi-host or linear-scaling capacity claim.

## Redis-to-PostgreSQL pipeline

`scripts/benchmark_pipeline.py` is restricted to localhost and the AegisFlow Compose
network. It publishes synthetic flow metadata through Redis, waits for exact hybrid
detection and durable PostgreSQL persistence, and requires both consumer groups to end
with zero pending and zero lag.

The first 2,000-flow run exposed the database boundary: single-row transactions and
repeated full-incident reconstruction timed out after 150 seconds with 1,828 flows and
detections durable. The detector had already drained its input. After bounded 64-row
transactions and a transaction-local incident-context cache, the identical gate completed:

| Measure | Batched pipeline result |
|---|---:|
| Persisted flows/detections | 2,000 / 2,000 |
| End-to-end duration | 25.39 s |
| End-to-end throughput | 78.78 flows/s |
| Batched Redis ingress | 21,260.41 flows/s |
| Detector inference p50 / p95 / p99 | 10.18 / 13.22 / 17.93 ms |
| Detector processing p50 / p95 / p99 | 12.56 / 15.86 / 20.64 ms |
| Final flow queue pending / lag | 0 / 0 |
| Final detection queue pending / lag | 0 / 0 |

That is at least 6.46 times the incomplete baseline persistence rate, but PostgreSQL and
incident persistence remain the end-to-end limiter. The exact report is
[`pipeline-compose-2026-08-09.json`](benchmarks/pipeline-compose-2026-08-09.json).

A two-detector Compose smoke then sent 1,000 new flows through the shared Redis consumer
group. Both replicas processed eight batches and both queues drained to zero. This proves
partitioned horizontal consumption and recovery mechanics, not linear scaling: database
persistence dominated that run, and its accumulated benchmark history made it unsuitable
for a capacity comparison.

## Runtime controls and failure semantics

- `AEGISFLOW_DETECTOR_BATCH_SIZE` defaults to 64 and is bounded to 512.
- `AEGISFLOW_DETECTOR_BATCH_WAIT_MS` defaults to 250 ms and is bounded to 5 seconds.
- `AEGISFLOW_PERSISTENCE_BATCH_SIZE` defaults to 64 and is bounded to 256.
- Detection outputs use one atomic Redis pipeline per batch; flow acknowledgements use one
  multi-ID command only after every output is published.
- PostgreSQL commits a persistence batch atomically. Drift evidence is still durable before
  Redis acknowledgement.
- Malformed Redis JSON and schema-invalid or feature-invalid rows are hash-only quarantined
  without poisoning valid rows. Model-wide inference or database failures leave the batch
  pending for recovery.
- Multiple detector containers share the `detectors` consumer group. Redis partitions entries;
  deterministic detection IDs and database uniqueness keep replay idempotent.

## Reproduction

Local model/serialization profile:

```text
make benchmark
```

End-to-end local Compose profile, after the stack is healthy:

```text
docker compose -f compose.yml -f compose.demo.yml run --rm --no-deps api \
  python -m scripts.benchmark_pipeline --total 2000 --timeout-seconds 150 \
  --publish-batch-size 64
```

Ten-minute paced durable-path run (defaults shown):

```text
make benchmark-sustained SUSTAINED_DURATION=600 SUSTAINED_RATE=50 \
  SUSTAINED_OUTPUT=sustained-compose-local.json
```

Multi-worker persistence recovery:

```text
make multiworker-acceptance
```

Use explicit filenames for retained evidence. The command starts only PostgreSQL, Redis,
API persistence, and the detector; stop them afterward with `make demo-stop` when they are
no longer needed. A nonzero exit is an acceptance failure even when a JSON report was
written.

Two detector replicas:

```text
docker compose -f compose.yml -f compose.demo.yml up -d --scale detector=2 detector
```

Repeat measurements on representative hardware and traffic before choosing replica,
batch, stream, database, or alerting thresholds. Redis/PostgreSQL server tracing, sustained
multi-hour replay, multi-host orchestration, and larger production-like incident mixes
remain required before an organizational capacity claim.
