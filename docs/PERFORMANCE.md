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

Two detector replicas:

```text
docker compose -f compose.yml -f compose.demo.yml up -d --scale detector=2 detector
```

Repeat measurements on representative hardware and traffic before choosing replica,
batch, stream, database, or alerting thresholds. Redis/PostgreSQL server tracing, sustained
multi-hour replay, multi-host orchestration, and larger production-like incident mixes
remain required before an organizational capacity claim.
