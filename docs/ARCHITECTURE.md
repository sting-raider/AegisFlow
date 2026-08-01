# Architecture

```mermaid
flowchart LR
    P["Demo / PCAP / explicit live interface"] --> S["Sensor adapters"]
    E["Suricata EVE or fixture"] --> S
    S -->|FlowEvent v1| Q1["Redis stream\nor bounded in-process queue"]
    Q1 --> D["Detector\nknown + anomaly + fusion"]
    D -->|DetectionResult v1| Q2["Detection stream"]
    Q2 --> A["API / incident core"]
    A --> DB["PostgreSQL\nSQLite demo fallback"]
    A -->|REST + WebSocket| UI["React dashboard"]
    D --> H["Drift + model health"]
    A --> X["Deterministic explanation\noptional sanitized provider"]
```

Runtime processes remain coarse: `sensor`, `detector`, `api`, and `dashboard`.
PostgreSQL, Redis, and optional Suricata are infrastructure. Training is an offline
CLI. The one-process demo composes the same adapters, contracts, feature pipeline,
detection engine, and repository used by distributed mode, so it is useful in CI
without pretending to validate infrastructure recovery.

Data contracts reject invalid input at boundaries. Events are idempotent by UUID.
Feature order and transformations are versioned; model bundles carry checksums,
thresholds, labels, metrics, and provenance. Payload storage and active response are
out of scope.

Both Redis hops use consumer groups with at-least-once delivery. A consumer acknowledges
only after publishing the next-stage event or committing the database transaction. Stale
pending entries are reclaimed after 30 seconds by default. Malformed events are first
written to the dead-letter stream; database/Redis outages remain visible as pending or
lagging queue work and retry metrics rather than being mislabeled benign.
