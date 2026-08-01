# Dashboard

The React dashboard uses a navigation-chart visual language: deep channel/slate
surfaces, sonar teal, signal coral, and warning amber. The live flowline is the one
signature element. Bahnschrift carries operational headings, Segoe UI body copy, and
Cascadia Mono data.

Views cover overview, live alerts/evidence/feedback, incidents, flow filtering, hosts,
models/drift, and system health. Demo data is always disclosed. Loading, empty, error,
keyboard focus, responsive layout, and reduced motion are explicit states.

Overview derives real flow throughput over the loaded window, severity pressure,
known-versus-unknown counts, active incidents, protocol distribution, top source and
destination hosts, queue/sensor state, production model metadata, and recent drift.
The live alert ledger can pause/resume WebSocket updates and filter by endpoint, reason,
severity, or verdict. Its evidence drawer exposes source provenance, acknowledgement,
and feedback without changing the original detection.

Flow explorer filters by endpoint, protocol, and time, paginates the loaded records,
opens associated detection/signature/feature evidence, and exports explicitly selected
records through the default-anonymized API. Host detail derives risk, recent activity,
fan-out, protocol use, and alert history from stored flows and alerts. Model/drift shows
the production pointer, schema, validation metrics, observed score distribution, drift
ledger, and model health errors. System health reports only backend-provided values and
labels unavailable telemetry as `not reported` rather than fabricating it.

Incident cards open a detail drawer backed by the incident detail API. It shows alert
count, acknowledgement count, maximum risk, escalation count, explainable grouping
reasons, mapped attack stages, endpoint route, chronological risk timeline, analyst
status controls, and the separately fetched advisory explanation. AI and deterministic
fallback text are labelled distinctly. Analyst notes are durable audit events and are
kept out of detection, retraining, and optional explanation context.
