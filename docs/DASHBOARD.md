# Dashboard

The React dashboard is a network-intelligence brief for an analyst deciding what changed
and what needs attention. Its light-first editorial system uses mineral paper, deep ink,
patina teal, signal vermilion, and evidence ochre. Georgia carries the editorial display
hierarchy, Segoe UI/Aptos carries working copy, and Cascadia Mono carries measurements.
The dark live-signal edition ribbon is the one signature element; the surrounding cards
stay quiet, softly rounded, and deliberately asymmetric. Automatic dark mode retains the
same hierarchy instead of becoming a separate product skin.

Views cover overview, live alerts/evidence/feedback, incidents, flow filtering, hosts,
models/drift, and system health. Navigation markers describe each view's real job
(`Brief`, `Triage`, `Cases`, `Traffic`, `Entities`, `Detection`, and `Operations`) rather
than presenting decorative numbering. Demo data is always disclosed. Loading, empty,
error, keyboard focus, responsive layout, automatic dark mode, and reduced motion are
explicit states.

Accessibility is part of the browser acceptance gate. The overview, every analyst view,
and the evidence dialog pass Axe without violations in Chromium. The same test exercises
the skip link, current-page semantics, modal labelling and focus, keyboard dismissal, and
the analyst feedback path. Current 1440-pixel and 390-pixel rendered screenshots live in
`docs/images/`; visual QA also covers the automatic dark palette.

The API client can receive a short-lived access token through `setAccessToken`; it keeps
that token in memory only and sends it as a bearer credential for REST and as the bounded
WebSocket subprotocol documented in `AUTHENTICATION.md`. Demo mode needs no credential.
A production deployment should place the dashboard behind an identity-aware proxy or add
an organization-specific OIDC authorization-code/PKCE shell; this repository does not
persist browser tokens or fabricate a generic login session.

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
ledger, and model health errors. System health reports backend throughput, explicit
drops, worker latency, Suricata/signature state, queue capacity pressure, retention, and
recent health events; an unavailable value remains `not reported` rather than fabricated.
It also reports the active identity mode, model-governance switch, loaded runtime model,
and separate operational/audit retention windows.

Incident cards open a detail drawer backed by the incident detail API. It shows alert
count, acknowledgement count, maximum risk, escalation count, explainable grouping
reasons, mapped attack stages, endpoint route, chronological risk timeline, analyst
status controls, and the separately fetched advisory explanation. AI and deterministic
fallback text are labelled distinctly. Analyst notes are durable audit events and are
kept out of detection, retraining, and optional explanation context.
