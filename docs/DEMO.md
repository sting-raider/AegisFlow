# Offline demonstration

`make demo` trains the deterministic fixture bundle, starts PostgreSQL, Redis, API,
detector, and dashboard, then runs the demo sensor. Wait a few seconds for the
detection and API consumers.

Expected observations:

- ordinary web/DNS flows remain benign;
- the fixture signature creates a known-attack result;
- scan/burst patterns create known or review alerts depending on the classifier;
- the novel outbound transfer creates a suspicious-unknown result;
- feedback adds an immutable record;
- model health shows schema/version and smoke-data limitations.

The validated fixture run persists 6 flows, produces 5 alerts across known and
unknown-behaviour paths, and groups them into 1 source-host incident. Exact risk
values are deterministic for the bundled bundle.

Stop with `make demo-stop`. The fixtures contain no exploit payloads.
