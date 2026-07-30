# Decision log

## D-001 — Clean-room rewrite

Use upstream as an architectural reference only. Its feature/inference parity and
packaging are unsafe to preserve, and the actual Apache-2.0 license conflicts with
the brief's MIT description. Alternative: fork and refactor. Rejected because it
would retain two UI generations, incomplete dependencies, and ambiguous contracts.

## D-002 — Distributed production profile, self-contained demo fallback

Use Redis Streams and PostgreSQL in Compose. The offline demo may use a bounded
in-process queue and SQLite while exercising the same domain logic. This keeps CI
and faculty demos reliable when Docker is missing, while integration tests validate
the infrastructure profile separately.

## D-003 — Scapy adapter before NFStream

Use a small deterministic Scapy flow aggregator for bundled PCAPs. NFStream remains
an optional adapter to evaluate in Linux containers. This avoids native-install
fragility and makes schema semantics testable. The live mode remains Linux-only and
explicit.

## D-004 — Conservative open-set baseline

Use calibrated supervised probabilities plus an Isolation Forest trained only on
benign smoke data. No anomaly is called a zero-day. Autoencoder work is optional
until the baseline is measurable.

## D-005 — Dashboard visual language

Audience: a SOC analyst or faculty reviewer. Job: understand why traffic was flagged
within one glance. Palette: `deep channel #0B1821`, `slate water #17313D`,
`chart fog #D9E3E8`, `signal coral #FF735C`, `sonar teal #53C7C2`, and
`warning amber #E9B44C`. Display/section type uses Bahnschrift Condensed, body uses
Segoe UI, and data uses Cascadia Mono. The signature element is a live “flowline”
strip that maps detections to packet-like marks. A generic neon-black cyber theme
was rejected; the revised navigation-chart language is specific to network flow,
keeps data legible, and spends visual boldness on one operational element.

## D-006 — Self-contained demo image

Bake the small checksum-verified smoke bundle into the backend demo image after
training. This avoids host bind-mount failures on Docker Desktop, makes offline
replay reproducible, and keeps the runtime filesystem read-only. A model promotion
therefore requires rebuilding the backend image. External production registries
remain valid only when they are immutable, access-controlled, and mounted read-only.

PostgreSQL and Redis are reachable only on the Compose network. Only the API and
dashboard bind loopback host ports, which avoids collisions and removes unnecessary
host exposure.
