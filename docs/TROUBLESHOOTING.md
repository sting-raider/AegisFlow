# Troubleshooting

- **Model unavailable:** run `make train-smoke`; verify all bundle checksums and the
  production pointer. Never bypass integrity validation.
- **No alerts:** check Redis health, detector logs, `aegisflow:dead-letter`, API
  readiness, and whether the sensor completed.
- **Dashboard reconnecting:** open `/health/ready`, verify the `/api` and WebSocket
  reverse proxy, then inspect browser network errors.
- **PostgreSQL migration failure:** confirm the database password/URL and run
  `alembic current` followed by `alembic upgrade head`.
- **Live capture rejected:** use Linux, specify an authorized interface, and follow
  `LIVE_CAPTURE.md`; demo/PCAP mode remains available.
- **Corrupt artifact:** restore the last valid version and production pointer. Do not
  load the file manually.
