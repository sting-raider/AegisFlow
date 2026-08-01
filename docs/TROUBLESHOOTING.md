# Troubleshooting

- **Model unavailable:** run `make train-smoke`; verify all bundle checksums and the
  production pointer. Never bypass integrity validation.
- **No alerts:** check Redis health, detector logs, `aegisflow:dead-letter`, API
  readiness, and whether the sensor completed.
- **Queue lag or pending work:** inspect `/api/v1/system/status`, `queue_lag` and
  `queue_pending` in `/metrics`, then check detector/API logs and Redis group state.
  Stale entries are reclaimed after `AEGISFLOW_PENDING_IDLE_MS` (30 seconds by default);
  do not delete a consumer group to clear an outage.
- **Dashboard reconnecting:** open `/health/ready`, verify the `/api` and WebSocket
  reverse proxy, then inspect browser network errors.
- **PostgreSQL migration failure:** confirm the database password/URL and run
  `alembic current` followed by `alembic upgrade head`.
- **PostgreSQL interruption:** restore database health and leave the API running. Failed
  transactions remain unacknowledged and are retried through pending-entry recovery;
  verify `database_errors_total` and that queue pending returns to zero.
- **Live capture rejected:** use Linux, specify an authorized interface, and follow
  `LIVE_CAPTURE.md`; demo/PCAP mode remains available.
- **Corrupt artifact:** restore the last valid version and production pointer. Do not
  load the file manually.
