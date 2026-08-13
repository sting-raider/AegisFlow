# Restore drill

Status: **PASS for disposable local PostgreSQL mechanics**

The acceptance harness creates an isolated Compose project named
`aegisflow-restore-acceptance`. It refuses to run if any container or volume with that
project label already exists, so it cannot silently replace a developer database.

Run it from a clean host with Docker Compose:

```bash
make restore-acceptance RESTORE_OUTPUT=docs/acceptance/restore-local.json
```

The harness builds the API image, starts project-scoped PostgreSQL and Redis volumes,
runs every migration, and seeds deterministic synthetic metadata. It then records every
table count and a SHA-256 digest of sorted primary identities, creates a temporary
`pg_dump -Fc --no-owner --no-acl`, force-drops only the isolated database, restores into
a clean database with `pg_restore --exit-on-error`, reruns migrations, and compares the
complete snapshots. A real API process must subsequently report ready and return the
expected flow, alert, and incident counts. The dump and isolated volumes are removed even
when the drill fails.

The retained CI result from 2026-08-13 passed all controls:

- 15 tables matched before and after, including migration state;
- 6 flows, 6 detections, 5 alerts, 1 incident, 5 incident memberships, 1 analyst-feedback
  row, and 5 audit rows were preserved;
- the 39,687-byte custom-format dump had SHA-256
  `aa9bc6b4bae39aab17cefc5d372b4d019c556a256495dc9b3f275d975df6822f`;
- destructive restore took 0.50 seconds and the complete isolated drill took 102.00
  seconds on the GitHub-hosted runner;
- the API smoke passed, cleanup passed, no backup was retained, no developer volume was
  touched, no packet payload was stored, and no external target was contacted.

The machine-readable result is
[`acceptance/restore-ci-2026-08-13.json`](acceptance/restore-ci-2026-08-13.json), produced
by [GitHub Actions run 31689272384](https://github.com/sting-raider/AegisFlow/actions/runs/31689272384).

This does not validate a managed backup product, encryption, off-host durability,
retention, access control, recovery point objective (RPO), or recovery time objective
(RTO). Those remain deployment-owner acceptance items.
