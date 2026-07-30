# Live capture

Live mode is Linux-only and requires an explicit authorized interface:

```bash
make live INTERFACE=eth0
```

The current adapter fails closed after validating the OS/interface request because the
NFStream/native capture validation matrix has not yet passed. For deployment, run
Suricata with `CAP_NET_RAW` (and only capabilities proven necessary), ingest its EVE
flow/alert output, and keep application containers unprivileged. Never use a broad
`privileged: true` container.

Do not monitor networks without authorization. Payload retention is disabled. Prefer
a SPAN/TAP interface and document local privacy/retention policy.
