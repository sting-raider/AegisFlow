# Live capture

Live mode always requires an explicit authorized interface. For a presentation on
Windows or Linux, start an isolated live ledger and the host NFStream sensor with:

```text
uv run python -m scripts.presentation_live --interface "Wi-Fi"
```

Replace `Wi-Fi` with the exact authorized interface name (`eth0` on many Linux hosts).
The launcher starts only the core Docker services, exposes Redis on loopback for the host
sensor, and does not run the demo sensor or seed synthetic records. It uses the separate
`aegisflow-live` Compose project so prior demo data cannot appear. Its ledger is
intentionally ephemeral: the launcher removes only that project's volumes before start
and after shutdown. Press Ctrl+C to stop the sensor and isolated stack. A separate
terminal can cleanly stop it after an interruption:

```text
uv run python -m scripts.presentation_live --stop
```

The hardened Linux-container path remains available with:

```bash
make live INTERFACE=eth0
```

The Linux live profile uses NFStream 6.6.0 in a dedicated `sensor-live` image stage. The
container runs as UID/GID 10001, has a read-only filesystem, and receives only
`NET_RAW`. A file capability is applied only to that stage's Python interpreter;
ordinary API, detector, and demo images remain executable with `cap_drop: ALL`.
Promiscuous mode is disabled.

Verified evaluation paths:

```bash
# No network namespace and no capabilities are needed for bounded replay.
docker run --rm --network none --read-only --cap-drop ALL \
  -v "$PWD/tests/fixtures/demo.pcap:/captures/demo.pcap:ro" \
  --entrypoint python aegisflow-backend \
  scripts/evaluate_nfstream.py --pcap /captures/demo.pcap

# The built-in probe refuses non-loopback interfaces and emits only local UDP.
docker run --rm --network none --read-only \
  --security-opt no-new-privileges --cap-drop ALL --cap-add NET_RAW \
  --entrypoint python aegisflow-sensor-live \
  scripts/evaluate_nfstream.py --interface lo --loopback-probe
```

The bundled PCAP produces two canonical flows. The isolated Linux loopback probe
produces one completed flow as the non-root account. NFStream's PCAP path is verified on
Windows. Windows live capture requires Npcap at `C:\Windows\System32\Npcap` and remains
experimental until an authorized isolated interface probe is recorded. Missing interfaces,
missing native libraries, unsupported platforms, and invalid files fail visibly.

Do not monitor networks without authorization. Payload retention is disabled. Prefer
a SPAN/TAP interface and document local privacy/retention policy.
