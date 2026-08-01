# Live capture

Live mode is Linux-only and requires an explicit authorized interface:

```bash
make live INTERFACE=eth0
```

The live profile uses NFStream 6.6.0 in a dedicated `sensor-live` image stage. The
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
produces one completed flow as the non-root account. NFStream's native engine does not
load on the supported Windows development host; use Scapy PCAP replay there. Missing
interfaces, missing native libraries, unsupported platforms, and invalid files fail
visibly.

Do not monitor networks without authorization. Payload retention is disabled. Prefer
a SPAN/TAP interface and document local privacy/retention policy.
