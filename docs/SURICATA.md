# Suricata integration

The optional profiles pin `jasonish/suricata:8.0.6`. Replay is bounded to an explicitly
mounted PCAP, has no network, and uses a read-only root filesystem. It runs as root
with every capability dropped except `DAC_OVERRIDE`. That one capability
capability is necessary because the pinned image makes its configuration mode `0600`
and fresh bind-mounted output directories may be root-owned. Live configuration
requires an explicit Linux interface and never uses `privileged: true`.

```bash
make suricata-replay PCAP=/absolute/path/capture.pcap
```

`packages/detection/suricata.py` incrementally accepts JSON lines up to 1 MiB, retains
partial lines until complete, and emits visible processing errors for malformed input.
It parses alert, anomaly, flow, DNS, TLS, and HTTP records; normalizes severity;
deduplicates through a bounded LRU; and exposes reader health counters. Only an
allow-list is retained. DNS names, TLS SNI/subject/issuer, and HTTP hostnames are
SHA-256 hashed, and packet payload fields are never copied.

Correlation prefers the EVE/community flow ID, then a direction-independent endpoint
tuple plus a three-second time tolerance. For multiple correlated alerts, the sensor
attaches the strongest severity to the flow envelope.

The bundled 252-byte PCAP and safe local rule were replayed through Suricata 8.0.6 with
networking disabled and only `DAC_OVERRIDE`. Suricata read three packets and emitted one alert, one DNS event,
and two flow events. AegisFlow parsed all four with zero errors and correlated the
alert to one of two Scapy flows. The six-record EVE fixture covers every supported type
when Docker or Suricata is unavailable.

Rule snapshots must be reviewed and checksum-pinned. The updater accepts HTTPS only,
limits downloads to 64 MiB, verifies a lowercase SHA-256 digest, confines writes to
`configs/suricata/rules`, and atomically replaces the destination:

```bash
uv run python scripts/update_suricata_rules.py \
  --url https://rules.example.invalid/community.rules \
  --sha256 <reviewed-lowercase-sha256>
```

Demo mode uses a deterministic fixture signature and does not require Suricata.
Test every new ruleset through offline replay before promotion. Rule updates are never
automatic and detections never trigger blocking.
