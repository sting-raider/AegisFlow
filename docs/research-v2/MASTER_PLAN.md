# Detector v2 master plan

Date started: 2026-08-22.

## Research question

Can packet-sequence representations, protocol/connection-state semantics,
domain-invariant representation learning, and explicitly approved target-site benign
calibration materially improve cross-environment and previously unseen-behaviour
detection while maintaining an operationally acceptable benign false-positive rate?

## Predeclared hypothesis

First-N-packet sequence semantics carry discriminative information that survives
environment change better than aggregate-flow statistics, because attack tooling
leaves characteristic early-packet size/direction/timing patterns (for example Mirai
Telnet handshakes, Torii DNS/beacon patterns) even when aggregate counters differ
between sites.

## Relationship to v1 evidence

The v1 negative result (`docs/FINAL_ACCEPTANCE_REPORT.md`, `docs/research/conclusion.md`)
stands unchanged. This phase never tunes against the four frozen v1 reports; their
published numbers are quoted only as motivation. All v2 evidence lives in
`docs/research-v2/` and `configs/research-v2/`.

## Absolute boundary

- The v1 frozen reports (UNSW official split, UNSW held-exploits, CSE chronological,
  UNSW-to-CSE) remain final-only evidence for the v1 smoke model. Their rows, labels,
  predictions, errors, distributions, or repeated evaluations must not feed v2
  development.
- v2 uses a new development pool (packet-sequence capable) and reserves a final
  environment before development experiments begin.
- A fail-closed verifier (`scripts/verify_research_v2.py`) binds the predeclared
  protocol, source hashes, and permitted use before any experiment result is accepted
  into the record.

## Predeclared development objectives (fixed before experiments)

- benign FPR <= 1% (target <= 0.5%) on every held-out environment;
- unseen-family direct suspicious_unknown recall >= 50% averaged over held families,
  with no family at exactly zero unless its observability tier is LOW for >90% of rows;
- unknown detection-or-review >= 80% mean over held families;
- known malicious recall >= 90% where observability is HIGH/MEDIUM;
- ECE <= 0.10 for the calibrated known-attack head;
- no catastrophic held-environment collapse (no environment with benign FPR > 5%);
- CPU single-flow inference latency <= 10 ms and batch throughput >= 500 flows/s on the
  recorded development host;
- worst-environment metrics are reported next to every mean; means alone never justify
  selection.

Failure of these objectives after honest execution yields Outcome B (material
improvement without full gates) or Outcome C (NO-GO), per the goal definition.

## Development pool (packet-sequence capable)

Eight official Stratosphere IoT-23 individual-scenario PCAPs from the official CTU host
(`mcfp.felk.cvut.cz`), processed through AegisFlow's own sensor adapters so training
shares the runtime feature contract:

| Scenario | Role | Family |
|---|---|---|
| CTU-IoT-Malware-Capture-34-1 | malware env | Linux.Mirai |
| CTU-IoT-Malware-Capture-8-1 | malware env | Linux.Hakai |
| CTU-IoT-Malware-Capture-42-1 | malware env | Linux.Torii |
| CTU-IoT-Malware-Capture-20-1 | malware env | Linux.Mirai (Trojan-labelled rows) |
| CTU-Honeypot-Capture-4-1 | benign env | honeypot devices |
| CTU-Honeypot-Capture-5-1 | benign env | honeypot devices |
| CTU-IoT-Malware-Capture-35-1 | benign env | real device (v1 unused) |
| CTU-IoT-Malware-Capture-43-1 | benign env | real device (v1 unused) |

Per-flow labels come from the official Zeek `conn.log.labeled` ground truth shipped in
the same scenario directories (Benign / Malicious with category). Flows are joined to
labels by unordered endpoint pair + protocol + time-overlap matching, never by row
position. Exact URLs, checksums, and sizes are recorded by the reproducible downloader
and verified at preparation time.

Reserved final evaluation environment: **CTU-13 scenario 8 (rbot)** — a different
malware family, different year, same official host, never used for any v2 fitting,
calibration, or selection decision. It may be evaluated exactly once for a locked
challenger. If acquisition proves impossible, the reservation falls back to
CTU-IoT-Malware-Capture-43-1 held out of all development, decided before any model is
fitted.

## Architecture plan

Multimodal challenger: packet-sequence encoder + portable aggregate branch +
connection-state semantics + domain-adversarial option + OOD scoring + approved-site
benign calibration + transparent risk fusion v2 with reason codes. No LLM anywhere in
the detection path. No payload contents are ever read or stored.

## Execution schedule

Five days, prioritized: (1) sequence extraction and parity, (2) PCAP-capable data,
(3) sequence baseline, (4) sequence+aggregate, (5) cross-environment evaluation,
(6) domain adversary, (7) site calibration, (8) held families, (9) OOD, (10) ablations,
(11) runtime integration only if qualified, (12) performance, (13) documentation.

## Outcomes

- A: locked challenger passes predeclared gates and its one reserved final evaluation.
- B: material improvement over v1 without passing every gate (documented honestly).
- C: NO-GO with quantified regression analysis and the next missing observable named.
