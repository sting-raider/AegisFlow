# Detector v2 development datasets

All sources come from the official Stratosphere/CTU host `mcfp.felk.cvut.cz`. Raw files
stay under ignored `data/pcap_v2/`; only this documentation, the pinned hash manifest
`configs/research-v2/pool-hashes.json`, and reproducible tooling are committed.

## Acquisition

Reproducible downloader: `scripts/download_pcap_v2.py` (official-host-only guard,
resumable range requests, SHA-256 pinning via `configs/research-v2/pool-hashes.json`).

## Pool roles determined by official per-flow labels

Label counts are taken from each scenario's official Zeek `conn.log.labeled`
(case-normalized). Scenario designations do not decide roles; row-level ground truth
does.

| Scenario | Official family | Labeled malicious / benign rows | Effective role |
|---|---|---|---|
| CTU-IoT-Malware-Capture-34-1 | Linux.Mirai | 21,222 / 1,923 | **malware env** (Mirai) |
| CTU-IoT-Malware-Capture-8-1 | Linux.Hakai | 8,222 / 2,181 | **malware env** (Hakai) |
| CTU-IoT-Malware-Capture-42-1 | Linux.Torii | 6 / 4,420 | benign-leaning env |
| CTU-IoT-Malware-Capture-20-1 | Trojan (IoT-23 designation) | 16 / 3,193 | benign-leaning env |
| CTU-Honeypot-Capture-4-1 | honeypot devices | 0 / ~205 labeled | benign env |
| CTU-Honeypot-Capture-5-1 | honeypot devices | 0 / labeled benign | benign env |
| CTU-IoT-Malware-Capture-35-1 | real device (v1 unused) | pending download | benign env when available |

The 42-1/20-1 finding reproduces a known IoT-23 property: several "malware" scenario
captures contain almost no labelled malicious connections. v2 treats their flows as
benign evidence because that is what their official per-flow labels say.

## Prepared sequence records (joined flow-level labels)

Prepared by `training/v2/prepare_sequences.py`: PCAP replayed through the runtime
`PcapAdapter`, joined to Zeek labels by unordered endpoint pair + protocol +
<=1 s interval gap. Output under ignored `data/sequences_v2/<scenario>.jsonl`.

| Scenario | Records | Malicious | Families | Benign | Unmatched pcap flows |
|---|---:|---:|---|---:|---:|
| 34-1 | 3,064 | 2,972 | c_and_c 2,655; ddos 211; port_scan 106 | 92 | 1,598 |
| 8-1 | 2,064 | 2,056 | c_and_c 2,056 | 8 | 0 |
| 42-1 | 1,507 | 0 | - | 1,507 | 1,665 |
| 20-1 | 44 | 7 | other_attack 7 | 37 | 586 |
| hp4-1 | 193 | 0 | - | 193 | 245 |
| hp5-1 | 273 | 0 | - | 273 | 532 |

Unmatched pcap flows are flows outside the Zeek-labelled window or without a label
candidate; they never enter training or evaluation.

## Attack-family coverage for held-family experiments

- **c_and_c**: present in 34-1 (2,655) and 8-1 (2,056) — two independent environments.
- **ddos**: only 34-1 (211).
- **port_scan**: only 34-1 (106).

Holding out c_and_c tests unseen-family detection across environments; ddos/port_scan
holdouts test single-source unseen-family detection.

## Reserved final environment

CTU-13 scenario 8 (rbot, 2011, same official host, different year/family) is reserved
for exactly one locked final evaluation. Fallback if unusable:
CTU-IoT-Malware-Capture-43-1 held out of all development.
