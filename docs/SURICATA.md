# Suricata integration

`packages/detection/suricata.py` accepts bounded JSON lines, ignores non-alert events,
normalizes severity, hashes the raw line, and emits only allow-listed structured
metadata. Malformed/partial lines fail visibly.

Demo mode uses a deterministic fixture signature and does not require Suricata.
Production correlation should prefer community ID, then a bounded timestamp plus
normalized endpoint tuple. Deduplicate on signature ID, flow ID, timestamp bucket,
and raw-event hash. Test new rules offline before promotion and pin the rule snapshot.
