# Strict-family corrected development error analysis

Source: `docs/research-v2/registered-results/DEV2-FAMILY-002.json`. Executed from clean
commit `365903128b0db36128e0846960a89b72fe8a7a74`, using the configuration registered in
`9be5306`. No frozen final evidence was accessed, no threshold was adjusted, and no
candidate was selected. This is a development NO-GO, not final Outcome B.

## Observed failure modes

- C&C: zero direct detection or review on 4,710 distinct model inputs in either site
  orientation. The largest known score is 0.02720, below the smaller review cut 0.94428.
  The largest embedding distance is 80.349, below the smaller review cut 96.578.
  4,705 inputs are HIGH observability, four MEDIUM and one LOW. Missing packet sequences
  alone therefore do not explain these misses. The C&C-excluded fit has 1,500 benign
  inputs but only 11 malicious inputs (seven DDoS, four port scan); that training support
  is too narrow to establish broadly generalizable open-set geometry.
- Site shift: the same seeded fitted C&C model has identical artifact hashes in both
  orientations, yet independent benign FPR changes from 4/181 (2.21%) to 86/181 (47.51%).
  In the latter orientation the Wilson 95% interval is 40.37–54.76%. The calibrated
  benign score distribution is not transferable to the other benign device. This is
  measured site sensitivity, not evidence that a universal threshold is safe.
- DDoS: zero detections/reviews on seven distinct inputs. Five are HIGH observability,
  two LOW. The zero-recall Wilson upper bound is 35.43%; the tiny effective sample cannot
  establish broad family performance. Independent benign FPR is 14.36% or 0% depending
  on orientation.
- Port scan: all four inputs receive direct detection. With hp4 calibration, all four
  are known-channel verdicts, so direct suspicious-unknown recall is zero. With hp5,
  two are suspicious unknown and two known. The 50% unknown recall interval is
  15.00–85.00%; this does not qualify the representation. The former orientation has
  8.29% benign FPR; the latter has 0% direct FPR but 12.71% review-inclusive benign rate.
  The known-head direct cuts are only 0.000001252 and 0.000015806. Thus a `known_attack`
  verdict here means the preregistered binary head exceeded a benign-budget cut, not
  confident recognition of a known attack family. This semantic limitation must be
  addressed before deployment; do not reinterpret those verdicts as unknown detections.

## Budget and uncertainty interpretation

There are only 181 deduplicated benign calibration inputs at each site. A 0.5% per-channel
budget permits zero calibration flags (`floor(181 * .005) = 0`), so each direct cut is
above its calibration maximum. This is the predeclared rule, not post-hoc threshold
selection. Independent FPR is still high in several rotations. Even 0/181 false positives
has a Wilson upper bound of 2.08%, above the 1% direct-alert objective. Row-wise intervals
also ignore correlation within a capture; two orientations are not independent replication.

## Resource evidence

All six rotations completed in 51.472 seconds after input admission. Fit times range
4.800–7.360 seconds. Single-record P95 latency is 0.390–1.060 ms; batch-128 P95 is
3.338–8.639 ms. Sampled process peak RSS is 428,556,288–435,707,904 bytes, including loaded
data and Python/Torch. These are CPU model-stage measurements, including tensor building,
preprocessing and OOD; they exclude PCAP parsing and durable Redis/PostgreSQL processing.
They do not replace the separate sustained-capacity evidence.

## Consequence and next research work

Do not promote this model family or reopen frozen evaluation. Preserve all six outcomes.
The strongest justified next direction is broader independent benign-site evidence and
larger diverse held-family support, together with learned-embedding origin diagnostics
and the required missingness/numeric/temporal ablations. A deployed operator-approved
baseline workflow remains separate unfinished work. These observations do not prove
that flow/sequence detection is impossible, and they do not authorize tuning final tests.
