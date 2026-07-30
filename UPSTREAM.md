# Upstream reference

AegisFlow was architecturally informed by
[`isaiah-harville/NIDS`](https://github.com/isaiah-harville/NIDS) at commit
`277c4ff12be35e5f855a1aaff75de816f3f10f7a` (2025-03-21).

No upstream source file is copied into the AegisFlow implementation. The upstream
service boundaries, NFStream experiment, and dashboard concept were reviewed; the
runtime, contracts, preprocessing, persistence, detection logic, tests, and UI were
rewritten.

Important licensing note: the referenced revision's `LICENSE` file contains the
Apache License 2.0, while its README links to it as “MIT License.” AegisFlow preserves
the actual Apache-2.0 license text and documents the discrepancy rather than assuming
MIT terms.

See `docs/UPSTREAM_AUDIT.md` for source-level findings.
