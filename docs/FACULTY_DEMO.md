# Faculty demonstration (8 minutes)

1. **0:00–0:45 — Claim and safety.** State the honest detection claim. Show the demo
   banner and explain payload-free, no-blocking defaults.
2. **0:45–1:45 — Architecture.** Trace sensor → Redis → detector → Redis → API/Postgres
   → WebSocket dashboard. Mention the SQLite/in-process CI fallback.
3. **1:45–2:45 — Reproducible replay.** Run `make demo`; show six synthetic scenarios
   arriving on the flowline.
4. **2:45–4:15 — Evidence.** Open a known-signature alert and compare classifier,
   anomaly, signature, risk, reason codes, and model versions.
5. **4:15–5:15 — Unknown behavior.** Open the unusual transfer. Emphasize
   `suspicious_unknown` and that statistical novelty is not proof of a zero-day.
6. **5:15–6:10 — Analyst workflow.** Record “requires investigation.” Show that the
   original detection remains unchanged and incidents explain their grouping rules.
7. **6:10–7:15 — ML correctness.** Show the fixed feature registry, train-only scaler,
   bundle manifest/checksums, grouped smoke split, and honest smoke metrics.
8. **7:15–8:00 — Resilience and limits.** Show health/metrics, non-root Compose, model
   corruption test, limitations, and the explicit live-capture guard.

Expected result: known and suspicious-unknown outcomes are visibly distinct, the
dashboard uses stored API data, and every decision can be traced without an LLM.
