# Final-phase requirements audit

Audit date: 2026-09-02. Status: **incomplete**. This audit supersedes earlier
repository-wide completion claims in the acceptance reports. The engineering baseline
remains usable and the recorded local OIDC, restore, kind, and capacity results remain
valuable. They do not establish every requirement of the final brief.

Authority: the 35-section final-phase brief attached as `pasted-text-1.txt`.
Evidence baseline: public commit `88ea3801886fd3b27563aab5f52a52d1272e2d80`;
historical CI run `32635976457` passed ten jobs. That workflow did **not** contain the
new `verify_research_v2` step. Local verification of the initial guard passed 238 tests
with 84% backend coverage; those checks establish implementation behavior, not research
validity or full-project completion.

## Findings requiring correction

1. `training/v2/run_held_family.py` HF1 and HF2 allow `c_and_c` in fitting and evaluate
   `c_and_c` from another malware capture. These are cross-capture/malware-variant tests,
   not whole-label-family holdouts. HF3 does exclude C&C from fit but includes its target
   calibration capture in fitting. The old JSON results remain historical observations;
   they cannot support the stated strict held-family claims.
2. The same harness includes hp4/hp5 in the fitting scenarios while using them as site
   calibration pools. `run_domain_adversarial.py` also includes hp4 in fitting and uses
   hp4 for target-site calibration. Independent approved benign validation is absent.
3. The domain-adversarial report records embedding origin balanced accuracy
   0.93874--0.94378. The claim that *no representation* exceeds 0.90 overlooks these
   learned embeddings. The 0.797 raw-feature result is a different diagnostic.
4. The five v2 JSON reports omit actual execution commit, prepared-data fingerprints,
   exact split identities, and recorded memory/latency. Their publication commit is
   recoverable, but it must not be relabelled as their execution commit. The 0.066 ms /
   749,000 flows/s figures occur in prose without a retained machine-readable benchmark.
5. The newly added verifier initially hashed Windows CRLF bytes even though the tracked
   reports are LF. The 2026-09-02 regression reproduced and fixed this for both checkout
   formats. Hash verification alone cannot prove partition isolation or scientific eligibility.
6. The source search found research calibration and bundle governance, but no complete
   deployed observation → approved benign statistics → human activation → rollback
   workflow for a site baseline (brief §9). This remains required repository work.
7. Existing rollback instructions and successful pod replacement do not demonstrate
   bad API-image rollback, bad detector-image rollback, or failed migration simulation
   (§25). Dedicated measured evidence remains required.
8. `FusionNet` combines sequence and portable aggregate tensors, not the separate TCP
   connection-state tensor. Earlier architecture prose overstated the trained model's
   inputs. Corrected experiment metadata must record the exact representation used.
9. The old deduplication fingerprint omitted aggregate service features and collapsed
   three distinct inputs. Exact sequence/mask/aggregate deduplication is now regression
   tested (6,674 unique inputs). Percentile cuts also violated budgets with tied scores;
   exact tie-aware cuts are tested. Fresh clean-code preparation is complete and bound
   in `DEV2-FAMILY-002`; its registered six-rotation execution completed from clean
   code `3659031`. All six outcomes are preserved as a development NO-GO; none authorizes
   final evaluation or model promotion. See `research-v2/registered-results/`.
10. Corrected `DEV2-ORIGIN-002` evaluates benign captures excluded from three frozen
    encoders, with grouped folds and train-fold numeric transforms. Every encoder retains
    an origin warning under at least one transform. Numeric-only input remains near 0.89;
    mask-only folds are unevaluable. Preserve 15 convergence and two transformed-alias
    failures. The first attempt's missing failed-fold times were reproduced and fixed;
    the unchanged-protocol repeat has identical scientific results and full cost evidence.
11. Missingness-study preparation exposed independent invalid-entry filtering in the
    shared sequence encoder. It now rejects malformed metadata and the FlowEvent contract
    rejects nonfinite packet timings. Worker quarantine tests pass; differential checking
    preserves exact tensors/masks on all 7,145 prepared rows. No prior result is rerun.

## Requirement-by-requirement status

“Partial” includes evidence that is too narrow to prove the complete requirement.
“Conditional” means a trigger has not been reached; it is not silently waived.

| Brief section | Current evidence | Status / evidence still needed |
|---|---|---|
| 1. Autonomous execution | Progress, decisions, research logs; committed milestones | Ongoing; keep incomplete work explicit |
| 2. Frozen boundary | Frozen manifest, `verify_frozen_evidence`, tests | Verified for four retained reports; no new final run authorized |
| 3. New development pool | v1 pool/provenance; v2 PCAP hashes/preparation | Clean v2 preparation and FAMILY-002 splits bound; tiny deduplicated DDoS/scan support remains a limitation |
| 4. Two feature schemas | `packages/features/research.py`, parity/state tests | Shared A/B implementation present; runtime activation depends on selection (§18) |
| 5. Numeric representation | ORIGIN-002 and completed MISSINGNESS-001 three-view/four-transform comparisons | Mixed paired results and 24 transformed-alias failures retained; learned robust-sequence and origin-remediation work remains |
| 6. Baselines | DEV-SUP/ANO reports, model configs | v1 comparisons retained; v2 reproducibility/cost evidence incomplete |
| 7. Open-set representation | v2 fusion embeddings/Mahalanobis | FAMILY-002 fails; ORIGIN-002 confirms retained benign-site information; detector representation/ablation work remains |
| 8. Unknown vs uncertainty | Runtime fusion/reason codes, separate v2 channels | Runtime baseline tested; v2 claims require corrected evidence |
| 9. Site baseline workflow | Research quantiles; existing model governance | Incomplete deployed observation/approval/activation/rollback workflow |
| 10. Operational budgets | v1 curves; v2 exact union budgets and independent benign results | FAMILY-002 measured: worst independent FPR 47.51%; objectives fail, no deployment claim |
| 11. Development error analysis | `docs/error_analysis/`, DEV-ERR | v1 retained; v2 scientific/provenance audit requires correction |
| 12. Ablations | DEV-HYB and v2 comparison reports | Partial; strict-family and no-domain-leakage comparisons unresolved |
| 13. Whole-family holdouts | v1 harness; corrected FAMILY-002 six rotations | Corrected exclusion/row checks executed; 4,710 C&C, 7 DDoS, 4 scan inputs; negative and sample-limited |
| 14. Cross-environment evaluation | v1 rotations; corrected MISSINGNESS-001 single/combined-source matrix | Narrow linear/raw-distance transfer completed with independent sites and 52/72 paired triples; learned/context/signature comparisons remain |
| 15. Strict experiment registry | v1 registry; historical v2 archive; corrected FAMILY/ORIGIN-002 | Corrected studies bind executed clean code/data/splits/config/costs/artifacts and explicit failed coverage; historical v2 remains unvalidated |
| 16. Final frozen acceptance | Four historical smoke rejection reports | Conditional: no eligible locked challenger, no new final test |
| 17. Acceptance decision | v1 development NO-GO | Development rejection valid; final brief stop condition not yet proved |
| 18. Selected-model runtime integration | Shared representations | Conditional on selecting a challenger; none selected |
| 19. Stage profiling | Benchmark/profile reports; batching/incident normalization | Partial: verify every named stage against retained measurements |
| 20. Sustained/failure scenarios | 10m/30m reports; 30fps PASS; worker/recovery tests | Partial: map database slowdown and Redis restart *during load* to measured artifacts |
| 21. Partition/resharding semantics | Multi-worker persistence drill; bounded context | Partial: context routing and resharding acceptance not demonstrated |
| 22. Local real OIDC | Retained Dex acceptance report | Verified for recorded disposable IdP checks; organizational integration external |
| 23. Local cluster drill | Retained kind acceptance report | Verified for recorded single-node deployment mechanics |
| 24. Restore drill | `RESTORE_DRILL.md`, retained 15-table report | Verified for recorded disposable PostgreSQL restore |
| 25. Disaster/rollback | Recovery tests, governance tests, rollout instructions | Partial: bad API/detector images and failed migration need measured drills |
| 26. Security validation | 74-test security acceptance report | Partial until each named attack is mapped to a test; no external attack authorized |
| 27. Tenancy decision | D-050 and security/operator docs | Complete: one organization/security domain per deployment |
| 28. Production validator | `production_check.py`, negative/positive tests | Implemented; current smoke/config intentionally NO-GO |
| 29. Release provenance | Release manifest/SBOM job and retained aggregate report | Local build evidence present; registry signing external; current milestone CI pending |
| 30. Operator docs | All named runbooks present | Partial: add tested site-calibration and failure-drill procedures |
| 31. Academic evidence | Research package and negative results | Partial: correct v2 claims, provenance, and reproducible performance tables |
| 32. Scope restrictions | No automatic blocking; no LLM detector | Preserved; no dashboard redesign or frozen-data tuning |
| 33. Priority order | This audit and progress backlog | Correct research evidence first, then remaining acceptance work |
| 34. Stop condition | Earlier Outcome-B prose | Not achieved; do not redefine no candidate + passing CI as full completion |
| 35. Final report | 23 sections present | Draft/historical; revise to verified final state only when open requirements close |

## Next implementation order

1. Complete the remaining learned detector/context/signature ablations and broaden
   effective development support. MISSINGNESS-001 now has a completed clean run:
   84 evaluated models, 24 transformed-alias entries and 168 site results; none reaches
   50% direct unknown recall on its target attack mixture. Source addition and the
   three representation treatments are compared on matched rows with missing pairs
   explicit. Its common-support exclusions are a limitation,
   not proof of full-capture generalization. FAMILY-002
   has corrected provenance but fails development gates and has tiny effective samples
   for two families; do not reuse the old unvalidated results as replacement evidence.
2. Use those development results to choose a defensible next representation/data study.
   Preserve all negatives and keep final data sealed until an eligible challenger is locked.
3. Implement approved site-baseline activation and complete the specific failure/rollback
   and partitioning drills. Reconcile this matrix against their actual outputs.
4. Publish a green milestone, then issue a final verdict only when the brief's complete
   stop condition is supported.
