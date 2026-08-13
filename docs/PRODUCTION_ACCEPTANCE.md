# Production acceptance

Current verdict: **NOT ACCEPTED / IN PROGRESS**

Last updated: 2026-08-13

The repository is a demoable engineering and evaluation platform. The current detector is
scientifically rejected and there is not yet enough operational evidence to deploy it as a
production NIDS. Detection never authorizes automatic blocking.

| Acceptance area | Required evidence | Current status |
|---|---|---|
| Frozen-evidence integrity | Exact report/config/source hashes; final-only policy; CI guard | Pass |
| Portable representation | Universal schema, explicit missingness, robust transforms, parity | Implementation passes; development evidence open |
| Temporal representation | Bounded shared training/runtime semantics and parity | Implementation passes; 43,009 IoT-23 rows replay Schema B; candidate selection open |
| Fresh development corpus | Reviewed provenance/licensing/hashes and non-frozen boundary | Pass for initial experiments: 3 official environments and 6 temporal IoT capture groups |
| Dataset-origin diagnostic | Balanced deduplicated source classification and ablation | Full Schema A blocked at 0.95416; categorical ablation clears at 0.68428 |
| Challenger evidence | Registered baselines, costs, ablations, repeated held-family and cross-environment results | Complete for current family; cross-fitted calibration fails and records a development scientific NO-GO |
| Final scientific gate | Candidate locked before exactly one frozen run; governed GO/NO-GO | No eligible candidate; frozen run not authorized and remains sealed |
| Sustained capacity | 10/30-minute plus burst/failure tests with loss, lag, latency and resource budgets | 10-minute 50 flows/s local point passes; 30-minute 50 flows/s is a NO-GO on latency/depth/growth despite exact recovery. Lower-rate ladder and failure matrix open ([10m](benchmarks/sustained-compose-windows-2026-08-13-50fps-10m-postfix.json), [30m](benchmarks/sustained-compose-windows-2026-08-13-50fps-30m.json)) |
| Multi-worker correctness | Partitioning, recovery, idempotency and shared state under sustained load | Pass for local Compose persistence workers: controlled pending-work SIGKILL/reclaim/restart, 6,000/6,000 exact conservation, zero final depth ([evidence](acceptance/multiworker-compose-windows-2026-08-13.json)); multi-host scaling remains deployment-specific |
| Real local OIDC | Local IdP, roles, token/JWKS lifecycle and abuse cases | Pass on disposable local Dex profile ([evidence](acceptance/oidc-ci-2026-08-13.json)); organizational IdP validation remains deployment-specific |
| Local Kubernetes | Actual kind/k3d deployment, probes, policies, migration, rollout and failure drill | Open |
| Restore | Disposable database backup and measured restore validation | Open |
| Security acceptance | Controlled auth, input, secret, network and privilege abuse tests | Open |
| Production validator | Fail-closed unsafe-config checks | Open |
| Release evidence | Reproducible artifacts, SBOM/provenance and release manifest | Open |
| Final report | `docs/FINAL_ACCEPTANCE_REPORT.md` with safe-claim boundary | Open |

Production acceptance can end in either a GO for one immutable candidate/environment or a
scientifically valid NO-GO. A NO-GO does not erase the completed engineering platform; it
prevents unsupported detector claims.
