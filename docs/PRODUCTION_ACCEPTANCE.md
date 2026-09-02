# Production acceptance

Current verdict: **Final-phase acceptance incomplete; detector NO-GO**

Last updated: 2026-09-02 (evidence through 2026-08-23)

The engineering platform and several local acceptance drills are verified. The full
stop condition remains open: research validity, deployed approved site baselines, and
specific bad-image/failed-migration drills require work. See
[REQUIREMENTS_AUDIT.md](REQUIREMENTS_AUDIT.md). Detection never authorizes automatic blocking.

| Acceptance area | Required evidence | Current status |
|---|---|---|
| Frozen-evidence integrity | Exact report/config/source hashes; final-only policy; CI guard | v1 passes; new v2 archive check added locally, subsequent CI pending |
| Portable representation | Universal schema, explicit missingness, robust transforms, parity | Complete for the implemented schemas; v1 origin gate blocks the current portable candidate |
| Temporal representation | Bounded shared training/runtime semantics and parity | Complete for research: 43,009 Schema-B rows plus six packet-sequence environments; no candidate selected |
| Fresh development corpus | Reviewed provenance/licensing/hashes and non-frozen boundary | Pass: three v1 environments and six checksum-pinned IoT-23 sequence environments |
| Dataset-origin diagnostic | Balanced deduplicated source classification and ablation | Full Schema A blocked at 0.95416; categorical ablation clears at 0.68428 |
| Challenger evidence | Registered baselines, costs, ablations, repeated held-family and cross-environment results | v1 negative evidence retained; v2 partition/provenance corrections required |
| Final scientific gate | Candidate locked before exactly one frozen run; governed GO/NO-GO | No eligible candidate; frozen run not authorized and remains sealed |
| Sustained capacity | 10/30-minute plus burst/failure tests with loss, lag, latency and resource budgets | Required clean-runner 30 flows/s × 30 minutes passes ([evidence](acceptance/sustained-compose-linux-ci-2026-08-13.json)); 50 flows/s × 30 minutes remains a recorded capacity NO-GO; representative target capacity is external |
| Multi-worker correctness | Partitioning, recovery, idempotency and shared state under sustained load | Pass for local Compose persistence workers: controlled pending-work SIGKILL/reclaim/restart, 6,000/6,000 exact conservation, zero final depth ([evidence](acceptance/multiworker-compose-windows-2026-08-13.json)); multi-host scaling remains deployment-specific |
| Real local OIDC | Local IdP, roles, token/JWKS lifecycle and abuse cases | Pass on disposable local Dex profile ([evidence](acceptance/oidc-ci-2026-08-13.json)); organizational IdP validation remains deployment-specific |
| Local Kubernetes | Actual kind/k3d deployment, probes, policies, migration, rollout and failure drill | Pass on disposable kind runner: migrations, replicas, TLS, NetworkPolicy, idempotent replay, replacement/recovery, and cleanup ([evidence](acceptance/kubernetes-ci-2026-08-22.json)) |
| Restore | Disposable database backup and measured restore validation | Pass for local PostgreSQL mechanics: 15 tables and primary identities match after destructive restore; API smoke and cleanup pass ([evidence](acceptance/restore-ci-2026-08-13.json)). Managed backup/RPO/RTO remain deployment-specific. |
| Security acceptance | Controlled auth, input, secret, network and privilege abuse tests | Pass: 74 tests across six controlled categories on a clean runner ([evidence](acceptance/security-ci-2026-08-13.json)); organizational penetration testing and target controls remain external |
| Production validator | Fail-closed unsafe-config checks | Implemented with negative controls for identity, secrets, CORS/WebSockets, provider TLS, datastore exposure, filesystems/capabilities, model/evidence/approval, readiness, retention, and backup. The checked-in rejected smoke model correctly remains a production NO-GO. |
| Release evidence | Reproducible artifacts, SBOM/provenance and release manifest | Pass: clean-runner SBOMs and bound NO-GO manifest are retained ([evidence](acceptance/release-ci-2026-08-13.json)); current main is green in run `32635976457`; registry digests/signing remain release-owner work |
| Operator package | Installation, deployment, configuration, identity, sensor, model, backup, incident, troubleshooting, upgrade, rollback, performance, capacity and security procedures | Existing runbooks retained; tested approved-site calibration and specific failure-drill procedures remain incomplete |
| Final report | `docs/FINAL_ACCEPTANCE_REPORT.md` with safe-claim boundary | Draft/historical verdict superseded by the requirements audit |

The detector remains a development NO-GO. The final brief has not reached a proven stop
condition. Successful local exercises do not waive the remaining requirements in
`docs/REQUIREMENTS_AUDIT.md`.
