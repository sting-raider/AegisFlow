# Kubernetes deployment baseline

This Kustomize base deploys the API, detector workers, and dashboard. It deliberately
does not create PostgreSQL, Redis, TLS, credentials, or model/evaluation content. Use
managed stateful services and an organizational secret manager.

Concurrent API init containers serialize Alembic through a PostgreSQL advisory lock.
In-process retention is disabled for the replicated API; one daily CronJob owns cleanup
with `concurrencyPolicy: Forbid`, while system status reports the external policy.

Before rendering:

1. Replace both image names and tags in `kustomization.yaml` with immutable image
   digests from the organization's registry.
2. Replace every `example.invalid` identity, origin, and ingress value.
3. Create `aegisflow-runtime-secrets` out of band with `AEGISFLOW_DATABASE_URL` and
   `AEGISFLOW_REDIS_URL`. Never commit that Secret.
4. Provision the named TLS Secret and populate the two RWX volumes with a reviewed model
   registry and immutable evaluation reports. If the storage class cannot provide RWX,
   use an external versioned object/model registry instead of weakening consistency.
5. Adapt the ingress-controller namespace in `network-policy.yaml`. The checked-in
   policy assumes `ingress-nginx` and otherwise denies ingress.
6. Keep governance disabled until backup, restore, rollout, and detector restart
   procedures have been exercised in that cluster.

Render without applying:

```text
kubectl kustomize infra/kubernetes > rendered-aegisflow.yaml
```

The base is a deployment starting point, not evidence of production capacity. Database,
Redis, storage, ingress, and identity-provider limits must be validated in the target
environment. Prometheus scraping of `/metrics` needs a viewer credential because metrics
are authenticated outside demo mode.

## Disposable local acceptance profile

`../kubernetes-local-acceptance` deploys this base into a disposable kind cluster with local
PostgreSQL/Redis, loopback-only ingress, a generated test TLS certificate, local images,
and the synthetic demo identity/traffic fixture. It exists only to prove deployment
mechanics and must never be adapted into a production environment. Run it through
`make kubernetes-acceptance`; the harness refuses to replace an existing cluster with its
fixed acceptance name and deletes only that cluster during cleanup.
