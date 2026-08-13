# Release evidence

The CI release-evidence job builds backend and dashboard images from one clean commit,
generates CycloneDX SBOMs with checksum-pinned Syft, and creates a bounded JSON manifest.
The manifest ties together:

- application version and exact Git commit;
- immutable local Docker image content IDs, sizes, and SBOM hashes;
- Alembic migration head;
- the production model pointer, bundle/checksum manifest, and feature schema;
- the pinned Suricata image and local rule hashes;
- production-validator and dependency-lock hashes;
- CI builder/run provenance and the scientific eligibility verdict.

The current result must say `production_eligibility: no-go`: no challenger passed
development selection, no candidate was locked, and frozen final evidence remains sealed.
Reproducible software artifacts do not change that scientific result.

Run the generator only after building both images and producing nonempty CycloneDX JSON:

```bash
uv run python -m scripts.build_release_manifest \
  --backend-image registry.example/aegisflow-backend@sha256:... \
  --dashboard-image registry.example/aegisflow-dashboard@sha256:... \
  --backend-sbom /release/backend.cdx.json \
  --dashboard-sbom /release/dashboard.cdx.json \
  --output /release/aegisflow-release.json
```

It refuses a dirty workspace, invalid/empty SBOMs, missing migration head, missing rules,
or a corrupt model checksum. CI records local image content IDs; an operator must replace
build references with verified registry digests, sign images and the manifest using the
organization's release identity, publish provenance/transparency evidence, and retain the
artifacts in the approved registry. Never commit large SBOMs or signing credentials.
