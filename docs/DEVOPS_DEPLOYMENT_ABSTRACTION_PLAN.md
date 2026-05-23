# DevOps Deployment Abstraction Plan

_Last updated: 2026-05-18_

## Goal

Create a DRY deployment abstraction for Marty self-hosted and cloud deployments so Docker Compose, Kubernetes, customer bundles, image builds, license enforcement, and commercial image hardening all reuse the same deployment metadata.

The intended commercial model is:

- sell Docker/Kubernetes deployable images for self-hosted deployments;
- require a valid signed Marty license before runtime services start;
- support customer/operator secret delivery through Docker Compose secrets and Kubernetes Secrets;
- support commercial artifact profiles where images are production-packaged, signed, scanned, and license-gated;
- keep development/source images available for internal iteration and support.

## Current status

| Area | Status | Notes |
| --- | --- | --- |
| Runtime license gate | In place | `services/entrypoint.sh` and `scripts/load-openbao-token-and-start.sh` run `python -m marty_common.license_gate` before service start when enforcement is enabled. |
| Signed self-host licenses | In place | Ed25519 JWT issuance and validation exist in `packages/marty_common/license_issuer.py` and `packages/marty_common/licensing.py`. |
| Docker Compose self-host secrets | In place | `license_key` is mounted as a file-backed secret; the license public verification key is embedded in the runtime image. |
| Kubernetes license secret path | Partial | `scripts/deploy-kubernetes.sh` creates license values in `marty-secrets`; required-secret enforcement is driven by the shared schema, while literal generation is still duplicated. |
| Commercial image release hardening | Planned | Production distribution focuses on license enforcement, pinned tags, image signing, SBOMs, vulnerability scans, and removal of dev/test artifacts rather than code hiding. |
| Deployment metadata reuse | Starting | This plan introduces catalogs/stacks/bundle manifests and a read-only runner skeleton. |

## Design principles

1. **Images enforce licensing.** Compose/K8s should supply secrets, but every runtime image must refuse to boot without a valid license when `MARTY_LICENSE_ENFORCEMENT=required`.
2. **Deployment facts live once.** Service lists, secret requirements, stack layers, artifact profiles, and bundle assets should be data, not repeated shell/Python/Makefile fragments.
3. **Make remains a thin operator UX.** Existing target names should continue to work while delegating to the shared deployment runner over time.
4. **Commercial images are a separate artifact profile.** Do not make development images painful; build hardened self-host images through explicit commercial profiles.
5. **Never print secrets.** Deployment planning, validation, and CI output must use secret names and paths only, never values.
6. **Do not depend on code hiding.** Treat licensing, support contracts, image signing, SBOMs, vulnerability management, and customer trust as the production distribution controls.

## Proposed abstraction

### Catalogs

- `deploy-config/catalog/services.json` — canonical service IDs, groups, image/build metadata, and runtime names.
- `deploy-config/catalog/secrets.json` — secret schema, required/optional status by stack, and no-log policy.
- `deploy-config/catalog/license-policies.json` — required issuer, plan tier, products, and deployment mode per policy.
- `deploy-config/catalog/artifacts.json` — source/debug vs commercial production image profiles.

### Stack profiles

- `deploy-config/stacks/selfhost-production.json`
- `deploy-config/stacks/selfhost-beta-tunnel.json`
- `deploy-config/stacks/tunnel-beta-dev.json`
- `deploy-config/stacks/kubernetes-production.json`

Each stack profile declares env files, compose files, compose profiles, domains, required service groups/services, required secrets, artifact profile, and license policy.

### Bundle manifests

- `deploy-config/bundles/selfhost.json`

Bundle manifests own the file list used to create customer-facing bundles so assets like nginx templates, tunnel proxy config, scripts, secret examples, and docs are not hardcoded in Python.

### Runner

A small Python package under `packages/marty_devops` provides read-only validation and plan rendering first:

- load catalogs;
- validate referenced services/secrets/artifacts/license policies;
- validate bundle assets exist;
- render redacted stack plans;
- produce compose command previews without executing them.

A thin CLI wrapper lives at `scripts/marty-deploy.py`.

## Commercial image hardening roadmap

### Phase C1 — Artifact profile metadata

- [x] Define artifact profiles for `source-debuggable` and `selfhost-commercial`.
- [x] Track license enforcement expectations in artifact metadata.
- [x] Add catalog validation that self-host commercial stacks cannot use a non-commercial artifact profile unless explicitly overridden.

### Phase C2 — Commercial Dockerfiles

- [ ] Add `services/Dockerfile.commercial`.
- [ ] Add `services/Dockerfile.migrations.commercial`.
- [ ] Add `ui/Dockerfile.selfhost-commercial` if frontend source-map stripping/minimization differs from current production UI image.
- [ ] Build Python packages as wheels instead of editable installs.
- [ ] Remove tests, docs, dev helpers, caches, and source maps from commercial images.

### Phase C3 — Release packaging checks

- [ ] Add image inspection tests that fail if secrets, `.env` files, test fixtures, caches, or dev-only tools appear in commercial images.
- [ ] Confirm frontend source maps are excluded from `ui-selfhost` images.
- [ ] Confirm every customer-facing service uses an immutable image tag and digest in release manifests.
- [ ] Confirm startup license checks fail closed when `MARTY_LICENSE_ENFORCEMENT=required`.

### Phase C4 — Release controls

- [x] Add local image signing hooks with Cosign.
- [x] Emit local SBOMs, vulnerability scan reports, release manifests, and checksums.
- [ ] Add registry entitlement checks tied to license/customer records.
- [ ] Support customer-specific image tags/channels.

## Implementation phases

### Phase 1 — Metadata and read-only runner

- [x] Add this tracking document.
- [x] Add service, secret, license, artifact, stack, and bundle metadata.
- [x] Add `packages/marty_devops` loader/validator.
- [x] Add `scripts/marty-deploy.py` plan/validate CLI.
- [x] Add focused unit tests for catalog validation and redacted compose planning.

### Phase 2 — Start delegating existing commands

- [x] Add Make targets for catalog validation and stack planning.
- [x] Keep existing operator targets unchanged.
- [ ] Gradually replace hardcoded Make service lists with catalog lookups.

### Phase 3 — Bundle generation from manifest

- [x] Move self-host bundle asset list into `deploy-config/bundles/selfhost.json`.
- [x] Update `scripts/package-selfhost-bundle.py` to read the bundle manifest.
- [x] Add a bundle packaging smoke test that does not require publishing images.

### Phase 4 — Shared secret schema

- [x] Refactor `scripts/check-selfhost-production.py` main running-service health list to consume the deployment catalog.
- [x] Refactor `scripts/check-selfhost-production.py` to consume `secrets.json` for self-host required secret file validation.
- [x] Refactor `scripts/deploy-kubernetes.sh setup-secrets` required-secret enforcement to consume `secrets.json`.
- [ ] Generate the `kubectl create secret generic marty-secrets` literals from `secrets.json`.
- [x] Check self-host secret example coverage from the schema.

### Phase 5 — Build/release abstraction

- [x] Add provider-neutral `scripts/build-push-registry.sh` and keep `scripts/build-push-ocir.sh` as a compatibility wrapper.
- [x] Refactor image build service lists to consume `services.json`.
- [x] Add local self-host commercial image build and release artifact commands.
- [ ] Add image inspection checks for commercial profiles.

### Phase 6 — Kubernetes rendering

- [x] Map the service catalog into Kubernetes deployment image updates.
- [x] Add provider-neutral `scripts/deploy-kubernetes.sh` and keep `scripts/deploy-oracle.sh` as a compatibility wrapper.
- [ ] Validate K8s secret mounts match the shared secret schema.
- [ ] Add stack profile for customer Kubernetes bundles.

## Done criteria

- A new service is added in one catalog location and becomes available to Compose, K8s image updates, bundle validation, and checks.
- A new required secret is added in one schema location and appears in Compose/K8s validation and docs.
- Self-host commercial images fail fast without a valid license.
- Commercial images are pinned, signed, scanned, SBOM-backed, and free of dev/test artifacts.
- Docker Compose and Kubernetes deployments use the same license policy and artifact metadata.
- Operator-facing Make commands remain stable.
