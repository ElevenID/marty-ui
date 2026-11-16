# Platform / installer extraction audit

Source inspected: `ElevenID/marty-ui`, default branch `main`, commit `9e098423b5d98bc1bb50147f6cf1412973256144` (inspection snapshot).

## Execution checkpoint

On November 15, 2026 (America/Denver), the public [`ElevenID/platform`](https://github.com/ElevenID/platform) destination existed with a README-only `main` branch. Its repository ID is `1459541945`; active default-branch ruleset `27350361` and Actions restrictions are recorded in the [restructuring checkpoint](README.md#destination-repository-checkpoint). No required status check is configured yet.

Repository creation and initial branch/Actions policy are complete. Installer source ownership classification, destination CI and release/provenance migration remain pending. Bootstrap CI in a small platform-specific PR, verify its actual check names and results, then add the required status gates. Keep each subsequent installer extraction batch separate from website and Canvas work, and commit/push its validated checkpoint before starting the next batch.

## Architectural responsibility

The new `platform` repository is the customer/operator entry point for obtaining, verifying, installing, configuring, upgrading, diagnosing and recovering an ElevenID product release.

It consumes signed immutable artifacts. It must not become a monorepo for application, backend, protocol, Canvas or private commerce source.

## Current installer and deployment surface

The current monorepo contains a large installer-related implementation. Candidate areas include:

- Bootstrap entry points: `install.sh`, `manage-ui.sh`.
- Installer/self-host docs: `QUICK_START.md`, `SELFHOST_BUNDLE.md`, `SELFHOST_DEPLOYMENT_CHECKLIST.md`, `SELFHOST_OPENBAO.md`, `SELFHOST_PRODUCTION.md`, `ORACLE_DEPLOYMENT.md`, plus installer and hosting documents under `docs/`.
- Deployment catalogs: `deploy-config/catalog/`, `deploy-config/stacks/`, `deploy-config/bundles/`, `deploy-config/schemas/`.
- Installer Compose overlays: `deploy-config/compose/selfhost-installer/`.
- Production deployment definitions: `docker-compose.selfhost*.yml`, `docker-compose.ui-*.yml` and referenced runtime overlays, subject to ownership review.
- Kubernetes packaging: `deploy/helm/`, `deploy/k3s/`, selected `k8s/` manifests.
- OpenBao operator and host integration: selected `openbao/`, `docker/openbao*`, `deploy-config/host/` and bootstrap assets.
- Installer/release scripts: `scripts/installer_*.py`, `scripts/installer-*.sh`, `scripts/verify_installer_provenance.py`, `scripts/installer_channel.py`, `scripts/installer_promote.py`, `scripts/installer_publish_admission.py`, `scripts/product_*.py`, `scripts/release_*.py`, `scripts/package_production_deployment.py`, `scripts/build_selfhost_image_lock.py`, `scripts/prepare_kubernetes_helm_values.py`, and selected self-host/Kubernetes lifecycle helpers.
- Relevant workflows: `.github/workflows/installer-acceptance.yml`, `installer-promote.yml`, `installer-publish-admission.yml`, `installer-publish-channel.yml`, `kubernetes-chart.yml`, `nightly-release.yml`, `prepare-nightly-claim.yml`, `prepare-stack-tag.yml`, `product-authenticated-intake.yml`, `product-packages.yml`, `product-verification.yml`, `publish-stable-candidate.yml`, `release-environment-preflight.yml`, `release-pipeline.yml`, `release-tag-handoff.yml`, `selfhost-prepared-consumer.yml`, `tombstone-stack-release.yml`.
- Relevant tests: installer, self-host, Kubernetes, product package, release transaction, provenance, Windows lifecycle, backup and recovery tests.

These are candidate inventories, not a blanket transfer list. The current installer-related path search returns hundreds of files because installer qualification shares test fixtures, runtime service definitions, product packaging and CI. Each path needs explicit ownership and dependency classification.

## Critical separation: installer vs product runtime

The current `deploy-config/catalog/services.json` describes actual runtime service roles, including gateway, auth, organization, credential-template, trust-profile, issuance, applicant, notification, verification, revocation and others. These are product deployment inputs, not service implementation source.

`deploy-config/bundles/selfhost.json` lists deployment bundle assets, including Compose files, OpenBao config, secret templates, Nginx configuration and operator helpers. Some referenced files are product-owned runtime artifacts and some are installer-owned orchestration. Split ownership carefully:

- `platform`: installation UX/CLI, host preflight, deployment orchestration, artifact verification, release catalog, deployment profiles, upgrade/recovery orchestration and platform-owned templates.
- Product/application/service repositories: service images, service implementation, database migrations and service-specific runtime behavior.
- `core` / `protocol`: protocol implementation and normative contracts.
- `subscriptions`: private billing and commerce.
- Canvas repository: Canvas source and Canvas-specific runtime components, under the parallel Canvas migration.
- Shared release contract: versioned service catalog/schema and product release manifest, with a single declared owner and compatibility policy.

Do not copy service source into `platform`. Do not move a deployment file until its owner, consumers and update cadence are known.

## Current bootstrap contract

`install.sh` is a GitHub-hosted bootstrap shim. It verifies and invokes the signed operator rather than embedding the complete installer. It currently documents Linux amd64, regular non-root user, no-new-privileges and an already-running rootless Docker daemon. Managed OpenBao is default; optional foundation/external OIDC and typed application settings are explicit inputs.

The new `platform` repository must preserve this trust chain and rootless behavior. Its bootstrap must fetch the operator from the `platform` release, verify exact source-bound signatures/provenance before execution, and verify remaining payloads before provisioning. It must not silently fall back to unverified source or moving tags.

## CI/CD migration risks

Many current workflows are scoped to `github.repository == 'ElevenID/marty-ui'` and use its repository identity, environment secrets, artifact names and release tags. Moving them requires:

- New repository identity and protected environments.
- Recreated secrets/variables through an administrator, without copying secret values into files.
- New OIDC/Sigstore workflow identities and attestation policies.
- Explicit permissions for cross-repository artifact reads and dispatches.
- Updated workflow repository guards and source lineage checks.
- Updated release tags, artifact coordinates and documentation.
- Separate ownership for app/backend builds versus installer/package verification.
- Retained audit evidence and old release verification during transition.

Do not assume that moving a workflow YAML file alone transfers its environment secrets or trust.

## Tests and evidence

The current repository has extensive installer/self-host/Kubernetes test coverage. Candidate test families include `tests/test_installer_*.py`, `tests/test_selfhost_*.py`, `tests/test_kubernetes_*.py`, `tests/test_product_*.py`, `tests/test_release_*.py`, `tests/test_verify_installer_provenance.py`, `tests/test_windows_*.py`, plus fixtures and Node-based acceptance tests.

The migration must preserve test ownership and test data provenance. Tests that need live product services should consume published test images or controlled fixtures, not pull application source into the installer repository.

## Acceptance gates

1. Clean checkout of `platform` can build/test the installer and deployment tooling without `marty-ui`.
2. Bootstrap verifies signed installer/operator before execution.
3. Release catalog selects exact immutable compatible components.
4. Rootless Docker, no-new-privileges and managed OpenBao contracts remain intact.
5. Compose and Kubernetes render from platform-owned deployment inputs and versioned product contracts.
6. External OIDC, origin/TLS, diagnostics and automatic-stop safeguards remain qualified.
7. Upgrade, rollback, backup and recovery pass on disposable installations.
8. Fresh install and upgrade tests do not mutate existing production data.
9. Cross-repository provenance validates original producer repository, workflow, commit, run and attempt.
10. Production migration occurs only after separate explicit qualification and cutover approval.

No installer or deployment source has been moved in this audit PR.
