# Deployment Config Layout

This directory separates deployment concerns by target environment to reduce accidental cross-domain or cross-stack configuration drift.

## Structure

- env/selfhost-production
- env/tunnel-beta
- compose/selfhost-production
- compose/tunnel-beta
- catalog/services.json
- catalog/secrets.json
- catalog/license-policies.json
- catalog/artifacts.json
- stacks/*.json
- bundles/*.json

## Rules

- selfhost-production uses elevenidllc.com values.
- tunnel-beta uses beta.elevenidllc.com values.
- tunnel-beta-experiments adds resettable beta-only experiment services such as
  Canvas LMS at canvas-test.elevenidllc.com and a beta-safe Canvas Credentials
  mirror receiver at canvas-sandbox.elevenidllc.com.
- Do not reuse one env file across both targets.
- Do not put a separate beta/staging hostname in selfhost production `UI_ADDITIONAL_BASE_URLS`; that makes the secondary hostname use the production Keycloak issuer.
- Keep secrets in external secret directories, not in this repo.

## Canonical Runtime Files

- Beta tunnel runtime env: .env.tunnel.beta.local
- Beta tunnel make targets: beta-up, beta-public-ui, beta-tunnel-start, beta-check
- Beta experiments make targets: beta-experiments-up, beta-canvas-experiments-bootstrap
- Selfhost production runtime env: .env.selfhost.production.local
- Selfhost production make targets: selfhost-prod-up, selfhost-prod-check, selfhost-prod-logs
- Selfhost production compose: docker-compose.selfhost.prod.yml
- Tunnel overlay compose: docker-compose.profile.tunnel.yml
- Kubernetes deployment script: scripts/deploy-kubernetes.sh
- Registry image build/push script: scripts/build-push-registry.sh

## Deployment catalog

The catalog files are the canonical source for deployment metadata that is shared by Make targets, bundle packaging, checks, and future Kubernetes/image release flows.

Portable Canvas acceptance uses `catalog/canvas-oss.lock.json` for the exact
upstream source/image pin and `catalog/canvas-oss-portability.json` for the
fixed OSS/hosted/outside-gate coverage contract. See
`docs/CANVAS_OSS_PORTABILITY_PIPELINE.md` for the local runner and beta binding.

Useful commands:

- `python scripts/marty-deploy.py validate`
- `python scripts/marty-deploy.py plan selfhost-production`
- `python scripts/marty-deploy.py plan tunnel-beta-experiments` for the beta Canvas experiments stack
- `python scripts/marty-deploy.py plan selfhost-beta-tunnel` only when beta intentionally routes into the same self-host production stack
- `python scripts/marty-deploy.py plan kubernetes-production`
- `python scripts/marty-deploy.py compose-command selfhost-production config`
- `python scripts/marty-deploy.py secrets kubernetes-production --field env`

Local image release commands:

- `make selfhost-images-ghcr-setup`
- `make selfhost-images-build-dry-run TAG=2026.05.0`
- `make selfhost-images-build TAG=2026.05.0`
- `make selfhost-images-build-push TAG=2026.05.0`
- `make selfhost-images-artifacts-dry-run TAG=2026.05.0`
- `make selfhost-images-release-artifacts TAG=2026.05.0`
- `make selfhost-images-sign TAG=2026.05.0 COSIGN_KEY=/secure/operator-only/cosign.key`
- `make selfhost-images-verify-signatures TAG=2026.05.0 COSIGN_PUBLIC_KEY=/secure/operator-only/cosign.pub`
- `make package-selfhost-bundle`

Builds run on the operator machine and push to GHCR only when the `*-push` target is used. Customer deployments should use immutable `SELFHOST_IMAGE_TAG` values, not `latest`.
Release artifacts are staged under `dist/releases/<tag>/` and include SBOMs, vulnerability scan reports, digest inspection output, schema-v2 `release-manifest.json`, `release-evidence.md`, and `checksums.sha256` when the required local tools are installed. Cosign signing and verification use image digest refs, not mutable tags.

Use the templates in this directory as documentation and copy sources for new operators.
