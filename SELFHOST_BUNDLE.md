# Self-Hosted Customer Bundle

This bundle is the image-based distribution for the open-source self-host stack. It carries the runtime compose files, secret templates, Keycloak import assets, and wrapper scripts needed to run the deployment without the full source tree.

## What is inside the bundle

- `docker-compose.yml` as the generated image-based runtime compose file operators should run
- `.env.selfhost.production.example` with the non-secret settings contract
- `docker/secrets/selfhost.example` as the tracked placeholder secret set
- `config/keycloak` for the realm import and theme assets
- `scripts/bootstrap-selfhost-vault.sh` as the operator helper for configuring an external Vault/OpenBao instance and minting the scoped runtime token
- the runtime `docker/*` and `scripts/*` files still mounted by the compose stack

## Image contract

The bundle is an image-only packaging format. Its image roles must be published
and qualified together before a customer installation; the packager does not
produce them. The v1.1.231 public release publishes `ui`, `services`, and
`migrations` OSS images, but not this bundle's `ui-selfhost`, `db-migrate`, or
`cloudflared-wrapper` roles. Do not treat that release as a ready-to-install
self-host bundle.

- `SELFHOST_IMAGE_PREFIX=ghcr.io/elevenid/marty-ui`
- `SELFHOST_IMAGE_TAG=<released-version>`

The intended UI role is `ui-selfhost`, excluding the public marketing and blog
surface. It is not among the v1.1.231 public images.

Set `SELFHOST_IMAGE_TAG` to the released immutable version you want to run. Do not use `latest` or `--build` with the bundle.
For a digest-pinned bundle produced with `--image-lock`, the rendered Compose
images no longer use `SELFHOST_IMAGE_TAG` or `MARTY_ISSUANCE_IMAGE`; the
qualified image lock supplies those references instead.

Use the image artifacts and verification evidence from the release workflow, then
stage this bundle with `make package-selfhost-bundle` (Rust 1.95.0 and Docker
Compose required). Packaging checks the image configuration; it does not publish
images, authenticate their provenance, or deploy the stack. The former
`selfhost-images-*` Make targets and Python packager are no longer present.

Optional arguments retain directory and ZIP output:

```bash
make package-selfhost-bundle SELFHOST_BUNDLE_ARGS='--output-dir /existing/parent/customer-bundle --archive /existing/parent/customer-release'
```

An opt-in `--image-lock /path/to/qualified-images.json` binds every rendered
Compose service to an exact `registry/path@sha256:<64 lowercase hex>` reference.
The JSON must use schema `marty.selfhost-image-lock/v1`, a `release` matching
`release/stack-lock.json`, and a `services` object keyed by every rendered
Compose service name. Packaging rejects missing/extra services, mutable image
references, and a release mismatch, then includes the lock in the bundle as
`.marty-selfhost-images.json`. This is a binding mechanism, not a qualification
claim: the release process must first verify the image digests, provenance,
signatures, licensing, and clean installed stack. No current public release
provides such a qualified self-host image lock.

`--archive` appends `.zip` to its basename. ZIPs contain the bundle directory,
runtime files and directories. Unix packaging preserves executable modes;
Windows-produced archives do not qualify POSIX shell permissions. Release
bundles require the Linux packaging gate. Existing output is rejected by default.
`--replace` accepts only an unchanged bundle carrying the generated
`.marty-selfhost-bundle.json` inventory and retains the previous directory in a
reported backup location. Choose a new archive basename for every run; existing
archives are never overwritten. Paths through symlinks/reparse points, repository
roots, source assets, and overlapping output/archive paths are rejected.

Bundle generation fails if the staged output contains Docker `build:` keys or mutable image tag aliases such as `latest`, `prod`, `main`, or `dev`.

Compose source files (including transitive `extends` inputs) are staged for
rendering and removed only from the generated bundle after flattening. The
extracted ZIP must render without the source checkout. Operator secret files
remain external; packaging does not load their values.

## First run (after a qualified image/bundle release)

1. Copy `.env.selfhost.production.example` to `.env.selfhost.production.local`.
2. For an unpinned bundle, set `SELFHOST_IMAGE_TAG` and
   `MARTY_ISSUANCE_IMAGE` (the exact matching issuance OCI digest). A
   digest-pinned bundle gets both image references from its qualified image
   lock; these two settings may be left unused. Set `PUBLIC_DOMAIN`,
   `PUBLIC_API_URL`, `UI_BASE_URL`, `BAO_ADDR`, `SELFHOST_STATE_DIR`,
   `CREDENTIAL_LOGIN_POLICY_ID`, and `MARTY_ORG_ADMIN_EMAIL` in
   `.env.selfhost.production.local`. For unpinned bundles the issuance image is
   intentionally empty; Compose rejects it until set. The operator must verify
   its URI and digest against the qualified stack manifest; Compose does not
   authenticate that match. The example `FLOW_CALLBACK_DESTINATIONS` maps the
   default `MARTY_ORG_ID` to Auth's internal Compose-network HTTP callback.
   Update it whenever the organization ID or internal Auth URL changes; Flow
   validates the callback registry at startup. External destinations require
   HTTPS.
	If the same stack also serves a secondary UI hostname, set `UI_ADDITIONAL_BASE_URLS` and include the same origin in `CORS_ORIGINS`; otherwise social-login callbacks from that host will fall back to `UI_BASE_URL`. Do not add a beta/staging hostname here when it has its own stack and Keycloak.
3. Copy `docker/secrets/selfhost.example` to a directory outside the bundle and set `SELFHOST_SECRET_DIR` to that directory.
4. Replace every required secret placeholder file.
5. Run `scripts/bootstrap-selfhost-vault.sh` with a bootstrap `BAO_TOKEN` or `BAO_TOKEN_FILE` to configure the external Vault/OpenBao instance and write `openbao_service_token`, or place an equivalent least-privilege token in `SELFHOST_SECRET_DIR` yourself:

   The bundled helper runs OpenBao 2.7.1 by its immutable multi-architecture image digest (`quay.io/openbao/openbao@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf`). This pins the helper executable, not the external OpenBao server or a qualified installed-bundle release.

```bash
BAO_ADDR=https://vault.example.com \
BAO_TOKEN_FILE=/path/to/bootstrap.token \
SELFHOST_SECRET_DIR=/path/to/selfhost-secrets \
./scripts/bootstrap-selfhost-vault.sh
```

6. Pull the published images:

```bash
docker compose --env-file .env.selfhost.production.local pull
```

7. Start the stack:

```bash
docker compose --env-file .env.selfhost.production.local up -d
```

## Useful commands

```bash
docker compose --env-file .env.selfhost.production.local ps
docker compose --env-file .env.selfhost.production.local logs -f edge cloudflared gateway keycloak
docker compose --env-file .env.selfhost.production.local down
```

## No-Canvas composition preview

`docker-compose.selfhost.no-canvas.yml` is an opt-in overlay for testing a
deployment without the Canvas worker. The default bundle still starts that
worker, preserving existing Canvas installations on upgrade. To inspect the
overlay against an extracted bundle, layer it explicitly:

```bash
docker compose --env-file .env.selfhost.production.local \
  -f docker-compose.yml -f docker-compose.selfhost.no-canvas.yml \
  config --hash canvas-sync-worker
```

Compose should report the worker as disabled. This is a configuration preview,
not a qualified no-Canvas product: issuance still carries Canvas secret,
migration, and code dependencies. Do not use the overlay for an existing Canvas
installation. Production use and a default switch require a pre-up migration
check, no-Canvas startup/business evidence, and a rehearsed upgrade/rollback.

## Notes

- The open-source services start without a commerce service or license gate.
- Set `CREDENTIAL_LOGIN_POLICY_ID=50000000-0000-0000-0000-000000000004` to enable the Keycloak **Present Open Badge Credential** flow.
- `scripts/check-selfhost-production.py` verifies that every `UI_BASE_URL`/`UI_ADDITIONAL_BASE_URLS` origin produces a matching `/v1/auth/callback` redirect before Google sign-in starts.
- Keep the real `SELFHOST_SECRET_DIR` outside any agent-visible workspace.
- Keep `SELFHOST_STATE_DIR` on durable host storage; that bind-mounted tree is the portable runtime dataset for backup and future cloud migration.
- The bundle expects an operator-managed external Vault/OpenBao endpoint. It does not ship an in-stack bootstrap vault anymore.
