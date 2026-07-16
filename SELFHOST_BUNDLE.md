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

The bundle pulls the published self-host images instead of building from source.

- `SELFHOST_IMAGE_PREFIX=ghcr.io/elevenid/marty-ui`
- `SELFHOST_IMAGE_TAG=<released-version>`

The UI service uses the published `ui-selfhost` image variant, which excludes the public marketing and blog surface from the self-host product bundle.

Set `SELFHOST_IMAGE_TAG` to the released immutable version you want to run. Do not use `latest` or `--build` with the bundle.

Operators publish the images from a local workstation with `make selfhost-images-build-push TAG=<released-version>`, generate release artifacts with `make selfhost-images-release-artifacts TAG=<released-version>`, sign/verify with the Cosign targets, then stage this bundle with `make package-selfhost-bundle`.

Bundle generation fails if the staged output contains Docker `build:` keys or mutable image tag aliases such as `latest`, `prod`, `main`, or `dev`.

## First run

1. Copy `.env.selfhost.production.example` to `.env.selfhost.production.local`.
2. Set `SELFHOST_IMAGE_TAG`, `PUBLIC_DOMAIN`, `PUBLIC_API_URL`, `UI_BASE_URL`, `BAO_ADDR`, `SELFHOST_STATE_DIR`, `CREDENTIAL_LOGIN_POLICY_ID`, and `MARTY_ORG_ADMIN_EMAIL` in `.env.selfhost.production.local`.
	If the same stack also serves a secondary UI hostname, set `UI_ADDITIONAL_BASE_URLS` and include the same origin in `CORS_ORIGINS`; otherwise social-login callbacks from that host will fall back to `UI_BASE_URL`. Do not add a beta/staging hostname here when it has its own stack and Keycloak.
3. Copy `docker/secrets/selfhost.example` to a directory outside the bundle and set `SELFHOST_SECRET_DIR` to that directory.
4. Replace every required secret placeholder file.
5. Run `scripts/bootstrap-selfhost-vault.sh` with a bootstrap `BAO_TOKEN` or `BAO_TOKEN_FILE` to configure the external Vault/OpenBao instance and write `openbao_service_token`, or place an equivalent least-privilege token in `SELFHOST_SECRET_DIR` yourself:

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

## Notes

- The open-source services start without a commerce service or license gate.
- Set `CREDENTIAL_LOGIN_POLICY_ID=50000000-0000-0000-0000-000000000004` to enable the Keycloak **Present Open Badge Credential** flow.
- `scripts/check-selfhost-production.py` verifies that every `UI_BASE_URL`/`UI_ADDITIONAL_BASE_URLS` origin produces a matching `/v1/auth/callback` redirect before Google sign-in starts.
- Keep the real `SELFHOST_SECRET_DIR` outside any agent-visible workspace.
- Keep `SELFHOST_STATE_DIR` on durable host storage; that bind-mounted tree is the portable runtime dataset for backup and future cloud migration.
- The bundle expects an operator-managed external Vault/OpenBao endpoint. It does not ship an in-stack bootstrap vault anymore.
