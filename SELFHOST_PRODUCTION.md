# Self-Hosted Production Stack

This stack is for running a production-like Marty deployment on the same machine as the dev stack and the integration-test containers without port, network, or volume collisions.

## What is isolated

- Compose project name: `marty-selfhost-prod`
- Local edge/UI port: `19080` by default, bound to `127.0.0.1`
- Local gateway port: `18000` by default, bound to `127.0.0.1`
- Local Keycloak admin port: `18180` by default, bound to `127.0.0.1`
- Persistent host bind mounts under `SELFHOST_STATE_DIR` for Postgres, Redis, and applicant storage
- Standalone OpenBao state and exports under `SELFHOST_OPENBAO_STATE_DIR` and `SELFHOST_OPENBAO_EXPORT_DIR`
- Dedicated Cloudflare tunnel sidecar driven by its own env file
- Optional same-stack beta tunnel sidecars for the rare case where `beta.elevenidllc.com` should intentionally route to this same self-host edge and Keycloak

## Config boundary map

To avoid cross-domain redirect and OIDC drift between environments, use the scoped layout in [deploy-config/README.md](deploy-config/README.md).

- Selfhost production guidance: [deploy-config/env/selfhost-production/README.md](deploy-config/env/selfhost-production/README.md)
- Tunnel beta guidance: [deploy-config/env/tunnel-beta/README.md](deploy-config/env/tunnel-beta/README.md)

## What is production-specific

- `MARTY_MIGRATION_PROFILE=selfhost-production` skips demo/beta seed data and keeps the shipped applicant catalog limited to the Open Badge login credential
- The Marty default org migrations still run
- Persistent self-host databases should treat released migrations as immutable; if a seeded system artifact is wrong, ship a forward repair migration instead of editing historical revisions. See [docs/MIGRATION_GOVERNANCE.md](docs/MIGRATION_GOVERNANCE.md).
- The Marty admin seed still runs, but you must change `MARTY_ORG_ADMIN_EMAIL` to a customer-controlled address before the first migration run
- Keycloak cleanup removes the demo human users after realm import
- Keycloak client redirect/web origins are replaced from `UI_BASE_URL` plus `UI_ADDITIONAL_BASE_URLS` by default, which prevents stale beta/staging callbacks from lingering after a hostname is moved to another stack
- Trust-profile and issuance use an operator-managed external Vault/OpenBao endpoint instead of an in-stack bootstrap vault
- Docker Compose secrets mount files into `/run/secrets/*`, and the self-host wrappers load them into the exact processes that need them
- Docker Compose bind-mounts the runtime state from `SELFHOST_STATE_DIR`, so the database, Redis append-only data, and applicant storage stay portable on the host filesystem
- The standalone OpenBao compose project bind-mounts its file backend and recovery material from `SELFHOST_OPENBAO_STATE_DIR`, so it survives reboot and ordinary Docker cleanup the same way
- The self-host startup scripts fail fast if required secret files still contain placeholder `change-me` values
- The self-host application and migration containers validate the signed license before startup and default to requiring `plan_tier=system`
- Only the scoped vault service token is mounted into application containers; bootstrap or root credentials stay outside the stack
- The gateway rate limiter defaults to `300` requests per minute unless you explicitly override it

## How secrets work

This self-host stack now uses Docker Compose `secrets:` for sensitive values. On local Docker Compose, that means the secret files are mounted read-only into the container instead of being stored in the tracked env file.

- Non-secret settings stay in `.env.selfhost.production.local`
- Secret values live in files under `SELFHOST_SECRET_DIR`
- Docker mounts those files at `/run/secrets/*`
- The self-host wrapper scripts export the final environment variables before the target process starts
- Runtime state lives under `SELFHOST_STATE_DIR`, which should also live outside the repo so Docker bind-mounts survive reboot and `docker system prune`
- Standalone OpenBao state lives under `SELFHOST_OPENBAO_STATE_DIR`, and OpenBao export archives go under `SELFHOST_OPENBAO_EXPORT_DIR`

This is better than a plaintext `.env.production`, but it is still file-backed local secret handling. It is not the same thing as a remote secret manager or Swarm/Kubernetes encrypted-at-rest secret store.

It also does not protect secrets from an AI agent if the real secret directory lives inside the agent-visible workspace. If the agent can read the workspace, and the real secret files are in that workspace, the agent can read them too.

For agent-safe use, keep the real `SELFHOST_SECRET_DIR` outside the repo and outside any folder exposed to the agent session. The tracked directory under `docker/secrets/selfhost.example` is only a placeholder template.

For prune-safe persistence and future cloud transfer, keep `SELFHOST_STATE_DIR` and `SELFHOST_OPENBAO_STATE_DIR` outside the repo as well. Because Postgres, Redis, applicant storage, and the standalone OpenBao backend are bind-mounted from host directories, they survive reboots and ordinary Docker cleanup, and you can later copy or synchronize that directory tree to another host or managed storage service.

## Customer bundle export

To stage the image-based customer bundle from this repo:

```bash
python scripts/package-selfhost-bundle.py
```

That writes `dist/selfhost-bundle` with the runtime assets, secret templates, Keycloak import files, and a generated `docker-compose.yml` that already targets the published images. Use the `README.md` inside that staged bundle for customer-facing pull and startup commands.

## First run

1. Copy `.env.selfhost.production.example` to `.env.selfhost.production.local`
2. Create external host directories for `SELFHOST_SECRET_DIR`, `SELFHOST_STATE_DIR`, `SELFHOST_BACKUP_DIR`, `SELFHOST_OPENBAO_STATE_DIR`, and `SELFHOST_OPENBAO_EXPORT_DIR`
3. Copy `docker/secrets/selfhost.example` to `SELFHOST_SECRET_DIR`
4. Replace the required secret file contents in that external directory
5. Install the signed license as `license_key` inside that external directory. The CLI validates the license against the Marty issuer public key embedded in the runtime package; it does not mint a license locally:

```bash
cat /path/to/customer-license.jwt | node ../marty-cli/bin/marty.js license install-selfhost \
	--env-file .env.selfhost.production.local \
	--token-stdin
```

On PowerShell, the same flow is:

```powershell
Get-Content C:\path\to\customer-license.jwt -Raw | node ..\marty-cli\bin\marty.js license install-selfhost --env-file .env.selfhost.production.local --token-stdin
```

If you are operating as the issuer yourself, use the internal issuer tool in [tools/selfhost-license-issuer/README.md](../tools/selfhost-license-issuer/README.md) to generate the Ed25519 signing keypair outside the repo and write a signed license directly into `SELFHOST_SECRET_DIR` without printing the JWT. On this workstation, keep the private key under `../marty-selfhost-prod/license-issuer/keys`, adjacent to but not inside `SELFHOST_SECRET_DIR`. The runtime public key remains build-time trusted material; `--public-key-file` is only a dev/test override for validating alternate issuer keys before they are embedded in a release image.

6. Start the standalone OpenBao stack described in [SELFHOST_OPENBAO.md](SELFHOST_OPENBAO.md), or set `BAO_ADDR` to another container-reachable external Vault/OpenBao address if you already run one elsewhere
7. If you are not using the standalone OpenBao compose project, use `scripts/bootstrap-selfhost-vault.sh` with a bootstrap token to configure the external vault and write `openbao_service_token` into `SELFHOST_SECRET_DIR`, or place an equivalent least-privilege token there yourself:

```bash
BAO_ADDR=https://vault.example.com \
BAO_TOKEN_FILE=/path/to/bootstrap.token \
SELFHOST_SECRET_DIR=/path/to/selfhost-secrets \
./scripts/bootstrap-selfhost-vault.sh
```

8. Set the non-secret production settings such as hostname, ports, host state directories, optional integrations, `MARTY_ORG_ADMIN_EMAIL`, and any license policy overrides
9. Set `CREDENTIAL_LOGIN_POLICY_ID=50000000-0000-0000-0000-000000000004` so the Keycloak **Present Open Badge Credential** flow points at the seeded OpenBadgeLogin policy
10. Build the UI bundle on the host:

```bash
cd ui
npm ci
npm run build:selfhost
cd ..
```

11. Start the stack:

```bash
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml up -d --build
```

## Make targets

If you prefer a shorter operator surface, [Makefile](Makefile) now includes self-host production targets. These require GNU make.

```bash
make selfhost-prod-license-init-keypair
make selfhost-prod-license-issue
make selfhost-prod-openbao-up
make selfhost-prod-ui-build
make selfhost-prod-up
make selfhost-prod-check
make selfhost-prod-ps
make selfhost-prod-logs
make selfhost-prod-down
```

The recommended same-machine bootstrap path is:

```bash
make selfhost-prod-license-issue
make selfhost-prod-bootstrap
make selfhost-prod-check
```

## Required secret files

Create these files under `SELFHOST_SECRET_DIR`:

- `postgres_password`
- `keycloak_db_password`
- `marty_db_password`
- `keycloak_admin_password`
- `marty_api_client_secret`
- `issuance_api_key`
- `openbao_service_token`
- `cloudflare_tunnel_token`
- `cloudflare_beta_tunnel_token` when you enable the optional `beta-tunnel` compose profile
- `license_key`

The stack will refuse to start if any required secret file still contains a placeholder value such as `change-me-postgres`.

The default self-host policy is controlled with non-secret env vars in `.env.selfhost.production.local`:

- `MARTY_LICENSE_ENFORCEMENT=required`
- `MARTY_LICENSE_REQUIRED_ISSUER=marty-license-issuer`
- `MARTY_LICENSE_REQUIRED_PLAN_TIER=system`
- `MARTY_LICENSE_REQUIRED_PRODUCTS=ui-app`
- `CREDENTIAL_LOGIN_POLICY_ID=50000000-0000-0000-0000-000000000004`

`CREDENTIAL_LOGIN_POLICY_ID` is the seeded OpenBadgeLogin presentation policy used by the Keycloak **Present Open Badge Credential** button. If it is blank, the auth service now shows a friendly HTML error page, and `scripts/check-selfhost-production.py` will flag the deployment as incomplete.

`license_key` is not a locally generated password. It is a signed license token issued by the licensing authority. The issuer's PEM-encoded Ed25519 public key is embedded in the self-host runtime image, and the CLI command above validates the token against the configured issuer, required plan tier, and required product set before writing it into `SELFHOST_SECRET_DIR`.

These can be blank if you are not using the integration:

- `google_client_id`
- `google_client_secret`
- `google_analytics_measurement_id`
- `google_site_verification`
- `smtp_password`
- `square_access_token`
- `square_webhook_signature_key`

`google_client_id` and `google_client_secret` are the OAuth web client credentials used by Keycloak's Google identity provider. When `KEYCLOAK_SOCIAL_LOGIN_ENABLED=true`, both files must contain real values and the Google Cloud OAuth web client must allow this redirect URI:

```text
https://<PUBLIC_DOMAIN>/realms/<KEYCLOAK_REALM>/broker/google/endpoint
```

For the ElevenID self-host deployment, that callback is:

```text
https://elevenidllc.com/realms/11id/broker/google/endpoint
```

`google_analytics_measurement_id` is the GA4 `G-...` measurement ID. It is public by nature, but the self-host UI startup wrapper can read it from `SELFHOST_SECRET_DIR` and expose it to the SPA at container start.

`google_site_verification` is the Google Search Console verification token. It is also public by nature, but the self-host UI startup wrapper can inject it into the served `index.html` at container start.

## Persistent host state

The self-host compose file now stores runtime state in host bind mounts under `SELFHOST_STATE_DIR`:

- `postgres/` for the PostgreSQL data directory
- `redis/` for Redis append-only persistence
- `applicant/` for applicant-side file data

This is the state you should preserve for reboot recovery, host migration, and future cloud transfer. Keep that directory tree on durable storage and treat `SELFHOST_BACKUP_DIR` as the place to stage database dumps or file archives before copying them to cloud storage.

## Persistent OpenBao state

The standalone OpenBao deployment keeps its file backend and recovery material in `SELFHOST_OPENBAO_STATE_DIR`.

- Keep that directory on durable storage
- Treat it as production-secret material because it contains init, root-token, and unseal-key data
- Use `SELFHOST_OPENBAO_EXPORT_DIR` to stage export archives created with `python scripts/export-selfhost-openbao.py --env-file .env.selfhost.production.local`

See [SELFHOST_OPENBAO.md](SELFHOST_OPENBAO.md) for the compose file and recovery flow.

## Cloudflare tunnel routing

Configure the production Cloudflare tunnel hostname to target `http://edge:80` inside this compose project. Keep the existing beta/dev hostname pointed at the beta/dev tunnel stack when beta has its own Keycloak.

If `beta.elevenidllc.com` should point at the same self-host production edge, keep the primary tunnel on `http://edge:80` and start the optional beta tunnel profile. The beta Cloudflare tunnel should target `http://tunnel-nginx-proxy:80`; the proxy preserves the incoming `Host` header and forwards traffic to the self-host `edge` service.

Do **not** start the optional self-host beta tunnel profile when beta is a separate environment with its own Keycloak. In that case, beta traffic must use the normal beta tunnel stack, and production `UI_ADDITIONAL_BASE_URLS`/`CORS_ORIGINS` must not include the beta origin.

1. Put the beta Cloudflare tunnel token in `SELFHOST_SECRET_DIR/cloudflare_beta_tunnel_token`.
2. Set `UI_ADDITIONAL_BASE_URLS=https://beta.elevenidllc.com` and include beta in `CORS_ORIGINS`.
3. Start the sidecars:

```bash
make selfhost-prod-beta-tunnel-up
```

The default `selfhost-prod-up` target does not start the beta profile automatically, so customer deployments that only serve one hostname keep the simpler single-tunnel shape.

The auth service intentionally trusts only configured UI origins when it builds the OIDC callback URL. If beta is omitted from both `UI_ADDITIONAL_BASE_URLS` and `CORS_ORIGINS`, `/v1/auth/login` will fall back to `UI_BASE_URL` and Google sign-in will return users to the primary production hostname.

The host-published edge, gateway, and Keycloak ports in this reference stack are loopback-only by default. Keep them that way unless you have a separate reason to expose them directly and have already put host firewall and TLS controls in place.

The external issuer for auth should be the same public hostname served by the edge proxy, for example:

```text
PUBLIC_DOMAIN=prod.example.com
OIDC_ISSUER_URL_EXTERNAL=https://prod.example.com/realms/11id
```

## Useful commands

```bash
make selfhost-prod-config
make selfhost-prod-check
make selfhost-prod-openbao-ps
make selfhost-prod-openbao-export
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml ps
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml logs -f edge cloudflared gateway keycloak
docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml down
```

## Operational note for OpenBao

This stack no longer runs an in-cluster bootstrap vault. The operator-managed Vault/OpenBao endpoint at `BAO_ADDR` must already be initialized, unsealed, and reachable from the Docker network before trust-profile and issuance start.

For the same-machine production scaffold, the recommended path is the standalone compose project in [SELFHOST_OPENBAO.md](SELFHOST_OPENBAO.md), which publishes OpenBao on `127.0.0.1:${SELFHOST_OPENBAO_HOST_PORT}` and keeps `BAO_ADDR=http://host.docker.internal:${SELFHOST_OPENBAO_HOST_PORT}` for the application containers.

Use `scripts/bootstrap-selfhost-vault.sh` when you want the repo to configure the required transit, PKI, KV, and `credential-service` policy against another existing external Vault/OpenBao instance and mint the scoped runtime token into `SELFHOST_SECRET_DIR/openbao_service_token`. The bootstrap credential used for that helper should stay outside the stack and outside the tracked secret directory.