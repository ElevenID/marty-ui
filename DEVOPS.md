# DevOps & Maintenance Runbook

## Secrets Management

### GitHub Actions — `REPO_ACCESS_TOKEN`

A classic Personal Access Token (PAT) is used for cross-repo operations in CI/CD.

| Repo | Purpose |
|------|---------|
| `ElevenID/marty-core` | `repository_dispatch` to marty-credentials and marty-verifier on release |
| `ElevenID/marty-ui` | Checkout private repos (marty-core, longfellow-zk, marty-credentials) in CD pipeline |

**Scopes:** `repo` (full)
**Owner:** `burdettadam`
**Rotation:** Check expiration date in [GitHub Settings > Tokens](https://github.com/settings/tokens). When expired:

```bash
# After creating a new PAT in the GitHub UI:
echo "<new-token>" | gh secret set REPO_ACCESS_TOKEN -R ElevenID/marty-core
echo "<new-token>" | gh secret set REPO_ACCESS_TOKEN -R ElevenID/marty-ui
```

### OCI Vault — Production Secrets

**Vault:** `marty-secrets` in `marty-production` compartment (us-phoenix-1)
**Encryption Key:** `marty-secrets-key` (AES-256)
**Management endpoint:** `https://efu4k54kaafau-management.kms.us-phoenix-1.oraclecloud.com`

Secrets stored (sourced from `.env.production`):

| Secret | Naming Pattern |
|--------|---------------|
| `CLOUDFLARE_TUNNEL_TOKEN` | `marty-prod-cloudflare-tunnel-token` |
| `IMAGE_TAG` | `marty-prod-image-tag` |
| `KEYCLOAK_ADMIN` | `marty-prod-keycloak-admin` |
| `KEYCLOAK_ADMIN_PASSWORD` | `marty-prod-keycloak-admin-password` |
| `KEYCLOAK_DB_PASSWORD` | `marty-prod-keycloak-db-password` |
| `MARTY_API_CLIENT_SECRET` | `marty-prod-marty-api-client-secret` |
| `OCIR_AUTH_TOKEN` | `marty-prod-ocir-auth-token` |
| `OCIR_REGISTRY` | `marty-prod-ocir-registry` |
| `OCIR_TENANCY_NAMESPACE` | `marty-prod-ocir-tenancy-namespace` |
| `OCI_REGION` | `marty-prod-oci-region` |
| `OCI_USERNAME` | `marty-prod-oci-username` |
| `POSTGRES_PASSWORD` | `marty-prod-postgres-password` |
| `RABBITMQ_ERLANG_COOKIE` | `marty-prod-rabbitmq-erlang-cookie` |
| `RABBITMQ_PASSWORD` | `marty-prod-rabbitmq-password` |
| `SESSION_SECRET_KEY` | `marty-prod-session-secret-key` |

**Retrieve a secret:**
```bash
oci secrets secret-bundle get --secret-id "$SECRET_ID" \
  --query 'data."secret-bundle-content".content' --raw-output | base64 -d
```

**Deploy script:** `scripts/fetch-secrets.sh` sources all secrets into shell env.

### Bitwarden — Team Credentials

**Account:** `admin@elevenidllc.com`
Stores service account passwords, API keys, and other shared credentials not suited for OCI Vault.

### Known Issues

- **OCI_REGION** is set to `us-ashburn-1` but should be `us-phoenix-1` — needs rotation in vault.

## CI/CD Pipelines

### marty-ui

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `ci.yml` | Push/PR to `main` | Lint (ruff), UI tests (bun/vitest), service tests (pytest) |
| `cd.yml` | Tag `v*` or manual dispatch | Builds marty-rs wheel, 3 Docker images (services, UI, db-migrate), pushes to GHCR |

**Images published to:**
- `ghcr.io/elevenid/marty-ui/services:<tag>`
- `ghcr.io/elevenid/marty-ui/ui:<tag>`
- `ghcr.io/elevenid/marty-ui/db-migrate:<tag>`

**Deploy from GHCR:**
```bash
IMAGE_TAG=<tag> docker compose -f docker-compose.base.yml -f docker-compose.profile.ghcr.yml up -d
```

### marty-core

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `release-rc.yml` | Tag or manual | Build, test, release RC, dispatch to marty-credentials + marty-verifier |
| `release-stable.yml` | Tag or manual | Build, test, release stable, dispatch to marty-credentials + marty-verifier |

### Other Repos

| Repo | CI Status | Notes |
|------|-----------|-------|
| marty-credentials | `ci.yml` — test-rust, security, test-python, test-wasm | Has git auth step for private Cargo deps |
| marty-verifier | `ci.yml` — test-rust, security | Has git auth step for private Cargo deps |
| marty-authenticator | `flutter_build.yml` | Triggers on `main` and `master` branches |
| marty-microservices-framework | Full CI + beta publish | Publishes to `pypi.pkg.github.com/ElevenID/` |
| marty-protocol | CI exists | Docs/specs repo |
| longfellow-zk | CI exists | C++ library |

## Periodic Maintenance

- [ ] **Rotate REPO_ACCESS_TOKEN** — check expiration, regenerate PAT, update both repo secrets
- [ ] **Fix OCI_REGION secret** — change from `us-ashburn-1` to `us-phoenix-1` in vault
- [ ] **Review GHCR image retention** — prune old untagged images periodically
- [ ] **Update GitHub Actions versions** — check for major version bumps in actions/checkout, docker/build-push-action, etc.
- [ ] **Renew Cloudflare tunnel token** — if/when it expires
