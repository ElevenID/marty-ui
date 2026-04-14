# Self-Host Production Checklist

Use this checklist for the workstation-local production self-host setup and for future customer handoff.

## Host Paths

- [ ] `SELFHOST_SECRET_DIR` is outside the workspace
- [ ] `SELFHOST_STATE_DIR` is outside the workspace
- [ ] `SELFHOST_BACKUP_DIR` exists for staged backups and export archives
- [ ] `SELFHOST_OPENBAO_STATE_DIR` is outside the workspace
- [ ] `SELFHOST_OPENBAO_EXPORT_DIR` exists for OpenBao export archives
- [ ] `SELFHOST_STATE_DIR/postgres` exists
- [ ] `SELFHOST_STATE_DIR/redis` exists
- [ ] `SELFHOST_STATE_DIR/applicant` exists
- [ ] `SELFHOST_OPENBAO_STATE_DIR` exists

## Secret Material

- [ ] `postgres_password` exists and is non-placeholder
- [ ] `keycloak_db_password` exists and is non-placeholder
- [ ] `marty_db_password` exists and is non-placeholder
- [ ] `keycloak_admin_password` exists and is non-placeholder
- [ ] `marty_api_client_secret` exists and is non-placeholder
- [ ] `issuance_api_key` exists and is non-placeholder
- [ ] `openbao_service_token` exists and came from the external Vault/OpenBao bootstrap helper or an equivalent operator flow
- [ ] `cloudflare_tunnel_token` exists and came from Cloudflare Zero Trust
- [ ] `license_key` exists and came from the signed license issuer flow
- [ ] `license_public_key` exists and matches the issuer for `license_key`
- [ ] `node ../marty-cli/bin/marty.js license install-selfhost --env-file .env.selfhost.production.local --token-file ... --public-key-file ...` passes before deployment

## Non-Secret Config

- [ ] `.env.selfhost.production.local` points `SELFHOST_SECRET_DIR` at the external secret directory
- [ ] `.env.selfhost.production.local` points `SELFHOST_STATE_DIR` at the external host state directory
- [ ] `.env.selfhost.production.local` points `SELFHOST_BACKUP_DIR` at the backup/export directory
- [ ] `.env.selfhost.production.local` points `SELFHOST_OPENBAO_STATE_DIR` at the external OpenBao state directory
- [ ] `.env.selfhost.production.local` points `SELFHOST_OPENBAO_EXPORT_DIR` at the external OpenBao export directory
- [ ] `PUBLIC_DOMAIN`, `PUBLIC_API_URL`, and `UI_BASE_URL` are set for the production hostname
- [ ] `BAO_ADDR` points at the operator-managed external Vault/OpenBao endpoint
- [ ] `MARTY_ORG_ADMIN_EMAIL` is set to a customer-controlled address
- [ ] License policy settings match the intended production entitlement

## Build And Launch

- [ ] `docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.openbao.yml config` passes
- [ ] `docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.openbao.yml up -d` completes if using the local standalone OpenBao deployment
- [ ] `npm run build:selfhost` passes in `ui/`
- [ ] `docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml config` passes
- [ ] `docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml up -d --build` completes
- [ ] `docker compose --env-file .env.selfhost.production.local -f docker-compose.selfhost.prod.yml ps` shows healthy core services

## Recovery And Transfer

- [ ] The operator understands that Docker restarts the containers with `restart: unless-stopped`
- [ ] The operator understands that bind-mounted state under `SELFHOST_STATE_DIR` survives reboot and ordinary Docker cleanup
- [ ] The operator understands that bind-mounted OpenBao state under `SELFHOST_OPENBAO_STATE_DIR` survives reboot and ordinary Docker cleanup
- [ ] A backup procedure exists for copying `SELFHOST_STATE_DIR` into `SELFHOST_BACKUP_DIR`
- [ ] `python scripts/export-selfhost-openbao.py --env-file .env.selfhost.production.local` succeeds and the resulting archive is protected like production secrets
- [ ] A future cloud migration plan exists for transferring `SELFHOST_STATE_DIR`, `SELFHOST_OPENBAO_STATE_DIR`, `.env.selfhost.production.local`, and the secret directory through a secure channel