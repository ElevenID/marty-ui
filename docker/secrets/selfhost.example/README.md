# Self-Host Docker Compose Secret Files

These files are placeholders for the self-host deployment.

- Copy this directory to a location outside the workspace
- Put real secret values into the copied files
- Point `SELFHOST_SECRET_DIR` in `.env.selfhost.production.local` at that copied directory
- The container wrapper scripts read the mounted secret files and export the real environment variables before starting the app process

The self-host startup scripts intentionally fail if a required secret file is still blank or still uses the shipped `change-me...` placeholder values.

Do not keep the real secret directory under this repo if an AI agent can read the workspace. Docker Compose secrets on a local machine are still ordinary host files; they are not hidden from tools that can read the same directory.

Required files:

- `postgres_password`
- `keycloak_db_password`
- `marty_db_password`
- `keycloak_admin_password`
- `marty_api_client_secret`
- `issuance_api_key`
- `openbao_service_token`
- `cloudflare_tunnel_token`
- `license_key`

`openbao_service_token` should contain the scoped `credential-service` token for your operator-managed external Vault/OpenBao instance. The helper script `scripts/bootstrap-selfhost-vault.sh` can create it from a bootstrap token without keeping the bootstrap credential in the stack.

`license_key` is a signed commercial entitlement token. The issuer public verification key is embedded in the Marty self-host runtime image; customer deployments must not provide a replacement public key.

Optional files may be left empty when the related integration is disabled:

- `canvas_credentials_shared_secret`
- `canvas_credentials_api_token`
- `cloudflare_beta_tunnel_token`
- `google_client_id`
- `google_client_secret`
- `google_analytics_measurement_id`
- `google_site_verification`
- `smtp_password`
- `square_access_token`
- `square_webhook_signature_key`

`canvas_credentials_shared_secret` signs Canvas credential-sync callbacks between the Canvas integration surface and issuance service. Leave it empty when Canvas integration is disabled.

`canvas_credentials_api_token` is the organization-managed Canvas Credentials API bearer token used when `CANVAS_CREDENTIALS_PROVIDER=badgr_api`. It is not issuer signing key material; ElevenID still signs canonical credentials through the configured remote key store.

`cloudflare_beta_tunnel_token` is only required when the optional self-host `beta-tunnel` compose profile is enabled to route a second Cloudflare tunnel, such as `beta.elevenidllc.com`, into the same self-host edge.

`google_client_id` and `google_client_secret` are the OAuth web client credentials used by Keycloak's Google identity provider.

`google_analytics_measurement_id` is the GA4 `G-...` measurement ID. It is public by nature, but the self-host UI startup wrapper can read it from the secret directory for operator convenience.

`google_site_verification` is the Google Search Console verification token. It is also public by nature, but the self-host UI startup wrapper can inject it from the secret directory into the served `index.html`.
