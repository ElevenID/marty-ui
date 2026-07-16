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
- `integration_secret_master_key`
- `openbao_service_token`
- `cloudflare_tunnel_token`

`openbao_service_token` should contain the scoped `credential-service` token for your operator-managed external Vault/OpenBao instance. The helper script `scripts/bootstrap-selfhost-vault.sh` can create it from a bootstrap token without keeping the bootstrap credential in the stack.

`integration_secret_master_key` is a base64-encoded 32-byte AES key used by issuance to encrypt organization-managed integration secrets, such as Canvas Credentials API tokens. Generate it with:

```bash
python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
```

Optional files may be left empty when the related integration is disabled:

- `canvas_credentials_shared_secret`
- `cloudflare_beta_tunnel_token`
- `google_client_id`
- `google_client_secret`
- `google_analytics_measurement_id`
- `google_site_verification`
- `smtp_password`

`canvas_credentials_shared_secret` signs Canvas credential-sync callbacks between the Canvas integration surface and issuance service. Leave it empty when Canvas integration is disabled.

Canvas Credentials API tokens are configured by organization administrators from the Canvas integration wizard. Issuance stores them as encrypted integration secrets using `integration_secret_master_key`; do not put institution-specific Canvas Credentials bearer tokens in self-host deployment secret files.

The standalone read-only Canvas Credentials contract checker can still read `CANVAS_CREDENTIALS_API_TOKEN` or `CANVAS_CREDENTIALS_API_TOKEN_FILE` from an operator shell for one-off vendor sandbox validation.

`cloudflare_beta_tunnel_token` is only required when the optional self-host `beta-tunnel` compose profile is enabled to route a second Cloudflare tunnel, such as `beta.elevenidllc.com`, into the same self-host edge.

`google_client_id` and `google_client_secret` are the OAuth web client credentials used by Keycloak's Google identity provider.

`google_analytics_measurement_id` is the GA4 `G-...` measurement ID. It is public by nature, but the self-host UI startup wrapper can read it from the secret directory for operator convenience.

`google_site_verification` is the Google Search Console verification token. It is also public by nature, but the self-host UI startup wrapper can inject it from the secret directory into the served `index.html`.
