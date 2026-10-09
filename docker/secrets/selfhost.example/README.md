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
- `grpc_service_token`
- `notification_webhook_secret`
- `notification_applicant_event_token`
- `workload_identity_ca_cert`
- `signing_keys_workload_server_cert`
- `signing_keys_workload_server_key`
- `pp_workload_server_cert`
- `pp_workload_server_key`
- `flow_workload_client_cert`
- `flow_workload_client_key`
- `flow_workload_server_cert`
- `flow_workload_server_key`
- `auth_workload_client_cert`
- `auth_workload_client_key`
- `applicant_workload_client_cert`
- `applicant_workload_client_key`
- `verification_workload_client_cert`
- `verification_workload_client_key`
- `deployment_profile_workload_client_cert`
- `deployment_profile_workload_client_key`
- `compliance_profile_workload_client_cert`
- `compliance_profile_workload_client_key`
- `flow_application_event_hmac_key`
- `flow_webhook_secret`
- `token_hmac_key`
- `openbao_service_token`
- `signing_keys_openbao_token`
- `didcomm_issuance_openbao_token`
- `notification_openbao_token`
- `haip_kms_token`
- `cloudflare_tunnel_token`

`flow_webhook_secret` authenticates verification-completion callbacks between the flow and auth services. Generate a random value of at least 32 bytes and use the same secret for both services.

`openbao_service_token` should contain the scoped `credential-service` token for your operator-managed external Vault/OpenBao instance. The helper script `scripts/bootstrap-selfhost-vault.sh` can create it from a bootstrap token without keeping the bootstrap credential in the stack.

`signing_keys_openbao_token` is a distinct token with `credential-service` and `signing-keys-managed` policies, issued without the default policy. Only signing-keys receives managed key create/rotate access. The bootstrap scripts mint it; an external OpenBao operator must supply an equivalent scoped token.

The Signing Keys TLS certificate must chain to `workload_identity_ca_cert` and
contain the `signing-keys` DNS name. Its key terminates the private
integration-secret transport and is distinct from every non-exportable KMS
application key. Rotate it with the CA/trust file and restart Signing Keys,
native Issuance, and the Canvas worker together so cached TLS clients adopt
the new trust root.

`didcomm_issuance_openbao_token` is a separate token with only the `didcomm-issuance` policy and no default policy. Native Issuance uses it to read public sender versions and request complete authcrypt envelopes; key creation and rotation remain operator operations. The self-host OpenBao bootstrap mints it after mounting the DIDComm plugin. An external operator must provide the equivalent policy and token.

`notification_openbao_token` is the narrower `notification-webhook-service` token. Only the Notification workload receives it; other services and the migration job must not mount it.

`haip_kms_token` is the dedicated OpenBao plugin token for HAIP response-key creation and decryption. The self-host OpenBao bootstrap mints it without the default policy from `docker/openbao-haip-workload-policy.hcl`; only signing-keys receives it. An external OpenBao operator must provision an equivalent token and policy before starting the stack.

`flow_application_event_hmac_key` is a distinct random value of at least 32
bytes shared only by the Applicant and Flow services. It authenticates approval
events that can create credential offers; do not reuse `grpc_service_token`.

Optional files may be left empty when the related integration is disabled:

- `canvas_credentials_shared_secret`
- `cloudflare_beta_tunnel_token`
- `google_client_id`
- `google_client_secret`
- `google_analytics_measurement_id`
- `google_site_verification`
- `smtp_password`

`canvas_credentials_shared_secret` signs Canvas credential-sync callbacks between the Canvas integration surface and issuance service. Leave it empty when Canvas integration is disabled.

Canvas Credentials API tokens are configured by organization administrators from the Canvas integration wizard. Issuance stores them in purpose-bound envelopes encrypted by the remote KMS through signing-keys; do not put institution-specific Canvas Credentials bearer tokens in self-host deployment secret files.

The standalone read-only Canvas Credentials contract checker can still read `CANVAS_CREDENTIALS_API_TOKEN` or `CANVAS_CREDENTIALS_API_TOKEN_FILE` from an operator shell for one-off vendor sandbox validation.

`cloudflare_beta_tunnel_token` is only required when the optional self-host `beta-tunnel` compose profile is enabled to route a second Cloudflare tunnel, such as `beta.elevenidllc.com`, into the same self-host edge.

`google_client_id` and `google_client_secret` are the OAuth web client credentials used by Keycloak's Google identity provider.

`google_analytics_measurement_id` is the GA4 `G-...` measurement ID. It is public by nature, but the self-host UI startup wrapper can read it from the secret directory for operator convenience.

`google_site_verification` is the Google Search Console verification token. It is also public by nature, but the self-host UI startup wrapper can inject it from the secret directory into the served `index.html`.
