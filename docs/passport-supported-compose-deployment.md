# Supported physical bureau callback Compose bindings

These overlays stage the production-mode Rust callback path without changing the
normal base or selfhost composition. Use the matching overlay only after a
physical bureau profile and its API endpoint are accepted and the provider's
raw-body HMAC key is imported into OpenBao. The profile ID must match the durable job
binding. The callback signer is a separate process and uses the shared Rust
signer code; it never uses the beta signer process.

For the base stack, compose with `docker-compose.base.yml` and
`docker-compose.profile.passport-provider-base.yml`. Set
`PASSPORT_PROVIDER_SECRET_DIR` to a directory containing
`passport_callback_signer_api_key`,
`passport_callback_signer_bao_token`, and `marty_db_password`. The last file must
match the base PostgreSQL password. The base OpenBao container joins the
internal callback network. Its callback token must have only the
`passport-provider-callback-service` policy, even when the base OpenBao container is
in dev mode.

For the selfhost stack, compose with `docker-compose.selfhost.prod.yml` and
`docker-compose.profile.passport-provider-selfhost.yml`. The same three files
reside in `SELFHOST_SECRET_DIR`; the bootstrap script can mint
`passport_callback_signer_bao_token`. Set `BAO_ADDR` to the external OpenBao
address. The signer uses outbound access to that address and receives the
dedicated token; ingress has no OpenBao token. Neither overlay publishes the
signer or ingress port.

Set `MARTY_SERVICES_IMAGE` to the reviewed immutable shared-image digest and
`PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID` to the registered physical bureau
profile, and `PASSPORT_PROVIDER_HMAC_KEY_VERSION` to the version returned by
`scripts/import_passport_provider_hmac.sh`. The provider key source file is
never mounted in an application container. Verify the actual OpenBao token's
policy and effective capabilities; source files alone cannot establish them.
The signer API key must have at least 32 characters and differ from the normal
signing credential.
The ingress and signer fail at startup if their required files are missing.

The gateway selector remains off after adding either overlay. Only after a
physical-provider acceptance run, set
`PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED=true` and
`PASSPORT_PROVIDER_INGRESS_SERVICE_URL=http://passport-provider-ingress:8021`
for the selected stack. Keep the native callback and KMS gates enabled for the
same accepted environment. Roll back by disabling the gateway selector first,
then removing the overlay; never restore a local-key or Python callback owner.
