# Supported consumer passport callback signer gate

The production-mode signer uses shared Rust callback signing code plus a
supported-only provider HMAC verification route. The beta-only signer has no
provider verification route. Neither process activates physical ingress unless
its separate deployment selector is enabled.

The process starts only with `ENVIRONMENT=production` and
`PASSPORT_SUPPORTED_CALLBACK_SIGNER_ENABLED=true`. It reads a dedicated
`PASSPORT_CALLBACK_SIGNER_API_KEY_FILE` (at least 32 characters) and
`PASSPORT_CALLBACK_SIGNER_BAO_TOKEN_FILE`; plain environment credential values
and the ordinary `BAO_TOKEN` / `OPENBAO_SERVICE_TOKEN` are rejected. The
`SERVICE_NAME` is `passport_callback_signer_supported`. It binds port 8018
unless `PASSPORT_CALLBACK_SIGNER_BIND` is set.

`docker/openbao-init.sh` defines `passport-provider-callback-service` with
`create` and `update` on the internal callback HMAC key and verify-only access
to `transit/verify/passport-provider-callback-*`. It cannot generate a provider
HMAC, read/export a key, or use generic transit signing. The beta-only signer
retains the separate `passport-callback-hmac-service` policy.
`scripts/bootstrap-selfhost-vault.sh` can mint a separate token in
`passport_callback_signer_bao_token`. Before any supported deployment, verify
the actual mounted token's policy and effective capabilities against the live
OpenBao instance. A token bearing the general `credential-service` policy, key
read/export rights, or other transit signing rights fails this gate. Source
configuration alone cannot prove the permissions of a supplied token.

For each base, selfhost, and K8s consumer, the deployment review must show a
trusted ingress as the only peer holding the signer API key, a private network
connecting that ingress and signer, and no host port or gateway route to the
sign endpoint. The ingress must not receive the OpenBao token. No runtime
service mounts the provider HMAC source key. Import it under the
profile-derived, non-exportable Transit reference with
`scripts/import_passport_provider_hmac.sh`; configure ingress with the returned
key version. Ingress sends exact provider bytes and signature to the private
verifier before parsing or job lookup. Rolling back disables ingress and signer
together without restoring a local-key or Python owner.
