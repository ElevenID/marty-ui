# Supported consumer passport callback signer gate

The production-mode signer uses the shared Rust `isolated_signer_router` and is
separate from the beta-only signer. This source path does not activate a
physical bureau ingress or replace Python callback ownership.

The process starts only with `ENVIRONMENT=production` and
`PASSPORT_SUPPORTED_CALLBACK_SIGNER_ENABLED=true`. It reads a dedicated
`PASSPORT_CALLBACK_SIGNER_API_KEY_FILE` (at least 32 characters) and
`PASSPORT_CALLBACK_SIGNER_BAO_TOKEN_FILE`; plain environment credential values
and the ordinary `BAO_TOKEN` / `OPENBAO_SERVICE_TOKEN` are rejected. The
`SERVICE_NAME` is `passport_callback_signer_supported`. It binds port 8018
unless `PASSPORT_CALLBACK_SIGNER_BIND` is set.

`docker/openbao-init.sh` defines `passport-callback-hmac-service` with only
`create` and `update` on
`transit/hmac/passport-bureau-callback-marty-hmac`.
`scripts/bootstrap-selfhost-vault.sh` can mint a separate token in
`passport_callback_signer_bao_token`. Before any supported deployment, verify
the actual mounted token's policy and effective capabilities against the live
OpenBao instance. A token bearing the general `credential-service` policy, key
read/export rights, or other transit signing rights fails this gate. Source
configuration alone cannot prove the permissions of a supplied token.

For each base, selfhost, and K8s consumer, the deployment review must show a
trusted ingress as the only peer holding the signer API key, a private network
connecting that ingress and signer, and no host port or gateway route to the
sign endpoint. The ingress must not receive the OpenBao token. The signer must
not receive a physical bureau webhook secret. The current provider ingress
contract in `contracts/passport-bureau-provider-ingress-behavior.json` must be
implemented and accepted before these bindings can be enabled. Rolling back
disables both ingress and signer and restores the existing Python route owner.
