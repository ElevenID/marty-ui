# Disposable self-host issuer fixture

`scripts/setup_selfhost_synthetic_fixture.py` is the post-start setup hook for
the exact-ZIP runner. It uses the installed Keycloak admin API only to create
one disposable operator; the selected test authenticates through the public
PKCE path. The hook creates two purpose-specific profiles through Marty's
public issuer-identity API. It checks their public keys against two
non-exportable P-256 keys in a disposable external OpenBao transit store, then
signs a source/ZIP/lock-bound custody document. It uses an SD-JWT fixture and
does not require a CSCA, DSC, or external CA.

Use a disposable loopback stack only. Set `MARTY_ORG_ADMIN_EMAIL` in the
Compose env file to a synthetic address such as
`operator@selfhost.marty.invalid` **before** the fresh migrations. Set
`MARTY_ORG_ID` to the exact seeded organization UUID and `PUBLIC_DOMAIN` to a
local test domain that resolves to the installed edge. The selected issuer and
verifier DID values must both equal
`did:web:<PUBLIC_DOMAIN>:orgs:<MARTY_ORG_ID>` (percent-encode `:` in a domain
port). The fixture provisions separate `vc_jwt_issuer` and
`oid4vp_request_signing` managed keys for that DID. Set the eight
`SELFHOST_*` public-journey inputs documented in the integration suite,
including the synthetic user's password, through an operator secret runner.
The runner passes the exact Compose model path, secret root, source SHA, ZIP
digest, lock digest, and fresh evidence/signature output paths to the hook.

Additional hook inputs:

| Variable | Value |
| --- | --- |
| `SELFHOST_BAO_AUDIT_URL` | Loopback HTTPS URL for the **same** disposable OpenBao instance used by `signing-keys`; port must match the installed `BAO_ADDR` and its CA must be staged as `openbao_tls_ca_cert` in the private secret root |
| `SELFHOST_BAO_AUDIT_TOKEN_FILE` | Outside-repo file containing a token with policy `selfhost-qualification-audit`, at most one-hour TTL, and only `read` on `transit/keys/cred-issuer-*` and `transit/keys/oid4vp-verifier-*` |
| `SELFHOST_KMS_JWK_TOOL` | Set by the installed runner to a fresh `public-kms-jwk` build from the clean exact release source; the Rust converter parses the audited OpenBao PEM and its public coordinates must equal the resolved issuer JWK |
| `SELFHOST_CUSTODY_SIGNING_KEY_FILE` | Outside-repo, short-lived Ed25519 private PEM approved for this exact qualification release |

Before issuing the audit token, the operator must inspect the actual
`selfhost-qualification-audit` ACL and confirm it grants only `read` on the
two transit key metadata path families above. The fixture checks the token's
policy names and TTL, but does **not** prove the policy's ACL contents or
record them as verified custody evidence.

Generate a test-only signer in an operator-controlled directory outside the
repository. Never commit the private key:

```bash
openssl genpkey -algorithm ED25519 -out custody-test.key
chmod 0600 custody-test.key
openssl pkey -in custody-test.key -pubout -out custody-test.pub
sha256sum custody-test.pub
```

Add only the reviewed public-key SHA-256 to
`deploy-config/selfhost-kms-custody-trust-roots.json` in a protected source
commit, then prepare a new ZIP/receipt from that exact commit. This branch
contains a disposable test signer digest for review; it is not present in a
published bundle. The hook
signs with `openssl pkeyutl -sign -rawin`; the runner verifies the exact
evidence bytes with the source-approved public key before starting the public
journey. Remove the short-lived private key and OpenBao audit token after the
disposable run. The signed statement records both managed transit key
references, versions, and public profile selector tuples. The test separately
exercises issue, present, verify, revoke, and denial through public routes.

The hook requires `SELFHOST_GATEWAY_URL` and `SELFHOST_KEYCLOAK_URL` to be
loopback HTTP URLs, and `SELFHOST_BAO_AUDIT_URL` to be loopback HTTPS. It
verifies OpenBao TLS with the staged CA, not ambient trust settings. The
installed Compose model
must show the same synthetic operator and organization in `db-migrate` and
`keycloak-configurator`, with `signing-keys` using the matching
`host.docker.internal` OpenBao port. The gateway and Keycloak URLs must match
the exact loopback ports published by the installed `edge` and `keycloak`
services. A domain/DID mismatch, public-key
mismatch, exportable transit key, root or long-lived audit token, missing
signer approval, or incomplete
Keycloak/profile setup fails the run. A passing hook remains **unqualified**
until the exact fresh installation and release publisher gates pass.
