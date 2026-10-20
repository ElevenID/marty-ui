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
`MARTY_ORG_ID` and `SELFHOST_ORG_ID` to the same seeded organization UUID, and
`PUBLIC_DOMAIN` to a local test domain that resolves to the installed edge.
Use the installed `MARTY_ORG_SLUG` (default `marty`) for the DID path. The
selected `SELFHOST_ISSUER_DID` and `SELFHOST_VERIFIER_DID` must both equal
`did:web:<PUBLIC_DOMAIN>:orgs:<MARTY_ORG_SLUG>` (percent-encode `:` in a domain
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
| `SELFHOST_BAO_AUDIT_TOKEN_FILE` | Outside-repo file containing a token with policy `selfhost-qualification-audit` and at most one-hour TTL; see the exact metadata and self-inspection ACL below |
| `SELFHOST_KMS_JWK_TOOL` | Set by the installed runner to a fresh `public-kms-jwk` build from the clean exact release source; the Rust converter parses the audited OpenBao PEM and its public coordinates must equal the resolved issuer JWK |
| `SELFHOST_CUSTODY_SIGNING_TOKEN_FILE` | Outside-repo file containing a short-lived token scoped to the source-approved, non-exportable Ed25519 Transit signer |
| `SELFHOST_CUSTODY_CHALLENGE`, `SELFHOST_RUN_ID`, `SELFHOST_FIXTURE_SHA256` | Fresh runner-generated challenge and exact prepared run/fixture identity; never supply or reuse these manually |

Before issuing the audit token, the operator must inspect the actual
`selfhost-qualification-audit` ACL. It must grant `read` on the two transit
key metadata families and exact custody signer, `read` on
`auth/token/lookup-self`, and `update` on `sys/capabilities-self` for the
runner's own effective-capability check. It must grant no other paths. OpenBao
returns HTTP 403 for `sys/capabilities-self` without that explicit `update`
capability; this was verified against the disposable Raft instance. The
fixture checks policy names and TTL, and the runner checks effective access
to the signer and selected forbidden paths. The operator must still review
the full ACL for unrelated grants.

After starting the disposable Raft-backed OpenBao project, provision its
non-exportable custody signer with the reviewed source helper. Run it as root
because it reads OpenBao's protected root token from its state directory; the
helper first checks the staged image lock, exact Compose project, state mount,
healthy container and loopback port. It does not copy the root token into the
stack secret root:

```bash
source_root=/srv/qualification/marty-ui-release
# Use the exact started Compose project; staged previews record it in
# openbao.json, while the full-qualification runbook sets this variable.
openbao_project=${openbao_project:?Set the started OpenBao Compose project}
sudo python3 "$source_root/scripts/provision_selfhost_custody_signer.py" \
  --endpoint "https://127.0.0.1:${SELFHOST_OPENBAO_HOST_PORT}" \
  --state-root "$openbao_state_root" --output-root "$secret_root" \
  --project-name "$openbao_project"
evidence_identity_root="$(dirname "$openbao_state_root")/evidence-identity"
sudo install -d -m 700 "$evidence_identity_root"
sudo python3 "$source_root/scripts/provision_selfhost_evidence_identity.py" \
  --mode bootstrap --bao-addr "https://127.0.0.1:${SELFHOST_OPENBAO_HOST_PORT}" \
  --bao-ca "$openbao_state_root/tls/ca.crt" \
  --root-token-file "$openbao_state_root/root.token" \
  --output "$evidence_identity_root"
```

The printed public-key digest is an install-local diagnostic, not a release
source edit. Each fresh OpenBao instance may generate a distinct signer.
Only the public PEM and scoped token leave OpenBao; no custody private key file is
created. If the token expires before the installed run, repeat the signer helper
with `--refresh-token --identity-root "$evidence_identity_root"`; it verifies
the public key and policy, mints through a separate narrow AppRole, and revokes
the prior token through that token's `revoke-self` capability. The initial
helper uses the OpenBao API's `no_parent` field and checks
that token lookup reports an orphan, so revoking the provisioning root token
does not revoke the scoped signer token. The hook independently checks the
orphan flag, policy, and TTL, then reads the
non-exportable Ed25519 key metadata, proves export and unrelated signing are
denied, and calls Transit `sign` on the exact source/ZIP/lock-bound evidence
bytes, including the runner's fresh challenge and prepared run/fixture identity.
The runner independently reads the live key metadata from the owned,
image-locked OpenBao instance and verifies the signature with that public key
before the public journey. Remove the scoped token after the disposable run.

To rotate the evidence AppRole without the bootstrap root, create a separate
private sibling such as `evidence-identity-next` and run
`provision_selfhost_evidence_identity.py --mode rotate --bao-addr "$bao_url"
--bao-ca "$openbao_state_root/tls/ca.crt" --identity "$evidence_identity_root"
--output "$next_identity_root"`. The command verifies the replacement login
before retiring the old SecretID. Use the new directory for subsequent
`--identity-root` refreshes. If retiring the old SecretID was interrupted,
`--mode retire --identity "$next_identity_root" --retired-identity
"$evidence_identity_root"` completes the operation; keep both private until it
confirms the old login is rejected.

If refresh fails and `selfhost_custody_signer_token.new` remains in the private
output directory, stop rather than minting another token. The old-token revoke
response may have been lost; either token may still be valid. Using the scoped
evidence identity, inspect both token statuses without printing their values.
Revoke a live token through its own `revoke-self` capability and remove `.new`
only after OpenBao confirms revocation or that token's expiry,
then rerun `--refresh-token`. Keep `.new` private and do not delete it merely
because the OpenBao API is unavailable.
The signed statement records both managed transit key references, versions,
and public profile selector tuples, plus the attestation key reference and
version. The test separately exercises issue, present, verify, revoke, and
denial through public routes.

The hook requires `SELFHOST_GATEWAY_URL` and `SELFHOST_KEYCLOAK_URL` to be
loopback HTTP URLs, and `SELFHOST_BAO_AUDIT_URL` to be loopback HTTPS. It
verifies OpenBao TLS with the staged CA, not ambient trust settings. The
installed Compose model
must show the same synthetic operator and organization in `db-migrate` and
`keycloak-configurator`, with `signing-keys` using the matching
`host.docker.internal` OpenBao port. The gateway and Keycloak URLs must match
the exact loopback ports published by the installed `edge` and `keycloak`
services. A domain/DID mismatch, public-key
mismatch, exportable transit key, root or long-lived audit token, wrong OpenBao
owner/image/loopback port/CA, replayed challenge, or incomplete
Keycloak/profile setup fails the run. A passing hook remains **unqualified**
until the exact fresh installation and release publisher gates pass.
