# Marty public verification with OpenBao

This opt-in overlay supplies the two new Flow file inputs through the existing
Compose deployment. It is absent from default stack/bundle selections. It
changes no image, service command, port, TLS setting, gateway authority, issuer
profile or organization membership. Applying it enables public admission, so
the existing website/public-enablement hold applies. Configuration rendering
alone does not authorize deployment or qualify signing.

The current elevenidllc deployment is being updated by another workstream.
Keep this overlay unapplied there until that deferral is explicitly lifted.

Use a compatible accepted release of Gateway, Flow, Presentation Policy and
Signing Keys. Run its ordinary migration job first; then verify Flow's owned
schema includes migration0004/public receipts. An old service image cannot
create the `demo_holder_binding` purpose or enforce the current policy digest
contract. Do not apply this overlay to an older or mixed release.

## Dedicated age demonstration

Prepare these objects through their existing authenticated management owners.
Capture returned IDs, versions, registry revisions, verification methods and
the policy owner's full configuration digests. Do not insert database rows or
reuse member-login policies, templates or signing keys.

| Object | Prepared configuration |
| --- | --- |
| Organization | Existing Marty organization; visitors receive no membership. |
| Issuer | Dedicated managed ES256 identity, `vc_jwt_issuer`, `SD_JWT_VC`. |
| Synthetic holder | Different DID/key, `demo_holder_binding`, `SD_JWT_VC`, ES256; managed reference starts with `demo-holder-`. |
| Verifier | Separate `oid4vp_request_signing` identity; standard DCQL requests. |
| Credential template | `Marty Synthetic Age`, VCT `urn:marty:demo:age:1`, selective disclosure, `dc+sd-jwt`, no date of birth/email. |
| Claims | Boolean `age_over_18`, boolean `age_over_21`, optional string `display_name`; all selectively disclosable. These are issuer assertions, not newly derived predicates. |
| Default specimen | Fictional age20: true/false threshold claims, display name `Alex Example`, bound to the dedicated holder. |
| Policy variants | 18+; 21+; 18+ with optional display name; 21+ with optional display name. Each threshold requires its signed boolean to equal true. Unrequested display name has no condition. |
| Flow definitions | One approved active verification-only `oid4vp_presentation` definition/version per variant, referencing its policy and required trust/deployment authorities. |
| Initial traffic bounds | 20 starts/minute, 500/day, 25 active; tenant-wide counters. Requalify changes against expected traffic and provider limits. |

For local managed did:web publication, use single path slugs such as
`did:web:<canonical-domain>:orgs:marty-demo-age`, `marty-demo-holder` and
`marty-demo-verifier`. The document owner can claim distinct slugs for one
organization; it rejects a slug owned by another organization. Nested paths
such as `:orgs:marty:demo:age` are not supported by this publication owner.
Use the actual deployment capability prefix and verify each public DID's exact
ID, key and assertion relationship before activation. A configured hostname is
not evidence that DNS, routing or TLS is ready.

Create dedicated trust/compliance/status configuration suitable for fictional
data. Trust must pin the intended demo issuer/key and type, without accepting
ordinary production or arbitrary self-signed credentials. Preserve signature,
issuer trust, validity, required status, holder, nonce and audience checks in
every variant. Use the saved definition's actual deadline; result access ends
ten minutes later. The minimal admission receipt lasts thirty days.

Issue fixtures through the canonical owner with the dedicated managed issuer;
do not put private keys in Flow or generate credentials in the browser. A
24-hour positive fixture can be renewed after 18 hours, with policy credential
age limits consistent with that lifetime and fresh session-bound proofs still
required. Check publication/status dependencies and replacement readiness,
stage the operator file atomically, and recreate Flow on the same compatible
release to load it; this configuration is read at startup, not hot-reloaded.
Keep the fixed holder binding during renewal. Catalog changes require new
consent; pending sessions can need a fresh preview/run. Persisted selections
and deadlines are not rewritten or extended. Deliberate
expired/tampered/untrusted fixtures need separate labels and qualification;
they must not be renewed or treated as successful readiness probes by accident.

## Authority and file inputs

Provision the distinct grant MAC authority
`marty-sign-grant-flow-demo-holder-v1` through the existing OpenBao operator.
Default bootstrap still creates the seven original grant origins. This overlay
does not provision the new origin or update verifier policy; stage and qualify
those separately before using it.
Flow's dedicated token may update only
`transit/hmac/marty-sign-grant-flow-demo-holder-v1/sha2-256`. It must not mint
wallet-request, issuer, certificate or other grant origins. Signing Keys needs
verification permission on
`transit/verify/marty-sign-grant-flow-demo-holder-v1/sha2-256`, without this
minting permission. Keep existing origin authorities and token boundaries.
The credential holder's asymmetric key is separate from this grant MAC key.
Qualify these actual permissions and negative origin/purpose cases before use.

Stage two absolute host file paths in protected operator storage, outside Git:

- `MARTY_PUBLIC_VERIFICATION_CONFIG_PATH`: the actual operator JSON described in
  [the Flow contract](../../../rust/services/flow/PUBLIC_VERIFICATION.md),
  including the authorized execution principal, dedicated verifier/holder DIDs,
  exact HTTPS application origin, finite variants, issued specimens and full
  policy digests. This file contains server-owned configuration and signed
  fictional credentials, never private keys or visitor data.
- `MARTY_PUBLIC_VERIFICATION_HOLDER_MINT_TOKEN_FILE`: only the dedicated mint
  capability. Never supply a bootstrap/root token or the wallet-request token.

The config bind is read-only and refuses automatic host-directory creation.
Only Flow receives this new token. Existing OpenBao TLS/CA, service-auth and
wallet-request token inputs remain required. This overlay explicitly selects
`openbao-transit`; it does not reset an AWS authority file or silently translate
AWS configuration. AWS deployments require their separately qualified origin
ARN/configuration and must not use this overlay.

## Render, qualify, enable and roll back

Preserve the deployment's approved, ordered base/bundle/hosting files and append
`deploy-config/compose/public-verification/compose.openbao.yml`. Use the normal
Compose `config` operation to review the merged model first. Only Flow's new
environment entries, read-only config mount and dedicated secret should differ.
Do not expose Flow directly or broaden CORS; the exact application origin and
capability header must work through the configured gateway.

Before enablement, qualify real managed signing, public DID resolution, actual
workload-authenticated policy evaluation and a supported external wallet. Run
default success, 21+ policy denial, request/disclosure changes, invalid type,
signature/trust/status/expiry, origin/capability, replay, cancellation and
retention cases against the exact release and config. Confirm fixture renewal
and primary-store deletion operations, and document backup/log/export scope.
Verify the initial legacy public-session inventory and reconcile genuine rows
without receipts through the existing owner. Keep publication disabled until
the required explicit authorization is recorded.

For feature-off rollback, omit this overlay and recreate Flow using the same
compatible release and approved base file sequence. Confirm the public catalog
returns404 and the retention worker still removes previously admitted payloads.
Do not roll back to an older binary without a separately qualified custodian
for outstanding deletion deadlines. Preserve operator files/keys and recovery
evidence; disabling admission does not authorize deleting them.
