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
Reviewed operator inputs are in [openbao/](openbao/): the non-exportable HMAC
key specification, its single-path mint policy, and a verifier policy containing
the original seven verification paths plus this eighth origin. Compare the
existing verifier policy before applying a change; preserve unexpected/custom
rules for explicit disposition rather than replacing them blindly. A later
default initializer run restores its seven-origin policy, so an enabled demo
needs the reviewed extension reconciled again before admission resumes.
Flow's dedicated token may update only
`transit/hmac/marty-sign-grant-flow-demo-holder-v1/sha2-256`. It must not mint
wallet-request, issuer, certificate or other grant origins. Signing Keys needs
verification permission on
`transit/verify/marty-sign-grant-flow-demo-holder-v1/sha2-256`, without this
minting permission. Keep existing origin authorities and token boundaries.
The credential holder's asymmetric key is separate from this grant MAC key.
Qualify these actual permissions and negative origin/purpose cases before use.
Default `credential-service` and `signing-keys-managed` policies do not cover
`demo-holder-*`. The optional `signing-keys-demo-holder.hcl` adds P256-only
creation/public reads and prehashed SHA256 signing for that prefix. Attach it
only to the Signing Keys custody workload, alongside its existing policies;
Flow receives only the MAC mint policy. This is a workload prefix boundary;
Signing Keys must still enforce organization, identity, purpose and grant
admission. The custody policy permits neither export, import, backup, deletion,
export configuration, grant minting nor signing other purpose prefixes. Keep
the existing custody token unchanged until a compatible release and its complete
service admission path have been qualified. This overlay does not replace or
issue that token.

The existing disposable probe has a selected local qualification mode:

```sh
python scripts/probe_signing_keys_openbao_policy.py --public-demo-grant
```

It first discovers all three exact native tests, then creates its own pinned,
loopback-only TLS OpenBao, marked Redis and a fresh PostgreSQL fixture. The
database name and nonce guard are fixed by the controller; an inherited test
database URL cannot select another database. PostgreSQL data lives in tmpfs.
It applies these policy
inputs only there, checks all eight origins' MAC isolation and the demo token's
provisioning/signing denials, and runs the native file-backed demo minter and
one-use verifier race. It also creates a non-exportable asymmetric demo key
using a distinct custody token, checks real signatures/tamper rejection and
privilege denials, and executes the native pinned-version ES256 adapter with
independent public-JWK verification. It verifies removal of the owned container
IDs. A cross-service acceptance case creates the synthetic holder through the
actual Signing Keys identity API and uses Flow's production HTTP client with
its file-backed minter. It checks public-JWK signatures, tenant/DID/key/purpose/
payload binding, actual concurrent replay admission, format/profile rejection
and absence of a wallet-minter fallback. The service fixture uses a distinct
token containing the existing Signing Keys policies plus the opt-in custody
policy; the prefix-only token remains separate for privilege-denial tests.
That case also provisions distinct remote issuer/verifier keys, issues the
fictional specimen with the issuer's real grant, and exercises public catalog,
preview, consent-bound launch, example and result recovery routes against real
Flow PostgreSQL persistence. Core verification and the actual policy evaluator
produce age18 success and age21 denial; a tampered specimen remains an input
rejection without nonce consumption. Results omit claims and credential data.
Membership, template metadata and trust/status transports are explicit local
fixtures, and the real policy evaluator is called through an in-process adapter.
The same journey runs through the production Gateway and its real HTTP upstream
to Flow. The fixture audits workload-token forwarding and removal of spoofed
browser authority, exercises CORS preflight, closed management access, duplicate
headers, bounded bodies and no-store responses. Preflight resolves only an
existing public GET/POST target for a configured Origin; it never reaches Flow
or opens a management route.
The regular `--grant-verifier` probe also includes these cases. Their scope is
the isolated Gateway/Flow canonical example journey, remote custody and service
signing admission. Governed deployed readiness,
retention/renewal operations and real-wallet interoperability need their own
qualification. All three owned fixture container IDs are removed and verified.
The optional browser mode additionally requires the UI's installed dependencies
and its cached Puppeteer Chromium before any backend is created:

```sh
python scripts/probe_signing_keys_openbao_policy.py --public-demo-browser
```

It serves the actual application source and shared Rust/WASM API client through
an owned loopback Vite server and fresh headless browser profile. Requests use
real cross-origin HTTP to the fixture Gateway; no verification response is
intercepted or fabricated. The browser verifies consent gating, age18 success,
reload recovery without a second launch, the optional21+ selector with fresh
consent and canonical denial, then a390px wallet QR/request/cancellation view.
The native fixture also checks persisted nonce counts after browser work.
Only public URLs cross into the browser worker; KMS/database credentials stay
outside its environment. Vite proxying is pinned to the owned Gateway and HMR
is disabled. Browser/Vite shutdown and backend removal are checked. The ordinary
grant mode does not require a browser; the two modes are mutually exclusive.
Screenshots are written under `rust/target/public-verification-browser` for
local review and should be preserved with qualification evidence before parking
the checkout. This mode uses application source through Vite, explicit local
membership/template/trust/status fixtures and the actual in-process policy
evaluator. It does not establish production HTTPS/DNS, authentication-service
readiness, a published bundle or external-wallet interoperability.
There is no endpoint/operator-secret option for pointing this probe at an
existing deployment.

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
