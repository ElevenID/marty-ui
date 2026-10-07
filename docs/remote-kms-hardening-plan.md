# Remote KMS hardening implementation and landing plan

Status: active. Updated: 2026-10-07 (America/Denver).

Owner: Codex working with the repository maintainer. This file is the canonical
cross-repository progress tracker. Update it at meaningful implementation,
review, validation, and landing checkpoints, including concrete commit, PR,
artifact, and test references. A merged library change alone does not complete
the service or release boundary.

## Objective and working agreement

Complete remote key custody throughout the migrated Rust issuer and verifier
services, their cryptographic dependencies, supported interfaces, and shipping
artifacts. Remove production access to long-lived credential private-key
generation, import, export, retention, and local signing. Complete remote
DIDComm authcrypt custody and integration-secret master-key custody while
preserving supported behavior and existing encrypted data.

The user resumed this work on 2026-10-07 and requested large feature PRs to reduce
CI/CD cost, self-review for regressions and feature loss, security and general
quality, and Rust-first, DRY implementation. Earlier migration-first deferrals
are now implementation inputs rather than reasons to leave the work paused.

Prefer shared Rust contracts and implementations at their existing canonical
owners. Keep orchestration and provider concerns separate from cryptographic
preparation and verification. Reuse established services before introducing a
new backend. Do not duplicate key policy, tenant validation, encodings, or error
handling across services. Do not weaken security gates to preserve old APIs.

TLS identities, ephemeral protocol/session keys, and intentional wallet/device
keys are separate capabilities. Inventory and isolate them explicitly; removing
issuer private-key support must not break these supported product features.
Ordinary application secrets may need to be read by their consumer; distinguish
that requirement from non-exportable custody of their encryption master key.

User clarification on 2026-10-07: remove local issuer key generation and signing
from service and acceptance tests as well. Relocating that code to a harness or
`cfg(test)` is not the final solution. Use remote KMS issuance, the existing Rust
test wallet and opaque signer agent for holder proofs, and public signed vectors
for verification tests. Keep private-key operations only in separately justified
wallet/product or cryptographic conformance boundaries. Preserve the acceptance
assertions and real protocol behavior while changing how inputs are produced.

## Verified starting point

The investigation refreshed origin refs and inspected source and PR history on
2026-10-07. These are source findings, not new build or deployment qualification.

| Area | Evidence and consequence |
| --- | --- |
| Hardened Core | Main `a5cb567`; KMS capability split PR 308, API removal PRs 313 and 315, corrections PRs 317 and 318 are merged. Reuse this work. |
| Native services | UI main `d2dcd0630` pins most Core crates to compatibility 0.1.62 at `bdbd1510`. Its ECDSA surface still exports local key generation and signing. The lockfile also contains 0.2.0 crypto through passport SOD issuance; this does not remove 0.1.62. |
| Credential issuance | Native JWT-VC, SD-JWT, and mdoc builders already prepare, remotely sign, and assemble. Preserve and migrate these seams. |
| DIDComm | Native issuance still parses `sender_x25519_private_key` and retains private bytes in prepared authcrypt state. `DIDCOMM-KMS-001` remains unimplemented. |
| Integration secrets | Native `IntegrationSecretCipher` holds a raw 32-byte AES key. Credentials pins canonical marty-rs 0.2.0 but retains verification wheel 0.1.60. `INTEGRATION-SECRET-KMS-001` requires compatible data migration. |
| BYOK | The old adapter sends `private_key_pem`; the retained patch changes it to `key_reference`. No matching authenticated backend contract or active UI caller was established in the prior audit. Do not infer deployed exploitability or invent an endpoint. |
| Test isolation | Native qualification code includes local-signing fixtures and old authority features. Identify production build roots and isolate fixtures before updating pins. |

### Preserved branches

All three worktrees were clean. No matching PR was found for these branch names.
Commit counts describe history divergence, not the number of missing fixes.

| Repository | Branch | Tip | Unique commits / behind main | Treatment |
| --- | --- | --- | --- | --- |
| marty-core | security/kms-boundary-hardening-v1 | e261464 | 10 / 33 | Map each change to merged replacements; port only missing behavior or tests. |
| marty-credentials | security/kms-boundary-hardening-v1 | e740e16 | 5 / 39 | Reconcile compatibility bindings, quarantine and boundary tests against current consumers. |
| marty-ui | security/kms-boundary-hardening-v1 | 827ab777b | 1 / 208 | Preserve attribution; port BYOK behavior after the route contract is proven. |

Keep these references until reconciliation and recoverability are recorded.
Use fresh branches based on current main; do not blindly merge historical trees.

## Feature PR grouping and cost control

Use one cohesive feature PR per repository where possible. Cross-repository
dependencies require separate PRs; a single PR cannot span repositories.

| Group | Scope | Landing dependency |
| --- | --- | --- |
| Core feature PR, if needed | Shared remote envelope/storage contracts and cryptographic boundaries, missing canonical APIs, fixture support, compile-fail enforcement, documentation and self-review corrections. | Backend feasibility and consumer contract tests demonstrated first. Preserve current consumers where safe; never restore forbidden production APIs. |
| UI native hardening feature PR | Hardened Core adoption across service roots, DIDComm remote custody, integration-secret migration, supported BYOK wiring, test isolation, dependency/artifact guards and acceptance evidence. This tracker belongs here. | Exact reviewed Core revision and proven remote backend capabilities. |
| Credentials compatibility retirement feature PR | Remove obsolete compatibility custody paths and pins once their native replacements and data reads are qualified; preserve required rollback behavior without private-key fallback. | Qualified native service artifacts and supported routing/cutover evidence. |
| Integration acceptance feature PR | Migrate the production-image positive verifier probe to a qualified external fixture or separate acceptance artifact while preserving actual shipped verifier execution and assertions. | Coordinated UI packaging change; the existing caller executes the probe inside the published service image. |
| Dependency fork PRs, only if necessary | Narrow missing cryptographic capability separation that cannot be achieved at existing owners. | Demonstrated production graph gap; ElevenID forks only. No upstream disclosure or publication is implied. |

Batch local implementation and review corrections before pushing. Do not create
one PR or CI run per small fix or per test. Use targeted local tests while
iterating, then a complete relevant local matrix before hosted qualification.
Run the required PR and merge-queue checks; never bypass protections, weaken
checks, or claim that an earlier revision qualifies a changed final head.
Consolidate final pin updates and release preparation after dependency heads are
stable. Split a group only when dependency ordering, reviewability, or rollback
safety provides a concrete reason, and record that reason here.

## Work tracker

| ID | Work and exit evidence | Status |
| --- | --- | --- |
| K1 | Reconcile preserved branches; map every supported production binary, image, wheel, Cargo root and release pin; enumerate current signing/encryption paths and explicit secret-class exceptions. | In progress |
| K2 | Prove backend support for non-exportable DIDComm sender agreement/authcrypt with actual recipient decryption; select the smallest shared Rust boundary and record supported provider scope. | In progress; pinned OpenBao rejects X25519 creation |
| K3 | Implement DIDComm scoped/versioned references and remote operations; bind tenant, sender DID/key, recipient documents and frozen attempt inputs; preserve rotation, expiry, retries, replay, cancellation and unknown-outcome semantics. | In progress; native Rust remote client and issuance seam compile, live route qualification pending |
| K4 | Design and implement opaque integration-secret custody and existing AES-GCM envelope migration; prove legacy reads, tenant/purpose isolation, tamper rejection, restart, rotation, recovery and atomic repository behavior. | In progress; synthetic migration, database recovery, native process restart/rotation and binding rejection passed; packaged image and OpenBao restore acceptance pending |
| K5 | Adopt hardened Core across Rust services and fork pins; replace removed APIs and broad features; isolate fixtures and qualification binaries; eliminate compatibility crypto from production graphs. | In progress; candidate 0.2 pins compile signing-keys, issuance and Flow with explicit temporary compatibility edges; workspace/test matrix pending |
| K6 | Establish actual supported BYOK route/schema and tenant/certificate binding; integrate reference-only UX and server rejection of private material, preserving existing onboarding behavior. | In progress; public external OpenBao registration-to-issuer/certificate live Rust route passed; packaged gateway, other-provider acceptance and review pending |
| K7 | Reconcile Credentials compatibility retirement with native owner selection, published artifacts and encrypted-data readability; remove obsolete raw-key adapters and wheel requirements where qualified. | In progress; preserved boundary commits ported to current main in a fresh Credentials branch, production/local opt-in builds and targeted Python tests passed; published artifact and native cutover still pending |
| K8 | Add production-root feature, forbidden-API, binding and artifact checks; exercise real remote operations and negative paths; complete all three self-review passes. | Pending |
| K9 | Land grouped feature PRs through required checks; qualify exact release artifacts and supported cutover/rollback; update durable evidence and close the goal only after acceptance below. | Pending |

### First execution steps

1. Finish K1 using fresh refs and the actual production packaging commands,
   separating test-only code from compiled service capability.
2. Trace supported KMS provider operations and native DIDComm interfaces to
   resolve K2. Signing or wrap/unwrap APIs are not proof of non-exportable
   X25519 support. A reference that eventually exports a private key fails.
3. Inventory integration-secret ciphertext versions and repository transactions
   before choosing K4 migration mechanics. Use synthetic data for local testing.
4. Record concrete API contracts and failing regression probes, then implement
   cohesive Rust changes locally across isolated repository worktrees.

## Review and validation gates

Review our own complete diff before each hosted qualification batch and again
after material corrections. Record findings, fixes and evidence for each pass.

- Regression and feature preservation: compare against the supported behavior
  inventory and frozen contracts. Cover credential formats, DIDComm anoncrypt
  and real authcrypt, sender authentication, recipient decryption, retries,
  routing, certificates, sessions, wallet interactions and old ciphertext reads.
  No silent fallback to legacy owners, anoncrypt, plaintext or local signing.
- Security: inspect tenant and purpose authorization, key reference ownership,
  public-key/certificate binding, exact payload/signature binding, memory/config
  custody, logs/errors, serialization, replay, expiry, rotation, backend failure
  and downgrade paths. Confirm private members are rejected at public inputs.
- General quality and DRY: use canonical shared Rust implementations and typed
  boundaries; review async/cancellation behavior, bounded resource use, error
  handling, maintainability, unnecessary dependencies and documentation.

Validation must distinguish fixture tests, actual backend tests and final
artifact evidence. Mocks alone cannot establish custody or interoperability.
Run meaningful targeted tests during development, then required formatting,
lint, service integration and unchanged protocol/compliance suites. Inspect
normal/build dependency graphs separately from dev/test graphs, including
feature unification and duplicate Core versions. Prove removed APIs cannot
compile from production roots and inspect shipped bindings and symbols.

Qualify each supported provider/algorithm combination actually advertised;
unsupported capabilities fail clearly before use. Test wrong-key, cross-tenant,
wrong-recipient, tamper, backend outage, rotation and interrupted operation
paths. Retain immutable failed-run evidence. Record actual final binary/image
size where useful; target-directory size is not shipped size.

Dependency-internal signing primitives may be coupled to public verification.
Audit and state that limit explicitly. Do not claim binary-level absence of all
signing machinery from a feature flag or symbol scan alone. Remove unwanted
capability where feasible and record any unresolved acceptance limitation.

## Completion criteria

- All supported production issuer/verifier roots use the hardened cryptographic
  boundary, with no old compatibility dependency restoring private-key APIs.
- Credential signing and long-lived DIDComm sender-key operations use remote,
  non-exportable custody; application configuration and memory contain references
  rather than those private keys. No fallback restores local custody.
- Integration-secret master-key custody is opaque and remote; existing data is
  readable through a qualified migration with tested rotation and recovery.
- BYOK interfaces accept public certificates and authorized remote references,
  reject private material server-side, and preserve supported onboarding.
- TLS, ephemeral session and intentional wallet/device behavior remain supported
  through explicit product capabilities; test signers cannot enter release roots.
- Regression, security and quality self-reviews have no unresolved required
  corrections; production graph/API/artifact and real backend acceptance pass.
- Grouped feature PRs are merged through required protections, exact release
  artifacts and supported cutover/rollback are qualified, and this tracker links
  the evidence. Any external access or deployment prerequisite still missing is
  recorded as unfinished work, not treated as acceptance.

The active goal is complete only when these criteria are met. Do not silently
reduce scope when a backend or deployment prerequisite is unavailable. Continue
independent implementation and record the precise remaining dependency. Changes
to live key policies, key deletion or irreversible data migration require their
specific operational context; prepare a concrete reviewed operation first.

## Evidence and progress log

### Public verifier input implementation checkpoint

The in-progress positive verifier binary now accepts a bounded public JSON input
on stdin (`presentation`, `issuer_public_jwk`) instead of generating issuer and
holder keys. Registered private JWK members and extra input fields are rejected.
Its canonical verifier and eight policy/check assertions remain in the shipping
binary. The temporary test-only signing helper was removed after the user
clarification; the probe's unit tests contain no private-key creation or signing.
The direct P-256 dependency is removed and OID4VCI selects verifier/SD-JWT instead
of the wallet capability. Compatibility Core adoption is still outstanding.

Integration branch `security/remote-kms-acceptance-20261007`, based on integration
main `845dd1a`, commits `99b9aff` and `a3e0646`, supplies stdin with
`docker run -i`. The harness now requires an
absolute `marty-kms-positive-verifier-input` executable path and its exact SHA-256
digest. It executes that producer for each run, rejects absent, oversized and
private-key-bearing public input, then executes the verifier in the pinned image.
Core branch `security/remote-kms-fixture-20261007` at `6d98e73` adds that
non-publishable Rust
producer using canonical Core remote issuance and wallet presentation APIs. It
asks two separately scoped authenticated signer agents for the exact signing
inputs; those agents bridge to remote KMS. Neither producer nor harness generates
or loads issuer/holder private keys. No second local signing implementation was
added. This is implementation and local parser/build evidence, not yet real KMS,
wallet, image, tenant or release acceptance. Next run the producer against two
actual remote KMS keys and the exact image, including tampered/negative cases.

Validation so far: Rust 1.95.0 probe tests passed (2); the Core producer passed
`cargo +1.95.0 check --locked -p marty-test-wallet --bin
marty-kms-positive-verifier-input` and focused Clippy with `-D warnings`;
the integration harness unit file passed
(301 passed, 2 skipped), and Ruff checks passed. The previous
three-test run exercised the superseded local-signing intermediate and does not
qualify this final direction. No hosted CI or artifact acceptance has run.

Self-review checkpoint: the stdin parser bounds total bytes before JSON parsing,
rejects private/unknown key fields and keeps diagnostic errors free of input
contents. The final focused Rust run with verifier/SD-JWT features passed both
tests under `--locked`; rustfmt and diff checks passed. General compatibility
remains deliberately unqualified: the harness's fresh input producer must be
wired before the coordinated feature PRs land. Positive and tampered-signature
acceptance will run against KMS/wallet output, replacing the removed locally
signed positive unit fixture. No passing parser test substitutes for that gate.

### Production and acceptance inventory checkpoint

The public shared image is built by `services/Dockerfile` through
`scripts/build-rust-service-binaries.sh`. It explicitly builds and copies these
24 binaries: `marty-event-stream`, `marty-gateway`, `marty-revocation-profile`,
`marty-signing-keys`, `marty-passport-callback-signer`,
`marty-passport-callback-signer-supported`, `marty-notification`, `marty-flow`,
`marty-organization`, `marty-passport-acceptance-api-key`, `marty-auth`,
`marty-credential-template`, `marty-presentation-policy`,
`marty-verifier-positive-gate`, `marty-trust-profile`, `marty-applicant`,
`marty-device-registration`, `marty-verification-service`,
`marty-issuance-service`, `marty-canvas-sync-worker`, `marty-passport-beta-bureau`,
`marty-passport-provider-ingress`, `marty-deployment-profile`, and
`marty-compliance-profile`. Its opt-in self-signed passport build adds
`marty-issuance-service/passport-self-signed-test` to the same binary list.

`marty-verifier-positive-gate` generates issuer and holder private keys and
locally signs credentials. This capability is explicitly shipped, not merely
present under unit-test compilation. The integration repository invokes it
inside the production image in `scripts/credentials_verifier_artifact.py`.
Removing it without replacing that actual-artifact acceptance path would lose
coverage. A coordinated integration acceptance PR is therefore necessary.
Preserve the positive checks while moving key creation to a separate test owner
and keeping verification exercised in the shipping runtime.

Other build roots include `rust/services/Dockerfile.ci` and the dedicated
event-stream, signing-keys and revocation-profile Dockerfiles. The CI multi-target
build has a different binary set from the public shared image. Both dependency
cooking stages build the workspace, so narrowing the final binary list alone
does not qualify the compiled feature graph. Remaining K1 work includes full
release/wheel ownership, standalone products, and per-root feature resolution.

Integration-secret raw-key consumers include issuance startup, the Canvas sync
worker and `canvas_oauth_postgres.rs`. The existing envelope is base64 of a
12-byte nonce followed by AES-GCM ciphertext and tag, with no tenant/purpose AAD
in the inspected implementation. Preserve reads during migration and bind new
envelopes to repository identity and purpose. Import/rewrap compatibility is
still unproven; never assume an OpenBao ciphertext prefix supplies that proof.

### Isolated provider capability evidence

On 2026-10-07, `python scripts/probe_kms_hardening_capabilities.py` passed against
the locally available CI-pinned image
`quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878`.
The image reports OpenBao 2.5.2, revision
`932fcf892eba8d646a9bfc58a59ea3b2475b17fa`. The script creates only synthetic
material in a disposable container with no network, ports or host mounts and
removes that container afterward.

- Both `x25519` and `ecdh-x25519` key creation return unsupported-key-type errors.
- `transit/derive-key` exists and accepts P-256/P-384/P-521 base keys plus a
  PEM peer public key, storing the derived symmetric output as a new named,
  non-exportable Transit key. It does not support X25519 or perform the
  ECDH-1PU/JWE key schedule and envelope required by current DIDComm.
- Non-exportable AES-256-GCM key creation, encryption, old-version decryption
  after rotation, tamper rejection and explicit key-export rejection passed.
  Plaintext backup remained disabled.
- No real recipient, application data migration, deployed provider or tenant
  authorization acceptance is claimed by this probe.

2026-10-07 security pin update: OpenBao's
[GHSA-8w8f-r2xv-4q4j](https://github.com/openbao/openbao/security/advisories/GHSA-8w8f-r2xv-4q4j)
states that 2.5.2 is affected by a Transit key-creation denial of service
available to a token with write access to `transit/keys/*`; 2.5.5 is patched.
The new ephemeral VC-API holder-proof namespace grants key creation, so 2.5.2
must not be used for release qualification of that route. CI, the disposable
passport-acceptance image catalog, and the capability-probe script now pin
`quay.io/openbao/openbao@sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452`.
The image reports OpenBao 2.5.5, revision
`028992583c693c4de6350b8aa52ff85e30375a99`. The isolated capability
probe passes on that exact digest and still rejects X25519 key creation.
The route-level holder-proof test also passes against disposable 2.5.5 with
the scoped `credential-service` policy token, including HTTP auth, proof
verification, deletion and stale-key reconciliation; that instance was removed.
The affected Python CI/provisioning tests pass (137 tests across
`test_ci_workflow_performance.py` and
`test_passport_supported_provisioning_plan.py`).
Earlier 2.5.2 findings remain historical evidence; requalify live routes,
storage migration/recovery and production image deployment against the patched
pin before release. Existing operator-managed OpenBao instances are not
upgraded by changing this repository and need their own cutover evidence.
Read-only `bao version` inspection on 2026-10-07 found the running local
`marty-selfhost-openbao-openbao-1` and `elevenid-beta-openbao-1` containers
still on 2.5.2; an additional local `sad_galileo` container also reports
2.5.2. Do not treat the updated repository pins as a live remediation. The
[2.6.x release notes](https://openbao.org/community/release-notes/2-6-0/)
list later security fixes, so 2.5.5 is a patched compatibility checkpoint
for the newly discovered Transit denial of service, not yet the final
production-version decision. Qualify the chosen current supported OpenBao
version with the actual plugin, file-storage snapshot/unseal, migration,
restart, and rollback before replacing either persistent instance.

The upstream [ECDH change](https://github.com/openbao/openbao/pull/811) and
[documentation issue](https://github.com/openbao/openbao/issues/1350) explain why
generic ECDH support must not be mistaken for DIDComm capability. Next: examine
an existing remote messaging agent or provider extension that implements the
required protocol with non-exportable custody; do not substitute another curve,
export a sender key, or downgrade authcrypt to make the pinned Transit API fit.

2026-10-07 DIDComm specification recheck: the current [v2.1 specification](https://identity.foundation/didcomm-messaging/spec/v2.1/)
lists X25519, P-384 and P-256 as **required** key-agreement curves and P-521 as
optional; it marks P-256 deprecated in favor of P-384. Its v2.1 changelog
mentions service-endpoint and empty-body changes, not a cryptographic profile
change. Authcrypt still requires ECDH-1PU in a JWE, with both NIST P-curves and
X25519 listed for `ECDH-1PU+A256KW`. The current [editor's draft encryption
section](https://github.com/decentralized-identity/didcomm-messaging/blob/main/docs/spec-files/encryption.md)
has the same curve and algorithm requirements. Thus a P-384-capable KMS can
participate in a mutually supported P-384 exchange, but selecting that curve
alone does not remove X25519 interoperability or satisfy a conformant
implementation's required curve support. The published [OpenBao Transit key
types](https://openbao.org/docs/secrets/transit/) expose P-256/P-384/P-521
ECDSA signing, not a complete ECDH-1PU JWE operation. Our observed Transit
P-curve `derive-key` operation also does not assemble authcrypt inside the
custody boundary. No DIDComm spec update solves the KMS-only gap; retain the
OpenBao plugin path and qualify complete, non-exporting X25519 authcrypt with
real holder decryption. Do not confuse HAIP's separate P-256 ECDH-ES response
encryption with DIDComm sender authcrypt.

Additional 2026-10-07 provider screening: [AWS KMS DeriveSharedSecret](https://docs.aws.amazon.com/kms/latest/APIReference/API_DeriveSharedSecret.html)
documents NIST ECC or SM2 key pairs, so it does not establish X25519 support.
[Cosmian documents X25519 key-pair creation](https://docs.cosmian.com/versions/kms/5.26.0/kmip_support/_create_key_pair.html),
but that does not establish a non-exporting operation that produces the two
ECDH-1PU inputs or a complete DIDComm envelope. These are source-screening
results only; no provider has passed a real recipient-decryption exercise.

Strategy decision for the current capability gap: keep the existing X25519
ECDH-1PU authcrypt profile and fail closed when its remote backend is absent.
Define one narrow Rust provider contract for a scoped, versioned sender key
reference and the exact authcrypt operation. First qualify an existing remote
KMS/HSM-backed messaging service or provider that keeps the sender private key
non-exportable and performs ECDH-1PU inside that trusted boundary; its output
must decrypt under the current holder and preserve authenticated sender headers.
A software sidecar merely relocating an exportable private key fails this goal.
Returning a raw ECDH shared secret to issuance also fails the strict
cryptographic custody boundary. A vendor's X25519 key creation, generic ECDH,
ECIES or signing claim is insufficient. If no existing backend passes, evaluate
a dedicated OpenBao secrets-engine plugin. [OpenBao 2.5.x supports external
secrets-engine plugins](https://openbao.org/docs/2.5.x/plugins/) as separate
processes; that mechanism does not add
X25519 to Transit or automatically inherit Transit's key custody. The plugin
would need its own reviewed non-exportable key lifecycle, storage protection,
backup and rotation policy, process isolation, API authorization and audit,
and the complete normative ECDH-1PU operation without returning shared or
private key material to issuance. A plugin that uses an exportable key outside
OpenBao's protected custody is not a solution. This is a distinct security
review and deployment dependency, not a silent provider switch. If no
qualifying backend exists,
authcrypt release remains blocked while independent Core adoption,
integration-secret custody and BYOK work continue. Do not use local-key fallback
or change recipient curve/profile to make an available KMS fit.

2026-10-07 existing-plugin investigation: the [first-party OpenBao plugin
collection](https://github.com/openbao/openbao-plugins) lists its secrets and
KMS plugins, but none claims X25519 ECDH-1PU or DIDComm authcrypt. Targeted
searches found a [Securosys OpenBao secrets-engine
plugin](https://github.com/securosys-com/openbao-plugin-secrets-engine)
that routes key operations to an HSM, but its published interface advertises
ECIES and lists encrypt, decrypt, sign, verify, wrap and unwrap operations;
it does not document an agreement/authcrypt endpoint or an X25519 key type.
The vendor's [v3.x
firmware algorithm table](https://docs.securosys.com/primus-hsm/Overview/algorithms_and_functions/v3.x/)
does list X25519 agreement outside FIPS mode, which makes hardware capability
plausible but does not establish the plugin API or complete authcrypt. It is an
investigation lead, not a qualifying solution. No plugin with the required full operation was
discovered; that is not proof that none exists. Generic GCPKMS, PKCS#11,
Transit, ECIES or HSM integration is not evidence of the required operation.
Before building anything, recheck candidates and require a working
recipient-decryption proof.
If we implement a custom OpenBao secrets-engine plugin, use its [supported Go
SDK](https://openbao.org/docs/2.5.x/plugins/plugin-development/) for the plugin;
keep the application-facing provider contract and orchestration in Rust. The
OpenBao 2.5.x documentation says other languages would require a nontrivial
reimplementation of the plugin protocol. No plugin design or implementation
has been qualified as satisfying the KMS-only custody gate yet.

2026-10-07 Go implementation screening: the [Go standard `crypto/ecdh`
package](https://pkg.go.dev/crypto/ecdh) supports X25519 and rejects an
all-zero ECDH result, so it can keep both ECDH-1PU agreement outputs inside
the plugin process. [go-jose/v4](https://github.com/go-jose/go-jose) lists
ECDH-ES/JWE but not ECDH-1PU; the [Hyperledger Aries Go
framework](https://github.com/hyperledger-aries/aries-framework-go) is
archived. Neither is a maintained, drop-in full-authcrypt backend. The
[ECDH-1PU draft](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04)
requires `Z = Ze || Zs`, SHA-256 Concat KDF, and the JWE authentication tag
as a KDF input in key-wrapping mode. Any Go implementation must keep those
intermediate secrets inside the plugin and be checked against independent
DIDComm holder decryption, normative vectors, bad-point/all-zero rejection,
tamper cases and multi-recipient behavior. Go is not installed on this Windows
host; a pinned Go container can provide a reproducible build/test toolchain.

The proposed narrow Rust-to-plugin contract is: provision an X25519 sender
key inside the plugin's OpenBao barrier-backed storage, returning only an
opaque tenant-scoped, versioned reference, public key and authorized DID key
ID; resolve that exact reference and public binding during preflight; send
bounded plaintext plus the frozen sender DID/key ID and the recipient DID,
authorized X25519 key IDs and public keys to one `authcrypt-pack` operation;
return only the complete DIDComm JWE. The plugin must independently check
tenant/key ownership, sender DID/key/public binding, plaintext `from`/`to`,
recipient key IDs and input bounds before ECDH-1PU. It must never return a
private key, `Ze`, `Zs`, raw shared secret or KEK. Rust retains DID resolution,
document authorization, delivery/retry/unknown-outcome orchestration and
frozen-attempt identity; the Go plugin owns key lifecycle and the complete
cryptographic operation. Pin key versions across retries and define explicit
rotation/retirement and OpenBao storage snapshot recovery. This contract is
design work, not a qualified backend; do not replace the current authcrypt
policy until the plugin passes real recipient decryption and process recovery.

2026-10-07 implementation checkpoint: `openbao/didcomm-authcrypt/internal/jwe`
now contains a Go, plugin-process-only X25519 `ECDH-1PU+A256KW` /
`A256CBC-HS512` envelope packer. It accepts a sender key object only inside
the plugin module, never serializes it, and returns a complete JWE. The first
local review corrected an over-restrictive recipient key-ID check that would
have rejected `did:web` hostnames containing dots and explicitly clears the
ephemeral agreement buffer even when slice append reallocates. A pinned
`golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59`
container passes `go test ./...` and `go vet ./...`; checks include RFC 3394
AES key wrap and the ECDH-1PU draft Appendix B.9 Concat KDF value. This is
only a primitive checkpoint: the OpenBao SDK backend, barrier-backed versioned
key store and authorization, independent Rust holder decryption, tamper and
multi-recipient cases, reload/storage recovery and production integration
remain to be implemented and reviewed before K2 can pass.

2026-10-07 secrets-engine checkpoint: `openbao/didcomm-authcrypt/backend`
now uses OpenBao Go SDK v2.5.1 to create X25519 sender keys in the plugin,
store private versions only through OpenBao's logical storage, expose public
key/version metadata, rotate without overwriting old versions, and pack with
an exact version. The `pack` endpoint checks sender and recipient DID/key-ID
syntax and plaintext `from`/`to` before invoking the packer. The binary is
served through the supported Go plugin entry point. `go test ./...` and
`go vet ./...` pass in the pinned Go container; the backend test covers
create/read/rotate/old-version pack, foreign recipient and sender rejection,
public-only responses and rejection of caller-supplied private fields.

A disposable OpenBao 2.5.5 dev server loaded the actual Linux plugin binary
(`sha256:143200e28bb3341dd6b1a0b9765cccfcaa5bf635c5266876323726f3e158ab5b`).
It created and packed a synthetic DIDComm message through live HTTP endpoints;
the independent Rust `affinidi-messaging-didcomm` 0.14.0 holder decrypted the
JWE with authenticated sender and normative (non-legacy) key wrapping. The
holder used the published DIDComm v2.1 Bob test vector in a temporary ignored
probe, not a checked-in private-key fixture. A scoped OpenBao policy allowed
reading only the tenant's sender public metadata and denied cross-tenant read
with HTTP 403. Live input probing found that the OpenBao framework silently
ignored unknown create fields, including `private_key`; explicit allowlists
were added to create, rotate and pack, and the rebuilt binary rejects the
private field with HTTP 400. An in-memory storage test also caught and fixed
premature clearing of a buffer retained by `logical.Storage.Put`. The latest
self-review added duplicate top-level plaintext-field rejection to avoid
ambiguous `from`/`to` interpretation; the exact rebuilt binary returned HTTP
400 for a duplicate `from`, and its JWE still decrypted in the Rust holder.
The same binary's scoped policy read succeeded for `tenant_a` and returned
HTTP 403 for `tenant_b`. All live tests used an isolated disposable dev server;
its container was stopped and removed afterward.

This is still feasibility evidence, not K2 acceptance or a production plugin.
The first dev server used in-memory storage and root-created keys. A separate
disposable OpenBao 2.5.5 server with file storage loaded the same binary,
initialized and unsealed, created version 1, restarted and unsealed again,
read back the identical public key/version, then packed an authenticated JWE
that the independent Rust holder decrypted. It rotated to version 2 with a
different public key while version 1 remained readable and could still pack
an independently decrypted JWE. This proves basic barrier-backed restart and
frozen-version behavior; it does not yet prove backup restore, multi-node
concurrency, plugin upgrade, retirement, or operational rollback. The plugin checks
that recipient key IDs belong syntactically to the supplied DID, but it cannot
independently establish that the supplied public keys were authorized by a
resolved DID document; the Rust caller must provide that authorization and
the trust boundary needs explicit review. Add strict document/public-key
binding, authenticated scoped key provisioning, tamper/low-order and
multi-recipient tests, storage snapshot/restart recovery, safe concurrency,
rotation retirement, pinned artifact packaging, real policy/tenant isolation,
and native Rust integration before removing the current authcrypt path.
The disposable recovery container was stopped and removed. Its ignored local
`.build` storage and test initialization material remain on this workstation:
automatic command review rejected both scoped recursive cleanup and deletion
of the specific initialization file. These temporary files are excluded by
the module's `.gitignore`; remove them once the local cleanup restriction is
resolved, before sharing or archiving this worktree.

2026-10-07 input-hardening review: the Go backend now uses one bounded,
recursive duplicate-key validator for plaintext and recipient JSON, rejects
excessive recipient/base64 input before decoding, and limits JSON nesting.
`go test ./...` and `go vet ./...` pass. The test corpus uses public DIDComm
v2.1 Bob keys to check two distinct wrapped recipient keys, rejects a
duplicate recipient `kid`, and rejects the all-zero X25519 point through the
backend callback. These are unit-level negative/shape checks on the newer
source head; the last live OpenBao + independent Rust holder proof was on the
earlier binary hash above. Repeat that live proof on a final reviewed binary
after native integration and any further plugin changes.

2026-10-07 lifecycle concurrency review: a new test ran twelve simultaneous
rotations against one key and exposed duplicate version assignments and lost
updates despite `StartTxStorage`. The backend now serializes create, rotate
and public-key reads with a process-wide lifecycle lock; twenty repeated
concurrency runs, the full Go suite and `go vet` pass. This fixes a single
plugin process. It is not evidence for concurrent writers in separate OpenBao
nodes or plugin processes; qualify the supported HA routing/storage model or
switch to a globally collision-resistant version identifier before release.

2026-10-07 version-reference revision: the plugin now assigns 128-bit random
lowercase-hex identifiers to private-key versions instead of incrementing
integers. Exact version paths no longer compare against a mutable numeric
current value, so simultaneous plugin processes cannot choose the same
storage slot in normal operation; the advisory `current_version` pointer can
still have last-writer-wins semantics across active processes and must not
drive a frozen issuance attempt. The process lock remains for local lifecycle
ordering. Twenty repeated concurrent rotation runs, full Go tests and `go
vet` pass. Disposable OpenBao 2.5.5 loaded the new binary
(`sha256:641e517d2eb3ce33de73b97725402ca598c094cd35ee7350e3e65e70a112313c`),
returned a 32-character opaque version, packed at that exact path, and the
independent Rust DIDComm holder decrypted the authenticated JWE. A live
rotation returned a distinct version and preserved the old version/public
key. The disposable container was stopped and removed. The earlier file-store
restart proof used numeric versions; repeat recovery and HA qualification
with the final opaque-version binary before K2 acceptance.

Native issuer interface review for K3: `NativeDidcommEnvelope` currently reads
`sender_x25519_private_key` from the issuer policy, retains the bytes in
`PreparedEncryptionMode`, and calls a synchronous local Core authcrypt packer.
The transaction already exposes `organization_id` before preflight; pass it
into `prepare_encryption` and require the versioned OpenBao key reference's
tenant to equal it. Preflight must compare the plugin's public key/version and
sender key ID to the resolved issuer DID document, freeze the selected
recipient key IDs/public values from the resolved holder DID document, and
call the plugin once for preflight. Make final `encrypt_prepared` asynchronous
and send the frozen sender reference/version, recipient set and plaintext to
the same scoped remote operation; preserve the current repository claim,
staging, retry and unknown-outcome sequence. Remove raw-key policy acceptance
and all local authcrypt calls from the production graph. Existing Canvas,
renewal, policy-contract and compose fixtures still generate raw keys and
need replacement with scoped disposable OpenBao/wallet setup rather than a
test-only local fallback.

2026-10-07 DIDComm curve check: the [DIF specification catalog](https://identity.foundation/specs/)
lists v2.1 as ratified, although the [v2.1 document](https://identity.foundation/didcomm-messaging/spec/v2.1/)
itself says "Working Group Approved." It already permits `ECDH-1PU+A256KW`
with X25519, P-384, P-256 and optional
P-521; [v2.0](https://identity.foundation/didcomm-messaging/spec/v2.0/)
listed the same curves, so this is not a new relaxation. The v2.1 changelog
mentions only service endpoint and empty-body changes, not cryptography.
The published v2.1 page still identifies itself as the latest stable version;
there is no newer DIDComm algorithm change to wait for. Current
[OpenBao Transit](https://github.com/openbao/openbao/blob/v2.5.2/builtin/logical/transit/path_derive_key.go)
does have NIST-curve ECDH key agreement since 2.2.0. The pinned 2.5.2
implementation accepts P-256/P-384/P-521, takes a PEM peer public key and
persists a new non-exportable symmetric key after its own KDF. It has no
X25519 key type and no complete ECDH-1PU/JWE operation. This corrects the
earlier claim that Transit lacked NIST-curve agreement altogether. The
non-exportable symmetric output is useful, but it cannot be assumed to match
DIDComm's JOSE Concat KDF or A256KW inputs; demonstrate the full envelope
inside the trusted boundary before treating it as an authcrypt backend.
Authcrypt still
requires ECDH-1PU in a JWE and A256CBC-HS512; a conforming DIDComm
implementation must support X25519, P-384 and P-256, with P-256 marked
deprecated in favor of P-384. A P-384 KMS key would be spec-compatible for
a particular exchange only if the sender
and each recipient DID document actually expose compatible P-384
`keyAgreement` methods and a real holder decrypts the envelope. Current Marty
issuer publication, disposable interoperability setup and frozen authcrypt
fixtures are X25519-specific; current Core `marty-didcomm` resolves authorized
X25519 methods rather than providing a general P-384 packer. Its current
`affinidi-messaging-didcomm` 0.14.0 dependency implements X25519, P-256 and
secp256k1 agreement, but not P-384; a P-384 route needs crypto-library work
as well as DID publication and remote custody. This is also a separate
interoperability gap against the v2.1 required-curve list. Multiple
recipient key types require separate
encryptions, so a P-384-only switch would lose the current X25519 holders.
[AWS KMS DeriveSharedSecret](https://docs.aws.amazon.com/kms/latest/APIReference/API_DeriveSharedSecret.html)
accepts NIST ECC key agreement, including [P-384 key
specs](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html),
but returns the raw shared secret by default;
it does not perform the complete DIDComm ECDH-1PU/JWE operation inside KMS.
Thus P-384 is a legitimate additional interoperability research track, not
proof of strict KMS-only custody or a replacement for the X25519 release gate.
Qualify an end-to-end P-384 holder route and a cryptographic provider boundary
before considering a separately negotiated curve/profile.

2026-10-07 K3 implementation checkpoint: issuance now has a native Rust
`RemoteDidcommKms` HTTP client for exact tenant/name/opaque-version references.
It reads the scoped token from a file for each operation, disables redirects
and proxies, bounds response bodies, and checks returned public-key and pack
metadata against the requested reference. `NativeDidcommEnvelope` now accepts
only `sender_key_ref` in authcrypt policy, binds its tenant to the transaction
organization, verifies OpenBao's sender public key is an authorized method in
the resolved issuer DID document, freezes authorized recipient X25519 methods,
and has OpenBao preflight and finally pack the JWE. The application encrypt
port is async so the final operation remains remote; anoncrypt still uses the
existing public-only local path. The explicit authcrypt compose profile now
requires a policy directory containing its policy and scoped OpenBao token.
`cargo +1.95 check -p marty-issuance-service --lib --bin
marty-issuance-service` and `--tests` passed after these changes. This is
source/compile evidence, **not** route-level remote custody acceptance.
Targeted Rust tests passed for exact reference and URL validation (2),
tenant/missing-KMS fail closed (1), policy reference validation (1), and the
remaining anoncrypt renewal/private-IP matrix (1). `cargo +1.95 fmt -p
marty-issuance-service` and `git diff --check` passed.
The opt-in `didcomm_remote_kms_live` test passed against disposable OpenBao
2.5.5 image digest
`sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452`
with Go plugin binary SHA-256
`641e517d2eb3ce33de73b97725402ca598c094cd35ee7350e3e65e70a112313c`.
It created a server-held sender key, minted an OpenBao token limited to
public-version read and exact-version pack, proved create was denied with
HTTP 403, resolved the public DID method, preflighted issuance through the
native Rust envelope, rotated the sender key, changed the policy file, and
packed the final message from the frozen old reference. Core's independent
holder decryptor authenticated the sender and recovered the exact plaintext.
The disposable container was stopped and removed. This is live **envelope**
evidence for issuance's adapter; it does not yet cover the claim/stage/send
workflow, packaged runtime image, restart/unseal with opaque versions, HA
current-pointer behavior, production tenant token provisioning, or the
Canvas acceptance path. The first setup attempt failed because its plugin
hash path was resolved below `rust/`; that run returned HTTP 404 and is not
counted as a pass. The corrected setup and test passed without changing the
plugin binary.

2026-10-07 K3 packaging checkpoint: `openbao/didcomm-authcrypt/Dockerfile`
builds the Go plugin with pinned Go 1.25 Alpine and OpenBao 2.5.5 base
digests; `.build` is excluded from Docker context. Local image
`marty-openbao-didcomm:local` built as image ID
`sha256:94fd08ef3b7e32cbdedf0e3f33e0566d6e868f328fcf3d6cc881fa606cbd1ce4`;
its installed plugin SHA-256 is
`34475431acf120c545061b37f0137ce58aedf40f76666b3f12d5f8ae48a9007c`.
Self-host OpenBao HCL specifies the plugin directory. Its server and
bootstrap compose services require the same reviewed image reference, and
bootstrap registers/mounts the plugin only when required, failing on a
missing binary or catalog hash drift. The developer authcrypt overlay selects
this image and requires plugin bootstrap. The self-host example and
production checker require an immutable `@sha256` reference. The local image
passed Docker build, shell syntax and both standalone self-host and developer
overlay Compose renders (with synthetic other-service inputs). A disposable
OpenBao instance loaded the packaged plugin, bootstrap completed twice, and
the opt-in Rust issuance authcrypt/rotation/holder test passed against it.
Disposable containers were stopped and removed. The image has **not** been
published by digest; no installed self-host runtime, coordinated plugin
upgrade/reload, production key provisioning or rollback has been qualified.
Catalog hash drift intentionally fails bootstrap until an explicit upgrade
has recovery evidence.
The exact default-base/native Compose model gate now accounts for the plugin
image, guarded mount and token-file bindings; all 12 selected models and
missing-policy-directory negatives passed locally. The self-host production
checker rejects a non-digest OpenBao plugin image reference. Python syntax
compilation and `git diff --check` pass; the full self-host runtime checker
still needs production dependencies and a running stack.

The old positive authcrypt test used an application private key and was
replaced with reference-tenant and missing-KMS fail-closed checks; the renewal
matrix currently covers anoncrypt only. The opt-in live adapter test covers
policy swap after preparation and old-version packing, but positive authcrypt
renewal and claim/stage/send still need a disposable real OpenBao and holder
test before release. The obsolete Python-policy contract and
Canvas acceptance policy fixtures still contain raw sender-key fields and
must be migrated or retired. A preexisting issuance verifier test called a
Core `#[cfg(test)]` helper unavailable to dependents; its broken adapter test
was removed pending a public-vector replacement. Do not count these coverage
gaps as qualified behavior.

### Hardened Core consumer checkpoint

2026-10-07 candidate adoption work is uncommitted and not release qualified.
Core main remains `a5cb567`. The UI workspace candidate now pins
`marty-crypto`, `marty-iso18013`, `marty-oid4vci`, `marty-verification` and
`marty-status` to its 0.2.0 API. Signing-keys, native issuance/Canvas worker,
and Flow production binaries passed targeted `cargo check`. The remote
credential builder now passes the DID-resolved public JWK to Core's opaque
prepare/assemble contract; Core 0.2 verifies the remote signature before
assembly. The old empty `IssuerKey` configuration was removed.

The Gateway's VC-API bridge formerly called `create_proof_jwt`, which Core 0.2
correctly makes test-only because it generates and signs a holder proof key
locally. The current uncommitted candidate delegates proof creation to a new
authenticated signing-keys endpoint: it creates a non-exportable OpenBao
Ed25519 key, binds the exact issuer URL and nonce, verifies the resulting
proof, and deletes the key. Targeted signing-keys/Gateway binary checks, the
Gateway forwarding test, and an opt-in live OpenBao proof test pass. This is
not release qualified: the production configuration and cleanup changes below
still need packaged-route and restart testing before review.
Flow's restartable HAIP response decryption also uses Core
0.1.62 private-JWK generation/decryption helpers; Core 0.2 offers an opaque
one-use in-memory session, which cannot decrypt an outstanding response after
a process restart. The candidate isolates those two Flow calls behind an
explicit `marty-verification-compat` dependency while preserving current
behavior. That compatibility edge pulls old `marty-crypto`, `marty-oid4vci`,
SD-JWT and isomdl revisions into Flow and must be removed before K5 closes.
The DIDComm 0.1.62 pin similarly remains until K2/K3 remote authcrypt exists;
the 0.2 API intentionally rejects caller-supplied sender private keys. The
passport `marty-emrtd-issuance` pin now targets Core `a5cb567`, aligning the
remaining eMRTD fork dependency. Native issuance and Canvas worker production
binaries passed `cargo +1.95.0 check` after this update. The signing-keys
certificate and lifecycle tests now use public OpenBao-issued vectors; passport
self-signed tests still need a remote or public-vector replacement. No broad
test, graph or release-artifact qualification is claimed.

2026-10-07 K5 test-build checkpoint: `cargo +1.95.0 test -p
marty-signing-keys --lib --locked -q` passes (122 passed, 7 ignored). The
`certificate_issuance.rs` and `csca_lifecycle.rs` test modules no longer import
Core's gated `cert_builder`/`keygen` or create issuer keys locally. Synthetic
public CSR and certificate PEM vectors were generated by a disposable pinned
OpenBao 2.5.2 PKI instance using internal keys, then checked into
`tests/fixtures/public_certificates` with custody provenance; the container was
removed after generation. Positive CSR proof, issuer key match, chain,
signature rejection, certificate validity, path-length and tenant-lease tests
compile and run under the normal library suite. No private key material was
copied into the repository. The previous full-chain scenario in which an
intermediate expires while its child remains valid is currently covered at
the chain-parent policy boundary only. Restore the complete scenario with a
remote-signed public vector before regression review closes. The short-lived
certificate tests use its embedded validity time so the suite does not depend
on wall-clock time. This does not qualify the seven ignored integration tests
or the full workspace.

2026-10-07 VC-API holder-proof custody follow-up: signing-keys now reads the
existing `BAO_ADDR` and `BAO_TOKEN`/`OPENBAO_SERVICE_TOKEN` configuration,
including the supported token-file secret, and binds proofs to the same
`ISSUER_BASE_URL` used by Gateway. Compose and Oracle Kubernetes signing-keys
manifests now supply that issuer origin. The OpenBao bootstrap policy grants
create/read/delete/config/sign only for `vcapi-holder-*`; its existing list
permission supports a five-minute reconciliation loop that deletes keys older
than one hour after a process crash or uncertain request outcome. The live
OpenBao 2.5.2 test passed with a minted `credential-service` policy token:
verified JWT proof, nonce rejection, immediate key deletion, and cleanup of
a simulated stale key. Both compose files parse with required deployment
variables supplied; targeted signing-keys and Gateway production-bin `cargo
+1.95.0 check --locked`, the targeted Gateway VC-API forwarding test, and
`git diff --check` pass. The disposable OpenBao
instance was removed. Remaining: exact packaged Gateway-to-signing-keys-to-
issuance round trip, restart/cleanup exercise, production policy migration and
artifact qualification. The current shared service token gains only the
temporary-key prefix privileges; review whether a dedicated token is warranted
before release.

2026-10-07 route-level acceptance follow-up: the ignored live OpenBao test now
starts the signing-keys HTTP router and uses the same `BAO_ADDR`, `BAO_TOKEN`
and `ISSUER_BASE_URL` variables as deployment. With a minted scoped
`credential-service` policy token, the route returned 401 without the internal
API key, returned a verifiable Ed25519 OID4VCI proof when authorized, and
returned 422 for a foreign issuer origin. It also retained the direct KMS
verification, wrong-nonce rejection, immediate deletion and stale-key reap
checks; the full test passed against disposable OpenBao 2.5.2. This proves the
signing-keys route and token policy, not yet the packaged cross-service flow.
The current signing-keys library suite also passes (124 passed, 7 ignored).

### Integration-secret custody seam

`IntegrationSecretCipher` currently holds a raw AES-256 key and stores standard
base64 of a 12-byte nonce, AES-GCM ciphertext and 16-byte tag. The database
column `organization_integration_secrets.encrypted_secret_value` is text; no
envelope version or tenant/purpose AAD is stored. Issuance startup and the
Canvas sync worker load the raw master key independently. The same PostgreSQL
vault serves OAuth, Canvas Credentials and management calls, making it the
canonical place to move encryption and decryption behind one async remote
storage interface. The existing Python vector proves the legacy layout but
does not prove deployed data or old-key availability.

Owner selection: the existing signing-keys service already hosts authenticated
internal OpenBao Transit operations for flow-key and passport-artifact envelopes.
Add a purpose-specific integration-secret envelope there, using a distinct
non-exportable Transit key and the existing provider transport. Issuance's
PostgreSQL vault remains the sole database owner and calls that envelope through
a typed async client; the Canvas worker uses the same client and policy. The
service token authenticates issuance to signing-keys, while the issuance vault
continues to enforce tenant-bound database selection. The envelope additionally
binds organization, secret ID, provider and purpose on decrypt. This reuses the
deployed remote-custody owner without duplicating OpenBao code in issuance.

2026-10-07 implementation checkpoint: signing-keys now has a dedicated
integration-secret Transit envelope and authenticated encrypt/decrypt endpoints;
the gateway forwards these with its trusted organization scope. A disposable
OpenBao 2.5.2 exercise passed remote round-trip, identity mismatch, tamper and
rotation checks. This is an API seam only: issuance and the Canvas worker still
use the legacy raw AES key, so K4 custody and migration remain incomplete. The
OpenBao plugin option above is separate K2 research and has not been built or
qualified as an X25519 solution.

2026-10-07 follow-up checkpoint: issuance now has a typed Rust client for the
versioned remote envelope and the PostgreSQL vault has an explicit remote
storage constructor. All four identity fields flow from the database row into
remote decrypt; remote mode rejects legacy ciphertext instead of silently
falling back. The isolated client contract passed with a synthetic server.
Production startup still selects the legacy constructor and reads a raw master
key. The old key cannot be removed until a tenant-scoped legacy migration,
recovery proof and real remote database exercise pass; the remote constructor
alone does not establish K4 acceptance.
The typed client tests passed (identity forwarding, legacy rejection and
envelope schema checks), and the existing Canvas OAuth PostgreSQL contract
passed against a disposable PostgreSQL 16 instance after the vault refactor.
No production remote database round-trip is claimed.

The deployment inventory also shows a legacy Python issuance service alongside
the native Rust service, with the gateway retaining an exact legacy route
remainder. Before a database-wide cutover, verify whether any of those routes
can create or read `organization_integration_secrets`; stop every such writer
for migration or retire its route. The API, Canvas worker and any remaining
legacy owner must never run different ciphertext formats against the same
table. The self-hosted and Kubernetes manifests currently pass the raw master
key to more than one process, so deployment and provisioning changes belong in
the same K4 feature PR as the migration and remote-only startup.

2026-10-07 migration implementation in progress: an explicitly feature-gated
Rust `marty-integration-secret-migrate` binary now pages through the actual
PostgreSQL table under an advisory lock. `audit` needs only remote credentials
and decrypts every versioned envelope, failing on any legacy row. `migrate`
uses the old key only inside this one-shot process, authenticates each legacy
value, asks the remote envelope owner to encrypt it with database-bound tenant,
secret ID, provider and purpose, verifies a remote decrypt against the old
plaintext, and performs a compare-and-swap update. A rerun verifies already
migrated rows; a full remote audit runs after migration. The binary is absent
from the published service-image binary list. The opt-in
`scripts/test_integration_secret_migration_live.ps1` now exercised the built
Rust migration binary and signing-keys service against disposable PostgreSQL
16, Redis and OpenBao 2.5.2. It proved pre-migration audit failure, one-row
migration, idempotent rerun, remote-only audit with the old key removed from
the test environment, audit after Transit key rotation, and rejection after
changing the database-bound purpose. All disposable containers were removed.
This is not yet a qualified production cutover: active-writer exclusion,
snapshot/recovery, runtime switch and manifest changes remain.
Cutover sequence: stop every issuance and Canvas writer/reader; snapshot the
database and retain the old key under offline recovery control; run migration;
run `audit` with no legacy key in the environment; switch both native API and
worker to remote-only startup; then remove the raw key from all runtime
manifests and provisioning. Never run legacy and remote writers concurrently.

2026-10-07 native startup checkpoint: the Rust issuance API and Canvas worker
now construct only `KmsIntegrationSecretCipher` and refuse raw master-key
configuration. A shared typed-client preflight performs a remote round-trip
even for an empty table and authenticates every stored row against its database
identity before either process serves or consumes work. The offline migration
tool uses that same audit. Native Compose, self-host, beta, disposable passport
and Oracle Kubernetes bindings no longer pass the raw key to those Rust
processes; the legacy Python issuance service still receives it until K7
retirement is qualified. The disposable PostgreSQL/OpenBao/signing-keys test
passed again with empty-table KMS proof, wrong service credential rejection,
migration, idempotent rerun, rotation and purpose mismatch. Both native Rust
binaries and the migration binary passed `cargo check`; the typed-client tests
(2) and issuance config tests (40) passed. Base and self-host Compose closed
model gates passed, as did the focused Kubernetes/native-candidate tests (39).
The broader Python fixture run had 357 passing checks but 9 unrelated
`marty_common` import failures in this worktree; those and remaining process
fixtures that assume a local key must be reconciled before PR review. No
packaged process restart or snapshot recovery proof is claimed yet. The legacy
cipher still exists in the issuance library for compatibility tests and the
offline migration feature, so production artifact exclusion is not yet proven.
The Rust Kubernetes release-evidence test target had 12 passing tests and one
unrun operational path on this Windows host because `envsubst` is unavailable;
the corresponding focused Python manifest checks passed. The missing
`packages/marty_common` package is absent from this checkout's `HEAD`, not
caused by the KMS edits, but the nine import failures still prevent a clean
full suite claim.

2026-10-07 production-graph follow-up: `PostgresIntegrationSecretVault` now
has one storage path, the remote client; the raw AES implementation and its
direct `aes-gcm` dependency compile only with the explicit offline
`integration-secret-migration` feature. Default issuance and Canvas acceptance
targets compile, and the migration-feature Python AES vectors passed (2).
The OAuth PostgreSQL contract passed against disposable PostgreSQL 16 using a
keyless synthetic remote test server. Shared issuance and worker process
launchers now supply that remote endpoint instead of a raw master key. Their
runtime behavior still needs a fully migrated disposable service schema:
the isolated smoke attempt reached issuance startup but failed on a missing
pre-existing `issuance_transactions` table, before remote preflight. This is
fixture setup evidence, not a remote process pass. Retire the remaining raw
key assumptions in rendered deployment fixtures and qualify packaged startup,
recovery and exact production artifacts before closing K4.

2026-10-07 native integration-secret process checkpoint: the opt-in live
migration script now pins the patched OpenBao 2.5.5 image digest
`sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452`
instead of the floating `:2` tag. A separate disposable OpenBao 2.5.5,
PostgreSQL 16, Redis and actual Rust signing-keys process supplied a
non-exportable integration-secret Transit key. A synthetic organization-bound
secret was encrypted by the live signing route and stored as a versioned
remote envelope. With the small OID4VCI migration fixture, the actual local
Rust issuance executable reached `/health` and `/ready`. After Transit key
rotation it restarted and reached the same healthy/ready state while reading
the old-version envelope. Changing the stored purpose made issuance fail
startup with `InvalidEnvelope`; restoring it and supplying a wrong internal
signing key made startup fail with `Unavailable`.

The minimal fixture lacked Canvas worker tables: the worker passed remote
preflight but logged repository cycle failures, so that run is not a healthy
worker acceptance. To qualify the full schema without copying customer rows,
`pg_dump --schema-only --no-owner --no-privileges` read the current self-host
`marty` database and restored only DDL into a second disposable database.
The same synthetic remote envelope was inserted there. The actual Rust
issuance executable reached healthy/ready, and the Canvas worker remained
running through its cycle without those missing-table errors after the Transit
rotation. Changing that row's purpose made the worker exit with
`InvalidEnvelope` before its cycle. No data rows were copied from self-host,
and no running deployment was mutated. All disposable services were removed;
the local processes were stopped and their ports verified closed. This proves
local built-process remote preflight and fail-closed behavior on a schema
matching that self-host instance. It does not prove packaged image startup,
the complete deployed schema set, real tenant data, OpenBao backup/restore,
or a supported production cutover.

2026-10-07 cutover recovery checkpoint: the disposable live migration contract
now captures a PostgreSQL custom-format snapshot before migration, restores it
into a separate database after the primary database has passed remote-only
audit and Transit rotation, verifies the restored legacy envelope is exact,
then re-migrates the restored row and passes a remote-only audit with the old
key removed again. The script passed against PostgreSQL 16, OpenBao and the
actual Rust migration/signing-keys binaries; all test containers were removed.
This proves the database snapshot/re-migration procedure for the synthetic
row. It does not yet prove OpenBao key backup/restore, packaged service restart,
or rollback of a real deployment and its concurrent writers.
Do not use OpenBao's [Transit key backup endpoint](https://openbao.org/docs/next/api/secret/transit/)
for that missing proof: its documented response is a plaintext backup of all
key versions, contrary to this custody objective. Qualify a protected storage
snapshot and unseal recovery appropriate to the deployed OpenBao backend;
[integrated Raft snapshots](https://openbao.org/docs/next/commands/operator/raft/)
are one supported mechanism when Raft is the primary storage backend. The
current self-host OpenBao configuration uses `storage "file"`, so its actual
recovery proof requires an atomic protected copy of the persisted storage
directory plus the corresponding unseal material and a restored-instance
decrypt check. The disposable dev-mode test does not exercise that mechanism.

2026-10-07 OpenBao recovery follow-up: the opt-in
`scripts/test_openbao_file_recovery.ps1` passed with the deployed self-host
file-storage configuration in disposable OpenBao containers. It initialized a
non-exportable Transit key, encrypted synthetic plaintext, stopped the source
instance, copied its persisted storage to a separate Docker volume, started and
unsealed a restored instance, and decrypted the pre-snapshot ciphertext. This
is a cold, quiesced copy and does not export Transit key material. All owned
containers and volumes were removed. It proves a local storage restore path,
not the production backup system, off-host retention, key-share custody,
hot-snapshot consistency, or a coordinated PostgreSQL/OpenBao point-in-time
restore. Those remain cutover gates.

Review found `PostgresIntegrationSecretVault::value` committed `last_used_at`
before decrypting and updated by secret ID alone. The local UI branch now locks
the tenant-bound row, authenticates ciphertext first, and only then updates
tenant-bound usage in the same transaction. The focused Rust test target
compiled, and its tampered-ciphertext regression passed against a disposable
PostgreSQL 16 container; the container was removed. This is migration preparation,
not opaque custody yet. New ciphertext must carry an explicit version and bind
organization, secret ID, provider and purpose; production must not retain a
legacy raw-key read fallback. Legacy reads need an explicit qualified migration
and recovery window before raw-key configuration is retired.

2026-10-07 hardened Core dependency checkpoint: the Rust workspace now pins
`marty-didcomm` 0.2.0 at Core revision `a5cb567` with `kms-only` enabled and
`local-key-operations` absent. Issuance enables only `did_web` and
`encrypted-envelope` for public-key resolution and anoncrypt. The production
issuance library and binary pass `cargo +1.95 check`; `cargo tree -e features`
shows only those three DIDComm features. The revision returns validation
errors for X25519 method extraction, which production issuance now handles
fail closed. Issuance and Canvas acceptance test targets now compile without
the removed Core `decrypt_jwe` / `decrypt_authenticated_jwe` helpers. A shared
test-only adapter uses the independent holder DIDComm crate for envelope
decryption, and public DID fixtures use the validated constructors. All 40
focused native DIDComm unit tests and the delivery atomicity test pass. Static
synthetic holder private-key fixture values and older Canvas policy/setup
paths remain; replace them with
runtime holder or disposable KMS/wallet custody before acceptance. The live
authcrypt interoperability test must be rerun against the packaged plugin.
This checkpoint is not release qualification.

The Canvas dependency graph also still carries Core 0.1.62 through
`marty-flow`'s `marty-verification-compat` dependency. Its HAIP response path
locally generates and unwraps a private P-256 JWK via the legacy Core API.
Retire that compatibility edge through an opaque remote session-decryption
operation while preserving OID4VP/HAIP behavior; do not mistake the DIDComm
feature audit for a production-root-wide KMS proof.

2026-10-07 HAIP remote-custody prototype: the Go OpenBao plugin now has
`haip/keys/{tenant}/{flow}` create/read and
`haip/decrypt/{tenant}/{flow}/{version}` update paths. It generates P-256
inside OpenBao, returns only a public ECDH-ES JWK and random opaque version,
and decrypts bounded direct ECDH-ES/A256GCM compact responses behind an exact
tenant/flow/version path. Private key slots are immutable by version; a
last-writer-wins advisory current pointer cannot invalidate an already-issued
reference during a multi-worker race. In-memory plugin tests cover an actual
encrypted JWE, public-only output, idempotent create, wrong scope/version,
tampering, pointer replacement and missing-current-version failure.
`go test ./backend ./internal/jwe` and a pinned multi-stage image build pass
(local image ID
`sha256:0f902620d71a4574d558fffbdfb80398891000840e6dad52849f9e1eb28e4044`).
The signing-keys Rust service now exposes internally authenticated
`/internal/haip-response-keys/create` and `/decrypt` routes through its
OpenBao provider. They validate exact tenant/flow/version binding and a
public-only P-256 JWK before returning an opaque reference. Its library and
binary check, and the scope/JWK validation unit test passes. A broad
`cargo +1.95 check -p marty-signing-keys --tests` still fails in older CSCA
integration tests that import gated `marty_crypto::cert_builder`/`keygen` and
`marty_verification::issuance`; those fixtures need remote/public-vector
replacement, not a local-key feature flag. This is not a
live OpenBao acceptance. New Flow HAIP/DC-API request objects now obtain that
public JWK and scoped version reference through the signing provider; they
persist only the opaque reference and never invoke private-JWK wrap for newly
created sessions. Response decryption validates the tenant/flow/version and
public JWK before calling the remote operation. The request-object contract
was changed to remote non-exportable custody. `cargo +1.95 check -p
marty-flow --tests` and focused request-object (6), verification request (3),
verification start (3), and complete verification-submission (12) tests pass.
The signing-keys, Flow and Gateway production binaries also pass Cargo 1.95
checks after this wiring. The older
`vault:` branch remains for already-issued sessions and still pulls
`marty-verification-compat`; no production-root-wide custody claim follows
from the new-flow tests. Next: provision a least-privilege plugin token,
prove the rendered signing and Flow services against a live OpenBao plugin
and real holder response, measure and drain outstanding wrapped HAIP sessions
with their existing expiry/retry semantics, remove the wrap/unwrap private-JWK
path and `marty-verification-compat`, then prove restart, ACL isolation, real holder
response, and release artifacts. Key lifecycle/retention and multi-worker
current-pointer behavior need qualification before production cutover.

2026-10-07 HAIP custody follow-up: signing-keys now reads a separate
`HAIP_KMS_TOKEN_FILE` for each HAIP operation. No configured file, blank/oversize
contents, or an unreadable file fails closed; it never falls back to the broad
Transit token. The focused Rust token-rotation test observes the distinct
scoped token on successive requests and rejects an unconfigured HAIP token.
The self-host production compose now mounts a distinct `haip_kms_token` secret,
and its preflight checker requires that secret file. The checked-in
`docker/openbao-haip-workload-policy.hcl` grants only HAIP key create/read and
HAIP response decrypt routes; provision its token without OpenBao's default
policy. This policy is service-wide across HAIP flows, so the Rust
signing-keys authorization and tenant/flow binding are still security-critical.
It does not constitute a per-tenant OpenBao ACL.
The self-host OpenBao bootstrap now writes this policy and mints a separate
orphan token without the default policy into the signing-keys secret file.
On restart it reuses only a token with exactly that policy; an invalid or
overprivileged existing token fails closed for explicit rotation. The lookup
also rejects an identity-attached token, since identity policies can add
capabilities after issuance. OpenBao 2.5.5 token lookup omits the newer
`token_policies`/`identity_policies` fields, so the actual checked fields are
the effective `policies` list and empty `entity_id`; both passed live tests.
The example
secret inventory and OpenBao Compose mount were updated. Shell syntax and the
OpenBao Compose render pass. A disposable 2.5.5 file-storage instance ran the
full self-host bootstrap twice against persistent Docker volumes: it
initialized/unsealed the server, registered/mounted the plugin, minted the
HAIP token on the first run, and reused that same token on the second run.
The second run initially replaced the pre-existing `credential-service`
token because its older sign probe sent unpadded base64 `dGVzdA`, which
OpenBao rejected with HTTP 400 despite the token's `create, update` capability.
The probe now sends padded `dGVzdA==`. A fresh two-pass file-storage test
minted credential, Notification and HAIP tokens on the first run and reused
all three on the second, with no signing-probe rejection.
The two-pass test passed again after the identity-binding guard was added.
The disposable server and volumes were removed. The first test setup failed
because its Docker state volume was root-owned; a fresh test volume with UID
100 ownership passed. The normal self-host bind directory still needs an
operator permissions check. The complete rendered self-host signing-keys and
Flow services remain untested against this token.

The opt-in `TestHaipScopedLiveOpenBao` passed against a disposable OpenBao
2.5.5 process running the packaged Go plugin. It created an immutable remote
P-256 key, encrypted a compact ECDH-ES/A256GCM response outside the plugin,
and decrypted it with a flow-scoped token. Cross-flow decryption and key
creation were denied for that token. The same test loaded the actual checked-in
workload policy, minted a token without the default policy, proved HAIP
create/read/decrypt, rejected wrong-key ciphertext, and observed denied plugin
administration and DIDComm sender-key access. The disposable container was
removed. Root token lookup also confirmed the workload token carried the
dedicated policy alone. This proves the Go/plugin/OpenBao ACL boundary for those operations;
it is not full wallet or rendered Rust-service interoperability, and it does
not qualify production token provisioning. The first disposable registration
attempts failed on a malformed test-script SHA argument, before plugin mount;
the command was corrected to use the verified binary digest. The Go test and
cleanup then passed. Next wire/qualify the rendered Rust signing and Flow
services with a policy-minted secret, a real holder response, and restart.

2026-10-07 Rust signing route live checkpoint: an opt-in Go integration test
now calls the actual Rust `marty-signing-keys` HTTP process with an internal
API key. Against disposable OpenBao 2.5.5 with the packaged plugin and a
policy-minted token file, the Rust route returned an opaque HAIP reference
and public P-256 JWK; an independent Go JOSE holder encrypted a compact
ECDH-ES/A256GCM response to that key; Rust asked OpenBao to decrypt and
returned the exact plaintext. The test also observed HTTP 401 for an invalid
internal API key and HTTP 503 for cross-flow decryption. A disposable Redis
served the Rust process. `cargo +1.95 build -p marty-signing-keys --bin
marty-signing-keys` and `go test -run TestHaipRustSigningRouteLiveOpenBao -v
./integration` passed. The process, both containers and the synthetic token
file were removed. This qualifies the signing route with a Go test holder,
not a production image, Flow submission route, or real wallet app. The next
end-to-end gate is the actual Flow request object and submission path through
that Rust service, including restart and existing-session compatibility.

2026-10-07 Flow library live checkpoint: the Go holder test can emit a
temporary public-only input containing the remote HAIP reference, public JWK,
compact JWE and synthetic expected plaintext. An opt-in Rust Flow test then
uses `HttpSigningProvider` against the running Rust signing-keys service,
checks idempotent remote key creation and exact public/reference binding,
and calls Flow's real `decrypt_verification_response`. This exercises the
Flow JWE-header validator, scoped reference parser, HTTP adapter, signing
route and OpenBao decrypt together. The exact Go holder JSON was recovered;
a wrong Flow ID was rejected before remote decryption. `cargo +1.95 test -p
marty-flow --test haip_live_signing -- --nocapture` passed with the live
inputs. The first invocation accidentally resolved the input relative to the
`rust` directory and skipped; the test now fails on partial live configuration,
and the corrected invocation passed. The disposable OpenBao/Redis processes,
Rust service, scoped token and temporary input were removed. This is a
meaningful interop gate, but it bypasses the full Flow API, persistence and
submission transaction; it does not justify retiring the legacy HAIP read
path or claiming a production deployment.

2026-10-07 legacy HAIP drain audit preparation: the read-only
`scripts/audit_haip_response_custody.sql` aggregates Flow instances by
custody shape (`vault:` legacy envelope, remote reference, both, or orphaned
public key), lifecycle bucket, and status. It emits counts and date ranges,
not session IDs or key material. It also counts public JWK fields with an
unexpected private `d` member. A disposable PostgreSQL 16 instance with
synthetic rows proved separate live legacy, past-expiry legacy, remote live,
mixed terminal, and orphaned-public groups; an unrelated Flow row was
excluded. The query ran inside a repeatable-read, read-only transaction and
the container was removed. Before removing `marty-verification-compat` and
the `vault:` read branch, run it against every supported deployment and retain
aggregate evidence;
preserve in-flight wallet/retry semantics until all actionable legacy sessions
finish or expire, then separately plan cleanup of retained terminal ciphertext
and prove supported rollback without reintroducing local private-key custody.

2026-10-07 local deployment audit follow-up: the same read-only aggregate was
run against the `marty` database in the running `marty-selfhost-prod-postgres-1`
and `elevenid-beta-postgres-1` containers. The self-host database returned
zero HAIP response-key rows across 44 Flow rows. The beta database returned
23 `legacy_only` rows across 319 Flow rows: 2 `awaiting_wallet` past expiry
(latest expiry 2026-08-12 01:01 UTC), 7 cancelled, 13 completed, and 1 failed.
It returned no unexpired legacy session, remote reference, or mixed row. Both
databases reported zero private `d` members in the HAIP and OID4VP public-JWK
context fields. These are local-stack observations,
not proof for any other supported deployment. The current beta Flow image may
still issue legacy sessions; a zero-live count is not stable until the new
remote-custody writer is deployed and a post-cutover expiry window passes.
Review correction: although the submission domain function checked expiry
before cryptographic work, the direct-post and DC-API HTTP handlers decrypted
the response first. A keyless response to either of the two past-expiry beta
sessions would therefore have failed before the expected 410 transition.
Both handlers now transition nonterminal expired sessions before decrypting.
The transition reuses the existing domain event and repository compare-and-swap
path. A disposable PostgreSQL 16 HTTP test sent deliberately invalid compact
JWEs with no key provider configured; both routes returned 410 and persisted
`expired`, proving no legacy unwrap was attempted. The disposable database
was removed. The still-running beta image does not have this correction.

2026-10-07 DIDComm live interop rerun: the opt-in Rust issuance test passed
against a disposable OpenBao 2.5.5 container built from the pinned plugin
image. The mounted plugin binary SHA-256 was
`868240cf4d153235e84deb26673ff9b2496c9e141e7061aeea61a22310098333`.
An issuance-scoped token could read its public sender-key version and pack
with that exact version, but received HTTP 403 for key creation. After the
sender key rotated and the on-disk policy changed to anoncrypt, encryption
of a previously prepared message still produced Authcrypt. The independent
holder DIDComm library decrypted it and recovered the expected sender and
recipient key IDs and plaintext. `cargo +1.95 test -p marty-issuance-service
--test didcomm_remote_kms_live -- --ignored --nocapture` passed (one test);
the disposable container and test token were removed. The holder test still
creates an X25519 private key in the test process to exercise wallet-side
decryption. Replace that fixture with runtime wallet or disposable remote
holder custody before the strict no-private-test acceptance gate. This proves
the packaged plugin's sender interop, not production deployment, holder-key
custody, multi-recipient delivery, or persistence/restart behavior by itself.

A second disposable test used the self-host file-storage configuration with
the same packaged plugin. It created a sender key, stopped the OpenBao server,
started a new server on the same volume, unsealed it, read the exact old
public-key version, and packed Authcrypt using that pre-restart version. The
old public key was unchanged and the pack response named the same version.
The server and volume were removed. This proves a simple server restart with
persisted OpenBao storage; it does not yet prove cold snapshot/restore,
multi-node writer behavior, or decryption by a holder after the restart.

Terminal sessions are different: completed/failed sessions use the decrypted
payload to compute the canonical submission digest for `already_processed`,
replay conflict, or a same-result retry. Both encrypted-submission HTTP routes
now reject cancelled sessions with the existing invalid-state response before
decryption. A disposable PostgreSQL 16 test verified HTTP 400 and unchanged
`cancelled` status for direct-post and DC-API with deliberately invalid JWEs
and no key provider. The same test retained the two expired-session 410
checks; all four rows had synthetic legacy envelopes. The database was
removed. This reduces the beta terminal legacy-key dependency from 21 to
14 rows (13 completed and 1 failed) once the corrected image is deployed;
the running beta image still needs the key for all 21. No expiry check cuts
off the completed/failed retry path today. Do not scrub their ciphertext or
remove the `vault:` read branch merely because session expiry passed.

Migration design finding: the legacy Core generator assigns a random UUID
`kid` of the form `oid4vp-haip-<uuid>` to each P-256 key. A read-only
aggregate of the 23 beta legacy records found this shape on all records and
found zero whose `kid` matched the Flow instance ID. The current OpenBao
HAIP plugin derives `kid` from its unrelated random 32-hex key version.
Any KMS-internal import must preserve the existing public key and `kid` for
already-issued wallet requests, bind them to the exact tenant and Flow, and
keep the imported private key out of steady-state Rust services. The plugin,
Rust reference validator, and offline migration transaction must be designed
together; merely swapping the context field to a new reference would reject
old wallet JWEs. Qualify that migration or an explicitly reviewed
retry-retention change across every supported deployment before retiring the
legacy read path.

2026-10-07 HAIP legacy import implementation checkpoint: the Go OpenBao
plugin now has an offline-administrator-only `haip/import/{tenant}/{flow}`
route. It accepts the exact legacy Core P-256 ECDH-ES private JWK shape,
rejects duplicate/unexpected fields and invalid or mismatched scalars,
derives a stable 32-hex version from the legacy UUID `kid`, and retains the
original public coordinates and `kid`. Existing different keys cannot be
overwritten; an identical retry and a retry after a version write without a
current pointer can finish safely. Stored key loads verify the private/public
relationship. The normal HAIP workload policy grants no import path. Flow
and signing-keys now use one `marty-oid4vp-contract::haip_key` validator for
scoped references, public P-256 points and both new 32-hex and imported UUID
key IDs. The signing-key validation test no longer constructs a private key.

Go backend/JWE tests, the shared Rust contract tests, signing-key validation,
Flow request (3) and submission (12) tests, and both Rust library checks
passed. A disposable OpenBao 2.5.5 server with the rebuilt plugin denied
import under the checked-in HAIP workload policy (HTTP 403), allowed an
administrator to import and retry a synthetic legacy key, and returned the
unchanged public `kid` to the workload without `d`. The exact rebuilt plugin
binary SHA-256 was
`4e52f6cbd3b4db77b0d2a5ef32616bb684a411baa832a643478c458fe20a12fb`.
The opt-in Rust DIDComm sender Authcrypt interop test also passed against
this binary. Disposable containers and tokens were removed. The Go import
unit test and disposable live probe necessarily handle a synthetic private
JWK to exercise the one-time import; they are not yet the strict no-private-
test acceptance state.

This is an import capability, not a data migration. No legacy Flow row was
changed. A follow-up read-only beta aggregate found all 23 legacy records
have an object `haip_response_encryption_public_jwk`, while only 6 have an
object `oid4vp_response_encryption_jwk`; the other 17 store JSON `null` in
that second field. All 6 objects match the HAIP public JWK on every standard
member. The offline migrator must validate against the HAIP public JWK for
every row, compare the second field when it is an object, and leave an
existing JSON `null` untouched. It must not require both fields to be objects
or synthesize a new public field during historical migration.

Next build the offline migration tool with a narrowly scoped import token
and the legacy Transit unwrap token, record a resumable compare-and-swap
context update only after the OpenBao public response matches, and prove
real wallet JWE decryption plus exact terminal retry behavior before removing
the legacy Flow unwrap path. Qualify storage recovery, multi-writer behavior,
all supported deployment audits and rollback separately. Keep the import
permission absent from steady-state workload tokens.

2026-10-07 offline HAIP data migration checkpoint: a feature-gated
`marty-haip-response-key-migrate` binary now lives in Flow. The normal service
build excludes it. `audit` reads Flow rows and verifies each remote key via
an exact-version, public-only plugin read; `migrate` additionally requires
`HAIP_MIGRATION_OFFLINE=1`, a Transit-decrypt token file, and a separate
admin-import token file. The two checked-in policy templates grant only the
necessary Transit decrypt or HAIP import/version-read paths. It authenticates
the old organization/Flow/purpose-bound Transit envelope through the shared
signing-keys implementation, compares the decoded JWK's public members with
the stored HAIP public JWK before import, verifies the OpenBao response and
exact key version, then replaces the `vault:` context field with a scoped
reference using a context/timestamp compare-and-swap. It preserves the
historical OID4VP public field as object or JSON `null`. A KMS import that
succeeds before a database failure is safe to retry with the same key; an
unexpected concurrent database write fails closed. Private key material is
not printed or persisted in a new database field, but necessarily passes
through this isolated one-shot migration process and its TLS connection to
OpenBao. This is a controlled migration exception, not steady-state custody.

The Flow migrator binary and its two public-preflight/config tests built and
passed with `--features haip-legacy-migration`. Go backend and JWE tests
passed after adding public-only exact-version HAIP reads. A disposable
PostgreSQL 16/OpenBao 2.5.5 test used one synthetic completed row with an
OID4VP public object and one cancelled row with JSON `null`, both carrying
real Transit-wrapped legacy JWKs. The built migrator reported
`imported=2 remote_verified=2`; an independent audit reported
`legacy=0 remote_verified=2`; rerun reported `imported=0 remote_verified=2`.
SQL aggregates confirmed two remote-reference rows, one preserved JSON
`null`, and unchanged completed/cancelled statuses. The plugin binary SHA-256
in that test was
`8ffad64c12d739394dc0241049ef636608facd5a3a14e0913864f234635f20d1`.
The disposable containers and both token files were removed. A subsequent
public-only pre-import check was added to prevent importing a valid but
wrong public key before the database comparison; focused tests and the
feature-gated binary build passed after that edit. The full disposable
two-row cutover was then repeated with that final Rust binary and the same
plugin SHA. It again returned `imported=2 remote_verified=2`, audit
`legacy=0 remote_verified=2`, and rerun `imported=0 remote_verified=2`.
SQL aggregates again showed two remote-reference rows, one preserved JSON
`null`, and unchanged terminal statuses. Both disposable containers and
their scoped token files were removed. `cargo +1.95 check -p marty-flow
--bins` passed without the migration feature; Cargo metadata records the
migrator's `required-features = ["haip-legacy-migration"]`. Compose requires
an explicit reviewed OpenBao image digest rather than this local test tag.

No running beta or self-host Flow row was changed. Before any supported
cutover, freeze all Flow writers, snapshot both
PostgreSQL and OpenBao, run fresh inventory/audit on every supported
deployment, qualify actual wallet JWE and terminal replay through the Flow
HTTP path after migration, and prove restart/restore and rollback without
restoring local-key custody. The legacy `vault:` branch and compatibility
Core pin remain until those gates pass.
Deployment inventory, fresh audits, rollback behavior, and the full Flow
transaction test also remain required.

2026-10-07 terminal HAIP HTTP checkpoint: added the opt-in
`rust/services/flow/tests/haip_remote_http.rs` test. A disposable OpenBao
2.5.5 instance running the packaged Go plugin (binary SHA-256
`8ffad64c12d739394dc0241049ef636608facd5a3a14e0913864f234635f20d1`),
a dedicated policy token, disposable Redis/PostgreSQL 16, and the actual Rust
signing-keys HTTP process were used. The independent Go JOSE holder generated
a compact JWE for a remote P-256 key; its live signing-route test passed.
The Flow HTTP test then submitted that JWE to both direct-post and DC API
routes for completed and failed database rows carrying only the remote key
reference and public JWK. Exact-digest direct-post replay returned the
already-processed error; DC API returned the existing terminal projection;
both rejected a mismatched stored digest as a replay conflict. This proves
remote decryption occurs before terminal replay evaluation through the
real HTTP routes. The first test run found a test-only casing mistake in the
projected status expectation; after correction the full live test passed.
The disposable containers, process, scoped token file, and public-only holder
input file were removed. The rows were synthetic reference-only rows, not
rows converted by the offline migrator. This does not yet prove a migrated
historical row, a real wallet response, or release image/deployment behavior;
those gates remain open.

2026-10-07 migrated HAIP HTTP checkpoint: the Go live integration test now
generates a migration-only synthetic P-256 private JWK in memory, asks the
actual Rust signing service to wrap it under non-exportable OpenBao Transit,
and writes only the opaque `vault:` ciphertext, public JWK, expected scoped
reference and independently encrypted holder JWE to a disposable input file.
The Rust HTTP test can seed this legacy-shaped completed row in an explicitly
named loopback PostgreSQL test database and, in a separate invocation, require
that the offline migrator has replaced the envelope with the exact reference
and preserved the public fields before sending HTTP requests. The fixture
contains no plaintext private key and was removed after the test.

Against disposable OpenBao 2.5.5 with the packaged plugin SHA above,
PostgreSQL 16, Redis, and the real Rust signing-keys HTTP process, the initial
audit returned `legacy=1 remote_verified=0` and the expected nonzero exit.
The first migration attempt failed with `LegacyEnvelope` because the test
setup accidentally minted tokens bearing the literal policy name `$policy`;
root token lookup and a scoped Transit decrypt confirmed the 403. Correctly
minted, separately scoped `haip-transit`, `haip-import`, and `haip-workload`
tokens were verified by lookup. The migration then returned
`imported=1 remote_verified=1`; audit returned `legacy=0 remote_verified=1`.
The HTTP test passed exact and conflicting terminal replay behavior through
both direct-post and DC API for completed and failed statuses against that
same migrated row. Migrator rerun returned `imported=0 remote_verified=1`.
Independent SQL aggregate: one row, one remote reference, zero legacy
envelopes, zero private members in the public JWK, and the original OID4VP
public object retained. The disposable services, scoped token files, and
encrypted/public holder input were removed and their absence verified.
This establishes a synthetic legacy-to-remote-to-HTTP transaction, not
real historical-data cutover, wallet-app interoperability, persisted OpenBao
restart/restore, or release-artifact qualification.

2026-10-07 K6 supported-path reconciliation: the old trust adapter's
`POST /v1/organizations/{org}/trust-config/byok` has no matching gateway or
Rust backend route and included `private_key_pem`; no active component calls
that adapter action. The actual console issuer-identity screen attaches a
public certificate via `PUT /v1/signing-keys/issuer-identities/certificate`.
That route is in the gateway contract, receives gateway-injected trusted
organization scope, selects exactly one DID/purpose/format/algorithm issuer
profile, resolves the current managed KMS public key, and rejects a
certificate whose public key differs. Its Rust request type rejects unknown
fields, including caller-supplied private-key and KMS coordinates. The latent
trust adapter now delegates to the same public API with the issuer identity
tuple, leaf and chain; it rejects the old private-key field and private-key
PEM before network I/O. This is an identity reference, not an externally
supplied raw KMS key reference; key coordinates remain server-side. Existing
console certificate UX was already public-only and remains unchanged. Separately,
the key-management wizard already registers external signing services with a
provider key reference through the signing-service config route; the
provider-neutral issuer identity path resolves the compatible service/key from
the tenant registry and the certificate path validates against its current
public key. Source tracing does not prove an external-provider BYOK enrollment
or operational coverage of each advertised provider. Focused adapter/console/
gateway UI tests passed (3 files, 29 tests), followed by the expanded focused
adapter/mock test (7 tests); `tsc --noEmit`, lint of changed JS
(no errors), and a client build with prerender disabled passed. Standard build
was blocked by missing local Puppeteer Chrome after the required postinstall
compatibility patch; no product build defect is inferred from that host setup.
The Rust issuer request test passed with `private_key_pem` among forbidden
fields under Rust 1.95. The mock trust adapter now attaches certificates only
to an existing identity instead of fabricating a new imported key. Exact
packaged gateway/signing-service and real external KMS acceptance remain;
do not claim K6 complete from a source trace or mock.

2026-10-07 K6 live Rust route checkpoint: expanded the opt-in
`service_certificate_live_kms.rs` test and ran it under Rust 1.95 against
separately named disposable Redis 7 and pinned OpenBao 2.5.5 containers.
The test created an ES256 key only inside Transit, registered its scoped
service through the public Rust config route, obtained a CSR through the public Rust service
route, and used OpenBao PKI's internal CA key to sign that CSR. No test
process created or received a private signer or CA key. The public service
route attached the matching leaf/chain, rejected the CA certificate as a
wrong-key leaf (`409`), and rejected `private_key_pem` (`422`). The
provider-neutral issuer route created the tenant's DID-selected identity,
and the stored profile selected the external service's exact Transit key
reference. The public issuer-certificate route attached the matching
certificate, rejected the wrong-key certificate (`409`), and rejected a
different tenant scope (`403`). The DID document exposed one public method
without a JWK private scalar. The stored service certificate and chain
remained readable after the rejected writes. Initial test run failed at
OpenBao PKI because the role defaulted to RSA; setting EC/P-256 resolved
that, then a role rejected a space-containing CN, resolved by using a DNS
name. A later run exposed the obsolete pre-identity assumption that the
DID document would have no public methods; JWKS correctly remained empty
because this path did not explicitly publish to JWKS. The test now checks
that actual publication behavior. The
final opt-in test passed. Both labeled disposable containers were removed,
and their loopback ports were verified closed. This is actual OpenBao
custody and Rust in-process HTTP routing. A follow-up changed the fixture to
register through `PATCH /v1/signing-keys/config`, confirmed that the public
response redacts its OpenBao auth token while the tenant registry retains
the intended key reference, then reran the complete test successfully on
fresh disposable Redis/OpenBao instances. Those containers were removed
and their new loopback ports verified closed. Actual gateway authorization,
other external KMS providers, packaged binary/image behavior and release
cutover are unproven.

2026-10-07 K6 gateway authorization checkpoint: the Rust gateway runtime
now has a focused BYOK route test for public config `PATCH` and issuer
certificate `PUT`. Both reject anonymous callers (`401`), a bogus API key
even when accompanied by a session (`401`), and a session targeting an
organization for which the fixture has no membership (`403`) before any
upstream call. An authorized session forwards each request to signing-keys
with the authorized organization in the query and no caller API key. The
existing proxy-override contract test now includes both BYOK routes and
checks trusted tenant query replacement. Both gateway tests passed under
Rust 1.95. The first draft of the runtime test incorrectly expected a
session to be fixed to its active organization: gateway policy actually
allows a different requested organization when the user has its membership
and signing-key grant; the permissive fixture granted `attacker-org`. The
correct negative case uses `org-other`, which the fixture denies. This is
in-process gateway authorization with a recording upstream, not an exact
packaged gateway-to-real-signing-service exercise or live customer-provider
qualification.

2026-10-07 K6 broader library and input-boundary review: the complete Rust
gateway library suite passed (151 tests) after updating a stale route-count
assertion from 447/460 to 449/462 for the current runtime/override route set.
The signing-keys library suite passed (127 tests, 7 ignored). During review,
the public signing configuration `PATCH` accepted arbitrary JSON and could
silently discard an unexpected private-key field during normalization. The
requested-registry boundary now rejects private material before normalization,
reusing the CSCA detector for private-key field names, private JWK scalars and
PEM markers. A focused test covers nested and ignored-service input and keeps
public certificate/auth-reference input valid. This is source-level and unit
evidence; at this checkpoint a live public-route rejection and persistence
check remained for K6.

2026-10-07 K6 public-route rejection checkpoint: added the ignored
`public_config_rejects_private_material_without_changing_registry` route test.
With a freshly named disposable Redis 7 container, a loopback DB 13 URL and
nonce sentinel, the actual Rust public `PATCH /v1/signing-keys/config` route
returned HTTP 422 for a top-level `private_key_pem`, a nested `privateKey` in
an otherwise ignored managed service, and a private PEM marker embedded in a
`key_reference`. After each rejection the stored tenant registry exactly
matched its pre-request value. The test passed under Rust 1.95, `cargo fmt`
passed after formatting, and the labeled container was removed. This closes
the specific live rejection/persistence gap above; packaged gateway-to-signing
behavior and qualified customer-provider enrollment remain open.

2026-10-07 K6 gateway-to-signing network checkpoint: both Rust service
binaries compiled with `cargo +1.95 build --locked` at the current local
tree. The opt-in gateway test now uses the production `ReqwestUpstream` and
gateway route table to call a real loopback signing-keys HTTP router backed by
a nonce-guarded disposable Redis 7 DB 13. Anonymous registration returned
401, a session without membership for `org-other` returned 403, authorized
registration returned 200 and persisted the `org-1` registry, and a private
`private_key_pem` request returned 422 without changing that stored registry.
The first exact-filter invocation selected zero tests; the corrected full
`runtime::tests::...` invocation executed one test and passed. The complete
gateway library suite then passed (151 passed, 1 ignored); `cargo fmt` passed.
The Redis container was removed. The signing-keys dependency is test-only:
`cargo tree --edges normal -p marty-gateway` excludes it. This qualifies the
Rust gateway-to-signing HTTP path with local identity fixtures, not the
packaged images or live customer KMS onboarding. Exact image, real auth/tenant
providers and external-provider acceptance remain open.

2026-10-07 K5 production-graph recheck: `cargo +1.95 test --locked -p
marty-flow --lib` passed all 44 tests. An inverse normal-edge Cargo tree for
`marty-crypto@0.1.62` confirms that Flow's direct
`marty-verification-compat` dependency remains the source of old Core
cryptography. Its normal dependency edge reaches Flow and, transitively,
compliance-profile, deployment-profile, gateway and verification-service.
The live `vault:` fallback in Flow still unwraps a private JWK and passes it
to old Core for HAIP response decryption; the previously recorded migration
and drain gates are prerequisites for removing it. Do not treat the passing
Flow suite or newer direct Core pins as proof of a clean production graph.
The focused `verification_submission_behavior` suite also passed all 12
tests, including remote scoped-version decryption, terminal replay and the
retained legacy submission behavior. These are fixture-level regressions,
not evidence that old Core can be removed before supported data cutover.

2026-10-07 packaging review: the public `services/Dockerfile` builds all
Rust service binaries in one release layer and copies both gateway and
signing-keys into its shared image; `services/entrypoint.sh` selects the
canonical Rust binary for each service name. The separate CI multi-target
Dockerfile also copies those binaries into its gateway/signing-keys stages.
Current local Docker cache has no candidate gateway/signing-keys image, and
the Windows host reported about 12 GB free while existing stacks remain
running. A fresh all-workspace release image was not built in this checkpoint;
exact image behavior remains unqualified.

2026-10-07 fresh local HAIP drain inventory: reran the checked-in read-only,
repeatable-read SQL audit against the still-running self-host and beta
PostgreSQL containers without changing either database. Self-host again has
zero HAIP response-key rows among 44 Flow rows. Beta again has 23
`legacy_only` rows among 319 Flow rows: 2 `awaiting_wallet` past expiry
(latest expiry 2026-08-12 01:01 UTC), 7 cancelled, 13 completed and 1 failed.
Both report zero private `d` members in the HAIP/OID4VP public JWK fields,
and neither reports an unexpired legacy or remote-reference row. The beta
Flow container is still the published services image
`sha256:630e6783f7e28b3e346b993f5e3e8f21162672f7b1aeef62fbd259db2434dc73`
(revision `4596afaca3724e60a8dadbd4e227b6e765cb495c`, version `1.1.217`),
not the candidate native hardening tree. Self-host Flow uses local image
`sha256:74326f974e6a2ea0eacaa18be39670435b1e85307475c33c6f673939fb0c0329`
without a revision label. Stable counts show no new observed legacy rows in
these two local stacks, but they do not prove writer cutover, other deployment
inventories or rollback readiness. No live row or key policy was modified.

2026-10-07 Credentials K7 reconciliation: created
`security/remote-kms-retirement-20261007` from Credentials `origin/main`
`e109b6c`, preserving `security/kms-boundary-hardening-v1` intact. Ported all
five preserved commits into one prospective Credentials feature PR, resolving
current-main conflicts in the Rust binding, CI, OID4VCI and dependency-health
files. The local private-key Python binding requires explicit
`local-key-operations`; production `python`, `native` and `wasm` feature roots
no longer opt in. A stateless OID4VCI offer configuration replaces a
compile-incompatible placeholder `IssuerKey`, preserving public offer
creation. The legacy Python issuance adapter is lazily loaded and quarantined
for explicit local-key use. The last preserved commit pins the reviewed
`linked-data` fork; the production Python graph no longer contains `im` or
`sized-chunks`. `cargo check --locked` passed for production Python, explicit
local-key Python and native roots before the dependency patch, and production
Python passed again after it. Targeted Python boundary tests passed (18 tests);
format and whitespace checks passed. A focused compiled Rust boundary test
passed (one test, 24 filtered), confirming the production PyO3 module omits
local private-key functions while retaining public verification functions.
The Credentials workspace still pins Core
`08a0d43` / 0.1.61, so the old Core compatibility graph and any published
Python wheel remain unqualified for the KMS-only release. Native service
cutover, encrypted-data readability and artifact checks must precede removal
of the remaining compatibility code. No PR or release artifact was created.

2026-10-07 Credentials production feature-graph review: the first boundary
port hid private-key PyO3/WASM exports but still selected the `isomdl`
`issuer-local-signing` feature in the production Python dependency graph via
the workspace dependency's defaults. That is a custody-surface gap even
though the Python module test passed. The fresh Credentials branch now sets
`isomdl` default features off, enables local signing only through its three
explicit local-key feature sets, and changes CI's inverse graph check to
require absence in `native`, `python`, `wasm`, and `wasm-full` and presence in
the three local-key opt-ins. Cargo trees confirmed all seven feature sets;
`cargo check --locked` passed for production Python, native and explicit
local-key Python after the edit; both production and explicit local-key WASM
target checks passed as well. The stable wheel workflow now passes
`--no-default-features --features python` explicitly. `cargo fmt --check` and
`git diff --check` passed. The compiled production PyO3 boundary test was
rerun after this graph change and passed. This closes the specific `isomdl`
default-feature leak, but it does not prove the entire old Core 0.1.61 graph
lacks private-key implementations or that a release wheel has passed artifact
inspection.

- 2026-10-07: Investigation complete; source/history findings recorded above.
  No fresh build, live KMS test or deployment acceptance claimed.
- 2026-10-07: Plan created on UI branch
  `security/remote-kms-hardening-20261007`, based on `d2dcd0630`, in workspace
  `worktrees/kms-hardening-integration-20261007`. No historical branch changed.
  Next checkpoint: K1 inventory and K2 backend feasibility.

## Reference records

- [Core KMS implementation PR 308](https://github.com/ElevenID/marty-core/pull/308)
- [Core production crypto API removal PR 315](https://github.com/ElevenID/marty-core/pull/315)
- [Core audited boundaries PR 318](https://github.com/ElevenID/marty-core/pull/318)
- [DIDComm deferred work](https://github.com/ElevenID/marty-credentials/blob/e109b6c/docs/rust-migrations/didcomm-kms-outstanding.md)
- [Integration secret deferred work](https://github.com/ElevenID/marty-credentials/blob/e109b6c/docs/rust-migrations/integration-secret-secure-storage-outstanding.md)
- [BYOK preservation and contract hold](rust-migrations/marty-ui-worktree-cleanup-inventory-2026-09-07.md)
