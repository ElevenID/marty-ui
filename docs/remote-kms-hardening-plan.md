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
| K3 | Implement DIDComm scoped/versioned references and remote operations; bind tenant, sender DID/key, recipient documents and frozen attempt inputs; preserve rotation, expiry, retries, replay, cancellation and unknown-outcome semantics. | Pending |
| K4 | Design and implement opaque integration-secret custody and existing AES-GCM envelope migration; prove legacy reads, tenant/purpose isolation, tamper rejection, restart, rotation, recovery and atomic repository behavior. | In progress; disposable PostgreSQL/OpenBao migration and rotation passed; runtime cutover/recovery pending |
| K5 | Adopt hardened Core across Rust services and fork pins; replace removed APIs and broad features; isolate fixtures and qualification binaries; eliminate compatibility crypto from production graphs. | Pending |
| K6 | Establish actual supported BYOK route/schema and tenant/certificate binding; integrate reference-only UX and server rejection of private material, preserving existing onboarding behavior. | Pending |
| K7 | Reconcile Credentials compatibility retirement with native owner selection, published artifacts and encrypted-data readability; remove obsolete raw-key adapters and wheel requirements where qualified. | Pending |
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
- `transit/derive-key` exists and describes a named symmetric output; it does
  not establish an X25519 ECDH-1PU operation compatible with current DIDComm.
- Non-exportable AES-256-GCM key creation, encryption, old-version decryption
  after rotation, tamper rejection and explicit key-export rejection passed.
  Plaintext backup remained disabled.
- No real recipient, application data migration, deployed provider or tenant
  authorization acceptance is claimed by this probe.

The upstream [ECDH change](https://github.com/openbao/openbao/pull/811) and
[documentation issue](https://github.com/openbao/openbao/issues/1350) explain why
generic ECDH support must not be mistaken for DIDComm capability. Next: examine
an existing remote messaging agent or provider extension that implements the
required protocol with non-exportable custody; do not substitute another curve,
export a sender key, or downgrade authcrypt to make the pinned Transit API fit.

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

2026-10-07 DIDComm curve check: the [v2.1 editor's draft](https://identity.foundation/didcomm-messaging/spec/v2.1/)
is marked working-group-approved and
already permits `ECDH-1PU+A256KW` with X25519, P-384, P-256 and optional
P-521; [v2.0](https://identity.foundation/didcomm-messaging/spec/v2.0/)
listed the same curves, so this is not a new relaxation. The v2.1 changelog
mentions only service endpoint and empty-body changes, not cryptography.
Authcrypt still
requires ECDH-1PU in a JWE and A256CBC-HS512; P-256 is marked deprecated in
favor of P-384. A P-384 KMS key would be spec-compatible only if the sender
and each recipient DID document actually expose compatible P-384
`keyAgreement` methods and a real holder decrypts the envelope. Current Marty
issuer publication, disposable interoperability setup and frozen authcrypt
fixtures are X25519-specific; current Core `marty-didcomm` resolves authorized
X25519 methods rather than providing a general P-384 packer. Multiple
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
