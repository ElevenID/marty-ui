# Remote KMS hardening implementation and landing plan

Status: active. Updated: 2026-10-09 (America/Denver).

Owner: Codex working with the repository maintainer. This file is the canonical
cross-repository progress tracker. Update it at meaningful implementation,
review, validation, and landing checkpoints, including concrete commit, PR,
artifact, and test references. A merged library change alone does not complete
the service or release boundary.

## Objective and working agreement

Complete remote key custody throughout the migrated Rust issuer and verifier
services, their cryptographic dependencies, supported interfaces, and shipping
artifacts. Remove production access to long-lived credential private-key
generation, import, export, retention, and local signing. Remove every database
table and ORM/schema definition intended to store private keys in product
databases. Complete remote DIDComm authcrypt custody and integration-secret
master-key custody. There are
no public deployments and no old-data or backwards-compatibility requirement.

User clarification on 2026-10-08: do not create database migration scripts for
private-key table retirement. Ship a clean KMS-only schema and qualify it from
an empty database; existing beta/self-host data can be discarded. Remove
private-key table definitions, creation paths and data access code from the
candidate repositories. Public-only device key registries and remote KMS
reference records may remain after their columns and data flows are inspected.
Wallet-owned keys and TLS/session capabilities must not create a private-key
table in the service databases. A qualified deployment must contain no
private-key tables or secret-bearing key columns, including dormant tables
made by legacy ORM metadata or initialization code.

Active-goal acceptance amendment: KMS hardening is incomplete until every
product database created by the final Core, native UI and Credentials artifacts
has been inspected from a fresh install and contains no table intended for
private-key storage. Delete the corresponding table definitions and all
creation, read and write paths at source, including dormant test setup and
historical initialization chains that would recreate them. Do not add or ship
schema, data or compatibility migration scripts for this retirement. Verify
the assembled schema and representative runtime writes with disposable
databases; inspect generic JSON columns so private JWK/PEM material cannot
hide behind a neutral column name. Record the final table/column inventory
and test evidence in K10 before closing the active goal.

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

2026-10-07 test-custody review checkpoint: the OID4VCI registered-client
verification test in native Issuance still constructed P-256 private keys and
signed JWTs locally. It now reads only fixed public JWK and pre-signed assertion
vectors; positive verification, wrong-signer rejection, embedded-JWK rejection,
and public-key normalization remain covered. The three focused Rust tests
passed. This removes one test signer, not the full K8 test graph: the readiness
runtime and other service/acceptance fixtures still need the same custody
review before release.
Follow-up review found that readiness challenges generate fresh random nonces,
so its local RSA test signer cannot be replaced by fixed signatures without
losing the freshness assertion; move those positive tests to a disposable live
remote signer. The mdoc builder's positive test also constructs a holder private
JWK and uses a fixed issuer signature. At the candidate source head, its focused
test fails before signing because no issuer public JWK is configured; adding a
public issuer key then fails because the fixed signature does not verify. The
test needs a public holder JWK plus a real remote issuer signer and must retain
its certificate-injection assertion. The exploratory test edit was reverted;
this failing test is an unresolved feature/test-custody gate, not acceptance.
2026-10-07 resolution checkpoint: the credential-builder tests now share one
test-only OpenBao Transit adapter, guarded to a disposable loopback provider.
It creates non-exportable, non-imported P-256 issuer/DSC keys with the scoped
token, reads only provider public keys, signs the exact payload remotely, and
normalizes OpenBao DER signatures to the raw ES256 form required by JWT
assembly. SD-JWT, JWT-VC and mdoc positive tests retain their exact-input,
Open Badge, key-purpose and certificate-injection assertions; the mdoc holder
JWK is public-only. The old SD-JWT private-holder expectation is now a separate
fail-closed unit test that rejects `d` before signing. All three live positive
tests passed in the disposable OpenBao probe, followed by the coordinated
PostgreSQL/Raft restore proof. The normal credential-builder unit selection
passed six tests with those three explicitly routed to the live probe. The
readiness random-challenge signer remains open; hosted CI and release artifacts
have not yet run this checkpoint.
2026-10-07 Data Integrity test-custody follow-up: the same disposable Transit
adapter now supports provider-generated Ed25519 keys and remote EdDSA signing.
OpenBao returns that public key as base64 raw bytes rather than PEM, matching
the production Signing Keys adapter's public-only decoding. The positive Data
Integrity test retains canonicalization, credential ID and cryptosuite checks
without a Rust Ed25519 private key. Four live credential-builder format tests
passed in the disposable probe, then the Rust/PostgreSQL/Raft restore passed.
The normal credential-builder selection passed five tests with four live tests
explicitly run by the probe. Rust formatting and source diff checks passed;
hosted CI and exact release artifacts remain unqualified.
2026-10-07 readiness test-custody resolution: the three positive/negative
readiness challenge tests no longer create local RSA private keys or sign in
Rust. Their shared test fixture creates scoped, non-exportable RSA keys in the
disposable OpenBao cluster, reads public JWKs, and signs fresh random LTI and
DID challenges remotely. The published-key positive check, duplicate/private
metadata rejection and missing DID assertion-method rejection all passed in
the same live probe as the four credential formats and coordinated
PostgreSQL/Raft restore. The ordinary readiness unit selection passed four
tests; its three live cases are explicitly run by the probe in the OpenBao CI
job. Rust formatting, Ruff and diff checks passed. Hosted CI and exact
artifact qualification remain pending.

2026-10-07 Issuance library regression checkpoint: the first full
`marty-issuance-service --lib` run passed 564 tests but failed one DPoP verifier
test because it still invoked local JWT signing through hardened Core. The
ES256 and PS256 DPoP tests now consume public signed proof vectors; their
embedded-key, method, endpoint and RFC 7638 thumbprint assertions remain.
No private key or signing implementation is retained in that test module or
fixture. The three targeted DPoP tests passed, followed by the full Issuance
library suite: 565 passed, zero failed, eight opt-in tests ignored. Seven of
those opt-in live-format/readiness cases already passed in the disposable
OpenBao probe; the remaining ignored case requires separate qualification.
This is candidate source evidence, not hosted CI or a release artifact.

2026-10-07 Issuance integration regression checkpoint: the complete integration
test target set compiled. The first execution found that the HTTP signing
failure contract supplied an invalid Ed25519 issuer JWK for an ES256 case, so
native preparation rejected it before the mocked remote signer was called.
The harness now supplies algorithm-matched, public-only Ed25519 or P-256 JWKs
and retains the remote diagnostic, claim release and HTTP projection checks.
All five signing-behavior tests pass. The broader `--tests` run passed the
565-test library selection and all integration targets preceding
`http_behavior`, then stopped with two discovery-oracle mismatches
(`native_static_discovery_matches_the_python_oracle_contract` and
`native_tenant_discovery_matches_the_python_oracle_contract`; 10 other tests
in that target passed). Discovery metadata drift must be reconciled with the
Python oracle and the intended product contract before claiming the full
Issuance integration suite. This is a local candidate run, not hosted CI or
artifact qualification.

Follow-up Issuance matrix isolation: the pinned Core revision `a5cb567`
filters mdoc JWT holder-proof algorithms to ES256 (including a Core unit
assertion), while the frozen UI discovery contracts still advertised ES256
and EdDSA. The current Credentials Python implementation and its contracts
also advertise ES256 only for mdoc; all other format proof algorithms remain
ES256 and EdDSA. Running the complete Issuance `--tests` selection with only
the two named discovery assertions skipped passed every other test target;
the library portion reported 565 passed, zero failed and eight ignored.
The UI copies now update only the four mdoc proof-algorithm fields, exactly
matching the corresponding upstream Credentials contract files at revision
`8e3868b` (the later upstream static contract changes unrelated CORS headers).
The local provenance commit and SHA-256 entries were updated. The complete
11-test Python Issuance candidate suite and all 12 `http_behavior` tests
passed. The unfiltered `cargo +1.95.0 test --locked -p
marty-issuance-service --tests -j 1 --quiet` run then passed every target
with exit code zero, including 565 library tests (eight ignored opt-in cases).
Hosted CI and final artifacts are not qualified by these local checks.

Final custody decision on 2026-10-07: KMS-only is a release invariant. Do not
retain a legacy private-key unwrap, local cryptography fallback, private-key
import endpoint, compatibility adapter, or test fixture that restores those
capabilities. The planned KMS extension is Go because OpenBao's plugin SDK is
Go; the Rust services call it through scoped, versioned remote operations.
Existing local beta/self-host data may be discarded at cutover. Historical
migration experiments below document evidence only and are superseded as release
work. Fail closed on old ciphertext/Flow rows. Do not alter running stacks while
changing the candidate source; qualify a clean KMS-only deployment instead.
The release plan does not include a compatibility window, data migration,
legacy read path, or fallback switch. Remove obsolete adapters and test fixtures
instead of retaining them behind a feature flag. A release rollback may restore
an earlier artifact only outside the KMS-only acceptance boundary; it must not
silently restore local private-key custody in the qualified deployment.

2026-10-07 managed-signing tenant-boundary review: an adversarial Redis-backed
route test put tenant A's managed key into tenant B's active profile. Before the
fix, tenant B's explicit signing request returned 200 and reached the signer;
this was a real cross-tenant authorization flaw, not merely stale metadata.
The candidate Rust fix derives profile-owned managed references from the
profile's tenant, DID, purpose, format, and algorithm (or checks the tenant's
namespaced key), then uses that single rule in HTTP authorization and registry
inventory. Registry bindings without a tenant-owned name or validated active
profile no longer enter managed inventory. The compatibility signing layer also
requires the chosen reference and algorithm to appear in that tenant's live
managed inventory, covering internal calls and requests that omit the
reference. Managed-profile enrichment and public-key lookup also reject a
foreign reference before reading the provider. A regression now rejects
explicit and implicit foreign selection without reaching the signer. The
signing-keys library suite passed 130 tests (seven opt-in tests ignored), and
targeted Clippy passed with warnings denied.
An opt-in policy probe now starts separately labeled disposable pinned OpenBao
and Redis containers, applies the shipped policy, runs the Rust managed-key
adapter and Redis-backed cross-tenant route test, and removes both containers.
The provider-backed probe passed; it proves the scoped OpenBao operations and
the route boundary in the same disposable run. The mock signer counts calls,
and a separate real-provider test creates tenant A's key with the scoped token,
signs for tenant A, and rejects explicit and implicit use by tenant B's forged
profile. Next: review remaining profile resolution and internal signing paths,
run broader signing-keys tests, then include this with the large UI feature PR.
The UI source remains uncommitted for that grouped review; no deployment or
release artifact is qualified by this checkpoint.
2026-10-07 broad Signing Keys candidate check: all test targets compiled with
`cargo +1.95.0 test --locked -p marty-signing-keys --tests --no-run -j 1
--quiet`, then the unfiltered default `--tests` selection exited zero. Its
library portion reported 131 passed, zero failed and seven ignored; all
non-ignored integration targets also passed. Provider/Redis tests requiring
disposable external services remain opt-in, so this default run does not
replace the previously recorded live OpenBao/Redis policy proof or qualify
the final packaged artifact. Continue the cross-tenant and profile-resolution
self-review before committing the broader Signing Keys diff.
2026-10-07 holder-proof self-review correction: the new VC-API bridge had
enabled OpenBao key deletion before reading the key, while the shared managed
key reader correctly rejects deletion-enabled keys as inactive. The operation
now keeps deletion disabled during public metadata validation and remote
Ed25519 signing, then enables deletion only in mandatory cleanup; it returns
no proof if cleanup fails. The opt-in holder-proof test no longer attempts to
mount Transit with the scoped workload token. The existing disposable
OpenBao/PostgreSQL/Raft probe now builds and runs this live target in the same
provider batch as four credential formats, three readiness challenges and
coordinated restore. The first probe stopped at the test's unauthorized mount
setup; the corrected full probe passed, including actual holder-proof
verification, wrong-nonce and wrong-issuer rejection, authenticated HTTP
routing, ephemeral deletion and stale-key reaping. The probe removed its
disposable containers and volumes. Rust formatting, Ruff and diff checks
passed. Hosted CI and exact release artifacts remain pending.

2026-10-07 Signing Keys follow-up quality review: all-target Clippy passed with
warnings denied after the live holder-proof correction. Startup previously
silently skipped stale-key reconciliation when its OpenBao/issuer configuration
was invalid, leaving interrupted ephemeral keys without automatic cleanup.
When OpenBao is configured, Signing Keys now requires the holder-proof provider
to initialize before serving requests; the reviewed base, self-host and
Kubernetes Signing Keys manifests all supply `ISSUER_BASE_URL`. Targeted binary
Clippy and formatting passed. This startup correction remains in the broader
uncommitted Signing Keys feature diff for grouped review.

2026-10-07 managed inventory custody review: inventory had accepted any
tenant-named Transit key with a readable public JWK, even if that key was
exportable or imported. It now uses the shared managed-key metadata reader
and admits only keys whose provider flags prove active signing,
non-exportability, no plaintext backup, no deletion permission, and no import.
An unsafe tenant-named key is excluded and degrades inventory rather than
becoming a signable alias; valid managed keys remain available. The focused
regression and full default Signing Keys `--tests` selection passed (131
library tests passed, seven ignored), and all-target Clippy passed with
warnings denied. The first disposable OpenBao/Redis probe exposed a mock
Transit response in the cross-tenant route test that omitted custody flags;
the fixture now supplies the provider's explicit safe flags. The corrected
full scoped policy probe passed six managed prefixes, Rust adapter operations,
tenant routes and managed-profile routes, then removed its labeled containers.
This candidate source remains uncommitted with the broader Signing Keys diff;
hosted CI and exact artifacts are not qualified.

2026-10-07 cryptographic-operation custody review: the internal managed
Transit sign adapter could be called directly without the registry inventory
check. It now reads provider metadata immediately before signing and rejects
keys that are imported, exportable, backup-enabled, deletion-enabled, soft
deleted or unable to sign. The same read binds the requested algorithm to the
provider public JWK using the inventory's shared Rust mapping. A negative
adapter test proves an exportable P-256 key and an EdDSA request for that key
never reach the Transit sign endpoint; the missing-key golden test now proves
read-only failure before sign or mount creation. The unfiltered Signing Keys
`--tests` selection passed (132 library tests passed, seven ignored),
all-target Clippy passed with warnings denied, and the scoped OpenBao/Redis
policy, adapter, tenant and managed-profile probe passed. The first combined
OpenBao/PostgreSQL/Raft probe stopped after its live credential and holder
tests because its disposable Signing Keys startup lacked `ISSUER_BASE_URL`,
which is now required for interrupted holder-key cleanup. The probe supplies
the synthetic issuer URL and the complete rerun passed, including four live
credential formats, three readiness challenges, the holder proof and both
coordinated restore phases. Labeled disposable containers and volumes were
removed. These source changes remain in the broader uncommitted UI feature
diff; hosted CI and exact release artifacts remain pending.

2026-10-07 Flow grouped-feature checkpoint: the current HAIP/DC-API request
and submission candidate uses tenant/Flow/version-bound remote OpenBao key
references. Source review found that the old `vault:` private-JWK unwrap path
was removed from Flow, and both request construction and response decryption
reject a stored legacy key envelope. Expired or cancelled encrypted responses
are rejected before remote decryption, while terminal replay still decrypts
to compare the submission digest. The complete `marty-flow --tests` selection
built and passed locally with Cargo 1.95.0 and one build job; all-target Flow
Clippy also passed with warnings denied. Environment-gated
PostgreSQL and live OpenBao tests compile in that selection but require their
disposable fixtures for substantive execution; this run alone is not live
service, hosted-CI, or exact-image qualification. Keep Flow, its shared
OID4VP contract, the Go HAIP backend, and related consumer corrections in the
large UI feature PR; batch remaining fixes and local tests before one hosted
qualification run.

2026-10-07 Flow live-acceptance batch: the existing disposable coordinated
OpenBao/PostgreSQL probe now provisions the separate HAIP workload token file
for the Rust Signing Keys service, runs the independent Go JOSE holder test,
and executes Flow's live adapter, terminal HTTP replay and expired/cancelled
HTTP tests against isolated PostgreSQL databases. The Go tool is supplied by
the plugin Dockerfile's pinned builder image where it is absent on the host.
The complete probe passed on the final harness revision: four live Issuance
credential formats, three readiness challenges, ephemeral holder proof, Go
holder JWE generation, all three Flow targets, and both phases of coordinated
PostgreSQL/OpenBao Raft restore. Ruff, formatting, Python compilation and diff
checks passed. No labeled disposable containers or volumes remained. This
proves these candidate service paths with synthetic data; hosted CI, an
actual wallet app, the exact release image and supported deployment cutover
remain open.


2026-10-07 Flow HAIP reissue self-review: a persisted remote key reference
was locally well-formed but could be reused to publish another request object
after its actual OpenBao key version disappeared. The candidate now resolves
that exact tenant/Flow/version through a read-only Signing Keys route and
compares the returned public JWK and reference before reissuing. Signing Keys
uses the separate HAIP workload token and OpenBao's versioned public-key GET;
missing, unauthorized or mismatched keys fail closed without creating a new
key. Flow's request-object test covers successful reuse and a missing remote
key, its HTTP adapter test covers exact scope and version, and the independent
Go live route test covers both existing and missing versions. The final
disposable probe passed again with the live Go holder, Flow adapter and HTTP
paths, Issuance signing, holder proof and both coordinated restore phases.
The unfiltered Flow `--tests` suite, Signing Keys library suite (132 passed,
seven ignored), both packages' all-target Clippy with warnings denied,
targeted Rust formatting and diff checks passed. This remains in the broad
uncommitted UI feature diff; hosted CI and exact release artifacts remain
pending.

2026-10-07 HAIP CI-selection self-review: the packaged OpenBao/Flow live
probe was selected for plugin changes but could be skipped by a later PR that
only changed Flow's HAIP request/decrypt path or Signing Keys' HAIP provider.
The CI classifier now selects the existing OpenBao image/probe lane for those
specific production owners, the shared HAIP key contract and the live Flow
tests. An unrelated Flow library edit still skips that costly lane. The Go
container fallback also supplies Docker's host-gateway alias for Linux runners.
The focused classifier test and the full workflow-performance file passed
(124 tests); Ruff, Python compilation, YAML parsing, diff checks and a pinned
Go-container host-gateway smoke passed. This is local source evidence, not a
hosted CI run of the grouped UI PR.

2026-10-07 K5 production-graph review: the actual locked Rust workspace
metadata passed the candidate KMS-only guard for all seven Marty Core crates
at the reviewed `a5cb567` revision and isomdl 0.3.0 at `784a5294`; the
guard's nine mutation tests also passed. Cargo still warned about an unused
isomdl 0.2 patch from the old migration graph. That stale patch and its
`Cargo.lock` unused entry were removed; locked metadata passed the same guard
again without the warning, and the manifest/lock diff check passed. These
graph changes remain in the broad uncommitted UI feature diff. The guard
script and tests are still untracked files that must be included when that
feature diff is staged; this local metadata check does not qualify an exact
service image or hosted CI result.

2026-10-07 grouped-PR readiness inventory: Core's
`security/remote-kms-fixture-20261007` worktree is clean and ten commits ahead
of its recorded `origin/main`, with no PR for that head. It still contains
test-only issuer `IssuerKey` signing paths in OID4VCI's `formats/mod.rs` and
`issuer.rs`; those tests must be retired or supplied by remote signer coverage
before the Core feature PR can claim test-custody completion. The separate
Credentials retirement worktree remains dirty with compatibility removals,
and the UI integration worktree remains dirty with the large service,
deployment and test feature diff. No repository has a grouped feature PR or
qualified release artifact from these candidate worktrees yet. Keep their
changes batched locally; do not infer PR readiness from Core's clean worktree
alone.

2026-10-07 managed-profile follow-up: the canonical Rust profile binding
validator now rejects a managed key outside the profile tenant and tuple.
This covers create, update, and DID resolution before publication; direct
provider public-key lookup and profile enrichment retain their pre-read guards.
A focused unit test covers valid ownership, a foreign tuple-derived name, and
a foreign tenant namespace. The library suite passed 131 tests (seven ignored).
The broader signing-keys test-target run passed 170 tests with 41 opt-in tests
ignored when built one job at a time. Its initial parallel build ran out of
Windows compiler memory; it was not a test failure. Five opt-in managed-profile
route tests passed against disposable Redis and a mock Transit server after
the mock metadata was corrected to include the real provider's non-exportable,
non-imported signing flags. The scoped OpenBao policy and adapter checks plus
mock and real-provider cross-tenant route checks passed again; the probe
removed both disposable containers. These are local candidate checks, not
hosted CI or a qualified release artifact. Next: inspect other internal paths
that consume managed profile keys, then prepare the grouped UI feature review.

2026-10-07 DID-signing consistency review: `sign_with_issuer_did` now reads the
current managed KMS public key and requires it to match the published DID
verification method before signing. This closes a rotation/stale-publication
case where the route could otherwise return a signature that does not verify
under the method it reports. The opt-in managed-profile route suite now mutates
the mock provider to a distinct valid Ed25519 public key and expects a conflict
while the DID document remains stale; its positive create/resolve/sign and
missing-key assertions still pass. The disposable scoped OpenBao + Redis probe
passed again, including all five managed-profile route tests. The broader test
suite passed 170 tests with 41 opt-in tests ignored after this edit, built with
one Cargo job to avoid the earlier Windows compiler-memory failure. Targeted
Clippy passed with warnings denied. Hosted CI and release qualification remain
pending.

2026-10-07 OpenBao plugin HA checkpoint: [OpenBao 2.5's documented
model](https://openbao.org/docs/release-notes/2-5-0/) has one active writer;
standby write requests forward to the leader, while local reads can lag. The
repeatable `scripts/probe_didcomm_openbao_ha.py` builds the current Go plugin
source into the pinned OpenBao 2.5.5 image and starts a disposable three-voter
Raft cluster. It waits for plugin/key visibility on each standby before sending
nine concurrent DIDComm rotations through all three API endpoints. Every
returned version was unique and readable, and the current pointer selected a
committed version. Six concurrent HAIP create calls through all endpoints
returned the same version. After stopping the leader, a surviving voter became
active, retained the original DIDComm and HAIP versioned public references and
HAIP current pointer, and accepted another distinct DIDComm rotation. The
final probe passed and removed its labeled containers and network. Earlier
probe attempts returned 404 before standby visibility and timed out after
stopping the leader before all peers were voters; those attempts changed the
harness readiness checks, not plugin behavior. This is direct evidence for the
supported active/standby Raft topology, not a claim about independent
multi-primary writers, transactional fault injection, packaged release image,
or coordinated restore. Explicit version references remain the durable
cryptographic contract; the unversioned current pointer is advisory.

2026-10-07 transactional-storage self-review: OpenBao SDK v2.5.1's
`StartTxStorage` returns a no-op transaction, without an error, when the
backend does not implement `logical.TransactionalStorage`. The candidate
self-host config used file storage, so the plugin's version-plus-current
pointer writes were not atomic there. The Go plugin now rejects X25519 create
and rotate and HAIP create before writing when transactional storage is absent.
Its unit suite uses real transactional in-memory storage, exercises failed
metadata writes and verifies rollback, and asserts the nontransactional
storage writes nothing. A disposable file-backed OpenBao rejected both key
creates; the disposable dev server accepted both, and the three-voter Raft
concurrency/failover probe still passed. The candidate self-host config now
uses single-node Raft, and bootstrap checks for a Raft leader before setting
up the plugin. An exact clean bootstrap against the candidate config and init
script passed, including both key types. A static test protects the Raft
configuration. These are candidate-source and disposable deployment checks;
the release image, hosted CI, backup/restore and operating procedure remain
to qualify. No migration of existing file-backed self-host state is planned.

2026-10-07 packaged-plugin gate and Raft recovery checkpoint: the OpenBao CI
job now runs the file-storage rejection, exact self-host Raft bootstrap, and
three-voter forwarding/failover probes against its one built candidate image.
The probes take an explicit image tag in CI and avoid three repeat builds;
local CI-equivalent runs of all three passed. The obsolete opt-in file-storage
recovery script has been replaced by a Raft cold-copy proof using that same
candidate image. A disposable source initialized Transit and the DIDComm/HAIP
plugin, encrypted a synthetic value, and created both versioned key types.
After stopping the source and copying its whole state volume, the restored
single-node Raft instance became leader, decrypted the pre-snapshot Transit
envelope, and returned both original versioned public keys. The renamed
recovery proof passed locally and is now an OpenBao CI step. Hosted CI has
not run at this head. This is a local cold OpenBao-only restore; coordinated
PostgreSQL/KMS recovery, off-host backup handling, release image publication,
and full deployment qualification remain open.

2026-10-07 self-host backup correction: `scripts/export-selfhost-openbao.py`
previously copied the entire OpenBao directory without requiring shutdown;
that could produce an inconsistent archive after the switch to Raft. The
candidate exporter now calls OpenBao 2.5's authenticated local-loopback Raft
snapshot API while the disposable server is live, streams the snapshot to a
restricted archive, includes only the three bootstrap recovery files and
current config, and records a snapshot SHA-256. It refuses remote origins,
redirects, missing recovery files, and an export directory inside the Raft
state directory. A disposable source created Transit ciphertext and both
plugin key types, exported one live archive, and verified its manifest/hash.
The separate cold-copy restore recovered the ciphertext and versioned public
keys. A second clean replacement Raft node was initialized, received the
archive's `raft.snap` through OpenBao's force-restore API, restarted, and
unsealed with the original recovery key; it also decrypted the old Transit
ciphertext and returned both original plugin versions. Five focused exporter
security tests passed, including a live redirect target that received no root
token. The self-host runbook distinguishes snapshots from cold state copies
and limits force restore to a clean replacement cluster. This is disposable
single-node recovery evidence, not a qualified published-image disaster
recovery runbook. Coordinated PostgreSQL/OpenBao recovery, off-host archive
handling, and exact release image qualification remain open.
The OpenBao image lane and its required CI-gate selection were committed with
the reviewed Marty Core feature-graph check in UI commit `260e12755`.
The local workflow-policy and feature-graph tests passed 133 cases; hosted CI
has not run at this head.

2026-10-07 coordinated integration-secret recovery checkpoint: a new opt-in
Rust/PostgreSQL/OpenBao probe writes a synthetic integration secret through the
live Signing Keys route and scoped OpenBao token, verifies the stored envelope
and KMS-only startup scan, exports a live Raft snapshot and PostgreSQL dump,
restores both into clean replacement volumes, restarts Signing Keys, and reads
the same tenant-bound secret through Rust. This passed locally against the
candidate plugin image and pinned disposable PostgreSQL/Redis images. A source
review found that self-host bootstrap had not created the integration-secret
Transit key or granted its encrypt/decrypt/read paths; the candidate init script
now creates and validates a non-exportable AES-GCM key and scopes those paths.
The self-host bootstrap probe checks that metadata, a token-bound round trip,
and export denial so CI can catch regression. During probe development, force
removing OpenBao immediately after snapshot-force caused the restored Raft
barrier to reject the original unseal key; graceful shutdown and restart passed,
matching the standalone recovery test. This is a disposable source-head proof,
not a published-image or hosted-CI qualification. Off-host backup handling,
exact artifact cutover and multi-service release acceptance remain open.
The proof and bootstrap fix were committed as UI `bb07d9c0b`. The existing
OpenBao CI job now runs the coordinated probe with its single built candidate
image and a pinned Rust toolchain; its workflow contract test passed locally.
This wiring has not run in hosted CI yet.

2026-10-07 OpenBao extension checkpoint: the Go secrets-engine source is now
tracked on this branch in commit `7605fdf7d`. It provides remote X25519
DIDComm authcrypt and P-256 HAIP response decryption. Review found that a
corrupt stored X25519 version could pair the wrong public and private values;
the shared version loader now derives and checks the public key before read or
pack, and negative storage-corruption tests cover both operations. A local
candidate image built successfully, running the Go tests and `go vet` in its
Dockerfile; its mounted plugin binary SHA-256 is
`c127dbf6ecb402b475cc641e3be77b7d9fdbfd27302441ddb27b4aa5a7a4f307`.
`TestHaipScopedLiveOpenBao` passed against a disposable OpenBao 2.5.5 server
using that image and scoped workload policy. This is local source and plugin
behavior evidence, not a published or attested image. The subsequent HA
checkpoint above qualifies the supported active/standby writer topology; the
full Rust deployment and exact release artifact remain unqualified. No fallback
or legacy import is part of the release path.
Follow-up commit `9eaf94a44` makes HAIP key-version and current-pointer writes
one OpenBao storage transaction, matching X25519 creation/rotation. The
rebuilt local image passed `go test ./...` and `go vet ./...`; subsequent
disposable Raft concurrency and unit rollback-on-storage-failure checks passed
at the candidate source head. Packaged release qualification remains pending.

2026-10-07 CSCA test-custody checkpoint: UI commit `298023863` retires
`CscaAuthority` and local self-signed issuer-key generation from both
signing-keys CSCA lifecycle test targets. Public-only certificates preserve
same-key renewal, rotated-key rejection, subject matching, outbox and Redis
storage/HTTP assertions. The stale contract claim that Core's local
`marty-verification::issuance` is a supported issuer surface was removed;
signing-keys remains the managed CSCA owner. Seven lifecycle tests, 13 adjacent
HTTP contract tests, and both ignored storage/HTTP tests against disposable
Redis passed. Nine public PEM vectors were checked for expected public-key
relationships and no private-key PEM. Rust formatting and diff checks passed.
The disposable Redis container was removed. Other private-key tests and exact
release-artifact proof remain outstanding. The complete signing-keys test
target set also compiled under `cargo +1.95 test -p marty-signing-keys --tests
--no-run --locked`; this is compilation evidence, not a full runtime pass.

2026-10-07 CSCA internal-write boundary review: the authenticated internal
certificate import and renewal routes previously compared a certificate to a
caller-supplied JWK/reference without checking the managed provider. The
working tree now requires an active tenant CSCA profile, matching issuer DID
and exact key reference, and a fresh public key from that profile's KMS
provider before either write. Renewal also requires the prior certificate's
issuer DID to match; public certificate enrollment already had its own live
provider binding check. The lifecycle rejects private JWK members in
`expected_public_jwk` before storing the certificate. The Redis HTTP test now
proves that unbound internal writes fail closed while direct lifecycle tests
retain renewal/outbox behavior. The disposable OpenBao 2.5.5 + Redis passport
chain passed with forged internal import and renewal rejected as 422 and no
forged record persisted; the complete managed CSCA -> DSC -> SOD flow still
passed. A follow-up live run also imported a second certificate only when its
reference and public key matched the active OpenBao-backed CSCA profile, then
revoked that disposable copy. Seven lifecycle tests and 128 signing-keys library tests passed;
targeted Clippy with `-D warnings`, rustfmt and diff checks passed. Both
disposable services were removed. A further disposable OpenBao/Redis run
issued a second CSCA certificate through the same Transit-held key: internal
renewal accepted it with `reuse_key=true`, rejected it with `reuse_key=false`,
and preserved renewal lineage. After rotating the CSCA Transit key, internal
import rejected the stale certificate/public key and persisted no record.
This proves sequential rotation rejection, not an atomic concurrent rotation
race across profile lookup, provider read and lifecycle save. These code
edits are not yet committed as part of the grouped UI feature work.
The enrollment, internal import and internal renewal routes now acquire the
tenant rotation lease and save with the existing lifecycle CAS that verifies
both lease ownership and the issuer-profile revision. A live disposable
OpenBao/Redis acceptance held that lease: internal import returned 409 and
persisted nothing; after explicit release, the same managed import succeeded.
The first Redis route run after adding leases returned a transient 409 on the
next sequential request because the lease `Drop` releases asynchronously.
The routes now await explicit release on success and error; both Redis tests,
the full live passport chain and 128 signing-keys library tests passed again.
Targeted signing-keys and cross-service acceptance Clippy passed with
`-D warnings`; formatting and diff checks passed. The lease prevents
application-controlled profile rotation from interleaving a certificate
commit; an administrator rotating an OpenBao key directly outside the service
remains outside that lock and still needs operational restriction/qualification.

2026-10-07 deployment ACL review: the self-host bootstrap gives the shared
`credential-service` token read access to `transit/keys/cred-*`, but no key
creation or `transit/keys/*/rotate` capability. The Rust signing-keys managed
creation and rotation adapters call those endpoints, so tests using a root
token can pass while the production service token fails. The same token is
mounted into several other self-host workloads; adding management capability
to it would broaden all of them. Before release, issue a separate signing-keys
token combining the existing runtime policy with narrowly scoped managed-key
management rights, wire only the signing-keys service to that token,
and require the analogous scoped token in Kubernetes. Cover all currently
supported managed-key prefixes (`cred-issuer-`, `cred-dsc-`, `cred-holder-`,
`cred-presenter-`, `lti-tool-`, `oid4vp-verifier-`) without granting export,
delete, or arbitrary key configuration. The current runtime policy grants
sign/read only for two fixed `lti-tool-` and `oid4vp-verifier-` keys; the
signing-keys token also needs sign/verify/read on tenant-scoped managed keys
under those prefixes. A disposable OpenBao 2.5.5 ACL probe showed that the
naive `transit/keys/cred-*` create/read rule also matches
`transit/keys/cred-issuer-test/import` and `/config`. Its more-specific
prefix match wins over `transit/keys/+/rotate`, leaving that credential key
without update on `/rotate`, while `+/rotate` grants update for unrelated
keys. A second live probe added `transit/keys/+/import` and `/config` deny
rules; those lower-priority patterns did not override the `cred-*` grants.
Therefore the proposed wildcard management policy is **not** safe or
functional as written. Do not wire it. Resolve the lifecycle boundary with
an exact-key/operator policy or a purpose-built remote management operation
whose path and parameters cannot admit imported material or cross-purpose
rotation; preserve the managed-create/rotate product behavior. Then exercise
create/sign/rotate and negative import/config/export/foreign-key cases with
scoped tokens against disposable OpenBao, and assert a plain credential-service
token is denied create/rotate. The OpenBao administrator/root credential can
rotate outside the application lease; reserve it for an explicit operator
ceremony and verify the service fails closed on a changed key version. This
is an unresolved release blocker, not a compatibility or local-key fallback.

2026-10-07 managed Transit ACL candidate: OpenBao 2.5.5 supports request
parameter restrictions on a prefix policy. The working tree now provisions a
separate `signing-keys-managed` policy limited to the six supported managed
prefixes and each purpose's signing algorithms. It allows only the `type`
request parameter on key paths; the signing-keys token combines that policy
with `credential-service` and has no default policy. The shared credential
token retains no management rights. Self-host bootstrap, the external OpenBao
bootstrap helper, Compose, Kubernetes secret wiring, deployment catalog and
operator examples use a distinct signing-keys token. The Rust managed-key
reader marks a key invalid unless OpenBao reports non-exportable,
non-imported, non-deletable signing material with plaintext backup disabled.
Actual `docker/openbao-init.sh` installed the policy on disposable OpenBao
2.5.5. Its scoped token created and rotated all six prefixes to version 2
with `exportable=false`; LTI and OID4VP signing worked. The plain token
received 403 for creation and rotation, while the managed token received 403
for import, import-version, exportability configuration and private-key
export. The earlier single-prefix probe denied rotation under a different
prefix; the combined signing-keys token intentionally covers all six managed
purposes, so cross-purpose key access within that token remains a security
review point. A separate disposable self-host bootstrap
minted the token, then that token created and rotated a managed key. All
disposable containers and temporary token files were removed. The focused
deployment tests passed (170); signing-keys library tests passed (128 active),
the managed-custody negative test and targeted Clippy with `-D warnings`
passed, and shell syntax, rustfmt, JSON and diff checks passed. A direct
`docker compose config` invocation without the required self-host env values
could not validate the full rendered model; the focused model tests did pass.
The policy permits an empty key-create body to reserve a default AES key
under a managed prefix, but the Rust adapter cannot accept it as an active
signing key. It also permits an empty or `type`-only `/config` request; on
OpenBao 2.5.5 those did not enable export or import. Requalify these parameter
semantics against the exact pinned release image, and consider a narrower
purpose-built lifecycle endpoint if the name-squatting or cross-tenant scope
is unacceptable. External administrator rotation remains outside the app
lease. This is candidate working-tree code, not yet a grouped feature commit,
PR, or release artifact; do not deploy it independently of the hardening set.
The opt-in `scripts/probe_signing_keys_openbao_policy.py` now makes the scoped
ACL evidence repeatable using the repository's actual bootstrap script and
pinned disposable image. It passed locally for create, rotate, sign, and
non-exportable/provider-generated metadata on every managed prefix; import
and exportability configuration were denied for each. The plain token was
denied management, and the managed token was denied imported-version,
private export and unrelated `auth-session` rotation. The probe creates a
random labeled dev container and removes it in `finally`; Ruff check/format
passed. `bao version` for the pinned digest reported OpenBao 2.5.5 at revision
`028992583c693c4de6350b8aa52ff85e30375a99`; the disposable-image
catalog's stale 2.5.2 metadata has been corrected in the working tree.
The probe now also verifies the catalog version/revision against `bao version`
and offers `--rust-adapter`. With that option, it writes a synthetic disposable
guard marker and runs the ignored Rust `managed_policy_live_kms` test with the
scoped token as `BAO_TOKEN`. That live test created a provider-generated key,
read active public metadata, rotated to version 2, observed a changed public
key, and saw no private JWK member; it passed against the exact pinned digest.
The Redis-backed `live_managed_alias_requires_tenant_purpose_and_algorithm_before_kms_sign`
test also passed against disposable pinned Redis, rejecting wrong-tenant and
wrong-purpose selection before its mock signer. That is application-scope
evidence, not a per-tenant OpenBao ACL. The single signing-keys process still
holds a service-wide token for all six managed purposes and tenants; the Rust
authorization, deterministic tenant key names and registry/profile binding
remain security-critical. A full adversarial multi-tenant live-provider route
test and exact deployment artifact are still pending.

2026-10-07 current checkpoint: the Credentials feature branch now rejects
the Python DIDComm legacy owner, forwards HTTP initiation/delivery to native
Rust, and removes Python local-X25519 authcrypt and its private-key tests.
Python integration-secret repository writes/reads now use the Rust
signing-keys service's purpose-bound remote envelope API; old AES envelopes
and raw master-key configuration fail closed. The self-host production compose
candidate removes the Python issuance raw-key mount and uses the healthy
native owner. Base compose, self-host/Kubernetes deployment catalogs,
Kubernetes issuance secret binding and deploy script no longer distribute the
raw key; the Kubernetes native URL now points to the native service. Focused
Credentials boundary tests passed (80); adjacent Canvas LTI/worker/management
tests passed (79); the self-host model check and Kubernetes tests (52) passed.
These are source and local contract results, not an exact-image or live KMS
acceptance. Credentials now defaults Python gRPC off and rejects explicit enablement before
database startup. Python startup also performs a remote envelope round trip
before opening its database engine; self-host and Kubernetes issuance call
signing-keys directly to avoid a gateway readiness cycle (48 focused startup
and envelope tests passed). Kubernetes deployment now refuses a
disabled native selector and directs Flow RPC to Rust. Its Python deployment
tests passed (238), and the Rust release-evidence suite passed 12 of 13
tests; the remaining test requires `envsubst`, unavailable in this Windows
environment. The Python gRPC adapter and its Python-only RPC tests are now
removed; the generated protocol inventory remains, and the native Rust service
implements all twelve methods. Remaining K4/K7 work includes purging obsolete
conformance and historical fixtures; proving Python startup fails closed when
remote custody is unavailable against the live signing route; and qualifying
Rust and Python consumers against one clean KMS-backed database. Do not ship the
candidate compose independently of the Credentials branch.
Credentials committed this candidate as `ca0eede`, `a73c79d`, `aad4b48` and
`031308e` on
`security/remote-kms-retirement-20261007`; no PR or release artifact exists.
The Rust gRPC listener now rejects requests when no service token is
configured, and startup requires a non-placeholder token of at least 32
characters whenever gRPC is enabled, including development and test modes.
Focused Rust gRPC/config tests passed (11/40), and retained Python
issuance-surface tests passed (78). The full Python issuance-change suite
passed (122, with 21 skips) using the pinned Core `marty_rs` 0.2.0 Windows
wheel; its SHA-256 matched `release/dependencies.json` exactly
(`1fd8e4985a7d92ee14336ed98ececd597ba3aa2d275ca969b8fc358358da7967`).
The earlier eight SD-JWT/JWT-VC signature failures came from an older local
artifact. Building Credentials' own locked production-feature binding wheel
also succeeded, but that binding intentionally lacks current evidence-policy
capabilities and is only suitable for its narrower compatibility-boundary
checks, not the full issuance service suite. Artifact directories were kept
outside the source worktrees.
The six focused Credentials contract suites also passed (78) against the
pinned Core wheel. Credentials' local binding production-surface test passed
against its freshly built local wheel; that test is specific to the local
binding API and cannot be applied unchanged to Core 0.2.0, which has a
different remote-preparation API.
An exported-name inspection of the pinned Core Windows wheel found remote
credential preparation and signature-verification functions, but no
`generate_*_key`, local issuer-signing, or private-key import/export function.
This is a Python export check only, not production graph or binary proof.
The current Go DIDComm plugin Dockerfile built locally from this source head,
running `go test ./...` and `go vet ./...` in its build stage. The local image
was `sha256:cad95535474a601ca1ae22d86a13463536dac507666b4b31a4ee553be24085bd`
(83,321,705 bytes), with plugin binary SHA-256
`31c4432bfc4728a5f5cc85feb1546c9a6697488a76910eb1bf3e3905ed6b96a6`.
An isolated OpenBao 2.5.5 dev container registered that binary and mounted
the plugin. `cargo +1.95 test -p marty-issuance-service --test
didcomm_remote_kms_live --locked --offline -j2 -- --ignored --nocapture`
passed its live authcrypt test: OpenBao generated the issuer X25519 key, the
Rust sender packed through a scoped versioned reference after key rotation,
and the independent holder key decrypted and authenticated the sender. The
disposable container was removed; the running beta stack was untouched. This
proves this local source and image combination, not a published digest,
production deployment, or all K3 retry/recovery cases.
The native workspace `cargo +1.95 check --workspace --locked --offline -j2`
initially exposed Trust Profile's direct access to `DidDocument`'s now-private
`assertion_method` field. Trust Profile and Verification now use Core's
validated `assertion_methods()` / `set_assertion_methods()` interface,
including their test fixtures. The full workspace check passed after that
correction. The first check on C: was interrupted by disk exhaustion; the
successful check used a fresh non-incremental Cargo target and temp directory
on D:. This validates source compilation, not tests or release images.
The Trust Profile and Verification focused unit suites subsequently passed
(3 and 4 tests). Trust Profile's old fixture attempted to construct a DID JWK
with a private `d` member; the hardened Core type no longer exposes that
field. The replacement negative test verifies that a DID document containing
`d` fails deserialization, while positive fixtures use the validated public
constructors. This retains the rejection assertion without keeping a local
issuer private key in the test object.
An isolated OpenBao 2.5.5 dev container then held a Transit
`aes256-gcm96` integration-secret key with `exportable=false` and
`allow_plaintext_backup=false`. The current Signing Keys live test
`cargo +1.95 test -p marty-signing-keys --test
integration_secret_envelope_live_kms --locked --offline -j2 -- --ignored
--nocapture` passed against it. Remote encryption/decryption survived key
rotation, wrong tenant and purpose were rejected, and altered ciphertext
failed. The disposable container was removed. This proves the remote envelope
primitive on the current source; it does not by itself prove mixed consumers,
a clean database, service startup, or packaged release artifacts.
The mixed-consumer local acceptance now uses a real Signing Keys service
binary from this source head, disposable OpenBao 2.5.5 Transit
(`exportable=false`, `allow_plaintext_backup=false`), Redis and PostgreSQL 16.
The Rust PostgreSQL Canvas OAuth contract passed with an explicit opt-in URL
for the real Signing Keys route. Credentials' Python remote transport passed
its live startup round trip, then Python read Rust's persisted secret and wrote
a second remote envelope into the same clean database. A new opt-in Rust
cross-read passed: Rust's `verify_storage` startup scan accepted both rows,
decrypted the Python-written row, and hid it from a different tenant. Python
also confirmed its stored row contains a versioned Vault ciphertext and no
plaintext. The normal Rust contract still uses its keyless synthetic remote
server unless the live URL and API key are explicitly configured. The test
service was stopped and all three disposable containers were removed; the
running beta stack was untouched. This proves local source-level Rust/Python
database interoperability, not packaged service images, Redis/OpenBao storage
recovery, or release cutover.
The existing `scripts/test_openbao_file_recovery.ps1` was rerun against this
source head and passed. It cold-copied the self-host file-storage backend
after stopping OpenBao, unsealed a restored instance, and decrypted a
pre-snapshot ciphertext under a non-exportable Transit key. Its disposable
containers and volumes were removed. This proves local OpenBao storage
recovery; coordinated PostgreSQL/OpenBao restoration, off-host backup, and
exact packaged-image recovery are still unqualified.
Credentials still has issuer-private-key generation/export in the older BDD
steps (`tests/features/steps/credential_steps.py` and
`sd_jwt_conformance_steps.py`), and its binding CI still builds the
`local-key-operations` opt-in wheel for legacy tests. These are explicit K7
retirement items: replace issuer fixtures with remote KMS or public signed
vectors, preserve their useful assertions, then remove the opt-in issuer
surface and its CI lane. Holder/tool-key tests need separate classification.

## Verified starting point

The investigation refreshed origin refs and inspected source and PR history on
2026-10-07. These are source findings, not new build or deployment qualification.

| Area | Evidence and consequence |
| --- | --- |
| Hardened Core | Main `a5cb567`; KMS capability split PR 308, API removal PRs 313 and 315, corrections PRs 317 and 318 are merged. Reuse this work. |
| Native services | UI main `d2dcd0630` pins most Core crates to compatibility 0.1.62 at `bdbd1510`. Its ECDSA surface still exports local key generation and signing. The lockfile also contains 0.2.0 crypto through passport SOD issuance; this does not remove 0.1.62. |
| Credential issuance | Native JWT-VC, SD-JWT, and mdoc builders already prepare, remotely sign, and assemble. Preserve and migrate these seams. |
| DIDComm | Native issuance still parses `sender_x25519_private_key` and retains private bytes in prepared authcrypt state. `DIDCOMM-KMS-001` remains unimplemented. |
| Integration secrets | Native `IntegrationSecretCipher` holds a raw 32-byte AES key. Credentials pins canonical marty-rs 0.2.0 but retains verification wheel 0.1.60. The final cutover rejects old ciphertext and qualifies clean KMS-only storage. |
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
| Core feature PR | Shared remote envelope/storage contracts and cryptographic boundaries, missing canonical APIs, fixture support, compile-fail enforcement, documentation and self-review corrections. Include all remaining verifier test-custody migrations in this group. | Backend feasibility and consumer contract tests demonstrated first. Preserve supported consumers; never restore forbidden production APIs. |
| UI native hardening and integration acceptance feature PR | Hardened Core adoption across service roots, DIDComm remote custody, opaque integration-secret custody, supported BYOK wiring, deployment and packaging updates, test isolation, dependency/artifact guards, and production-image acceptance evidence. This tracker belongs here. | Exact reviewed Core revision and proven remote backend capabilities. Keep corrections and acceptance work in this PR rather than opening separate smoke or fixture PRs. |
| Credentials compatibility retirement feature PR | Remove obsolete compatibility custody paths, pins, adapters and private-key test fixtures; route supported operations to native owners. | Qualified native service artifacts and routing/cutover evidence. |
| Dependency fork PRs, only if necessary | Narrow missing cryptographic capability separation that cannot be achieved at existing owners. | Demonstrated production graph gap; ElevenID forks only. No upstream disclosure or publication is implied. |

Batch local implementation and review corrections before pushing. Do not create
one PR or CI run per small fix or per test. Treat a separate integration PR as
an exception only if a real cross-repository or artifact dependency prevents
the acceptance change from landing with its UI production implementation;
record that reason before splitting. Use targeted local tests while
iterating, then a complete relevant local matrix before hosted qualification.
Run the required PR and merge-queue checks; never bypass protections, weaken
checks, or claim that an earlier revision qualifies a changed final head.
Consolidate final pin updates and release preparation after dependency heads are
stable. Split a group only when dependency ordering, reviewability, or rollback
safety provides a concrete reason, and record that reason here.

2026-10-08 batching reaffirmation: finish each repository's broad feature
diff and its regression, security and quality self-review before opening its
PR. Keep follow-up corrections on that PR branch. Run focused local checks
during development and one complete local matrix on the assembled head, then
use hosted PR/merge-queue CI at dependency and final-head checkpoints rather
than for every fixture or smoke-test edit. The planned landing order remains
Core, UI native/integration acceptance, then Credentials retirement; pin
reviewed Core once in UI and Credentials once their consumers are ready.

2026-10-08 broad-PR execution decision: the current UI branch is the single
native hardening PR candidate. Fold passport artifact and callback custody,
local-key constructor/test retirement, Compose/Kubernetes packaging, provider
policy, the Go OpenBao extension, and end-to-end acceptance into that branch.
Do not open a separate passport or plugin PR just to gain an early CI signal.
The Core branch remains one cryptographic API/test-custody PR and Credentials
remains one compatibility-retirement PR. Before each PR is opened, consolidate
and review its full source diff, run the relevant local suite once at the
assembled head, then record the exact commit and proof. Open the dependent UI
PR after the reviewed Core revision is pinned; open Credentials after the
native owner and released-artifact boundary is qualified. Re-run hosted checks
only when required for a changed final head or merge queue.

2026-10-08 assembled-head PR queue (working branches, not qualified PRs):

| PR candidate | Current assembly state | Open/push gate | Hosted CI checkpoint |
| --- | --- | --- | --- |
| Core: [draft PR #355](https://github.com/ElevenID/marty-core/pull/355), `security/remote-kms-fixture-20261007` | Published clean head `d56c3fe52f195f7e8cc157fa03898efb5a89f701`, 76 commits ahead and 0 behind `origin/main`. The grouped API, verifier-fixture, storage and dependency-fork pin changes are in one PR. The local workspace, bindings, ZKP mock, feature-profile, lint, format and advisory gates described below pass. | Complete full regression/security/quality self-review, native Linux ZKP, exact wheel and hosted required checks. Resolve any findings on this same PR head before ready-for-review/merge. | Draft PR #355 opened 2026-10-08; first hosted CodeQL jobs queued at creation. Do not treat local gates or initial checks as final-head qualification. |
| UI: `security/remote-kms-hardening-20261007` | 92 commits ahead and 37 behind `origin/main` at `3db2f72b6`, with the large native/deployment/Go plugin/test diff still uncommitted. Treat all current custody changes as one feature candidate, including provider HMAC verification and exact-image acceptance. | Finish callback/provider and DIDComm end-to-end gates, reconcile upstream `main` on an assembled committed head, pin the reviewed Core SHA once, self-review the whole diff, then run the full local matrix. | One broad UI PR head after the Core dependency is reviewable; use required CI and merge-queue runs on the final integrated head. |
| Credentials: `security/remote-kms-retirement-20261007` | Committed retirement through `031308e` plus uncommitted binding, CI and test cleanup. Keep Python/Rust compatibility retirement together. | Preserve verification and product behavior, remove remaining private-key fixture paths, pin the qualified native/Core inputs once, self-review and run the complete local matrix. | One broad Credentials PR head after the native owner/artifact boundary is qualified. |

Commit cohesive checkpoints within each branch for reviewability, but do not
open a PR per commit. Combine fixture corrections, security findings, package
wiring and documentation with their owning feature. Run focused local tests as
the branch changes; save the expensive full local matrix for the assembled
head, repeating it only after material edits. Do not push a knowingly failing
candidate just to obtain hosted diagnostics. Preserve required CI and branch
protections; the cost reduction comes from fewer PR heads and fewer incomplete
pushes, not from skipping acceptance. If a dependency forces a split, document
the exact dependency and what proof moves with each PR before opening either.

2026-10-08 broad-change batching update: keep the Go OpenBao cryptographic
extension, its Rust callers, policy/bootstrap, packaging, failure probes and
positive end-to-end acceptance in the single UI native feature PR. Keep Core
verification fixture retirement, crypto boundary corrections and its final
feature-graph decision in the single Core PR. Keep Credentials Python/Rust
retirement and consumer tests in its one PR. Commit locally in reviewable
checkpoints and make the security, regression/feature-preservation and quality
self-review against each assembled PR diff. A coordinated ElevenID SSI fork is
the only prospective extra dependency PR: create it only if the exact shipped
Core boundary cannot be proven without removing SSI's transitive signing
capabilities, and preserve ES256 VCDM/Open Badges verification. Do not split
out small fixture, probe, documentation or CI-selection PRs.

2026-10-08 callback-custody batching checkpoint: Issuance configuration now
rejects process-held passport callback HMAC secrets, including file selectors,
and the native callback route requires the remote Signing Keys verifier. Active
Compose, example and beta selector surfaces no longer carry the raw secret.
The PostgreSQL HTTP contract is being migrated to an opaque callback signature
issued by its in-memory KMS transport fixture, so positive and negative
callback behavior remains covered without a local HMAC key. This transport
fixture is test evidence for the HTTP contract, not proof of remote custody.
The assembled disposable PostgreSQL contract passed after this migration;
the four-model native conformance composition also passed. The relevant Rust
test target compiled and formatting was applied locally.
The lower-level `BureauClient` local verification API and separate provider
ingress HMAC path still need retirement or remote verification. Keep those
changes, their tests, and the Go OpenBao capability work in the same UI feature
PR. Do not open that PR until the assembled branch passes local regression,
security and quality review and the exact Core pin is recorded.

2026-10-08 lower-level callback retirement checkpoint: `BureauClient` no
longer accepts or stores a webhook secret and no longer exposes local
`verify_webhook`/`parse_webhook`. Its outbound submission/polling role remains.
The Issuance PostgreSQL and public Gateway-to-Issuance acceptance contracts now
share one in-memory KMS transport fixture for exact-body, tenant-bound opaque
callback signatures. Both passed against separate databases in a disposable
PostgreSQL container (1 Issuance contract, 2 Gateway contract tests). Issuance
library: 563 passed, 8 ignored; library Clippy with warnings denied passed.
This removes the lower-level public local-secret API, but provider ingress
still verifies an external provider's hex HMAC using a process-held secret.
That path remains a KMS-only release blocker.

Provider-ingress next step: qualify OpenBao Transit's imported `hmac` key type
and `/transit/verify` against the provider's exact raw-body HMAC-SHA256 format
in a disposable live OpenBao probe. [OpenBao's Transit documentation](https://openbao.org/docs/secrets/transit/)
states that the HMAC key type supports key import and remote HMAC verification.
If the live format probe matches, import one provider-profile-scoped key under
operator control, expose only a narrow verify operation through Signing Keys,
and remove the raw secret mount from the ingress service, Compose, Kubernetes,
selectors and tests. Keep the shared secret available only for provider
provisioning outside application runtime; deny export by policy. If the live
probe disproves compatibility, implement the operation in the Go OpenBao
extension instead. Preserve ambiguous-job, tenant-binding, tamper, unavailable
KMS and signer-handoff behaviors in the same grouped UI PR.

2026-10-08 live feasibility result: a disposable OpenBao 2 dev instance
accepted `bao transit import ... type=hmac` for a synthetic provider key.
An independently computed HMAC-SHA256 of the exact callback bytes, converted
from lowercase hex bytes to `vault:v1:<standard-base64>`, verified through
`/v1/transit/verify/passport-provider-probe` with `data.valid=true`;
changing one body byte returned `data.valid=false`. The container was removed.
This proves the provider's HMAC format can use ordinary Transit for remote
verification; the Go extension remains required for DIDComm X25519/HAIP
operations, not for this provider HMAC. Next implement profile-scoped key
import/policy, narrow verifier transport, runtime secret removal and live
packaged acceptance. Do not count the synthetic dev probe as production policy
or packaged-image qualification.

2026-10-08 provider-ingress remote-custody candidate: the supported isolated
Rust callback signer now has a verify-only provider route. It hashes the exact
registered profile ID into a Transit key name, converts the provider's strict
lowercase hex HMAC to the configured `vault:vN` format, and asks Transit to
verify the exact callback bytes. The ingress passes the configured key version
and exact bytes to this route before JSON parsing and repository lookup; it no
longer reads or computes with a webhook secret. Both runtime processes reject
local provider-key source selectors. A shared Rust profile-ID validator keeps
the signer, ingress and handoff contract aligned. The physical beta overlay
now uses the supported signer binary because the beta-only signer has no
provider verification route. Compose and Kubernetes no longer mount the raw
provider key; selectors reject even empty legacy/source fields. The frozen
external wire vector remains without a local secret fixture.

The operator-only `scripts/import_passport_provider_hmac.sh` was exercised
against disposable OpenBao for both create (version 1) and explicit rotation
(version 2), with a non-exportable imported HMAC key. The pinned OpenBao policy
probe passed: the supported token verified a provider HMAC, rejected changed
bytes, and could not generate provider HMACs, read/export keys, or verify the
internal callback key; the beta token could not verify provider HMACs. Its
Rust adapter run also passed against that disposable OpenBao. The Issuance
PostgreSQL provider-ingress contract passed with remote-verifier transport
mocking; the relevant physical selector/Compose/Kubernetes and external-wire
contract tests passed (60 cases). Signing Keys library passed 133 tests with
7 ignored; Issuance library passed 563 with 8 ignored. This remains candidate
source and local evidence: re-run after final edits, qualify the exact packaged
services image and imported provider key under the deployment policy, then
complete cross-repository review, hosted CI and release gates in the same
grouped UI PR.

2026-10-08 provider-custody follow-up review: the runtime verifier and
operator import path now use the same full SHA-256 profile-derived Transit key
name and a selected positive key version. Rust profile validation was moved to
the shared `marty-passport-auth` crate for signer, ingress startup and handoff.
The production-mode signer has a supported-only verifier route; the beta-only
signer cannot expose it. The physical beta overlay therefore reuses the
supported signer from its base provider overlay. The old ingress HMAC helper
and frozen local shared-secret test fixture are removed. The provider contract
and operator docs now state remote verification and KMS-only rollback.
An existing Rust contracts CI lane runs the disposable OpenBao policy probe
and Rust adapter; no separate provider PR or hosted CI job is planned.
After these edits, physical selector/deployment/external-wire tests passed
(60), the broader Kubernetes model suite passed (254, 1 skipped), the shared
passport-auth unit tests passed (3), and the targeted supported signer route
test passed. Both changed service binaries and libraries passed warnings-denied
Clippy. Hosted CI and exact packaged-image verification have not run; the
grouped UI PR is not yet ready to open.
The existing CI/workflow planner suite passed (150 tests, 188 subtests),
Python Ruff passed, changed YAML parsed, and `git diff --check` was clean.
No grouped PR has been opened or hosted gate run on this candidate head.

2026-10-08 passport signer test-custody continuation: the CMS ECDSA format
unit test now uses fixed public `(r=1, s=2)` ES256/ES384 raw and DER vectors
instead of generating P-256/P-384 private keys and signing locally. It still
checks both encodings and malformed/zero signatures; its focused Rust test
passed. The dynamic CSCA/DSC chain and managed-signer tests in the same module
still generate local private keys and remain a K8 test-custody blocker. Migrate
their positive paths to remotely held signing keys and public certificate
artifacts without dropping chain, rotation, trust or malformed-signature
assertions. This focused result does not qualify the whole assembled UI head.

2026-10-08 passport public-vector resolution (supersedes the remaining
`passport_signer.rs`/reconciliation fixture gap above): two synthetic public
CSCA/DSC chains, CMS signatures and signed SODs are now shared by the managed
signer and PostgreSQL reconciliation tests. The mock signer serves a vector
only for the exact expected CMS input digest; no local `KeyPair`, `SigningKey`,
private-key decoding or signature generation remains in those two source
files. The seven signer unit tests passed, preserving chain, trust, wrong DSC,
rotation, tamper and payload assertions. A disposable PostgreSQL 16 run of
the five reconciliation tests first exposed a real 409 on partial recovery:
PostgreSQL's receipt time preceded the host validation timestamp by 25 ms.
The bound-job check now permits at most 30 seconds of cross-clock skew while
still requiring matching receipt/material digests and a validation time after
job creation. The regression test rejects a provenance timestamp 31 seconds
after the receipt. The five database-backed reconciliation tests then passed;
the full Issuance library run passed 563 tests, zero failed, eight ignored.
Rust package formatting and affected diff checks passed. Public vectors are
not remote-custody evidence; exact-image/backend acceptance and other test
fixtures remain K8 gates for the broad UI feature PR.

2026-10-08 Canvas LTI and DIDComm test-custody continuation: the Issuance
Canvas LTI integration target now loads public Ed25519 JWK coordinates and
pre-signed launch/orchestration JWT signatures from a shared vector file.
Each lookup binds the signature to the exact header-and-claims digest; the
test target contains no `SigningKey` or local JWT signing. All 29 Canvas LTI
tests passed, preserving launch orchestration, wrong-key and bounded JWKS
refresh behavior. The DIDComm test document helper likewise uses a fixed
public Ed25519 verification method instead of deriving it from a private
seed; its opt-in live target compiled. The actual holder decryption key in
that live target remains an intentional holder-side capability. Formatting
and affected diff checks passed. Continue auditing other acceptance fixtures
and qualify their real backend paths before K8 closure.

2026-10-08 Core cross-crate fixture retirement: the clean Core feature branch
at `5a7c546` was extended locally with public RSA active-authentication
challenge/signature vectors. Its exact-challenge and wrong-message tests pass
without generating an RSA private key. No other cross-crate source references
the former `marty-crypto-test-support` local ECDSA, Ed25519, RSA or private-key
serialization modules, so all four modules and their direct private-key
dependencies were removed; the crate now offers only disposable OpenBao
signing adapters and public-key constants. Its locked test target compiles,
Core verification's 353-test library selection passed (281 passed, 72 opt-in
ignored), and all verification integration test targets compiled. Warnings-
denied Clippy for test support and verification, formatting, and diff checks
passed. The active-authentication vector is public-only verification evidence,
not KMS custody evidence. Review the remaining crate-internal cryptographic
conformance/private-key tests separately and keep this correction in the one
Core feature PR before UI pins its final reviewed SHA.

2026-10-08 Core algorithm-identifier test-custody follow-up: the RSA-PSS
parameter-aware verifier unit tests now consume public signed vectors for
SHA-256, SHA-384 and SHA-512 with non-default salt lengths. They no longer
generate or parse RSA private keys or sign in the test module; the wrong-salt,
missing-parameter, SHA-1 and MGF-mismatch rejections remain. The focused
three-test selection and the complete 44-test `marty-crypto` library selection
with `signature-verification` passed, as did warnings-denied Clippy. These
fixed vectors are public verification inputs, not evidence of KMS custody.
Keep this correction in the broad Core feature PR and continue classifying
remaining crate-internal local-key tests by actual conformance/session/device
ownership before accepting the Core test graph.

2026-10-08 Core certificate test-custody follow-up: the X.509 CRL URI and PKD
metadata parser tests now read public DER fixtures, and the parameterized
RSA-PSS certificate-signature test reads a public issuer/subject certificate
pair. This retires their rcgen certificate generation and private-key
re-signing while retaining positive verification, algorithm-mismatch and
tampered-signature assertions. The focused parser and PSS selections passed;
the complete 135-test `marty-crypto` library selection with ECDH, signature
verification, CRL, OCSP and public-key codec features passed. Public fixtures
do not establish remote custody. The CRL/OCSP test builder and other
crate-internal key-generation tests still need classification or replacement.
Keep this in the single Core feature PR and run final assembled-head review
and checks before opening that PR.

2026-10-08 Core public-key codec test-custody follow-up: two serialization
unit tests generated local P-256 private keys but only asserted nonempty
generated bytes. They are replaced by one public-certificate vector test that
checks P-256 type detection, 256-bit size and malformed-DER rejection. This
test runs with the minimal `public-key-codec` feature instead of depending on
the full test-only key-generation graph. The focused selection and complete
134-test `marty-crypto` library selection passed; warnings-denied Clippy and
formatting passed. The lower count reflects two vacuous key-generation tests
replaced by one actual codec behavior test. Keep this with the broad Core PR.

2026-10-08 Core CRL/OCSP public-input follow-up: CRL metadata parsing and
revocation-membership tests now consume one synthetic public DER CRL instead
of generating a local CA key and signing two CRLs. The OCSP request-builder
test now consumes the existing public issuer/subject certificate pair instead
of generating and signing certificates. The minimal CRL selection passed three
tests; the OCSP request selection passed two tests; the 134-test full-feature
`marty-crypto` library selection and warnings-denied Clippy passed on the
edited head. These public fixtures do not establish authenticated or
freshness-valid responder behavior. The remaining CRL/OCSP response tests
still use local test-only signers; replacing them needs a time-aware public
vector or remote-signing fixture so fixed responses do not expire after seven
days. Keep all changes in the single Core feature PR.

2026-10-08 authenticated CRL custody follow-up (supersedes the CRL portion of
the preceding remaining-work statement): the CRL issuer, leaf and signed-CRL
inputs are now public DER vectors with a fixed validation instant. Production
`validate_crl` and `validate_crl_for_certificate` still read system time; a
shared internal clock-parameterized path lets the unit test exercise the same
authorization, signature and freshness logic without an expiring fixture.
The test checks revoked status, wrong issuer, future issue time, expiry and
tampered signature. The unused test-only `CrlBuilder`, including its local
ECDSA/RSA signing and private-key import paths, was deleted. Four focused CRL
tests and the 134-test complete `marty-crypto` library selection passed, as
did warnings-denied Clippy. This is public verification behavior, not a live
KMS signer proof. OCSP response tests and other test-only certificate/key
builders remain the next Core custody batch; keep it in the same feature PR.

2026-10-08 authenticated OCSP custody follow-up (supersedes the OCSP-response
remaining-work statements above): one public synthetic issuer/leaf pair,
second leaf, and signed good/revoked OCSP response pair now drive the five
request/response tests. The same internal clock-parameterized validator path
is used by the production system-clock wrapper and fixed-time tests. It
preserves good/revoked status, issuer responder authorization, certificate-ID
binding, signature tamper rejection, future-time rejection and expiration
rejection without ephemeral local CA or response keys. The now-unused
test-only `OcspResponseBuilder`, including its private-key import/signing
code, was deleted. The full 134-test `marty-crypto` feature selection,
warnings-denied Clippy and formatting passed on this head. Public signed
vectors prove verification behavior only; the live OpenBao acceptance remains
the remote-custody proof. Other test-only certificate/key-generation modules
and product integration gates remain; keep this in the broad Core PR.

2026-10-08 Core test-only authority module retirement: after the public CRL
and OCSP conversions, no remaining Rust caller used the `cfg(test)`
`cert_builder`, `keygen`, `pkcs12` or `sod_builder` modules. Those four modules
were deleted together, removing local issuer certificate/key generation,
private-key bundle construction and mock SOD signing from the test-capable
crypto crate. Unused `cms`, `p12`, `rcgen`, `tempfile` and X.509 builder dev
dependencies were removed from `marty-crypto`; the lockfile dropped its `p12`
and `rc2` packages. The complete crypto library selection now runs 112 tests
and passes; warnings-denied Clippy, formatting and diff checks passed. The 22
removed tests exercised only the retired local authority modules. This is not
a claim that the entire Core test graph is private-key
free: CAVP/conformance, other crate-internal signers, holder and session
paths need a purpose-by-purpose review. Production API exposure remains
unchanged because these modules were selected only by rustc `cfg(test)`.
The unreachable former `marty-verification/src/issuance/mod.rs`, which still
referenced the removed builder, was deleted too; verification's 353-test
library selection passed (281 passed, 72 ignored). All crypto test targets
compiled with the full feature selection. Keep the deletion and the new
public-vector checks in the single Core PR.

2026-10-08 Core codec test-custody continuation: the `marty-crypto`
serialization module still carried unreferenced `cfg(test)` private-key PEM,
DER, SEC1/PKCS#1/PKCS#8, raw-key conversion, key-type detection and public-key
derivation helpers. Those paths were removed while keeping all public SPKI/PEM
codec functions and the compile-fail boundary. The minimal `public-key-codec`
library selection passes its public-vector test; complete Core feature tests
and final dependency/self-review checks are still due on the assembled head.
Other signature conformance and session/holder private-key paths remain under
classification, so this does not close the full K8 test-custody gate.

2026-10-08 Core RSA test-custody continuation: RSA's test-only key generator,
private-key parser, and RS256/384/512 plus PS256/384/512 signing functions
were removed. The former local-signing conformance suite now consumes public
RSA SPKI/signature vectors for all six algorithms, checks message/key/tamper
and cross-scheme rejection, and verifies two distinct valid PSS signatures
for one message. Its six tests and the minimal RSA invalid-public-key unit
test passed. The synthetic-vector source is named
`rsa_public_verification.rs` rather than claiming an external CAVP suite.
The full 99-test `marty-crypto` library selection, all-targets
compilation, warnings-denied Clippy and formatting passed after unused RSA and
signature dev dependencies were removed. The lower count reflects retired
keygen/signing tests; supported public verification behavior remains covered.
This is public verification evidence only, not proof of remote signer custody.
Other local cryptographic conformance signers still require classification.

2026-10-07 batching decision: keep the Core SD-JWT format-test retirement and
wallet verified-presentation fixture migration in the *same Core feature PR*.
The wallet suite still imports the test-only `sign_sd_jwt(IssuerKey, ...)`
helper, retains issuer and holder private JWKs, and re-signs mutated JWTs.
Deleting that helper first breaks the Core test build; deleting wallet tests
would lose positive presentation and adversarial verification assertions.
Replace credential construction and mutation re-signing with disposable
OpenBao operations, and preserve wallet/device-key coverage only where it is
an explicitly supported holder capability. Then remove the helper, local
issuer-key fixtures and any redundant unit cases together. Keep this local
until the whole Core feature diff passes its regression, security and quality
review; pin it in UI once, then qualify the grouped Core, UI and Credentials
PRs in dependency order. Corrections to each group stay in its feature PR.

2026-10-08 wallet fixture review: the wallet verified-presentation file had
already moved to `remote_sd_jwt_wallet_public.json` and contained no issuer
private JWK or local re-signing, superseding the older fixture finding above.
Although `marty-oid4vci` sets `autotests = false`, `lib.rs` includes this file
as a wallet-gated crate-internal suite. All 13 tests pass through the library
selection with `--no-default-features --features wallet`. A proposed separate
Cargo test target was removed during self-review because it would duplicate
those tests and increase CI cost; the Core manifest is unchanged. The fixture
is public-only verification evidence, not remote issuer-custody evidence. The
separate live OpenBao issuer test remains the custody gate, and the complete
assembled Core matrix is still due.

## Work tracker

| ID | Work and exit evidence | Status |
| --- | --- | --- |
| K1 | Reconcile preserved branches; map every supported production binary, image, wheel, Cargo root and release pin; enumerate current signing/encryption paths and explicit secret-class exceptions. | In progress |
| K2 | Prove backend support for non-exportable DIDComm sender agreement/authcrypt with actual recipient decryption; select the smallest shared Rust boundary and record supported provider scope. | In progress; standard Transit lacks X25519, current Go OpenBao plugin image and native Rust sender passed an isolated live holder-decryption proof, and the plugin passed a three-voter active/standby Raft forwarding and failover probe; published image and production scope remain unqualified |
| K3 | Implement DIDComm scoped/versioned references and remote operations; bind tenant, sender DID/key, recipient documents and frozen attempt inputs; preserve rotation, expiry, retries, replay, cancellation and unknown-outcome semantics. | In progress; native Rust scoped/versioned authcrypt, rotation and local Raft capability/idempotence proofs passed; self-host and Kubernetes native-Issuance models mount a dedicated read/pack-only OpenBao token; the packaged direct Canvas renewal process passed anoncrypt/authcrypt holder decryption with a disposable plugin backend; Linux isolated gateway/Kubernetes processes, full retry/recovery and release deployment qualification remain |
| K4 | Implement opaque integration-secret custody with remote-only startup and new writes; reject old AES-GCM envelopes and raw master-key configuration; prove tenant/purpose isolation, tamper rejection, restart, rotation, recovery and atomic repository behavior. | In progress; live Transit rotation/binding/tamper, clean PostgreSQL mixed Rust/Python read/write/startup-scan, and disposable coordinated Rust/PostgreSQL/OpenBao Raft snapshot restore passed; packaged image, hosted CI and cutover qualification remain pending |
| K5 | Adopt hardened Core across Rust services and fork pins; replace removed APIs and broad features; isolate fixtures and qualification binaries; eliminate compatibility crypto from production graphs. | In progress; Core PR #355 published head `bd6e4cc` adds the public Canvas metadata boundary and has green exact-head hosted checks; protected review remains. Verifier PR #154 published head `1817638` pins this Core head, with 35 local `marty-sync` tests passing (one ignored) and green exact-head hosted checks. Credentials draft PR #313 published head `6097d55` pins the same Core head, with exact graph guard, 25/25 local library tests, warnings-denied Clippy and green exact-head hosted checks. UI draft PR #1192 remains published at `8ee6790ba`; its local repin uses Core's canonical metadata check, with the production and standalone graph guards passing. Authenticator draft PR #57 remains published at `e773596`; its local Core and Verifier repin eliminates a duplicate-Core lock graph, while the protected 90% Flutter coverage gate remains open. Final consumer artifacts and wallet cutover remain. |
| K6 | Establish actual supported BYOK route/schema and tenant/certificate binding; integrate reference-only UX and server rejection of private material, preserving existing onboarding behavior. | In progress; public external OpenBao registration-to-issuer/certificate live Rust route passed; packaged gateway, other-provider acceptance and review pending |
| K7 | Retire Credentials raw-key adapters, obsolete wheels and local private-key tests; prove native owner selection and published artifact behavior without old-data reads. | In progress; Python DIDComm/secret/gRPC and legacy issuer adapters and their old tests are removed, native HTTP owner is required and Python gRPC runtime is disabled. Grouped draft Credentials PR #313 published head `6097d55` pins Core `bd6e4cc`; the exact graph guard, 25 local library tests, warnings-denied Clippy, and exact-head hosted checks (19 success, one skipped) passed. The repository root remains an empty Python test-harness wheel; Core owns canonical native wheels. Browser behavior, replacement vectors and released-artifact qualification remain. |
| K8 | Add production-root feature, forbidden-API, binding and artifact checks; exercise real remote operations and negative paths; complete all three self-review passes. | In progress; CI now requires the locked Marty Core/isomdl feature graph and the packaged OpenBao image's storage, Raft failover and recovery probes. A local shared production-Dockerfile image passed the exact-image verifier gate with separate non-exportable issuer/holder Transit keys, plus tamper/private-JWK/cross-key negatives; hosted CI, release provenance, broader artifact/binding gates and self-review remain |
| K9 | Land grouped feature PRs through required checks; qualify exact release artifacts, clean KMS-only cutover and recovery; update durable evidence and close the goal only after acceptance below. | In progress; SSI fork PR #9 and Rust-only Issuance PR #1203 are merged. Core PR #355 `bd6e4cc`, Verifier PR #154 `1817638`, and Credentials draft PR #313 `6097d55` have green exact-head hosted checks; Core still requires protected review. UI draft PR #1192 `8ee6790ba` has two stale-contract failures in live CI run `37999429439`, locally corrected; its OpenBao plugin image and Rust Service Images jobs passed, while Canvas database contracts are still running. The next grouped UI push includes the JSON guard and canonical Core repin. Authenticator draft PR #57 `e773596` passes prior-head analysis, tests and builds but fails the protected 90% Flutter coverage gate; later retirement work and graph repin remain local. Exact release artifacts, mobile device proof, KMS-only cutover and recovery remain. No remaining cross-repository PR is release qualified or merged. |
| K10 | Remove every private-key database table and secret-bearing key column from clean-install DDL, ORM metadata, initialization and tests. Add no migration scripts; prove the fresh database schema and runtime writes contain only public keys or scoped remote references where key metadata is needed. | In progress; Credentials removed private-key ORM tables and historical creation paths; Core guards direct Open Badge public-key writes. UI uses a shared private-material policy across named JSON stores. Local fresh PostgreSQL 16 checks ran Organization, Credential Template and Rust Issuance migrations twice: 47 service tables, nine Issuance ledger entries and no private-key catalog entries; injected Alembic/key state was rejected. Local UI commits `a1ba39ba2` and `a804ccb56` add the catalog gate and generic JSON/JSONB value scan to the exact-image qualifier and protected passport producer before and after representative runtime writes; disposable PostgreSQL clean/injected cases passed. These source changes remain local. Exact signed-image execution, final assembled table/column inventory, self-host cutover and release proof remain. |

### First execution steps

1. Finish K1 using fresh refs and the actual production packaging commands,
   separating test-only code from compiled service capability.
2. Trace supported KMS provider operations and native DIDComm interfaces to
   resolve K2. Signing or wrap/unwrap APIs are not proof of non-exportable
   X25519 support. A reference that eventually exports a private key fails.
3. Remove raw integration-secret key startup and legacy read/write capabilities;
   qualify remote-only initialization, repository transactions and clean data.
4. Record concrete API contracts and failing regression probes, then implement
   cohesive Rust changes locally across isolated repository worktrees.

## Review and validation gates

Review our own complete diff before each hosted qualification batch and again
after material corrections. Record findings, fixes and evidence for each pass.

- Regression and feature preservation: compare against the supported behavior
  inventory and frozen contracts. Cover credential formats, DIDComm anoncrypt
  and real authcrypt, sender authentication, recipient decryption, retries,
  routing, certificates, sessions and wallet interactions on new KMS-only data.
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
- Integration-secret master-key custody is opaque and remote; old ciphertext is
  rejected, with tested rotation and recovery for new remote envelopes.
- Fresh database initialization creates no private-key tables or
  secret-bearing key columns; no legacy ORM path recreates them. No migration
  script is required or shipped for this retirement. Public-only device and
  remote-reference records remain only after column/data-flow review.
- BYOK interfaces accept public certificates and authorized remote references,
  reject private material server-side, and preserve supported onboarding.
- TLS, ephemeral session and intentional wallet/device behavior remain supported
  through explicit product capabilities; test signers cannot enter release roots.
- Regression, security and quality self-reviews have no unresolved required
  corrections; production graph/API/artifact and real backend acceptance pass.
- Grouped feature PRs are merged through required protections, exact release
  artifacts and clean KMS-only cutover/recovery are qualified, and this tracker links
  the evidence. Any external access or deployment prerequisite still missing is
  recorded as unfinished work, not treated as acceptance.

The active goal is complete only when these criteria are met. Do not silently
reduce scope when a backend or deployment prerequisite is unavailable. Continue
independent implementation and record the precise remaining dependency. Changes
to live key policies, key deletion or irreversible data migration require their
specific operational context; prepare a concrete reviewed operation first.

## Evidence and progress log

2026-10-07 K6/K8 public-input self-review finding: the signing-key service's
shared private-material check rejected ordinary private JWK objects and PEM
markers, but accepted `privateKeyJwk`/`privateKeyMultibase` named values and
JSON-encoded JWKs in metadata strings. The candidate now rejects those forms
before registry normalization, while retaining public JWKs and opaque remote
references. Two focused detector tests and the actual registry rejection test
passed; the signing-key service library suite passed 127 tests (seven ignored),
targeted Clippy passed with warnings denied, and package formatting passed.
UI branch commit: `da0d19afc`. This closes an input rejection gap, not the
full BYOK or artifact acceptance gate.
The same review found `normalize_legacy_registry` in the Rust signing-key
service and `createLegacyServiceFromConfig` in the UI still translate the old
flat `hsm_settings` shape. These are unnecessary compatibility paths under the
KMS-only decision. The follow-up candidate removes both translators and the
old HSM/Vault fields from the public config document and UI normalized model.
Requested and stored Rust registries now reject flat HSM/Vault fields rather
than silently translating or clearing them. The modern `services` array,
default selection and remote references remain. Focused Rust rejection passed;
the signing-key library suite passed 128 tests (seven ignored). Four UI test
files passed 24 tests, including current service wizard/page behavior and the
gateway contract; targeted ESLint passed. Integration-target compile and
Clippy with warnings denied passed, as did package formatting and the changed
live-contract target's compilation. The changed public config HTTP contract
passed against a fresh disposable Redis database with a verified sentinel;
it rejected the old flat `hsm_enabled` payload without losing managed KMS
purpose bindings. The neighboring public signing contract passed against
fresh disposable Redis and pinned OpenBao 2.5.5: it signed through a remote
registered key and rejected unbound selection, cross-tenant scope and private
key input. Both containers were removed after the runs. No legacy Redis data
is migrated, consistent with the no-public-deployment decision; exact
artifacts are not yet qualified.

The beta organization console audit still required the removed `hsm_enabled`
response field. It now selects a service by `default_service_id` from the
current `services` array, rejects missing/disabled selections, and records the
selected service in its inventory. Its release-check module passed 29 tests.
UI branch commit: `7185fa1b2`. This updates the audit source only; it does not
claim a beta deployment of the candidate.

2026-10-07 KMS-only scope correction: the maintainer confirmed there are no
public deployments and authorized dropping fallback, old behavior and old-data
compatibility. The HAIP read-only inventory, import, offline migrator and
synthetic migration proofs recorded later in this log are historical research,
not release requirements. The candidate now removes the HAIP private-JWK
import path from the Go OpenBao plugin, UUID `kid` acceptance, Flow's private
JWK unwrap/decrypt branch, generic Flow envelope routes and gateway forwarding,
and the old Core verification compatibility dependency. It also removes the
integration-secret offline migrator and feature-gated local AES cipher. The
new invariant is KMS-generated scoped HAIP keys with remote decrypt only,
plus remote-only integration-secret startup and rejection of old ciphertext.
Flow request/submission tests passed (18), OID4VP contract tests passed (20),
and the candidate Go plugin Docker build passed Go unit tests and vet. A wider
Rust compile and route-contract review are in progress. No live service or
database was changed.

Follow-up qualification on the same candidate: `cargo check --offline` passed
for Flow, Signing Keys, gateway and Issuance; Flow request/start/retrieval/
submission tests passed (25, including rejection of an old envelope alone or
alongside a remote reference). The Go plugin was rebuilt after adding a test
that its private-JWK import route is unavailable; Go tests and vet passed.
Signing Keys' remote HAIP unit tests passed (2), gateway's signing route
contract and retired-route 404 tests passed, the public protocol contract
checker passed, and CI planner/workflow tests passed (150 tests, 188 subtests).
HAIP HTTP tests compiled and returned success but their live branches require
disposable PostgreSQL and holder input; they do not constitute a fresh live
remote proof for this exact source head. Remaining: remove the Python issuance
service/raw master-key deployment path and old Credentials adapters, qualify
the exact KMS-only image through disposable service/wallet/database flows, then
self-review and land the grouped feature PRs.
Credentials' DIDComm and integration-secret deferred-work notes now record this
decision on `security/remote-kms-retirement-20261007` at `dcb34ed`; the
runtime removal work there is still pending.

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
This describes the `6d98e73` checkpoint; a later local remote-key run is
recorded below, while exact-image and release acceptance remain open.

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

The shipped `marty-verifier-positive-gate` was subsequently changed by
`4361f4718` to accept a bounded public presentation and issuer JWK on stdin;
it no longer generates issuer/holder private keys or signs credentials. Its
canonical positive verifier assertions remain in the shipping binary. The
base integration script still invokes that binary without stdin, so it cannot
qualify this new contract. The preserved integration branch
`security/remote-kms-acceptance-20261007` supplies a digest-pinned Core
producer and `docker run -i`, but has not yet run against two actual remote
KMS keys and an exact candidate image. Keep the gate packaged until that
producer-to-image route passes; it is verification-only capability, not a
local custody exception.

Other build roots include `rust/services/Dockerfile.ci` and the dedicated
event-stream, signing-keys and revocation-profile Dockerfiles. The CI multi-target
build has a different binary set from the public shared image. Both dependency
cooking stages build the workspace, so narrowing the final binary list alone
does not qualify the compiled feature graph. Remaining K1 work includes full
release/wheel ownership, standalone products, and per-root feature resolution.

Integration-secret raw-key consumers include issuance startup, the Canvas sync
worker and `canvas_oauth_postgres.rs`. The existing envelope is base64 of a
12-byte nonce followed by AES-GCM ciphertext and tag, with no tenant/purpose AAD
in the inspected implementation. Bind new envelopes to repository identity
and purpose, and reject old envelopes at cutover. Earlier import/rewrap
experiments are historical; never assume an OpenBao ciphertext prefix supplies
tenant or purpose binding.

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
legacy raw-key read fallback. The final KMS-only cutover rejects legacy reads;
the earlier migration/recovery experiments here are historical only.

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

2026-10-07 HAIP offline audit privilege review: the first migrator draft
required `HAIP_MIGRATION_IMPORT_TOKEN_FILE` even for its read-only `audit`
command, giving a preflight operator unnecessary access to the private-key
import route. `audit` now reads `HAIP_MIGRATION_READ_TOKEN_FILE`, while
`migrate` alone reads the import token and Transit-decrypt token. The new
`docker/openbao-haip-migration-audit-policy.hcl` grants read only on exact
tenant/Flow/version public-key paths. Its `+` single-segment syntax follows
[OpenBao's policy documentation](https://openbao.org/docs/concepts/policies/).
A disposable OpenBao 2.5.5 ACL check granted `read` on the versioned key path
and `deny` on import, decrypt and unversioned key paths; the container was
removed. The feature-gated Rust migrator passed `cargo +1.95 check --locked`
after the edit. No running stack or historical row was changed. A real
offline audit against the exact release plugin/image remains required.
The same review found that paginated `audit` queries previously used a fresh
database snapshot per page. The command now starts a read-only,
repeatable-read transaction before scanning and commits only after all remote
version checks succeed. A disposable PostgreSQL 16 concurrency probe returned
the initial row count on both reads while another session inserted a row;
the container was removed. The feature-gated migrator check and scoped
`rustfmt --check` passed after the edit. This makes one audit internally
consistent; a cutover audit still requires Flow writers to be stopped so new
rows cannot appear after its snapshot.

2026-10-07 plugin artifact CI checkpoint: the checked-in OpenBao plugin
Dockerfile now runs `CGO_ENABLED=0 go test ./...` and `go vet ./...` before compiling the
binary. The repository CI classifies plugin source and OpenBao policy changes
into a dedicated image-build lane, requires that lane through `ci-gate`, and
keeps it skipped for unrelated Rust-only PRs; merge-queue/full runs include
it. The new lane builds the pinned Go/OpenBao image and checks that the final
image contains an executable plugin. Local classifier/gate contract tests
passed (124), neighboring CI contract tests passed (58), and a local Docker
build ran the Go tests and vet successfully. The final local image was
`sha256:b7ce87b0e8d44f51aa89a55e284f702cb0ab766dd5f2f43c296e686a1e2ce411`
(83,328,215 bytes); its executable check passed. This local image is neither
published nor attested and does not replace the exact release artifact,
live KMS/wallet acceptance, or the stack release transaction. The plugin
release/promotion route remains to be designed and qualified.

2026-10-07 Credentials hardened-Core port checkpoint: the Credentials branch
workspace dependencies and lockfile now resolve all six Core crates at reviewed
revision `a5cb567e6cd50e5a85b3b125a0a2ab6eea1d9fb7` / 0.2.0 and `isomdl`
0.3.0 at `784a5294`. Cargo metadata shows `kms-only` on crypto, OID4VCI and
verification, with no Core default/local-key or isomdl local-signing feature.
`cargo +1.95 check --locked --offline --no-default-features --features native`
passed. The Python check initially exposed a missing verification-only BBS
feature; after selecting `bbs-verification`, the Python check passed. These
are compile checks, not wheel or runtime proof. The candidate removes the
three local-key opt-in features and their CI builds, deletes a private-key
SD-JWT test fixture, and moves remaining public-only binding contracts into
the production wheel test. A new Credentials CI metadata guard pins the six
Core crates and isomdl to reviewed revisions and rejects restored local-key
features; the actual graph passed and four negative mutations were rejected.
The subsequent source cleanup removed dead private-key Python and WASM
bindings, the orphaned local eMRTD issuance module, and local-key SD-JWT,
OID4VCI and browser issuance tests. The Python library and all-targets checks
passed without the earlier unexpected-`cfg` warnings; Rust formatting passed.
The deleted SD-JWT wire-format and proof-binding tests need public signed
vectors or remote signer acceptance replacements before feature-loss review
can close. Prefer the [RFC 9901 SD-JWT examples](https://www.rfc-editor.org/rfc/rfc9901)
for checked-in public signed vectors; the deleted test named RFC 9449, which
is not the finalized SD-JWT RFC. The published verification wheel is still the old 0.1.60 artifact
and must be replaced before K7 acceptance.
After the cleanup, `cargo +1.95 fmt --all -- --check`, both native and Python
`cargo check --locked --offline --all-targets` feature sets, and the compiled
PyO3 `production_module_excludes_private_key_operations` test passed on the
Credentials branch. The binding test exercised the actual registered module
and verified public exports remain. This does not qualify its release wheel.
Credentials CI and warm-cache workflows now build both Core wheels from one
reviewed Core checkout with `kms-only` selected on both; the verification
wheel export check rejects generic secret-byte and removed local-issuance
functions. The focused workflow contract test for these build inputs passed.
The hardened Core verification wheel's selected `python,kms-only,iaca,csca,eudi`
feature set passed a locked offline Cargo check in the Core worktree. A local
Windows `marty_verification_py-0.2.0-cp311-abi3-win_amd64.whl` then built from
that feature set. Importing the wheel confirmed `p256_public_jwk_to_pem` and
`open_badge_ob3_verify` are callable, and `aes_gcm_encrypt`,
`aes_gcm_decrypt`, `generate_random_bytes`, `open_badge_ob2_issue`, and
`open_badge_ob3_issue` are absent. This is local candidate evidence, not
published-artifact qualification or a publishable manifest hash.
The strengthened release-dependency contract intentionally failed because
`release/dependencies.json` still pins the old `marty-rs` and verification
wheel commits; exact hardened wheel publishing and SHA-256 pin updates are
required before that gate can pass.
A local Credentials `_marty_rs` 0.1.78 Windows wheel also built from the
candidate `python` feature set after the dead binding cleanup. Importing that
wheel confirmed remote mDoc prepare/complete, SD-JWT verification and BBS
verification exports remain callable, while local issuer-key generation,
local VC/mDoc issuance and DIDComm private-key operations are absent. This
candidate is distinct from the Core `marty-rs` wheel and does not qualify
the published release artifact.
Six compiled Python boundary tests passed with those two locally built wheels
installed together. After retiring the legacy Python issuer adapter and Behave
harness, 33 focused Credentials unit/workflow tests passed; the one release
dependency pin contract was deliberately excluded because the published
manifest still names the old Core artifacts. `git diff --check`, Rust
formatting, and workflow YAML parsing passed on the candidate branches.
The WASM target check could not complete on this Windows host because the
`ring` build requires `clang`, which is not installed here; it remains a CI
qualification item. The existing release-workflow contract still asserts the
old transitional Core pin and must be updated alongside the release artifact.

The dormant Python `adapters/services/issuance_service.py` generated local
issuer JWKs and signed W3C VC, SD-JWT, mDoc and Open Badge credentials.
Credentials now removes that adapter, `examples/local_key_usage.py`, the
private-key-dependent Behave suite under `tests/features`, and its manual
Makefile conformance targets. The service boundary test now asserts the
adapter and example are absent. The removed Behave scenarios were not in the
current GitHub CI workflow, but they covered SD-JWT disclosure encoding,
hashes, selective presentations and tamper detection; W3C VC 2.0 structure
and JWT tamper detection; Open Badges 3.0 structure and trust; issuance and
verification for W3C VC, SD-JWT, mDoc and Open Badges; credential lifecycle,
OID4VP, and ZK predicate behavior. Before K7 acceptance, map each useful
assertion to existing Rust tests or replace it with public signed vectors and
remote-KMS acceptance tests. Keep external-client signature verification
coverage; its source should be public fixed vectors or an opaque test signer,
not service-owned private keys.
Core's current test suite is not yet clean by that standard: for example,
`marty-verification/tests/open_badges_conformance.rs` generates Ed25519 issuer
JWKs and issues locally. Its structural assertions are useful; port them to
remote prepare/assemble behavior or public signed fixtures before claiming
test-side private-key retirement. Keep client-auth and wallet tests explicitly
classified, then replace local test signing where it merely supplies
verification input. `marty-oid4vci` and `marty-verification` set
`autotests = false`, but `src/lib.rs` explicitly imports many unregistered
`tests/*.rs` files as crate-internal tests. They were active in library test
runs, not dormant. The remaining imported local-signing BYOK, SD-JWT and Open
Badges cases require classification and replacement.

The Core branch now removes locally generated issuer `IssuerKey` use from
`marty-oid4vci/tests/sd_jwt_structural_boundaries.rs` and
`sd_jwt_managed_claim_boundaries.rs`, retaining validation,
external-signer-spy and prepared-payload assertions. These files previously
ran through `src/lib.rs` under the library's default/test feature graph. They
are now Cargo test targets
requiring `kms-only`, `issuer`, `sd_jwt`, and `mso_mdoc`, and Core CI invokes
that exact feature set. All 16 tests passed locally with locked offline
Cargo. The managed-claim test initially exposed that the remote signer path
verifies signatures against the configured public key; its dummy spy is
appropriate for pre-signing and negative checks, not a positive signed-token
round trip. Positive assertions now inspect prepared claims and disclosures;
valid remote-signer acceptance remains a separate required test. This narrows
two test-side private-key paths; it is not evidence that all Core tests are
cleaned up. Core branch commit: `80e97dd`; the follow-up removes their
crate-internal inclusion to avoid running the same cases under default features.
The next Core test-side audit found a higher-priority active path:
`marty-oid4vci/tests/signing_payload_semantics.rs` is registered and builds a
deterministic P-256 `SigningKey` inside a recording signer for JWT-VC and mDoc
positive assembly checks. The crate-internal `byok_prepare_assemble.rs` also
contained a private Ed25519 JWK and direct local-signing assertions. The active
scalar tests prove exact signing bytes and raw signature forwarding; preserve
those assertions using a real remote signer acceptance route before removing
their local key. Core `jwt_vc.rs` also retains `#[cfg(test)]` `IssuerKey`
signing code, so test-side retirement includes library unit-test paths, not
only `tests/*.rs` files. Neither a dummy signature nor a skipped target proves
positive issuance behavior.
The Core candidate removes that BYOK private-key fixture and replaces it with
an explicit KMS-only public-JWK JWT-VC preparation and bad-signature rejection
target. Its old positive prepare/assemble equivalence is already partly covered
by `signing_payload_semantics.rs` for ES256, but that active test still signs
locally. The removed BYOK fixture used EdDSA; its positive remote JWT-VC
round trip is not yet replaced, although public-only EdDSA preparation now runs
in CI. Full feature-loss review needs positive live
remote ES256 and EdDSA JWT-VC plus mDoc round trips.
The removed BYOK fixture had been imported by `src/lib.rs`; that import is now
removed, as are the two converted SD-JWT crate-internal imports. The two
SD-JWT suites run only through their KMS-only integration targets. The default
`marty-oid4vci --lib` suite passed after the change (317 passed, one ignored),
and the new public-JWK JWT-VC boundary target passed its three cases. The
default library suite still includes other local-key tests; this checkpoint
does not qualify it as KMS-only. Core branch commit: `2aec67c`.

2026-10-07 Core positive remote issuer proof: an opt-in Rust integration test
now requires a disposable loopback OpenBao marker before it creates any key.
It creates non-exportable ES256 and Ed25519 Transit keys, checks metadata,
root-token export failure, cross-key ACL denial, and that a sign-scoped token
cannot export a key, then signs JWT-VC with both
algorithms and mDoc with ES256. Core's normal assembly verifies those remote
signatures and the test checks the exact signed payload and signature bytes.
The test passed locally against disposable OpenBao 2.5.5 pinned at
`sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452`;
the test container was removed. A CI script now provisions the same pinned
image, marker and Transit mount before running the test, with cleanup on exit.
Its provisioning path passed a local shell smoke; hosted CI has not run yet.
The four focused KMS-only OID4VCI integration targets passed (21 tests), and
the live target passed after the final cross-key and export checks. Targeted
Clippy, Rust formatting, workflow YAML parsing, shell syntax and diff checks
passed. The Core library suite also passed again after adding the live-test
dependencies (317 passed, one ignored), and `cargo deny --locked --all-features
check advisories --deny yanked` passed.
The active `signing_payload_semantics.rs` test no longer constructs a local
P-256 `SigningKey`; its two public-only prepared-payload borrowing assertions
passed under `kms-only`. This closes the specific active local signer fixture
identified above but does not clean all remaining Core `cfg(test)` signers or
qualify production images and service routing. Core branch commit: `c2b54d7`.
The same disposable OpenBao test now also issues SD-JWT with both ES256 and
EdDSA, checks exact remote signing bytes and returned signature, and verifies
selective disclosure with the public JWK. The extended test passed against the
pinned disposable image; its container was removed. This proves a positive
remote replacement for SD-JWT issuance. The older crate-internal Ed25519
private-key conformance fixture still needs conversion without losing its
protocol assertions. Hosted CI has not run for the extension yet. Core branch
commit: `257f619`. The exact KMS-only test target compiled again after the
final test-name change; targeted Clippy, formatting, shell syntax and diff
checks passed.

2026-10-07 Core issuer-test retirement checkpoint: the live OpenBao test now
also rejects tampered SD-JWT signatures, a different Ed25519 public key, and
an unbound SD-JWT presented with verifier audience/nonce. Both IETF and W3C
SD-JWT forms issue and verify with the non-exportable ES256 and EdDSA keys.
The former `issuer_key_algorithm_binding.rs` suite and the typed local-key
admission test in `issuance_input.rs` were removed because they asserted
direct signing from private JWKs, a capability outside the KMS-only target.
New public-only `remote_jwt_vc_boundary.rs` tests retain rejection of
algorithm, declared-algorithm, curve, key-ID, and private-member mismatches;
they also check JWT-VC, SD-JWT and mDoc routes and a two-item batch fail
before returning credentials when public signer metadata is contradictory.
The KMS-only boundary target passed six tests, the live disposable OpenBao
target passed after these negative checks, and the default OID4VCI library
suite passed (308 passed, one ignored). Targeted Clippy, formatting and diff
checks passed. Core branch commit: `b2ee7c4`. This removes the obsolete raw
issuer-algorithm fixture; other crate-internal private-key tests, including
`sd_jwt_vc_conformance.rs`, still need conversion. Hosted CI has not run at
this head.

2026-10-07 Core SD-JWT conformance retirement: `sd_jwt_vc_conformance.rs`
no longer embeds the RFC Ed25519 private JWK or calls the test-only local
`sign_sd_jwt` API. A KMS-only CI target now uses public `RemoteSignerMetadata`
and `prepare_sd_jwt` to assert IETF identity, credential ID/JTI, W3C context,
type and subject layout, disclosure shape, plaintext exclusion, salt/hash
binding, and wrong-format rejection (six passed). Positive signed issuance and
verification remain in the disposable OpenBao target; it now also proves zero
and two disclosures with both ES256 and EdDSA and validates signed `jti` equals
the returned credential ID. The final live test passed and its container was
removed. Default OID4VCI library tests passed (289 passed, one ignored), and
the KMS-only issuer library graph passed (270 passed, one ignored). Targeted
Clippy, formatting, CI YAML parsing and diff checks passed. Core branch commit:
`75dbd57`. The lower default-library test count reflects moving conformance
coverage to its explicit KMS-only integration target and live backend test;
it is not a claim that all private-key tests are retired. Hosted CI and exact
release artifact qualification remain pending.

2026-10-07 Core JWT-VC local-path reduction: removed the duplicated
`cfg(test)` `sign_jwt_vc(IssuerKey, ...)` implementation, its generated private
`did:jwk` test keys, the unused `PreparedJwtVc::from_signing_input` test-only
reconstruction helper, and `jose::sign_compact_jwt` with its private-key
fixture. JWT-VC unit assertions now use public-only signer metadata and the
canonical preparation path. The remaining test-only `formats::sign_credential`
dispatcher calls `sign_credential_with_signer`, removing its second format
dispatch implementation; its `IssuerKey` signer and other crate-internal
local-key tests are still a retirement task. The disposable OpenBao test now
passes both ES256 and EdDSA JWT-VC through Core's public JOSE verifier and
rejects a mismatched expected algorithm. Its fresh container was removed.
Default library tests passed (288 passed, one ignored), no-default-feature
library tests passed (113), and the KMS-only issuer feature library tests passed
(269 passed, one ignored). Targeted live-test Clippy, formatting and diff
checks passed. Core branch commit: `c61b113`. Hosted CI and exact release
artifact qualification remain pending.

2026-10-07 Core Open Badges verifier-fixture retirement: the
`marty-verification/tests/open_badges_conformance.rs` suite no longer generates
Ed25519 issuer keys or calls the test-only OB2/OB3 issuance APIs. Four signed
OB2/OB3 vectors were minted once with disposable old test keys; only signed
credentials and public JWKs were retained. A recursive audit of all vector
JSON and the embedded `did:jwk` values found no private JWK members. The new
KMS-only integration target verifies OB3 mandatory structure, proof, issuer,
wrong-key rejection, image preservation and expiry rejection, plus OB2 hashed
recipient privacy, correct identity and wrong-identity rejection. Its six
tests passed. Adjacent default-library Open Badges tests passed (40), and
targeted Clippy, formatting, CI YAML parsing and diff checks passed. Core
branch commit: `f0b2af4`. The issuance functions in `marty-verification` are
already `cfg(test)`; other private-key tests and test-only issuers remain and
must still be retired. This is verifier-vector coverage, not a live KMS proof
of linked-data proof issuance. Hosted CI and release artifacts remain pending.

2026-10-07 Core Open Badges test-fixture retirement checkpoint: the remaining
`open_badges_tests.rs` crate-internal suite has been replaced by public signed
vectors in the KMS-only verifier conformance target. The 2018 and 2020
Ed25519 verification-method formats retain positive verification coverage;
missing document-store/method and unsigned legacy status-list negative cases
retain their assertions. The two added method vectors were minted once with
transient test keys and contain signed credentials and public verification
methods only. No issuer key generation or local signing remains in this Open
Badges test suite. The 12-test KMS-only target, 31 adjacent default-library
Open Badges tests, targeted Clippy, formatting, and diff checks passed. A
recursive audit found no private JWK members in the new vectors. Core branch
commit: `969ddc7`. This is verifier coverage, not live remote issuance of
linked-data proofs. Hosted CI and release artifacts remain pending.

2026-10-07 Rust feature-graph CI checkpoint: the existing Rust lint job now
resolves Cargo metadata once and applies both the MMF check and
`scripts/ci/check_marty_core_kms_boundary.py`. The new check requires all seven
Marty Core crates at reviewed revision `a5cb567e6cd50e5a85b3b125a0a2ab6eea1d9fb7`,
requires `kms-only` on crypto, DIDComm, OID4VCI and verification, rejects Core
`default`, `local-key-operations` and `test-fixtures`, pins `isomdl` to the
reviewed `784a5294` revision, and rejects its `default` or
`issuer-local-signing` features. The current locked workspace passed with
offline Cargo metadata. Nine focused guard tests passed, including negative
feature and dependency-pin cases. This gate catches feature resolution drift
in the UI workspace; it does not yet inspect compiled release binaries or the
Credentials wheel.

2026-10-07 Core remote holder-binding checkpoint: the ignored live Rust target
now makes distinct non-exportable ES256 OpenBao holder and issuer keys. The
production wallet prepares a proof JWT, the holder signs it through Transit,
and Core verifies its fresh nonce and signature before remotely signing a W3C
SD-JWT with only the holder's public JWK in `cnf`. A wrong nonce and a
tampered holder signature both fail while the issuer sign-call log is empty.
The assembled credential verifies with the remote issuer public JWK, retains
the selectively disclosed claim and public-only binding, and records exactly
one issuer sign call. Both live tests passed against a newly provisioned
disposable OpenBao 2.5.5; the container was removed. The exact KMS-only target
compiled with the wallet feature, targeted Clippy with `-D warnings`,
Rustfmt, shell syntax and diff checks passed. Core commit: `8f6706a`.
This covers the positive P-256 holder path but the old `scalar_sd_jwt_holder_binding`
and `issuer.rs` test-only private-key paths still carry other IETF, did:key,
non-SD-JWT and issuer engine assertions. Port those assertions through public
preparation and remote signing, then remove the local issuer and holder
fixtures. Hosted CI, PRs and exact release artifact qualification remain
pending.

2026-10-07 Core remote mDoc holder-binding checkpoint: the same disposable
OpenBao live target now takes the P-256 holder public JWK from the verified
wallet proof, prepares an mDoc with that exact device key, signs the COSE
Sig_structure through the non-exportable issuer key, and verifies the signed
IssuerSigned payload has the expected public-only `deviceKeyInfo.deviceKey`.
It also checks the remote sign bytes, returned signature and absence of extra
device key authorizations. Both live tests passed after this addition, the
disposable container was removed, and the exact target compiled and passed
targeted Clippy with `-D warnings`, Rustfmt and diff checks. Core commit:
`e0c7ab3`. The old `issuer.rs` mDoc fixture still has test-only private-key
branches and other protocol assertions to port or retire before deleting the
local issuer signing API. No hosted CI or PR was triggered for this checkpoint.
The next holder-proof gap is concrete: production
`WalletEngine::prepare_proof_jwt` accepts only P-256/ES256, while the old
scalar binding test covers Ed25519 `did:key` proof binding for IETF SD-JWT.
Extend the public-only prepared proof API to EdDSA with algorithm-bound
signature verification and a public-only Ed25519 `did:key` derivation, prove
it against a remote OpenBao holder key, then retire that local fixture.

2026-10-07 Core remote EdDSA holder proof and scalar fixture retirement:
`WalletEngine::prepare_proof_jwt` now accepts public-only P-256/ES256 and
Ed25519/EdDSA JWKs, returns the selected signing algorithm, and verifies an
exact 64-byte raw remote signature against that public key before assembling
the proof. Its public-only Ed25519 `did:key` derivation uses the existing
base58btc encoder shared with proof tests; private JWK members, wrong
algorithm metadata and malformed public encodings fail. A disposable OpenBao
test created a non-exportable Ed25519 holder key and a separate non-exportable
P-256 issuer key. It verified self-certifying `did:key` identity, wrong nonce,
wrong identity, invalid signatures, public-only `cnf`, and issuer signing of
the IETF SD-JWT only after valid proof. All three live tests passed. A
wallet-only KMS build passed, the KMS-only issuer/wallet library suite passed
(323 passed, one ignored), and targeted Clippy with `-D warnings` passed.
Core commit: `75f516e`.

The old 327-line `scalar_sd_jwt_holder_binding.rs` local issuer/holder
private-key suite and its crate import are now removed. The remote live target
adds explicit unbound JWT-VC/SD-JWT `cnf` absence checks, retaining the old
non-SD-JWT/direct-issuance distinction through production remote signing.
After deletion, the KMS-only issuer/wallet library suite passed (319 passed,
one ignored), all three disposable OpenBao live tests passed again, and
targeted Clippy, Rustfmt and diff checks passed. The test container was
removed. Core commit: `67d703d`. Other test-only local issuer methods and
fixtures in `issuer.rs`, `types.rs` and `holder_key.rs` still need retirement;
no hosted CI or PR was triggered for this checkpoint.

2026-10-07 Core mDoc x5chain remote conformance: the former crate-imported
`mdoc_x5chain_conformance.rs` fixture generated a private P-256 issuer key to
assert x5chain wire placement. Those assertions now run inside the disposable
OpenBao live issuer target: a non-exportable ES256 Transit key signs the mDoc,
and the test checks certificate chain bytes in the unprotected COSE header,
ES256 only in the protected header, no x5chain in issued namespace items, and
no value digest for x5chain metadata. All three live tests passed against a
fresh disposable OpenBao 2.5.5 and the container was removed. The old local
issuer fixture and its crate import were deleted. The KMS-only issuer/wallet
library suite passed after deletion (318 passed, one ignored); targeted Clippy
with `-D warnings`, Rustfmt and diff checks passed. Core commit: `ab376b1`.
Other crate-internal `IssuerKey` signing paths remain and need the same
assertion-preserving retirement before Core is PR-ready. No hosted CI or PR
was triggered for this checkpoint.

2026-10-07 Core issuer engine local-path retirement: the `IssuanceEngine`
test-only `issue_credential` / `issue_credential_in_format` methods and the
standalone private-JWK `create_verifiable_credential`, key-generation and
algorithm-detection helpers are removed. `IssuerConfig` no longer gains a
private `IssuerKey` field under `cfg(test)`, so its stateless protocol tests
use the same key-free configuration shape as production. The redundant
test-only `formats::sign_credential` dispatcher and now-dead local mDoc
holder-key helper were removed. Offer, token, authorization, PKCE and metadata
tests remain; mDoc metadata's ES256 holder-proof constraint remains in a
key-free test. Positive JWT-VC, SD-JWT, mDoc, holder binding, proof failures,
remote signer metadata mismatches and x5chain assertions are covered by the
existing KMS-only boundary and disposable OpenBao targets described above.
The KMS-only issuer/wallet library suite passed (309 passed, one ignored),
the six-test public-only remote issuer metadata boundary passed, and a
`marty-bindings` KMS-only production build passed with the revised config.
Targeted Clippy with `-D warnings`, Rustfmt and diff checks passed. Core
commit: `4e7b774`. This removes the issuer engine's local test signing path,
but other crate-internal `IssuerKey` format and wallet fixtures still remain.
No hosted CI or PR was triggered for this checkpoint.

2026-10-07 Core VDS-NC and ZK mDoc duplicate local-path reduction: the unused
test-only `sign_vds_nc(IssuerKey, ...)` wrapper and prepared-envelope
reconstruction helper are removed; the 18 focused VDS-NC tests passed under
KMS-only features. The duplicate `sign_zk_mdoc(IssuerKey, ...)` path and its
private-key fixture tests are removed; predicate rejection tests now invoke
the shared pure validator, and the remaining signer-contract tests use only
`sign_zk_mdoc_with_signer`. Five focused ZK mDoc tests and targeted Clippy
with `-D warnings` passed using `USE_ZK_MOCK=1` in a debug build. Rustfmt and
diff checks passed. Core commit: `3cb22d5`. A real Longfellow build on this
Windows host failed before Rust tests because the native compiler could not
find `openssl/sha.h`; this mock-mode result does not qualify real ZK or remote
KMS custody. The remaining `TestP256Signer` in the ZK signer-contract tests
still generates a local private key and needs a live remote replacement on a
host with the real Longfellow dependencies. No hosted CI or PR was triggered
for this checkpoint.

2026-10-07 Core ZK mDoc remote signer checkpoint: the remaining
`TestP256Signer` in `formats/zk_mdoc.rs` and its locally generated private JWK
are removed. Unit tests now exercise the shared predicate validator with
public/key-free inputs. An opt-in ZK-feature case in the disposable OpenBao
target signs a ZK-enabled mDoc with a non-exportable ES256 Transit key and
checks the predicate binding, proof-type metadata, issued boolean claim,
credential ID, exact remote signing bytes and returned COSE signature. All
four live cases passed with real OpenBao on this Windows host; the local ZK
native dependency was compiled in debug mock mode only, so this proves remote
issuer custody and ZK envelope wiring, not real Longfellow behavior. Four
focused key-free ZK validator tests passed, as did targeted Clippy with
`-D warnings` for the ZK and base feature sets, Rustfmt, shell syntax, CI
YAML parsing and diff checks. The disposable container was removed. The
existing Linux `zkp-native-security` job now runs the same live test with
`zk_mdoc` enabled after installing native OpenSSL dependencies, without mock
mode; its hosted result remains pending. Core commit: `7f0cf8c`. No PR or
hosted CI run was triggered at this checkpoint.
The live target now also checks that the issuer-signed `age_over_18` item is
the CBOR boolean `true`, rather than merely checking its name. All four live
cases passed again against a fresh disposable OpenBao and Rustfmt/diff checks
passed; the container was removed. Core follow-up commit: `078800a`.
Core remote SD-JWT coverage now checks the `vc+sd-jwt` header, selective
presentation of one of two disclosures, rejection of an unknown disclosure,
and signing an IETF numeric expiration beyond the VCDM calendar range with a
non-exportable ES256 key. The three live tests passed against a fresh marked
loopback OpenBao; Rustfmt and diff checks passed, and the container was
removed. Core commit: `9b03621`. The attempted local `IssuerKey` fixture
removal was reverted after the wallet verified-presentation test dependency
surfaced. That wallet suite is the next assertion-preserving migration in the
same Core feature PR. No hosted CI or PR was triggered for this checkpoint.
The first wallet verified-presentation replacement now generates separate
non-exportable issuer and holder P-256 keys in disposable OpenBao. Issuance,
public-only issuer resolution, wallet preparation, holder signing of the exact
prepared input, completion and audience/nonce verification all passed. The
same live case rejects a tampered issuer signature, an unrelated holder public
key and an unrelated holder signature without a Rust private-key fixture.
All four live Core test cases passed after this addition; targeted Clippy with
warnings denied, Rustfmt and diff checks passed. The disposable provider was
removed. Core commit: `12fa539`. The old wallet suite still contains local
private-key fixtures for additional mutations and boundary assertions; keep
migrating those before deleting the test-only local signer helper. Hosted CI
and the grouped Core PR remain pending.
2026-10-07 Core SD-JWT/wallet fixture retirement: the wallet verification
suite now reads an issuer-signed public SD-JWT vector generated by the marked
disposable OpenBao test; it contains issuer and holder public JWKs only. Its
13 fast negative/preparation tests pass without local key generation. The
live remote test preserves positive presentation, issuer tampering, wrong
holder key/signature, transitional protected type, signed private `cnf`
rejection and absent/malformed `kid` assertions. The test-only wallet private
signing API and SD-JWT `IssuerKey` format wrappers/fixture are removed; the
remaining format preparation tests use public-only signer metadata. The
KMS-only Core library suite passed 297 tests with one opt-in ignored, the
default library suite passed 269 with one opt-in ignored, and all four live
cases passed against a fresh OpenBao. Targeted Clippy with `-D warnings`,
Rustfmt, public-vector JSON validation and diff checks passed. The disposable
provider was removed. Core commit: `afd69ae`. Other Core format/batch
private-key fixtures remain; this is not Core PR readiness or hosted CI.
2026-10-07 Core mixed-batch remote checkpoint: the public ES256 batch API
issued JWT-VC, proof-bound SD-JWT and mDoc in caller order through a single
non-exportable OpenBao issuer key. The live test binds all three exact signer
inputs and returned raw signatures to assembled credentials, uses a separate
provider-generated holder public key without invoking its signer, and rejects
a duplicate route before an additional provider call. The signing-batch input
tests no longer create private holder keys merely to obtain public JWKs;
synthetic private members still exercise fail-closed rejection. All five live
Core cases passed against fresh marked OpenBao, the KMS-only library suite
passed 297 tests with one opt-in ignored, and targeted Clippy with warnings
denied, Rustfmt and diff checks passed. The container was removed. Core
commit: `9498920`. The broader test-only batch signers and mDoc local issuer
path still require assertion-preserving retirement. No hosted CI or PR yet.
2026-10-07 Core mDoc local-signer retirement: deleted the test-only
`sign_mdoc(IssuerKey, ...)` path, its private JWK COSE signer, and local issuer
fixture. Kept deterministic MSO/Sig_structure bytes, public holder device-key
validation, validity/error precedence, digest planning and batch preparation
in public-only unit tests. The disposable OpenBao acceptance suite now checks
the signed mDoc `issuerAuth` array without an outer COSE tag, the tag-24 MSO,
and every valueDigest against the complete tagged issuer item (rejecting the
inner-item digest), including the x5chain case. The KMS-only library suite
passed 293 tests with one opt-in ignored, the default library suite passed
265 with one opt-in ignored, and all five live OpenBao cases passed. Targeted
Clippy with warnings denied, Rustfmt and diff checks passed; the disposable
provider was removed. Core commit: `d0c97f9`. Broader batch fixture signers
remain. This does not qualify hosted CI, exact artifacts or the Core PR.
2026-10-07 Core high-S batch fixture retirement: the test-only P-256 high-S
signing key and both serial/concurrent local-signing tests are removed. A live
OpenBao wrapper receives genuine remote ES256 signatures and changes only the
public `s` representation to a valid high-S P1363 signature; it retains no
private key. The serial and concurrent batch executors both preserve those
exact bytes across JWT-VC, SD-JWT and mDoc. The wrapper serializes access to
its test client while exercising the concurrent batch assembly path; it does
not claim backend request overlap. All six live OpenBao cases passed, the
KMS-only library suite passed 291 tests with one opt-in ignored, and the
default library suite passed 263 with one opt-in ignored. Targeted Clippy with
warnings denied, Rustfmt and diff checks passed; the disposable provider was
removed. Core commit: `cb6a9e2`. Recording and concurrency scheduler
fixtures still sign locally in Core tests; their assertion-preserving
migration remains in the same grouped Core feature PR. Hosted CI is pending.
2026-10-07 Core batch pre-sign fixture separation: eight batch tests that
reject an invalid scope, duplicate route, invalid preparation, metadata
drift, empty batch or batch-wide executor error now use public ES256 metadata
and a signer that panics if called. This removes private-key custody from
those paths and strengthens their no-sign boundary; the old recording signer
now serves only tests that actually reach signature execution. All 25
signing-batch unit tests passed in the KMS-only feature set, the full KMS-only
library suite passed 291 tests with one opt-in ignored before the final
fixture simplification, and targeted Clippy with warnings denied, Rustfmt and
diff checks passed after it. Core commit: `53a83dc`. This is a local batch
within the still-unopened Core feature PR; result-envelope, assembly and
concurrency scheduler fixtures still need remote/public-only migration.
2026-10-07 Core batch envelope boundary: the eight result-envelope fault
cases now feed synthetic signature results into the private executor seam and
use the public-only panic-on-sign metadata fixture. Missing, duplicate,
unexpected, wrong-scope/batch/route and combined identity/signature/backend
faults must fail envelope validation before signature validation or a signer
call. All 25 signing-batch unit tests passed in the KMS-only feature set;
targeted Clippy with warnings denied, Rustfmt and diff checks passed. Core
commit: `457237e`. Reordered valid results, cryptographic signature faults,
assembly failures and scheduler behavior still use local signing fixtures
pending live remote replacements. No hosted CI or PR was triggered.
2026-10-07 Core batch backend/panic fixture retirement: the serial backend
failure test now simulates one accepted KMS call followed by a redacted backend
error using public metadata and synthetic pre-validation bytes. It still checks
the failing ordinal, exactly two calls with no retry, no partial output, and
secret redaction. Concurrent caller/spawned-worker panic tests likewise use
public metadata and synthetic peer results; they still assert panic payload,
worker joining, completed peer, active/peak calls and no duplicate jobs.
Neither fixture constructs or stores a private key. All 25 batch tests passed
in the KMS-only feature set; targeted Clippy with warnings denied, Rustfmt and
diff checks passed. Recording, signature-validation, assembly and concurrency
scheduler tests still have local test signing and require separate replacement.
This is local progress within the grouped Core feature branch, not live KMS
custody or hosted CI evidence. Core commit: `bc4efc8`.
2026-10-07 Core first-signature fault fixture retirement: wrong-length and
wrong-encoding faults at ordinal zero now receive synthetic executor bytes and
the public-only panic-on-sign signer. This verifies first-item ES256 rejection
without constructing a local signing key, while the envelope fault cases
continue to reject before cryptographic validation. The later SD-JWT and
multiple-invalid-signature cases still require valid preceding signatures and
remain on the local recording fixture pending live remote replacement. All 25
batch tests, targeted Clippy with warnings denied, Rustfmt and diff checks
passed. Core commit: `53660cd`; no hosted CI or PR was triggered.

2026-10-07 Core verifier-only test-custody checkpoint: the 13-test
`marty-crypto/tests/verification_only.rs` suite no longer constructs local
P-256, P-384, P-521 or Ed25519 signing keys. A public-only fixture now holds
SEC1/SPKI encodings and signed fixed-message vectors, preserving positive
verification plus wrong-key, tamper, cross-curve and malformed-SPKI cases.
The minimal `signature-verification` feature test passed all 13 cases, as did
targeted Clippy with warnings denied and Rustfmt. Core commit: `eea6e39`.
This does not retire local test signers in other Core modules or qualify the
Core feature PR.

2026-10-07 Core browser-verifier test-custody checkpoint: the wasm shared
verification-provider test no longer creates P-384 or Ed25519 signing keys.
Its fixed public JWKs and signatures retain both positive browser checks;
the RSA-PSS rejection test is unchanged. The actual
`wasm32-unknown-unknown` target ran through `wasm-bindgen-test-runner` with
two passes, and targeted wasm Clippy passed with warnings denied. Core commit:
`36a5386`. Other Core local-signing test fixtures still remain in the broad
feature branch.

The remaining `marty-oid4vci` batch tests require actual signatures on fresh
prepared payloads. Two runs of its recording signer produced 15 signatures
each with zero matching message hashes; assembly verifies signatures against
those fresh messages, so frozen signatures or a synthetic signer would weaken
the positive tests. Temporary tracing and synthetic edits were removed.

2026-10-07 Core batch recording-fixture migration: the local P-256
`RecordingSigner` has been removed. Five positive/order/fault/assembly tests
now use a test-only scoped OpenBao Transit signer and run in the required
disposable live-KMS CI lane. The test creates a non-exportable, no-backup ES256
key, verifies root and scoped export denial, and gives the signing client only
an exact-path sign policy. A new test independently verifies fresh JWT-VC,
SD-JWT and mDoc signatures against the remote public JWK and checks the raw
bytes and caller order. The marked local live lane passed all five migrated
batch tests and six existing issuer integration tests. The fast batch lane
passed 22 tests with five intentionally ignored for that live lane; targeted
Clippy with warnings denied, Rustfmt, Bash syntax and diff whitespace passed.
Core commit: `43ce153`. This does not establish hosted CI or Core PR
readiness. Next migrate `ConcurrentTestSigner` and other local
batch signing fixtures while preserving randomized ordering and scheduler
assertions; keep all fixes in the single broad Core feature PR. Qualify its
final head once, then pin it for the broad UI feature PR.

2026-10-07 Core concurrent-batch fixture migration: `ConcurrentTestSigner`
now uses the same marked disposable OpenBao test backend and holds no local
P-256 private key. Eight scheduler/differential/failure tests moved to the
required live lane, preserving batch sizes through 256, serial/concurrent
semantic comparison, independently verified signatures, overlap and worker
limits, failure ordering, metadata drift and no-partial-output checks. The
fixed-source SD-JWT byte comparison caches the first *remote* signature for
each identical message solely within that test, because OpenBao ECDSA may
produce different valid signatures across calls; all first-use signatures
still come from the non-exportable remote key and verify against its public
JWK. There is no signing-key construction or local signing operation left in
`marty-oid4vci/src/signing_batch.rs` tests. The complete marked local live
lane passed all 13 batch tests and six issuer integration tests. The full
KMS-only issuer library run passed 280 active tests with 14 ignored (13 batch
cases covered by this live lane); targeted Clippy with warnings denied and
Rustfmt passed.
Other Core test modules and the Core feature PR/release graph remain to be
reviewed; these are local results, not hosted CI or final artifact proof.
Core commit: `6b8d16a`.

2026-10-07 Core VDS-NC ES256 fixture migration: seven format tests that
prepare/sign/assemble VDS-NC or reject invalid country, malformed signatures,
wrong payloads and wrong keys now use non-exportable scoped OpenBao ES256 keys
in the same required live runner. The DER normalization test consumes the
provider's actual DER output and independently verifies the assembled raw
signature against its public key. The remaining five VDS-NC tests run in the
fast lane; its diagnostic fixture now derives only the public P-256 generator
point. The remote-credential test likewise derives only the P-384 public
generator point instead of constructing a private scalar. The local marked
live runner passed 13 batch, seven VDS-NC and six issuer integration tests;
the 22 remote-credential tests and five fast VDS-NC tests passed. Targeted
Clippy with warnings denied, Rustfmt, Bash syntax and whitespace checks
passed before the final public-point edit, with the focused VDS-NC tests
rerun afterward. P-384, Ed25519 and RSA VDS-NC signing tests still use local
private fixtures; migrate them with real provider capabilities in this same
Core feature PR. Core commit: `1ad6ffb`. No hosted CI or release-artifact
proof is claimed.

2026-10-07 Core VDS-NC remaining algorithms: the P-384, Ed25519 and
RSA-PSS signing tests now use non-exportable scoped keys on the marked
disposable OpenBao runner; no local private-key construction or signing
remains in `marty-oid4vci/src/formats/vds_nc.rs` tests. The shared test
provider lives once at the crate root and supplies ES256, ES384, Ed25519
and RSA-2048, avoiding duplicate unit-test harnesses. Live tests passed all
13 batch cases, all ten VDS-NC cases and six issuer integration cases.
The complete KMS-only issuer library run passed 270 active cases with 24
ignored (the 23 batch/VDS-NC live cases are covered by this runner).
Targeted Clippy with warnings denied, Rustfmt and whitespace checks passed.
The RSA test first exposed that OpenBao's default PSS salt is too long for
JOSE PS256. Setting `salt_length=hash` in the remote sign request passed
PS256, PS384 and PS512 signature verification. The UI Signing Keys
production OpenBao adapter currently omits that setting; correct it and
add a live contract test in the broad UI feature PR before claiming RSA-PSS
issuance compatibility. OpenBao documents the default `auto` and the `hash`
option at https://openbao.org/docs/next/api/secret/transit/ . Core commit:
`174bcf4`. No hosted CI or release-artifact proof is claimed.

2026-10-07 UI Signing Keys RSA profile correction: the production OpenBao
adapter now explicitly requests PKCS#1 v1.5 for RS256/384/512 and PSS with
`salt_length=hash` for PS256/384/512. This avoids Transit defaults silently
returning a signature incompatible with the requested JOSE algorithm. Golden
HTTP request vectors for RS256 and PS256 passed. A new disposable live test
created a managed, non-exportable RSA-2048 key under the scoped signing policy,
signed an RS256 payload through the Rust adapter, and independently verified
the returned signature against the key's public JWK. The full policy harness
including existing managed-key, tenant and profile cases passed after its
marker read used the disposable root guard token while signing remained on
the scoped managed token. All five golden-vector tests, 132 active Signing
Keys library tests (seven ignored), package Clippy with warnings denied,
Rustfmt, Ruff and scoped whitespace checks passed locally. This work remains
in the broad dirty UI feature worktree, without hosted CI or exact-image proof.
The managed key-creation and public-route surfaces currently advertise RS256
for RSA, not PS algorithms; the Core live VDS-NC proof plus adapter vector
do not establish a managed PS issuance route.

2026-10-07 Signing Keys encoding-contract self-review: RSA signatures from
OpenBao are raw bytes, so the production sign response now labels RS/PS
signatures `raw`; EC responses retain `der`. Every CSR/certificate consumer
checks for an EC algorithm or curve before requiring DER, so the RSA label
correction does not change those flows. The six static provider capabilities
now say `algorithm-dependent` because they advertise both EC and RSA/Ed
algorithms; the actual sign response specifies the encoding for its chosen
algorithm. Catalog, registry and signing golden vectors were updated together.
Local Signing Keys checks passed: 132 active library tests, 13 HTTP golden
tests, five provider golden tests, four registry golden tests; the Redis
storage contract is ignored without a disposable Redis URL. The scoped
OpenBao live policy probe, including managed RS256 verification, passed before
this static catalog correction. Keep this correction in the single broad UI
feature PR and requalify the final PR head before hosted CI.

2026-10-07 Core OID4VP conformance test-custody checkpoint: the verifier
conformance suite no longer constructs a deterministic Ed25519 private key
to sign fresh VP JWTs. Its 13 positive and negative signed-token cases use
the shared test-only scoped OpenBao Transit signer with a generated
non-exportable Ed25519 key and public JWK. The static pre-signed corpus token
remains a verification input; no private signing seed is embedded in this
test file. The disposable Core live-KMS runner now executes these cases in
the same OpenBao process as the issuer/batch tests, excluding only the two
pre-existing unimplemented SIOPv2 stubs. Local runner results: 13 batch, ten
VDS-NC, six issuer and 13 OID4VP live cases passed; 30 ordinary OID4VP
cases passed with 15 ignored outside the disposable runner (13 live plus
two SIOPv2 stubs); the verifier-only feature target independently passed the
same 30 ordinary cases. Targeted Clippy with warnings denied and Rustfmt passed.
The VP conformance checks verify signatures and protocol fields; they do
not by themselves prove DID-to-key authorization or release-image behavior.
Keep this fixture migration in the single broad Core feature PR and review
the remaining Core local-key tests before that PR is ready. Core commit:
`b185925`. No hosted CI or release-artifact qualification has run for this
revision.

2026-10-07 Core JOSE/OIDC/SIOP test-custody checkpoint: five OIDC ID-token,
four JOSE verification and two SIOPv2 thumbprint tests now sign with the
same disposable OpenBao fixture's scoped, non-exportable P-256 key. The
test-only `sign_test_compact_es256` helper accepts that remote signer and
does not reconstruct a P-256 secret. The JOSE private-JWK and algorithm
rejection test now uses the exact token matching its public JWK, and flips
a decoded signature byte for tamper testing. The marked live runner passed
all 11 new cases plus its 13 batch, ten VDS-NC, six issuer and 13 OID4VP
cases. The ordinary KMS-only library run passed 259 tests with 35 ignored;
the 11 live cases are exercised by the runner. Targeted Clippy with warnings
denied, Rustfmt, shell syntax and whitespace checks passed. Core commit:
`4e70788`. No hosted CI or release-artifact qualification has run for this
revision. Review of `marty-oid4vci/src/lib.rs` and `wallet.rs` confirmed
the old private-holder-key generation and signing methods are `cfg(test)`;
they still need test-custody retirement, but this review did not find them
exposed in a release build.

2026-10-07 Core wallet holder-fixture retirement: the two local P-256
proof tests now create non-exportable holder keys in disposable OpenBao,
derive the holder DID from the KMS public key, and call the production
public-only `prepare_proof_jwt`/signature-completion path. The wrong-key,
oversized-public-input and synthetic private-JWK rejection assertions remain.
The test-only `HolderKeyMaterial`, local proof signer, private JWK parser/
generator module and its exports are removed. The old test-only SD-JWT
presentation helper that signed a private JWK without verifying the issuer
is also removed. Its positive nonce, audience and `sd_hash` assertions now
run in the existing live remote issuer/holder presentation test, which
already checks issuer tampering and holder-key mismatch through the verified
production preparation API. The final local disposable runner passed the
two wallet proof tests, six issuer tests, 13 batch tests, ten VDS-NC tests,
11 JOSE/OIDC/SIOP tests and 13 OID4VP tests. The ordinary KMS-only library
run passed 252 tests with 37 ignored; all newly ignored signing tests ran in
the live runner. All-targets Clippy with warnings denied, Rustfmt and
whitespace checks passed. Core commit: `180ac7a`. This remains in the
single Core feature PR; hosted CI and exact release-artifact evidence are
pending.

2026-10-07 Core obsolete issuer fixture-path retirement: source audit found
that the `cfg(test)` `IssuerKey` signer implementation was no longer used to
issue credentials; only its self-referential diagnostic test constructed it.
Removed `IssuerKey`, its private-JWK signing/extraction/algorithm helpers,
and the direct `ssi-crypto` dev dependency. Retained the independent
authorization-session overflow test; existing remote signer and signing-batch
diagnostic tests continue to cover redaction, and the compile-fail doctest
still proves the local issuer API is absent to external consumers. The
KMS-only library run passed 251 active tests with 37 ignored, all-targets
Clippy passed with warnings denied, and ten compile-fail doctests passed
(three unrelated examples remain ignored). Cargo.lock changed only for the
removed direct dependency and feature-unification edge. Core commit:
`6274efe`. This does not retire the remaining fixed-key and proof test
fixtures, qualify hosted CI, or prove final release artifacts.

2026-10-07 Core RSA test-key retirement: removed the embedded RSA private PEM
from the remote-signature binding tests and the now-unused direct
`aws-lc-rs` dev dependency. The shared disposable OpenBao test signer now
supports explicit PKCS#1 v1.5 SHA-256 signing alongside its PSS path; it
generates non-exportable RSA-2048 keys, confirms export denial, and signs
under a sign-only scoped token. The RS256 live test preserves valid-signature,
payload-substitution and wrong-public-key assertions with two KMS keys.
The ordinary KMS-only library run passed 251 active tests with 38 ignored;
the new ignored RS256 case passed in the marked disposable live runner along
with 13 batch, ten VDS-NC, 11 JOSE/OIDC/SIOP, two wallet, six issuer and 13
OID4VP cases. All-targets Clippy with warnings denied, Rustfmt, shell syntax
and whitespace checks passed. Core commit: `09fd1f7`. Fixed local EC/Ed
signer fixtures and broader release qualification remain pending in the
same grouped feature PR.

2026-10-08 Core remote-signature binding fixture retirement: the ES256,
ES384 and EdDSA payload/public-key substitution cases now sign with
disposable non-exportable OpenBao keys under scoped policies. The shared
test fixture normalizes OpenBao's P-384 DER output to raw JOSE bytes before
verification. ES256K still has no signer in this Transit setup, so its
positive and two substitution checks use a checked-in public JWK/signature
vector generated once without retaining the private key; the unit test no
longer constructs or stores a secp256k1 signing key. All three new live
binding cases passed in the marked OpenBao runner, along with its existing
batch, VDS-NC, JOSE/OIDC/SIOP, wallet, RSA, issuer and OID4VP cases. The
ordinary KMS-only library run passed 250 active tests with 40 ignored;
all-targets Clippy with warnings denied, Rustfmt and whitespace checks
passed. Core commit: `0e98746`. This is verifier coverage for ES256K,
not proof of remote ES256K custody or extension capability. More Core local
signing fixtures and final PR/release qualification remain.

2026-10-07 production verifier artifact reconciliation: inspected the current
shipping Rust gate, its build/copy instructions and the preserved integration
branch rather than relying on the earlier pre-hardening inventory. The gate
contains only bounded public-input parsing, canonical verification and policy
assertions; its tests reject private JWK members. Base integration still calls
it without input, while the preserved acceptance branch has a SHA-256-pinned
Core producer, authenticated issuer/holder signer-agent IPC and stdin wiring.
The signer agents use a generic HTTPS signing endpoint; the actual separately
scoped KMS backend, positive producer output and exact-image verification have
not yet been exercised together. Next qualify that chain with real remote keys,
then bring the integration acceptance PR and release pin forward. Do not delete
the shipping verifier gate or claim its source-only review proves artifact
acceptance. The current candidate passed `cargo +1.95.0 test --locked -p
marty-presentation-policy --bin marty-verifier-positive-gate --quiet` (2 tests)
in the UI Rust workspace. Those cases prove public input parsing and rejection
of an unsigned presentation, not a positive image or KMS flow.
2026-10-07 local live positive verifier chain: Core's test signer agent now
supports an explicit OpenBao Transit mode over verified HTTPS, with a scoped
token, exact sign route, SHA-256 prehash and canonical DER-to-raw ES256
normalization. The original producer failed before signing because it supplied
the bare issuer DID as `verification_method_id`; Core correctly requires a
fragment key under that DID. The producer, issuer public JWK and UI gate now
use `did:example:verifier-runtime-gate-issuer#key-1`, while the credential's
issuer identity remains the bare DID. Core commit: `8bd3f08`.

A disposable TLS OpenBao 2.5.5 container at image digest
`sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452`
generated two separate ECDSA P-256 Transit keys. Metadata showed
`exportable=false` and `allow_plaintext_backup=false` for both. Separate
sign-only policies and ten-minute tokens denied both cross-key sign attempts
with HTTP 403. Two authenticated local Rust signer agents served the issuer
and holder; the Core producer used remote issuance and wallet presentation
APIs to emit fresh public-only input. The candidate UI verifier binary
returned `passed/PASS` with all eight checks; changing the issuer signature
caused rejection. The preserved integration branch's digest-pinned
`positive_oid4vp_public_input()` accepted a second fresh producer result.
Core's three focused agent/producer tests and Clippy with warnings denied
passed; UI gate's two tests, targeted Rustfmt and diff checks passed. The
disposable server, agent processes, scoped tokens and temporary fixtures were
removed after the run. This is strong local remote-KMS/wallet/verifier evidence
against the candidate binaries, but it is not an exact packaged-image,
published Core producer or release-pin qualification. The integration runner
still needs the grouped acceptance PR and exact-image execution. This was the
candidate-binary checkpoint; the subsequent local image run is below.
2026-10-07 local packaged verifier artifact checkpoint: the actual
`services/Dockerfile` shared image built from the current dirty UI feature
worktree using the locked release profile and all 24 shipping Rust binaries.
Its local image ID was
`sha256:8ebd21aa05108295db2cc171273f6a8ca2a8cff6b4f5d95fc7637eab6b58c99e`,
tagged `local/marty-ui-services:kms-candidate-20261007` with revision label
`local-dirty-kms-20261007`; the locked Core dependency resolved to published
`a5cb567e6cd50e5a85b3b125a0a2ab6eea1d9fb7`. The preserved integration
branch at `a3e0646` ran its SHA-256-pinned Core producer and `docker run -i`
against `/usr/local/bin/marty-verifier-positive-gate` in this image. A fresh
two-key TLS OpenBao Transit presentation returned `passed/PASS` and all eight
checks. The packaged binary rejected an altered issuer signature and a
private `d` member in the public issuer JWK. Separate sign-only issuer and
holder tokens were each denied with HTTP 403 on the other's route; key
metadata showed non-exportable, no plaintext backup. Empty stdin also failed.
The disposable OpenBao server, agents, scoped tokens and temporary inputs
were removed. This now proves the local shared-image path for that verifier
gate. It does not qualify a committed/published release digest, other service
routes, hosted CI, the full acceptance transaction or rollback. The image was
built before the following `.dockerignore` edit; that edit excludes
`docker/secrets/` from subsequent local build contexts because no Dockerfile
COPY/ADD consumes it. A cached rebuild after that edit produced local image
ID `sha256:c542cbb06b6ea72bb7180baf2a70ace4195b7ea7c10298f857033fdf8e11c903`
with the same runtime manifest
`sha256:5aefd4e33ec670b11eaf85f81a969463a7ea2655a7501e0d8d5481899df400b9`
and config `sha256:a52b7b535a2e2dc9b12078a6fdda2bcf7404db344035c89f257da482940c3375`;
its manifest-list ID changed with the context attestation. Full feature-diff
review and release qualification remain.

2026-10-07 grouped UI feature CI repair: the broad source review found three
CI-invoked packaged-image checks still requiring the retired
`INTEGRATION_SECRET_MASTER_KEY`. This would reject the new native startup before
CI could qualify the feature PR. The candidate now runs the Issuance image
smoke and 16 Canvas worker published-schema startup cases through a separate,
disposable no-key HTTP secret service. It enforces authenticated, identity-bound
encrypt/decrypt round trips for these packaging checks; the live OpenBao Transit
probe, not this synthetic service, qualifies cryptographic custody. Nine
packaged entrypoint cases now assert raw master-key rejection and supported API
key file preflight. The CI render fixture no longer supplies the retired key.
Local shared-image evidence: 9/9 entrypoint cases, 16/16 startup cases,
Issuance image smoke, and 33 focused Python fixture tests passed. This work
stays in the single broad UI hardening feature PR with the pending service,
deployment, and contract diff; do not open a narrow smoke-only PR or trigger
hosted CI for each correction. The packaged image is still a local dirty
candidate and hosted CI/release qualification remain pending.

2026-10-07 wider CI contract reconciliation: the Canvas runtime-selection test
still demanded a removed `integration_master_key` reader; it now checks the
forbidden legacy setting and supported API-key readers. The base native Compose
comparison explicitly accounts for the direct Signing Keys URL on the old
service versus the gateway route on the native profile, while retaining an
exhaustive field comparison across 12 rendered models. The self-host frozen
model comparison recognizes the dedicated Signing Keys OpenBao token as a
deliberate custody change and continues to reject any other unowned model
drift; default, empty, and custom interpolation plus ten required-input checks
passed. The focused 388-test Python configuration/security matrix, Ruff, and
diff checks passed. These repairs remain within the broad UI feature PR and
do not constitute release or hosted CI qualification.

2026-10-07 pre-PR local matrix continuation: `cargo +1.95.0 check --locked
--workspace -j 1` passed against the broad dirty UI source and reviewed Core
pin. The current Go DIDComm plugin image rebuilt from source; its Docker build
includes `go test ./...` and `go vet ./...` and reused the matching local build
cache. The base native Compose mutation fixture was missing the synthetic
OpenBao/plugin image now required by authcrypt; the self-host mutation fixture
was missing the dedicated Signing Keys token. Both fixtures now exercise their
negative assertions again, including wrong token file, binding and mount:
132 combined base/self-host tests passed. A further 182 targeted Python tests
and 188 subtests passed. The changed UI tests passed 16/16, ESLint reported zero
errors (166 pre-existing/general warnings), and the TypeScript/Vite bundle built
with `DISABLE_PRERENDER=1`. The normal local prerender failed only because the
pinned Puppeteer Chrome binary is absent from this Windows host; it still needs
the standard release build in CI. The full Rust `--workspace --no-run` test
target build is running; do not claim it passed until its process exits zero.

2026-10-07 local matrix result and renewal blocker: the complete UI Rust
workspace `cargo +1.95.0 test --locked --workspace --no-run -j 1` passed, then
an incremental final-source rerun passed after one Signing Keys test formatting
fix. Package-level Rustfmt checks passed for the changed service and acceptance
crates. The locked Cargo metadata boundary check also passed. The broad Python
suite reached 693 passed and three skipped before
`test_six_renewal_profiles_retain_distinct_runtime_obligations` failed: its
guard correctly expects both anoncrypt and authcrypt in the fast renewal
matrix, but the current fast test handles anoncrypt only. Worse, the packaged
Canvas renewal fixture still writes `sender_x25519_private_key` into policy
JSON. This is the already identified K3 test-custody/feature gap, now confirmed
as a current regression gate. Do not weaken the guard or claim renewal
acceptance. Move the packaged renewal path to the scoped non-exportable
OpenBao sender reference, run both modes and private-IP outcomes with holder
decryption and send-fence assertions, then restore the guard and full suite.

2026-10-07 reused live-probe qualification: the existing disposable coordinated
PostgreSQL/OpenBao Raft recovery script now compiles and runs the Issuance Rust
`didcomm_remote_kms_live` target in its already booted Go-plugin OpenBao
instance. Its scoped token test generated a non-exportable X25519 sender key,
packed authcrypt, and independently decrypted at the holder after rotation.
The complete combined local probe exited zero, including four remote format
tests, three readiness tests, holder proof, three Flow HAIP routes, the Go
integration test, and integration-secret write/restore/read phases. The
disposable resources were cleaned. This is local real-KMS evidence with no new
hosted CI lane; it does not yet cover positive renewal or a release image.
The broad Python suite also found a stale Kubernetes worker assertion that
still required `INTEGRATION_SECRET_MASTER_KEY`; it now rejects that deployment
binding while preserving the supported secret map. Its 12 focused tests pass.
The next full sweep requires the checked-out `Marty/packages/marty-common` on
this Windows host, while CI installs its pinned wheel; this local dependency
was verified with the affected deployment test. The known positive renewal
failure remains excluded only during independent-failure discovery and is
still a required pre-PR gate.

2026-10-07 broad-batch continuation: the UI/native and integration acceptance
changes are one feature PR group; open a separate acceptance PR only for a
recorded dependency that prevents this. The Kubernetes image-update Bash
mutation fixture now runs under mandatory native issuance and preserves the
pre-write guard; all 45 focused tests pass. A Python sweep then reached 3,371
passes and five skips before exposing a stale self-hosted DIDComm ownership
contract. The production Compose model now explicitly requires healthy native
issuance and probes the retained consumer's `/ready` endpoint; the contract
selects it as native and declares no legacy Compose model. All 105 focused
ownership and self-hosted Compose tests pass. The wider suite is being rerun
for other independent failures. Positive renewal authcrypt, hosted CI, PRs
and exact release qualification remain pending.

The independent-failure sweep then reached 3,504 passes before finding a
stale feature-regression assertion that expected the retired Core
`authority-issuance` feature edge; its seven focused tests pass with the
current locked feature boundary. It reached 3,509 passes before the frozen
self-hosted model guard rejected the new `/ready` healthcheck; that exact
owned change is now checked and normalized for the frozen comparison, and
83 focused Flow/self-host tests pass. The remaining test-file suffix passed
with 1,659 tests, three skips and 188 subtests after updating the retired
Gateway vector count and production Flow/Passport native URL ownership
contracts. The route contract still asserts nine retained Python passport
routes and opt-in Passport activation. This is local, segmented suite
evidence; rerun the complete suite after positive renewal is implemented.

2026-10-07 K3 deployment-custody checkpoint: the packaged renewal acceptance
still contains `sender_x25519_private_key`, and neither the self-hosted nor
Kubernetes production native-Issuance model previously supplied `DIDCOMM_KMS_ADDR`
and `DIDCOMM_KMS_TOKEN_FILE`. The self-hosted Compose model now mounts a
dedicated `didcomm_issuance_openbao_token` only into native Issuance and
requires the external OpenBao address. The shared OpenBao bootstrap installs
one `didcomm-issuance` policy that can read public sender versions and update
the pack endpoint, with no create, rotate or HAIP permission; both local
Raft bootstrap and external bootstrap mint a no-default-policy token. The
production preflight requires its token file. An actual disposable OpenBao
capability check caught and corrected a nested wildcard error (`*` granted
no access; single-segment `+` grants the intended paths). The complete local
coordinated Rust/PostgreSQL/OpenBao recovery probe then passed, including
exact read/pack allow and create/rotate/HAIP deny capabilities, live sender
authcrypt with holder decryption, and restore. A second bootstrap in the same
disposable Raft instance preserved the exact scoped DIDComm token. Self-host model mutation tests
and related provisioning/startup checks passed (121 passed, one skipped).
This is only self-host wiring and local backend evidence. The base opt-in
authcrypt overlay already declares KMS settings, but its policy/token fixture
still needs real scoped provisioning and packaged renewal proof. Kubernetes
wiring and packaged positive renewal with remote key references,
hosted CI and exact artifact evidence remain required in the same broad UI
feature PR.

2026-10-07 K3 Kubernetes source-wiring checkpoint: the native-Issuance
template now binds `DIDCOMM_KMS_ADDR` to the existing `BAO_ADDR` config key
and mounts only `DIDCOMM_ISSUANCE_OPENBAO_TOKEN` as the token file. The
deployment script requires that separate catalog secret and publishes the
same key in `marty-secrets`; the reference Secret template includes a
placeholder for operators. The closed Rust renderer checks the exact env,
volume, mount and image-update model. Its source contract caught an unrelated
stale Signing Keys expectation for the already separate token and now checks
`SIGNING_KEYS_OPENBAO_TOKEN` explicitly. Local checks: 196 Python tests and
188 subtests passed; the Rust Kubernetes integration target passed 12 of 12
tests runnable on this Windows host. Its one actual CLI/envsubst test could
not start because the host lacks `envsubst`; it remains for the Linux CI run.
This source and renderer evidence is not a packaged process, live Kubernetes
or release proof. The positive renewal path still must provision a scoped
non-exportable sender and remove its private-key fixture.
The Canvas Kubernetes renewal target compiled on Windows but reported its
Linux-only qualification guard and executed no renderer process assertions;
do not count that local zero-work result as acceptance.

2026-10-07 K3 live-test ACL correction: the Rust disposable-backend test's
issuer token policy still used `*` for nested version paths. The self-host
capability probe had already shown that this pattern did not grant the intended
read/pack operations. The test policy now binds read and pack to the single
created version, and the test checks that the same token cannot read or pack a
newly rotated version. Two coordinated Rust/PostgreSQL/OpenBao runs exited
zero; the second included both rotated-version 403 assertions, authcrypt and
independent holder decryption, Flow HAIP cases, and integration-secret restore.
The disposable backend and database were cleaned by the probe. Rustfmt and
diff whitespace checks passed. Packaged Canvas
renewal remains separate: provision a sender key inside disposable plugin
OpenBao, expose only its public X25519 value through the DID document, place
the versioned reference in policy, pass a distinct scoped token file through
the actual Compose/Kubernetes process fixture, and prove both encryption modes
and private-address outcomes. The Canvas Linux runner must start that plugin
backend before the exact packaged-process acceptance; the current vanilla
OpenBao service cannot satisfy this acceptance.

2026-10-07 K3 packaged-renewal implementation checkpoint: the shared Canvas
fresh-renewal fixture no longer constructs or writes a sender X25519 private
key. For each case it creates the sender inside disposable plugin OpenBao,
publishes only the returned public X25519 value in the issuer DID document,
uses the exact versioned `sender_key_ref` in policy, and gives native Issuance
only an owned token file with read on that version and update on its pack path.
The actual Compose renderer now overlays the owned KMS address and token path
after checking the source profile's `openbao:8200` and read-only token mount;
the Kubernetes resolver checks its template's `BAO_ADDR` and mounted token
path before replacing them with the test-owned loopback endpoint/file. The
Canvas CI lane builds the plugin candidate in the same broad feature batch.
Its runner starts a disposable host-loopback backend for direct cases; the
isolated gateway/Kubernetes acceptance children receive separate plugin
sidecars in their borrowed PostgreSQL network namespaces, preserving the
existing no-host-gateway and read-only child boundary. A new local probe
created sender keys through both topologies and verified both containers were
removed. The peer fixture now composes the existing opaque remote
integration-secret router with its Signing Keys test routes; that was required
for native startup's real remote encrypt/decrypt proof and does not add a local
master key. The local packaged direct renewal test then passed with published
PostgreSQL migrations, the native process, wallet capture, anoncrypt and
authcrypt holder decryption. The sender fixture refactor also passed its two
public-document tests; the closed Compose fixture has 66 passing Python tests,
including an actual authcrypt render. Rustfmt, Ruff, Bash syntax, workflow YAML
parse and whitespace checks passed.

This is local direct-process evidence, not Linux isolated gateway/Kubernetes
process acceptance, hosted CI, or release-image proof. The fast renewal
composition test now covers the full authcrypt/anoncrypt by private-address
2x2 matrix. Anoncrypt with the private-address allowance proves local holder
decryption; authcrypt without a remote backend proves fail-closed no-send
behavior in the fast suite. The packaged direct test above supplies positive
authcrypt with real OpenBao and holder decryption. The focused Rust test and
all 35 renewal-profile Python obligations passed; the complete suite remains
to be rerun.
The local Kubernetes Canvas target compiled, but its actual renderer test
returned at the Linux guard and two unguarded preparation tests could not run
without `envsubst` on Windows; the reference-resolution unit test passed.
Run the Linux Canvas lane after finishing its inner process qualification,
then rerun the complete local/hosted matrices before the broad UI PR.

2026-10-07 grouped Canvas regression checkpoint: the fast Issuance renewal
2x2 test passes, as do all 565 active Issuance library tests and the 35
renewal-profile guard tests. The Canvas CI preflight harness now models the
disposable plugin start, scoped test environment and teardown; its first 80
cases passed, its two full-mode cases passed after cleanup correction, and
its remaining 121 cases passed with one skip. The runner cleanup is now
bound to its owning Bash process and clears the container identity after
removal, preventing background relays or a second exit path from removing
the backend during a parallel target. All 124 CI-workflow performance tests
passed with the wrapped composition command required. Bash syntax, Ruff and
Issuance rustfmt checks passed. The full Python sweep is still in progress;
these focused results do not qualify Linux isolated Canvas processes, hosted
CI or release images.

The broad Python regression run exposed two stale exact-command assertions
after the Canvas runner gained a scoped OpenBao wrapper; both now require the
wrapped serial/parallel composition command, and the complete 124-test CI
workflow performance file passes. The shell harness detected duplicate
OpenBao teardown; the owner-bound cleanup correction passed the two exact
full-mode cases and the remaining 121 preflight cases (one skipped), after
80 earlier cases had passed. A rendered Flow/self-host comparison then found
that its shared model guard assumed the unexpanded BAO address expression;
it now accepts the explicitly supplied render input while still checking
the source template. The self-host model script passed default, empty and
custom renders and rejects missing/empty native `BAO_ADDR`; 83 focused tests
pass. A Python sweep through the first 3,514 tests reached that Flow case,
and the suffix from that file passed 2,237 tests, 23 skips and 188 subtests.
These are segmented local results, not a single uninterrupted full run.
Three targeted UI Vitest files passed 16 tests. Ruff, Bash syntax and diff
whitespace checks passed. The next pre-PR check is a single complete Python
run followed by Linux Canvas process acceptance and full Rust/service
qualification at the candidate head.

The final uninterrupted Python run completed against this UI feature worktree:
`py -3.12 -m pytest tests -q -x` with the checked-out Marty common and local
`packages` on `PYTHONPATH` passed 5,975 tests and 188 subtests, with 29 skips,
in 15m11s. This includes the exact Canvas CI shell-harness and rendered
self-host/Flow assertions corrected above. It does not run the Linux-only
isolated Canvas process cases or replace hosted qualification.

2026-10-07 Rust library regression checkpoint: the locked workspace library
suite found a stale Gateway runtime/proxy route-count expectation after the
two flow-key-envelope public routes were retired. The actual route tables
contain 444 public, 447 runtime and 460 proxy entries. The corrected exact
Gateway test passed, then `cargo +1.95.0 test --locked --workspace --lib -j 2
--quiet` completed with no failures, including 151 active Gateway tests, 565
active Issuance tests and 132 active Signing Keys tests. Ignored live tests
remain separate qualification obligations. Gateway/Issuance rustfmt and diff
whitespace checks pass. This is a local library matrix, not the full service
integration matrix or exact-image evidence.
The locked workspace `cargo metadata` output also passed
`scripts/ci/check_marty_core_kms_boundary.py`, confirming the candidate Core
and isomdl pins and forbidden-feature boundary locally; production artifacts
and hosted CI still need the same check at their exact final revisions.

2026-10-08 grouped Core proof-fixture checkpoint: the OID4VCI proof and
key-attestation tests no longer generate Ed25519, P-256, P-384 or secp256k1
private keys locally. Sixteen proof cases now sign with scoped,
non-exportable keys in the marked disposable OpenBao runner, including valid
proof controls, tamper rejection, DID/key identity, freshness, attestation
selection and rejection of private JWK fields. The old test-only
`create_proof_jwt` local signer is removed. ES256K verification retains a
public-only signed vector and tamper/algorithm-confusion assertions; it does
not establish remote secp256k1 custody. The ordinary KMS-only library suite
passed 235 active tests with 56 ignored, including these 16 live-routed
cases; Clippy passed with warnings denied. The full disposable runner passed
its existing batch, format, JOSE/OIDC/SIOP, wallet, signer, issuer and OID4VP
groups plus all 16 proof cases. Keep this in the single broad Core feature PR.
Core commit: `3ad12c9`. The next Core fixture review includes the remaining
fixed-key helpers in `signer.rs`. Finish that inventory and self-review, then run
the complete local candidate matrix before opening the grouped Core/UI/
Credentials PRs in dependency order. Hosted CI and exact release artifacts
still need qualification at their final heads.

2026-10-08 Core LTI fixture continuation: two LTI launch JWT tests now use a
scoped non-exportable OpenBao Ed25519 key, preserving the valid launch and
wrong-deployment checks. The crate no longer enables `ed25519-dalek` private
key generation features for tests. The live disposable runner passed both LTI
cases and all previously routed groups. With LTI enabled, the ordinary KMS-only
library suite passed 244 active tests with 58 ignored; Clippy with warnings
denied and Rustfmt passed. Core commit: `3ebd07b`. Keep this in the same broad
Core feature PR; hosted CI has not run.

The remaining Core fixed-key signer helpers are shared by mdoc preparation,
SD-JWT and batch/stage-evidence tests. Retire that group together so the
positive signature and certificate assertions continue to use matching KMS
public keys and signed payloads. Do not open a separate PR or trigger hosted
CI for these fixture changes; run the full local matrix and three self-review
passes on the assembled Core head first.

2026-10-08 Core public-only EC fixture checkpoint: the shared preparation-only
ES256 and ES384 JWK helpers now return the public coordinates of their
historical fixed vectors without constructing either private scalar. This
preserves ordinary mdoc, SD-JWT, batch and stage-evidence preparation tests;
the KMS-only plus LTI library suite passed 244 active tests, 58 ignored, and
Clippy passed with warnings denied. Core commit: `53f097e`. The separate
`test_signature` helper still locally signs ES256/ES384 mdoc outputs and is
the next retirement target. Its batch/scalar byte-equality tests sign the
same payload multiple times; OpenBao ECDSA signatures need not be byte-identical.
Replace those calls with one scoped remote signing context per case, share each
verified signature for identical payloads across scalar/batch comparisons,
and retain checks of signed bytes, public-key binding, caller order and
certificate/holder behavior. Do not substitute invalid or dummy signatures
to keep the comparisons passing.

2026-10-08 Core mdoc fixed-signature retirement: the above `test_signature`
helper is now removed. Six affected mdoc tests share scoped, non-exportable
OpenBao ES256/ES384 keys with their preparation JWKs. The test fixture verifies
each fresh signature against the exact prepared payload and public key, then
reuses it only for identical algorithm/payload comparisons, preserving the
batch/scalar byte-equality and 64 shuffled-schedule assertions. The exact
MSO and item commitments, nested-claim decoding, caller order and fault
rejection assertions remain. All six live mdoc tests passed in the disposable
runner alongside its existing groups. The ordinary KMS-only plus LTI suite
passed 238 active tests with 64 live-routed/other ignored cases; Clippy with
warnings denied, Rustfmt and diff checks passed. Core commit: `5866754`.
The Core branch still needs a complete test-custody inventory, full candidate
matrix and self-review before its one broad feature PR; hosted CI and release
artifacts remain unqualified.

2026-10-08 Core custody inventory after mdoc migration: a constructor search
finds no `SigningKey::`, `SecretKey::` or `RsaPrivateKey::` use in
`marty-oid4vci/src` or `marty-oid4vci/tests`. Three benchmark sources still
construct local P-256 signing keys (`sd_jwt_issuance`,
`support/remote_signature`, `es256_signing_batch`) and require a separate
custody/measurement redesign before claiming all Core fixtures are KMS-only.
`marty-crypto` still contains private-key primitives behind `cfg(test)` for
cryptographic conformance and certificate/key-generation source; its runtime
library module/feature graph is a distinct production-root boundary to
re-audit at the final dependency head. This search is a targeted inventory,
not proof of the complete Core or release-artifact boundary.

2026-10-08 Core benchmark custody resolution: all three remaining OID4VCI
benchmark private-key constructors are removed. The mdoc, SD-JWT and ES256
batch benchmark paths share a process-scoped, non-exportable OpenBao P-256
key and its public JWK. Their measured signing operations now include the
real remote Transit call; preparation-only measurements remain distinct.
The shared benchmark signer validates the disposable loopback marker and has
a sign-only token with a one-hour benchmark lease. The normal live runner
keeps benchmark execution opt-in; `MARTY_TEST_BENCH_SMOKE=1` runs Criterion
test-mode smoke, while `MARTY_TEST_BENCH_RUN=<whitelisted bench>` runs one
full benchmark under the same disposable backend. All five benchmark binaries
compiled and the smoke command exited zero; the mdoc issuance, SD-JWT
issuance and ES256 batch Criterion test-mode groups reported success. The
allocation and tail evidence programs reported their normal opt-in-disabled
status and were not claimed as measured evidence. All-target Clippy passed
with warnings denied, and a constructor search found no `SigningKey::`,
`SecretKey::` or `RsaPrivateKey::` use in OID4VCI source, tests or benches.
Core commit: `615e908`. This is still part of the one broad Core feature PR;
no hosted CI, full release benchmark run or exact artifact qualification is
claimed.

2026-10-08 Core benchmark CI reconciliation: self-review found that PR,
merge-group and feature-matrix jobs still invoked benchmark binaries without
the disposable OpenBao backend; those commands would fail after removing
local signing. The PR affected-package lane now runs basic and payload-matrix
benchmark smoke under one marked disposable backend only when OID4VCI or root
inputs are affected. Merge-group/workflow-dispatch preflight appends the same
smoke and matrix checks to its existing live OpenBao process. The separate
standalone benchmark calls were removed from non-PR feature-matrix and
merge-group steps, preserving checks while avoiding duplicate backend starts.
The local combined benchmark/matrix smoke exited zero. Workflow YAML parses,
Bash syntax and all 112 script policy tests pass. That policy run also exposed
an earlier ZK mdoc OpenBao step that had changed the pinned native-security
job without updating its job digest; the reviewed job still directly builds
and executes all four approved Longfellow binaries with exact count checks,
and its digest is now current. `check_release_contract.py` passes. Core
commit: `d8a9b4a`. Hosted CI has not run; do not treat this as merge-queue
evidence.

2026-10-08 grouped-PR local matrix checkpoint: the broad Core workspace run
found two benchmark support integration tests that required disposable
OpenBao but still ran in the ordinary local suite. The candidate now marks
only those two cases as live tests and runs both in the existing disposable
OpenBao benchmark and issuer lanes. All eight benchmark support cases pass in
their intended selection (six ordinary, two live), the five benchmark smoke
binaries pass locally, and the complete Windows Core workspace test selection
(`--exclude marty-zkp --exclude marty-bindings --features test-fixtures`)
exited zero after the correction. Workspace all-target Clippy and final
feature-graph/self-review gates are in progress. Keep this correction in the
single Core feature PR (commit `1ce1301`); no hosted CI has run for the final
candidate. Windows all-target Clippy including `marty-zkp` could not build its
C++ verifier because local OpenSSL headers are missing; CI-toolchain 1.97.1
all-target Clippy for `marty-didcomm` and `marty-oid4vci` passes with warnings
denied. The remaining Windows broad all-target lint was stopped after its
native OpenSSL rebuild dominated the run; Linux native-security and full
hosted workspace gates remain required. The earlier Rust 1.95 DIDComm lint
warning does not reproduce under CI's Rust 1.97.1.

2026-10-08 Core production-graph local review: the locked `features,no-dev`
trees for the exact CI issuer, verifier, crypto-public, ECDSA-verification,
DIDComm-public, CSCA, EMRTD and bindings roots were re-read at Core
`1ce1301`. The CI forbidden-feature patterns had zero matches, including
inverse default/KMS crypto and DIDComm roots, isomdl local issuer signing,
SD-JWT issuer/holder features, and the verifier's isomdl exclusion.
`check_verification_feature_boundary.py` and `git diff --check` passed.
This is local dependency-graph evidence, not binary-symbol or packaged-artifact
proof; final CI-toolchain checks and shipped release qualifications remain.

2026-10-08 Core bindings test-custody review: `marty-bindings/src/lib.rs`
still contains test-only private-key signing paths: a PEM-accepting VDS-NC
signing helper and P-256/RSA round-trip test, plus an Ed25519 SD-JWT binding
test. These are not packaged Python operations, but leaving them as ordinary
tests conflicts with the requested KMS-only test custody. The two additional
fixed-P-256 proof-JWT tests only exercised Core Rust APIs and duplicated its
disposable-OpenBao live proof case; they are removed in the candidate, with
compact-token, holder-ID and nonce assertions carried into the remote live
case. Replace the VDS-NC and SD-JWT binding test signers with disposable
remote signing or public signed vectors while retaining all binding, tamper,
wrong-key and reconstructed-claim assertions. Then remove the test-only PEM
signer and any no-longer-used private-signing dev dependencies. This remains
inside the one broad Core feature PR; re-run live and bindings tests before
claiming completion.

2026-10-08 Core bindings fixture continuation: commit `a209023` removes the
two fixed-P-256 proof-JWT tests from bindings and moves their compact-token,
derived `did:jwk` holder-ID and nonce assertions into the disposable OpenBao
proof case. The binding's Ed25519 private JWK/signer is replaced by a
public-only SD-JWT vector previously issued under marked disposable OpenBao;
the binding still verifies and reconstructs the disclosed `email`, plus the
ordinary `role` claim. The local live issuer runner passed all six issuer
cases and 13 OID4VP cases after the assertion correction; the targeted
SD-JWT binding test, all 55 bindings library tests, bindings all-target
Clippy with warnings denied, Rustfmt and diff checks passed. The VDS-NC
private-PEM helper and P-256/RSA test remain and are not accepted as final
test custody. A wider test-constructor scan also found locally signed SOD
fixtures in `marty-emrtd-issuance/tests/remote_sod.rs`; include those in the
same Core fixture retirement review. No hosted CI or PR at this head.

2026-10-08 Core EMRTD test-custody resolution: commit `68c6f38` moves the
marked-disposable OpenBao Transit fixture to the dev-only shared
`marty-crypto-test-support` crate, leaving OID4VCI a thin re-export. Its
scoped sign-only token, non-exportable key checks, export denial and loopback
marker are preserved. The EMRTD SOD tests now use those remote keys to sign
both synthetic document-signer certificates (through `rcgen`'s external
signer trait) and prepared SOD inputs. ES256, ES384, RSA PKCS#1/RS256 and
Ed25519 positive cases plus wrong-input, malformed-signature, wrong-key,
algorithm and data-group checks remain. The five remote-dependent cases run
in the existing disposable OpenBao lane; the pure algorithm-name case stays
in the ordinary suite. EMRTD no longer has direct local-signing dev
dependencies. All five live EMRTD cases passed, and the combined local live
issuer/OID4VP/EMRTD/benchmark smoke and matrix runner reached its end with no
terminal failures. The complete Windows Core workspace test selection
including bindings and excluding only ZKP exited zero; targeted all-target
Clippy (test support, EMRTD, OID4VCI), Rustfmt, script syntax,
`check_release_contract.py`, all 112 script tests and the verification
feature-boundary check passed. This is still local candidate evidence; hosted
CI, Linux native ZKP and exact release artifacts remain. The binding VDS-NC
PEM/private-key fixture is the next Core test-custody retirement.

2026-10-08 Core bindings test-custody resolution: commit `3691b03` retires
the remaining issuer private-key constructors in `marty-bindings/src`.
Preparation-only ES256/ES384 inputs now use a public-only fixture. The VDS-NC
ES256/PS256 sign-and-verify test, mdoc single-use assembly test and three
SD-JWT/JWT-VC prepared-handle tests now sign with scoped non-exportable
OpenBao keys under the shared disposable marker. The private-PEM VDS-NC
test helper is gone; bindings no longer declares direct P-256/P-384 dev
signing dependencies. All five live binding cases passed in the packaged
OpenBao runner, retaining positive verification, tamper, wrong-key, claim,
policy, barcode, malformed-signature and single-use assertions. The ordinary
bindings library selection passed 50 tests with these five correctly routed
to the live lane; bindings all-target Clippy with warnings denied, Rustfmt,
script syntax, release-contract and verification-feature policy checks, and
all 112 script tests passed. A constructor scan has no `SigningKey::`,
`SecretKey::` or `RsaPrivateKey::` in OID4VCI, EMRTD or bindings Rust sources
and tests. `marty-verification` still has test and explicitly gated product
cryptography that require a separate exception/fixture audit; do not infer
complete Core test custody from the three-crate scan. No hosted CI or PR yet.

2026-10-08 remaining verification-fixture inventory: the next Core review
must classify `marty-verification` local constructors by supported capability
before deleting or migrating them. Current targeted scan finds rcgen-generated
certificate chains in `tests/chain_validation_tests.rs`,
`tests/cross_validation.rs`, `tests/dtc_tests.rs`,
`tests/mdl_conformance.rs`, and test modules in `src/oid4vp.rs` and
`src/trust_sync.rs`; a local signer also appears in the VDS-NC verifier
test. Some `src` cryptography is explicitly feature-gated for device/session,
TLS or conformance use. Preserve positive chain, mismatch, status and
protocol assertions, move issuer-key fixture signing to the shared disposable
OpenBao signer or public signed vectors, and document any narrow intentional
wallet/device or cryptographic-conformance exception. This is an inventory,
not acceptance of those remaining local-key tests.

2026-10-08 Core VDS-NC verifier fixture checkpoint: Core commit `e7bd43f`
replaces local P-256 key generation and signing in
`marty-verification/src/verification/vds_nc.rs` with the shared scoped
disposable OpenBao signer. Its malformed-barcode case uses a public-only JWK;
the eight cases that need signed input run in the existing live-KMS lane.
The ordinary verification library passed 348 tests with eight live cases
ignored, all eight VDS-NC verifier live cases passed, and verification
all-target Clippy with warnings denied, Rustfmt, shell syntax and whitespace
checks passed. Keep this with the single broad Core feature PR. Remaining
verification certificate-chain, mdoc, DTC and cryptographic-conformance
fixtures still need classification or migration; this commit alone does not
qualify Core for a PR or hosted CI.

2026-10-08 verification boundary follow-up: the remaining certificate-chain
tests construct CA and leaf `rcgen::KeyPair` values across multiple modules,
including CRL and DTC cases that currently serialize and re-import CA private
PEM. They need a shared remote certificate-signing test adapter and retained
positive/negative chain assertions, not a blanket deletion. The local
`jwk::jws` issuer signers and JWK constructors inspected so far are
`#[cfg(test)]`; production JWK signing and private `d` construction have
compile-fail guards. HAIP response decryption and EAC/ PACE ephemeral session
key paths are distinct wallet/protocol capabilities and must be classified
against their supported feature gates before any removal. This distinction
keeps the broad Core PR focused on issuer custody without losing verification
or session behavior.

2026-10-08 shared remote certificate-fixture checkpoint: Core commit
`1f8c6a4` adds a single dev-only `rcgen` signing adapter backed by scoped,
non-exportable OpenBao Transit keys for ES256, ES384, RSA-2048/RS256 and
Ed25519. The EMRTD SOD tests now reuse that adapter instead of maintaining a
second signer implementation. Six mDL conformance cases and all 11
certificate-chain integration cases now generate CA/leaf signatures remotely;
their original positive, expiry, untrusted-anchor, mixed-algorithm,
point-in-time and parsing assertions remain. The required preflight live
runner executes those ignored cases on every Core PR. In the local full live
runner, the six mDL cases, 11 chain cases and five EMRTD SOD cases passed,
alongside the existing remote-issuer matrix; ordinary mDL selection passed
14 with six live cases ignored, ordinary chain selection correctly ignored
11, and ordinary EMRTD SOD selection passed one with five live cases ignored.
All-target Clippy for test support, EMRTD issuance and verification with
warnings denied, Rustfmt, script syntax and whitespace checks passed. This
is a local candidate checkpoint, not hosted CI, a full Core review or an
exact release artifact. Continue migrating remaining verifier test custody
within the same broad Core feature PR.

2026-10-08 verifier identity/trust-fixture continuation: Core commit
`d715e28` moves OID4VP x509-hash client-identity certificate bundles and
trust-sync registry certificates to the shared remote certificate adapter.
Both OID4VP live cases and both trust-sync live cases passed, preserving
leaf-hash, root omission, mismatched/private-input rejection, profile
validation and atomic rollback assertions. The ordinary verification library
passed 344 cases with 12 signed-input cases routed to the live lane, and
verification all-target Clippy with warnings denied, Rustfmt, script syntax
and whitespace checks passed. The full disposable OpenBao runner including
the earlier chain, mDL, issuer and EMRTD cases completed without failure.
Other verification test fixtures remain; no hosted CI or Core PR yet.

Core verifier fixture targets identified at this checkpoint were the DTC
behavior tests and the optional OpenSSL `cross-validation` certificate
generation suite. Their completed migrations and validation are recorded
below. Continue the verification-module inventory and remove test-only issuer
signing helpers that no longer have callers in the same Core feature PR.

2026-10-08 DTC test-custody correction and first live cases: although
`marty-verification/Cargo.toml` sets `autotests = false` and does not declare
`dtc_tests.rs` as an integration target, `src/lib.rs` includes that file as
the active `dtc_behavior_tests` unit-test module. The private-PEM test signer
therefore still has compiled callers; an attempted deletion was reverted
after the library test build exposed the import. Core commit `c9dee0d`
starts the actual migration: the canonical external-signing round trip and
normalized-record persistence case now use a shared remote DTC signing
helper, the public prepare/assemble route, and a scoped non-exportable ES256
OpenBao key. Both live cases passed, including DER signature verification and
public-PEM newline normalization; the ordinary verification library passed
342 with 14 live cases ignored, and all-target Clippy, Rustfmt, Bash syntax
and whitespace checks passed. The full disposable runner completed without
other failures. Remaining DTC trust-chain, EKU, tamper, status and Type2/3
cases still use the old embedded private PEM and test-only local signing
helper; migrate them before deleting that helper and key. The runner filter
must use the actual `dtc_behavior_tests` module name, and a zero-case run
must never count as coverage. No hosted CI or grouped Core PR yet.

2026-10-08 DTC test-custody completion: Core commit `dbee368` migrates the
remaining signed DTC behavior tests to the existing shared remote
certificate key and public prepare/assemble API, then deletes the embedded
private PEM, local signer/certificate constructors, and the test-only
`sign_dtc_json`/private-key decode/sign helpers from `src/dtc/mod.rs`.
The same remote signer supplies the DTC signature, public PEM and signer
certificate; a separate remote CSCA key signs the chain. All 27 DTC test
functions and their assertions remain: 24 remote-signing cases passed in the
full disposable OpenBao runner, while public-only cases remain ordinary.
The complete default verification package passed locally (library: 320
passed, 36 live cases ignored; its other declared test targets passed or
correctly routed live cases), verification all-target Clippy with warnings
denied, Rustfmt, script syntax, whitespace, verification-feature boundary
and release-contract checks passed. A source scan found no private PEM,
`signing_key_pem`, `KeyPair::` or local `sign_dtc_json` call in the DTC source
and behavior tests. This resolves that DTC fixture cluster but does not
complete the remaining verification test inventory or qualify hosted CI,
the Core feature PR, or a release artifact.

2026-10-08 chain-validator unit-fixture checkpoint: Core commit `2e2374a`
replaces local CA/leaf generation in all 14 signed chain-validator unit
cases with the shared scoped non-exportable OpenBao certificate signer.
The CRL and OCSP helpers now retain the scoped CA signer for signing instead
of serializing private PEM or decoding a P-256 private key. The original
valid/expired/not-yet-valid, trust-anchor, path-length, issuer-usage,
soft/hard-fail revocation and authenticated good/revoked OCSP assertions
remain. Seven public-only chain cases passed ordinarily; all 14 remote
cases passed in the full disposable live runner, which completed through
the downstream EMRTD tests. Verification all-target Clippy with warnings
denied, Rustfmt, Bash syntax and whitespace checks passed. This removes
local key constructors from `src/verification/chain.rs` tests; other
verification modules and the final broad Core review still remain. No
hosted CI, grouped PR or release artifact is qualified by this result.

2026-10-08 mDL document-signer profile checkpoint: Core commit `d15913f`
replaces `rcgen::KeyPair::generate` in the mDL signer-certificate profile
test with the shared disposable remote ES256 certificate key. Its five
positive/negative leaf, CA and key-usage assertions passed in one live test;
the other 11 mDL verifier unit cases stayed ordinary and passed. The full
disposable runner completed through EMRTD, and targeted all-target Clippy
with warnings denied, Rustfmt, shell syntax and whitespace checks passed.
The fixed P-256 keys elsewhere in this mDL test module represent mdoc
device-auth/session proof construction rather than issuer certificate
custody; classify them with the supported device capability before further
change. This is not hosted CI or full Core PR qualification.

2026-10-08 optional OpenSSL cross-validation fixture checkpoint: Core commit
`00c71a1` replaces all four local P-256 key generations in the three
certificate-generation cases with the shared scoped non-exportable OpenBao
certificate signer. The existing parsing, expiry and chain-verification
assertions remain. The Linux live runner now executes all 13 optional
cross-validation cases, including those three normally ignored signing
cases, under the marked disposable backend. A native Linux Rust 1.97.1 run
passed 13/13 with OpenSSL development headers; optional-feature all-target
Clippy with warnings denied, Rustfmt, Bash syntax and whitespace checks also
passed. This remains in the one broad Core feature PR; other verification
fixtures, full assembled-head review, hosted CI and release qualification
remain pending.

2026-10-08 mdoc direct-pin certificate fixture checkpoint: Core commit
`10999bd` replaces the six local signer-key generations in the compiled
`mdoc::authentication` direct-pin profile test with the shared scoped
non-exportable OpenBao certificate key. The valid direct pin and rejection
assertions for CA status, issuer-only usage, absent or mixed usage, and
malformed trust material remain. The exact ignored test ran and passed once
in the full disposable OpenBao runner, which completed through downstream
EMRTD signing without failure. Verification all-target Clippy with warnings
denied, Rustfmt, Bash syntax and whitespace checks passed. This stays in
the single broad Core feature PR; the CMS master-list fixture was the next
verifier test-custody target and is resolved at the checkpoint below. No
hosted CI, grouped PR or release artifact is qualified yet.

2026-10-08 CMS master-list fixture checkpoint: Core commit `0f7f39f`
replaces the locally generated and serialized P-256 signing key in the
compiled ICAO master-list round-trip test. A small test-only CMS `Signer`
adapter uses the same scoped non-exportable OpenBao key for the signer
certificate and the CMS `SignerInfo`, with no private PEM serialization or
re-import. The signed round-trip and tampered-content rejection assertions
remain; the exact ignored case passed under the marked disposable backend.
The complete live runner then passed through downstream EMRTD remote SOD
cases. Native Linux Rust 1.97.1 verification all-target Clippy with warnings
denied, Rustfmt, Bash syntax and whitespace checks passed. Keep this with
the one broad Core feature PR. Additional verification JWK/credential test
fixtures and the assembled-head self-review remain; no hosted CI, grouped
PR or release artifact is qualified.

2026-10-08 Open Badges public-key fixture checkpoint: Core commit `24ede0f`
replaces local Ed25519 keypair generation in the OB3 authorization-method
and method-parser tests with one shared valid public JWK coordinate. These
cases only consume public verification methods, so no KMS round trip or
private test key is needed. All 29 Open Badges unit tests passed, as did
verification all-target Clippy with warnings denied, Rustfmt and whitespace
checks. Signed status-list and VCDM credential tests still generate local
issuer JWKs; preserve their positive and negative proof behavior while
routing those fixtures through remote signing in the same Core PR.

2026-10-08 JWK public-fixture and unused-private-API checkpoint: Core commit
`556ca11` removes the unused test-only P-384 private generator and test-only
Ed25519 private import/export helpers. JWK serialization, thumbprint, set,
type and public import/export tests now use shared public P-256/Ed25519 JWK
coordinates. The `to_public` and private-member classification tests retain
synthetic non-key markers to prove sanitization without generating working
private material. Eight remaining JWK-key tests and verification all-target
Clippy with warnings denied, Rustfmt and whitespace checks passed. The JWS
round-trip test migration is recorded below; session-key JWE cases require
separate capability review.

2026-10-08 OB2 test-only issuer retirement: Core commit `b8c3cd5`
removes an uncalled `cfg(test)` OB2 issuance API and its private-JWK JWS
signing helpers. No integration or source test invoked that API; the
recipient-hash unit case still passes, and all 12 Open Badges public signed
vector conformance cases pass under the `kms-only` feature. Verification
all-target Clippy with warnings denied, Rustfmt and whitespace checks pass.
The production OB2 verifier and its signature, recipient and document-store
checks remain. This clears the only Open Badges caller of the test-only
`jws_sign` function, enabling its remaining JWS unit tests to move to remote
signing and the local signer to be deleted in the same broad Core PR.

2026-10-08 verifier JWS test-custody checkpoint: Core commit `07e8eaa`
deletes the test-only `jws_sign` entry point and local ES256, ES384, EdDSA,
HMAC and placeholder RSA signing dispatch, plus now-unused Ed25519 and random
symmetric JWK generators. Four JWS signature-dependent tests retain their
ES256/EdDSA positive, wrong-key and tampered-payload assertions and pass
against scoped non-exportable OpenBao keys in the complete disposable live
runner; parser tests use a harmless placeholder signature, and HS256
verification uses a fixed signed vector rather than a generated signing key.
That live runner completed downstream EMRTD signing. After the final
generator deletion, the complete ordinary verification library passed 296
cases with 57 live cases ignored, verification all-target Clippy with warnings
denied, Rustfmt, Bash syntax and whitespace checks passed. `jwk::jwe` still
uses short-lived protocol/session key fixtures and requires a separate
capability review. Signed VCDM and Open Badges status-list tests were the
next local issuer-JWK clusters; VCDM is resolved at the checkpoint below.
No hosted CI, grouped Core PR or release artifact yet.

2026-10-08 VCDM proof and VC-JWT fixture checkpoint: Core commit `a718a7f`
removes all local JWK generation and `ssi_jws` signing from the compiled
VCDM tests. Public-only preparation, bound and private-input rejection cases
use a shared valid public Ed25519 JWK; negative private-member cases inject
synthetic non-key markers. Five Data Integrity and five VC-JWT cases now use
scoped non-exportable OpenBao Ed25519/ES256 keys and retain completion,
resolver, did:key, Open Badge profile, wrong-key, tamper and validity
assertions. A shared test-support `sign_es256` method produces raw JOSE
signatures for both VCDM and JWS tests. The ordinary VCDM group passed 11
cases with ten live cases ignored; all ten live VCDM cases and four live JWS
cases passed on native Linux Rust 1.97.1 against a marked disposable OpenBao
backend. The complete disposable runner passed through downstream EMRTD
before the final shared-helper refactor. Final-diff verification all-target
Clippy with warnings denied, Rustfmt, Bash syntax and whitespace checks
passed. Open Badges signed status-list tests remain; no hosted CI, grouped
Core PR or release artifact is qualified yet.

2026-10-08 Open Badges status-list fixture checkpoint: Core commit `f2696ce`
moves the two dynamic OB3 credential/status-list signatures in five status
authority tests to scoped non-exportable OpenBao Ed25519 keys. The fixtures
reuse the Rust VCDM Data Integrity prepare/complete boundary and an internal
Multikey constructor, with public-only DID JWK resolution. The wrong-key
rejection uses a fixed public JWK. All five live tests passed against a marked
disposable OpenBao backend, including good/revoked/suspended/multibit status,
unsigned or invalid proofs, wrong key/issuer, binding and freshness, and
untyped document-store rejection. The uncalled test-only OB3 private-JWK
issuer API and its signing helpers/result type are removed. The lifecycle
manifest now lists verification as the supported OB3 interface; the verifier
retains acceptance of supported proof suites. The ordinary verification
library passed 281 tests with 72 live tests ignored, the 20 runnable doc
tests passed including removed-API compile-fail checks, all-target Clippy with
warnings denied passed, and Rustfmt, Bash syntax, JSON parsing and diff checks
passed. Keep this commit in the one broad Core feature PR. The broader
disposable runner and exact final Core head still need requalification after
the remaining fixture and custody work; hosted CI, grouped PRs, release
artifacts and the UI/Credentials cutover are not yet complete.

2026-10-08 Core Python and wallet feature-graph follow-up: Core commit
`c99e01a` removes the Python verification loader's optional OB2/OB3 local
issuance exports, so an offline/development extension cannot re-enable that
public private-key path through the package loader. The capability manifest
now lists OB2 and OB3 verification interfaces only. Eight wheel-import guard
unit tests, Python syntax and manifest JSON checks passed; the installed
Python package's pytest suite was unavailable in this environment because
`pytest` is absent, so this does not qualify a published wheel. A review of
`marty-oid4vci/tests/sd_jwt_wallet_verified_presentation.rs` showed the
wallet suite was already migrated in Core commit `afd69ae`: it uses an
OpenBao-signed public-only fixture and is included in library tests from
`src/lib.rs` because Cargo disables automatic integration tests. The older
batching note above describing it as still using private JWKs is superseded.
Core commit `5a7c546` repairs the wallet-only KMS test graph by enabling
`isomdl/issuer-planning` only for the dev dependency, gating five issuer-only
SD-JWT helpers on the issuer feature, and preventing the issuer-only benchmark
test target from compiling in a wallet-only graph. Its current-head
wallet-only production check passed; wallet-only library tests passed 147
cases with 42 live cases ignored, and wallet-only lib/test Clippy passed with
warnings denied. The combined issuer/verifier/wallet library passed 229 cases
with 62 live cases ignored and all-target Clippy passed with warnings denied.
The two fixes remain in the one broad Core feature PR; no hosted CI or final
release-artifact evidence is claimed.

2026-10-08 current UI candidate plugin and graph checkpoint: the locked UI
Rust workspace metadata passed `scripts/ci/check_marty_core_kms_boundary.py`,
and its nine unit guard cases passed. The guard still pins the earlier reviewed
Core revision `a5cb567e6cd50e5a85b3b125a0a2ab6eea1d9fb7`; the assembled
Core feature head must be reviewed and pinned once before final UI qualification.
The current Go DIDComm extension source built into local OpenBao image
`sha256:97601c42c8c087a30126ad7ab531b0fad81f42ead2504c767047c4c235483a50`;
the Dockerfile ran `CGO_ENABLED=0 go test ./...` and `go vet ./...` before
compilation. With that exact local image, the disposable Canvas host and
borrowed-network-namespace sidecars created versioned sender keys, and the
three-voter OpenBao Raft probe passed forwarding, key rotation and active-node
failover. These local results strengthen K2/K3/K8 candidate evidence but do
not prove an exact published image, isolated Gateway/Kubernetes recipient
delivery, hosted CI or a release cutover. Keep the plugin and acceptance
changes in the one broad UI feature PR.

2026-10-08 passport artifact custody checkpoint: UI's production
`PassportNativeConfig` now rejects both raw and file-backed local artifact-key
settings even when native passport is disabled, and `PassportHttpService`
cannot select its Fernet branch through production configuration. A passport
instance without managed artifact KMS reports unavailable and artifact
operations return 503. Active Compose, env examples and the aggregate beta
selector no longer forward or insert those key fields; the beta handoff
rejects their reintroduction. The historical issuance runtime surface is a
frozen upstream provenance artifact, so its former key inventory was retained
after the embedded hash test exposed the accidental edit. The 101 focused
native/self-host/Kubernetes Compose tests and 153 beta selector/aggregate
tests passed (two beta cases skipped). The first Issuance library run passed
564 tests with one frozen-surface provenance failure caused by that accidental
edit; after restoration, the full library passed 565 tests with eight ignored.
This closes the
production config fallback only. The direct `PassportArtifactCipher`/`Legacy`
constructor and local-key PostgreSQL fixture remain in compiled test-capable
code, and callback HMAC's raw-secret fallback is still present. Retire these
in the same broad UI feature PR, preserve positive passport behavior through
remote-KMS fixtures, then rerun the full Issuance library and integration
matrix on the assembled head. No hosted CI or artifact qualification claimed.

2026-10-08 passport artifact test-custody follow-up: the same UI feature diff
now removes `PassportArtifactCipher` and its Python/Fernet compatibility
tests, and deletes Fernet from the Issuance and workspace dependency graph.
The public `PassportHttpService::new` test constructor accepts only the
managed-KMS client; the prior Legacy variant is gone. The PostgreSQL passport
contract uses a bounded, tenant/artifact/chunk-bound HTTP KMS fixture and no
local artifact key. This fixture checks service and repository behavior; it is
not evidence of real provider custody, which remains covered by separate live
OpenBao probes and requires final exact-image qualification. The default
Issuance library passed 562 tests (eight ignored); the complete passport
PostgreSQL contract passed against a fresh isolated PostgreSQL 16 container.
The first database run encountered a Docker/host clock-skew assertion; its
bound now permits 30 seconds of positive skew, and the full second run passed.
The Issuance all-tests target compiles, the 13 focused passport HTTP unit
tests pass after simplifying the KMS-only adapter, `cargo tree -i fernet`
reports no such package, and Issuance library Clippy passed with warnings
denied. No hosted CI or broad UI PR has run on this assembled head.

The optional `passport-self-signed-test` build remains a separate unfinished
K8 custody finding: it still contains a local CSCA/DSC signer, fails to
compile against hardened Core because `marty_verification::issuance` is gone,
and CI still attempts to build it. Remove that feature and replace its
packaged positive path with a remote managed signer fixture in the same UI
feature PR; update build/CI/Compose contracts together. The raw callback
secret fallback and its tests also remain. Neither optional build nor callback
custody is qualified by the default suite above.

2026-10-08 self-signed passport build retirement checkpoint (supersedes the
optional-feature finding immediately above): the non-default
`passport-self-signed-test` Cargo feature, `PassportSigner::SelfSignedTest`,
the local CSCA/DSC signing function, its feature-only positive test, and the
alternate public image build argument/mode are removed. Every Issuance build
now rejects `PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED=true` before passport startup.
Shipping Compose and env examples no longer advertise or forward the flag;
the beta selectors and aggregate handoff reject its reintroduction. CI no
longer builds an alternate image, removes the now-unused packaged-test database
and lane, and reduces the explicit CI gate from 19 to 18 required results. The
default public-image negative boundary stays in CI. The existing disposable
OpenBao managed passport chain remains the real cryptographic positive
acceptance; its own exact packaged-process form is not established by this
source change, so final K8 artifact acceptance remains open. The conformance
model was reconciled with the already-retired integration master-key field and
the intentional Gateway signing route; its whole-model script passed.

The assembled source passed 563 Issuance library tests (eight ignored),
Issuance all-tests compilation and lib Clippy with warnings denied. The
passport PostgreSQL contract passed again on a fresh disposable PostgreSQL 16
container; an initial container startup race prevented database creation and
the subsequent retry ran the contract successfully. The coordinated Python
deployment/CI/selector selection passed 518 tests (two skipped), and the
conformance whole-model script, CI YAML parse and diff whitespace check passed.
No hosted CI, final image or grouped PR qualifies this head yet. K8 test
custody is still incomplete: `passport_signer.rs`'s ordinary unit tests create
local P-256/P-384 CSCA/DSC keys and sign dynamic mock responses. Move those
positive tests to remote OpenBao fixtures or public signed vectors while
retaining chain, rotation and malformed-signature assertions; do not confuse
feature retirement with complete test-key retirement. Raw callback HMAC
fallback also remains for the same broad UI feature PR.

2026-10-08 callback custody source reconciliation (supersedes the final
sentence above): the current Issuance `PassportNativeConfig::from_values`
rejects both `PERSONALIZATION_BUREAU_WEBHOOK_SECRET` and its file selector,
including before disabled-native return. `PassportHttpService` constructs a
`KmsWebhookVerifier` for callback mode and its negative test requires the
internal credential; the old raw-secret verification branch is absent from
that HTTP service. The beta aggregate selector and shipping Compose tests
also reject those selectors. This review found that the config check ignored
empty values, so it now rejects presence of both retired callback selectors
and both retired artifact-key selectors regardless of value, including when
native passport is disabled. The two existing targeted config tests and a new
disabled-passport boundary test pass. This is source evidence, not a fresh
packaged image or hosted-CI result; verify the exact assembled UI head before
closing the callback custody gate. Other local HMAC uses require
purpose-specific classification rather than being treated as this passport
callback fallback.

2026-10-08 assembled UI test-custody correction: the earlier statement that
ordinary `passport_signer.rs` tests still create local CSCA/DSC keys is stale.
The current source uses `passport_public_signatures.json` through the shared
`passport_test_vectors` module, with no `SigningKey` or `SecretKey` in those
files. The focused managed signer test passed, retaining the trusted-chain,
profile rotation, altered data-group, malformed SOD and wrong-signature
checks. The remaining passport gate is packaged/live managed signing and
final-head acceptance, not this already-retired test signer.

The Auth OIDC behavior test still built a deterministic P-256 private key,
signed an ID token locally and advertised its derived JWKS. It now verifies
a committed public-only ES256 token/JWKS vector instead, preserving rotated
JWKS refresh, identity claims and untrusted-origin refusal. The token is
synthetic and long-lived solely to keep verification tests independent of the
wall clock; no private JWK member is retained. `marty-auth` dropped its
test-only `p256` and `jsonwebtoken` dependencies and now explicitly requests
`marty-oid4vci/jose-verification`, which its production OIDC module imports.
Without that feature, the isolated Auth package build failed to compile; all
five OIDC behavior tests and the full Auth package suite passed after the
manifest correction. Auth all-target Clippy passed with warnings denied,
targeted rustfmt and diff whitespace passed, and the fixture shape was checked
for absence of private JWK members. The Rust lockfile was updated offline.
Workspace-wide `cargo fmt --all -- --check` hit Windows command-line length
error 206 before formatting any source; this is not a passing workspace-wide
format check. Keep this batch in the single broad UI feature PR; hosted CI and
the assembled-head matrix remain open.

2026-10-08 remaining explicit test-key classification in the inspected native
service/crate trees: `device-registration/tests/behavior.rs` creates an RSA
device key to prove possession of a random challenge, rotate it and reject
replay; it is device-owned, not issuer signing. The nine-test behavior target
passed. `flow/tests/siop_submission_behavior.rs` creates P-256 and Ed25519
wallet keys for self-issued SIOP tokens and negative claim/time cases; these
are holder-owned keys, not service issuer keys. Its four-test target passed.
The exact constructor scan found no other `SigningKey::`, `SecretKey::`,
`RsaPrivateKey::` or `KeyPair::generate` calls under `rust/services` and
`rust/crates` after the Auth OIDC conversion. This is a classified, narrow
source scan, not a complete proof of all possible local crypto paths.

Local worktree hygiene: `rust/crates/canvas-acceptance/%SystemDrive%/` contains
four untracked Windows cache database files under a literal `ProgramData`
subpath. They are not part of the feature diff and must not be staged. A
PowerShell recursive removal was rejected by execution policy after exact
path verification, so the directory remains visible as untracked; it is not
a PR or release artifact.

- 2026-10-07: Investigation complete; source/history findings recorded above.
  No fresh build, live KMS test or deployment acceptance claimed.
- 2026-10-07: Plan created on UI branch
  `security/remote-kms-hardening-20261007`, based on `d2dcd0630`, in workspace
  `worktrees/kms-hardening-integration-20261007`. No historical branch changed.
  Next checkpoint: K1 inventory and K2 backend feasibility.

2026-10-08 Core ECDSA test-custody checkpoint: the broad Core feature diff
removes the `cfg(test)` P-256/P-384/P-521 ECDSA key generators and private-key
signers and retires the first-party `cavp_ecdsa` source, which generated its
own signing inputs rather than consuming NIST CAVP vectors. Existing
`verification_only_public.json` covers public verification on all three
curves, SEC1/SPKI inputs, negative cases and cross-curve rejection; its suite
now also checks DER/raw JOSE normalization against the same public signatures.
This reuses one fixture set and leaves no ECDSA local signing helper in
`marty-crypto/src/ecdsa.rs`. The 14-test verifier-only integration target,
109 full-feature crypto library tests, all-target compilation, and full-feature
all-target Clippy with warnings denied passed locally; formatting and diff
whitespace checks were run after formatting. This is test-key retirement,
not KMS custody proof. The Ed25519 and ISO 9796 paths named here were retired
at the following checkpoint. No hosted CI or grouped PR has run on this head.

2026-10-08 Core Ed25519/ISO 9796 test-custody checkpoint: the broad Core diff
removes Ed25519's `cfg(test)` keypair, key generation, secret import/export,
signing and private PEM/DER parsing. The existing RFC 8032/public verification
suite now also checks its public wrapper, boolean result and malformed lengths.
The ISO 9796-2 Scheme 1 test-only RSA private signer is removed; recovery,
verification, wrong-message and tamper assertions use one fixed public signed
vector with no retained private key. Signing-only ECDSA/Ed25519/P-curve dev
dependency overrides and now-unneeded dev entries were removed. With the
lockfile updated, all 100 crypto library tests and every all-feature target
passed locally, as did the 14-test minimal signature-verification suite,
all-target Clippy with warnings denied and diff whitespace checks. Formatting
was applied. The dependent `marty-verification` library passed 281 tests with
72 ignored. Protocol-session ECDH remains intentionally separate from issuer
signing and still generates ephemeral keys. The broader Core and UI acceptance
matrices, final source audit, hosted CI and grouped PRs remain open.

2026-10-08 Core BBS test-custody checkpoint: the broad Core diff removes the
remaining crate-internal BBS issuer secret key, keypair generator and signer.
Both BLS12-381 SHA-256 and SHAKE-256 suites now consume fixed public
multi-message signatures. The tests retain signature verification, message
and signature tamper rejection, holder selective-disclosure proof creation,
proof verification, wrong disclosed-message rejection and presentation-header
binding. Existing known public signature/proof vectors also remain. This
retires local BBS issuer signing from `marty-crypto` tests without removing
holder proof generation, which needs a public issuer signature rather than an
issuer private key. The all-feature/all-target crypto tests passed (94 library
tests and each integration target), followed by targeted six-test BBS rerun
and all-target Clippy with warnings denied after simplifying the fixture
helper. This fixture is not evidence of remote BBS signing or KMS custody.
The Core source/consumer matrix and broad PR remain open.

2026-10-08 Core DIDComm raw-key feature retirement: full feature-graph review
found `marty-didcomm` still offered selectable `local-key-operations` with
caller-supplied long-lived X25519 authcrypt/decrypt APIs, even though KMS-only
bindings excluded it. The broad Core diff removes that Cargo feature, all
raw-key APIs/helpers and their private-key tests. It retains explicit
public-recipient anoncrypt with fresh ephemeral sender agreement and adds
public-only tests for protected DIDComm JWE profile, recipient KID binding,
missing key-agreement authorization and plaintext size. The CI positive lane
now uses only the supported envelope feature; its negative Cargo feature check
proves `local-key-operations` cannot be selected. The feature-boundary script
now rejects reintroduction. The 34 library, eight integration and five doc
tests pass under all features, all-target Clippy passes with warnings denied,
the feature-boundary six-test and release-contract 78-test suites pass, the
KMS-only Python bindings dependency compiles, and Cargo rejects the retired
feature. The bindings' explicit anoncrypt-only module-export test also passes.
The removed first-party raw-private-key Appendix C decryption test
is not remote custody evidence. Native remote-KMS DIDComm interoperability and
exact packaged-process tests must prove the supported authcrypt behavior
before the Core/UI PRs land. No hosted CI or PR qualifies this change yet.

2026-10-08 Core review correction: `did:peer:2` resolution sliced a segment at
byte 1 before establishing that its first UTF-8 character was ASCII. A
non-ASCII purpose could panic the resolver. The broad Core diff now returns
`InvalidDid`; the focused regression and all-target DIDComm Clippy pass.
The disposable OpenBao test-support crate also enabled P-256's local ECDSA
signing feature solely to return a verifier type. It now returns the same
ECDSA verifier type through `ecdsa-core/verifying`, and its direct P-256
dependency selects arithmetic/SHA-256 without signing. Its locked normal
feature tree contains neither `p256/ecdsa` nor `ecdsa/signing`; the test-support
crate compiles and OID4VCI benches still compile. This is a dependency-scope
correction, not a claim that all transitive cryptographic libraries lack
signing internals. The broad Core review and PR remain open.

2026-10-08 Core assembled checkpoint: commit
`c7f562467ba519d4dc4163ed61944f68d4d24279` groups the 46-file
public-vector cryptography cleanup, shared remote fixture narrowing,
raw-key DIDComm capability retirement, CI/feature-guard updates and parser
security correction into the existing broad Core feature branch. The Core
worktree is clean at that SHA, 71 commits ahead of `origin/main`. Local
evidence on this assembled batch includes crypto all-target tests, DIDComm
all-feature tests/Clippy, `marty-verification` library (281 passed, 72 ignored),
OID4VCI bench compilation, KMS-only bindings compilation and anoncrypt export,
six feature-boundary tests, 78 release-contract tests, formatting, staged
diff whitespace and public-fixture private-key scans. This is a reviewable
checkpoint, not the final reviewed Core SHA, complete local matrix, hosted CI,
PR, or consumer qualification. Do not pin it as final in UI/Credentials yet.

2026-10-08 exact-toolchain local rerun at Core `c7f5624`: Rust 1.97.1,
matching the CI workflow toolchain, passed `marty-crypto` all-feature/all-target
tests (94 library tests plus all integration targets), `marty-didcomm`
all-feature tests (35 library, eight integration, five documentation), and
all-feature/all-target Clippy for both crates with warnings denied. This is
local source qualification only; it does not replace the full Core matrix,
hosted required checks or dependent UI/Credentials artifact acceptance.

2026-10-08 Core consumer graph finding at `c7f5624`: the Rust 1.97.1
OID4VCI default suite passed (205 library tests with 60 ignored and all
integration targets), the no-default bindings suite passed (50 with five
ignored), and KMS-only bindings/issuer/verifier `cargo check` passed. A
normal-dependency graph check then found an unresolved *bindings* transitive
signing feature: `marty-bindings -> marty-verification -> SSI verification
packages`, including `ssi-claims`, `ssi-jwk`, `ssi-jws` and
`ssi-verification-methods`, enables `p256/ecdsa` and `ecdsa/signing`. The
KMS-only OID4VCI issuer graph does not. Local source inspection shows the
SSI crates couple ES256 verification and signing in their `secp256r1`
features (for example `ssi-jwk`'s optional P-256 dependency requests
`ecdsa`). This finding does not prove a Marty raw-private-key API or live
fallback, but it **prevents claiming that the KMS-only bindings dependency
graph lacks signing machinery**. Keep VCDM/Open Badges ES256 verification
working while assessing a verification-only fork or replacement boundary,
and inspect the exact wheel's symbols/API before artifact acceptance. The
current CI graph guard checks the issuer path, not this bindings transitive
path; it must not be cited as proof of the stronger bindings claim. No PR or
hosted CI has qualified this finding.

2026-10-08 Core verification consumer rerun: the Rust 1.97.1
`marty-verification --features test-fixtures` target completed successfully:
304 library tests passed (72 ignored), followed by the integration targets
with zero failures; one 11-test target was entirely ignored because its
external fixtures were unavailable. This preserves current VCDM/Open Badges
verification behavior as the baseline for any SSI boundary change. A Cargo
feature graph and local SSI manifest review show that `ssi-jwk/secp256r1`
declares `p256` with its `ecdsa` feature, while SSI verification-method and
claims features also select signing-capable dependencies. Removing those
features without a verifier replacement would drop supported ES256
verification, so no manifest-only removal is accepted. Next resolve whether
an ElevenID verification-only fork is justified or whether exact-artifact
API/symbol proof establishes the required no-private-key boundary while
documenting dependency-internal code. This remains an open Core review item.

2026-10-08 UI passport test-key source reconciliation: the earlier K8 note
that ordinary `passport_signer.rs` tests still create local CSCA/DSC P-256
keys is superseded by the current uncommitted UI feature diff. Those tests
now consume `passport_test_vectors.rs` and the public signed SOD/certificate
fixture; a source scan of both files found no private-key constructor,
serializer or local signing operation. The seven focused passport-signer
library tests pass on the current UI worktree. This closes that specific
test-key finding, not the full Issuance suite, live managed-signing or exact
image K8 gate. The UI branch still pins released Core `a5cb567`; do not pin
unreviewed `c7f5624` until the Core PR head and consumer matrix are final.

2026-10-08 local Core wheel boundary at `c7f5624`: `maturin build --locked
--release` used `marty-bindings/pyproject.toml`'s `no-default-features` and
`extension-module,kms-only` selection and produced the Windows abi3 wheel
`marty_rs-0.2.0-cp311-abi3-win_amd64.whl` (8,663,590 bytes; SHA-256
`5509e2502de833b62cf6900f016f47cfce86011df1465dedc52d05e5adcc9a5b`).
The wheel's native extension loaded from an isolated extraction. Its Python
surface lacked all 18 enumerated retired private-key/DIDComm entry points
and retained four checked remote prepare/assemble/verification functions;
the 24 wheel-backed `test_marty_rs.py` cases passed under Python 3.12.
This proves those Python exports for this local Windows wheel only. It does
not prove dependency-internal signing code absent, nor qualify the Linux
release wheel, hosted provenance, other Python modules or production service
images. Keep the SSI transitive-feature finding open and inspect exact
published artifacts before K8/K9 acceptance.

## Reference records

2026-10-08 Core mdoc presentation test-custody batch: commit
`e1dca334fd19243c95c5629ca4accb5c48dc3d13` extends the single broad
Core feature branch beyond `c7f5624` and leaves its worktree clean. The
ordinary mdoc authentication test no longer generates a P-256 issuer JWK,
creates a local issuer certificate/signature, or keeps a local `TestMdocSigner`.
It reads a public signed device response, transcript, device signature and
public certificate from `tests/vectors/mdoc_presentation_signed_public.json`.
The existing positive issuer/device/trust assertions and negative changed
transcript, tampered device signature and missing trust-anchor assertions
passed. The vector has only those four public fields; its certificate is
PEM `CERTIFICATE` with validity through 4096, and the mdoc was generated
with a five-year validity to avoid a one-day fixture expiry. Rust 1.97.1
`marty-verification --features test-fixtures --lib` passed 303 tests with
72 ignored, and library Clippy passed with warnings denied. The count is
one lower than the prior 304-test baseline because the removed test only
checked that a local test signer exported a public JWK; the presentation
verification behavior remains exercised. This does not close other Core
verifier test-key constructors, the SSI transitive signing-feature review,
hosted CI or wheel qualification. Do not pin this as final UI Core revision.

2026-10-08 Core SSI dependency-boundary scope correction at clean
`c7f5624`: `cargo tree` for the KMS-only bindings normal graph confirmed
`p256/ecdsa -> ecdsa/signing`. Local locked-manifest inspection identified
six independent P-256 ECDSA selectors in the enabled verification graph:
`did-method-key 0.5.0`, `ssi-crypto 0.2.1`,
`ssi-data-integrity-suites 0.4.0`, `ssi-jwk 0.4.0`, `ssi-jws 0.5.0` and
`ssi-verification-methods 0.3.0`. Each declares an optional `p256`
dependency with `features = ["ecdsa"]`. The ElevenID `sd-jwt-rs` fork's
`crypto-provider` dependency already requests `p256` with defaults off and
`ecdsa-core`/verification features; it is not by itself the direct selector
for `p256/ecdsa` in this graph. `marty-verification` uses SSI `AnySuite`
and `ssi-jws::decode_verify` for supported VCDM/Open Badges/VC-JWT checks,
and its remote Data Integrity preparation captures SSI's canonical signing
input through a placeholder `Signer` trait without possessing a private key.
Consequently a verification-only dependency fork, if exact-artifact policy
requires one, spans several coordinated SSI crates and must preserve those
proof and ES256 verification semantics. Do not describe it as a one-crate
manifest correction or remove ES256 support to make the graph green.

The local Windows abi3 wheel is stripped (`nm` reports no COFF symbols);
its PE export table lists the Python module initializer plus AWS-LC entropy
exports. That table cannot prove absence of dependency-internal signing
functions or prove their reachability. The already recorded isolated Python
API scan and 24 wheel-backed tests establish the public Python boundary
only. The Core review gate remains open pending a documented artifact-level
reachability decision or a coordinated verification-only fork with the
304-test verifier baseline, VCDM/Open Badges ES256 vectors, and final wheel
qualification. Keep this work in the one broad Core PR unless a separate
ElevenID dependency fork is demonstrably required.

2026-10-08 SSI source-level custody decision: inspection of the exact locked
registry sources confirms this is stronger than a redundant Cargo feature
flag. The enabled `ssi-crypto` P-256 path contains a `SecretKey` variant and
`AlgorithmInstance::sign`; `ssi-jwk` contains P-256 secret generation and
private-parameter conversions; `ssi-jws` contains ES256 local signing; and
`ssi-verification-methods` contains P-256 local signing methods. The enabled
`ssi-data-integrity-suites` source also contains P-256 proof-scoped key
generation and ECDSA signing. `did-method-key` requests the same broad
`p256/ecdsa` feature, although its source scan did not find a direct signer.
The existing `ElevenID/ssi-elevenid` dependency checkout is a `linked-data`
crate, not the SSI multi-crate workspace. Therefore the strict source-graph
version of KMS-only cannot be claimed from the current Core branch or from
the stripped wheel/API scan. Prepare one coordinated ElevenID-maintained SSI
verification-only dependency change across the affected crates, preserve
ES256/EdDSA VCDM and Open Badges verification and the remote Data Integrity
prepare/complete path, then pin that reviewed dependency in the broad Core PR.
If exact artifact analysis proves a smaller boundary sufficient, document the
specific proof before narrowing this dependency task. Do not remove ES256,
disable tests, or treat private-key APIs in transitive crates as harmless
merely because Marty does not currently export them.

The local preparation checkout is
`worktrees/kms-ssi-verification-only-20261008` on
`security/ssi-verification-only-20261008`, based on upstream SSI commit
`16cd58715aa209f3151560ad59bd6ac65b90fa89` (the tagged source for
`ssi-jws 0.5.0`, `ssi-verification-methods 0.3.0`,
`ssi-data-integrity-suites 0.4.0` and `did-method-key 0.5.0`; the same
workspace declares `ssi-crypto 0.2.1` and `ssi-jwk 0.4.0`). It is a clean
local branch, not an ElevenID remote fork or qualified dependency. The
source-level change must separate public verification from secret generation
and signing in all relevant crates and avoid transitive re-enablement by
their existing `secp256r1` feature forwarding. Validate the resulting Core
bindings graph and ES256/EdDSA vectors before deciding the smallest set of
patched packages and opening any dependency PR.

2026-10-08 SSI split feasibility correction (supersedes the proposed simple
fork path above): a local `ssi-crypto` experiment separated P-256 secret-key
constructors and signing behind an explicit feature and checked the crate in
an isolated Cargo harness. The baseline upstream workspace itself cannot
resolve a new lockfile because `libipld-core 0.14.0` requires yanked
`core2 0.4.0`, so the isolated harness was necessary. With `p256` defaults
enabled, the supposedly verification-only harness still selected
`p256/ecdsa -> ecdsa/signing`; with defaults disabled and only
`p256/ecdsa-core`, it failed to compile because `p256::PublicKey` needs
`arithmetic` and `p256::ecdsa::VerifyingKey` is gated on `p256/ecdsa`.
The upstream `p256/ecdsa` feature enables both `ecdsa-core/signing` and
`ecdsa-core/verifying`; `p256` also gates its curve `VerifyPrimitive`
implementation on that feature. Thus a six-crate SSI manifest/source split
alone cannot keep the existing ES256 verifier while removing the signing
feature. The experimental edits were reverted; the local SSI branch is clean
and no fork or Core pin was changed. The next Core decision needs either an
auditable shipped-artifact reachability proof that the dependency signers are
unreachable from issuer operations, or a broader replacement/fork of the
P-256 verification primitive plus SSI feature split. Preserve ES256 behavior
and do not claim the current graph is KMS-only merely because the public
Python API lacks signers. The isolated harness and failed whole-workspace
resolution remain under `artifacts/ssi-crypto-verification-check-20261008`.

2026-10-08 additional Issuance test-key retirement: a shared public P-256
coordinate fixture now serves both registered-client unit and HTTP behavior
tests without constructing `p256::SecretKey` merely to derive a JWK. Three
registered-client library tests and all 18 `oid4vci_management_behavior`
tests passed on Rust 1.97.1. Removing the old synthetic DIDComm issuer-secret
helper exposed three library-test consumers; those now use public issuer DID
documents and retain the separately classified holder decryption secret.
All 40 focused `initiation_didcomm::tests` passed, including remote-reference
tenant binding, no-KMS fail-closed behavior, embedded DID resolution and
private-IP refusal. A source scan of Issuance `src`/`tests` and Canvas
`tests` found no `SigningKey::from_bytes`, `SecretKey::from_slice`,
`sender_x25519_private_key`, or `authcrypt_parties` references after this
batch. That scan is limited to those exact constructors/names, not proof
that every test-only key path across the workspace is retired. Keep the
public-fixture and remote-reference changes in the grouped UI PR.
Rust 1.97.1 Clippy subsequently passed for the Issuance library and
`oid4vci_management_behavior` test target with warnings denied.

2026-10-08 DIDComm test-custody completion for the inspected Canvas and
Issuance fixture trees: the renewal private-IP refusal case now uses a
versioned remote sender reference and scoped OpenBao client, even though its
endpoint is rejected before transport. The shared DIDComm document fixture
no longer returns a synthetic issuer X25519 secret; it exposes public issuer
documents and the separately classified holder decryption key only. A
source scan of `rust/crates/canvas-acceptance/tests` and
`rust/services/issuance/tests` found no remaining
`sender_x25519_private_key` policy member or old issuer-secret constructor
in these trees. Rust 1.97.1 compiled the published Canvas target and passed
strict Clippy, the two public-document fixture tests, and the exact
`didcomm_renewal_private_ip_refusal_preserves_published_rows` test with owned
PostgreSQL and disposable OpenBao; all owned containers were removed. The
private-IP case proves refusal and unchanged durable rows, not successful
authcrypt. The earlier composed-delivery case proves successful authcrypt
and the mismatched sender failure. The full Canvas suite, hosted CI and
exact packaged artifact gate remain pending in the same UI feature PR.

2026-10-08 composed DIDComm custody batch: the in-process Canvas delivery
graph no longer writes `sender_x25519_private_key` to its issuer policy. A
single shared disposable sender fixture now provisions a versioned OpenBao
DIDComm key and exact read/pack token for both packaged renewal and composed
delivery. The policy contains only `sender_key_ref`; the envelope uses
`RemoteDidcommKms`, and its DID document carries the plugin's public key.
The wrong-sender test retains its pre-issuance failure assertion by binding
the remote key reference to a different public DID key, without constructing
or exposing a second private key. On Rust 1.97.1, the exact published Canvas
target compiled and passed strict Clippy. The focused
`didcomm_native_composes_crypto_https_and_published_durability` test passed
locally with owned published PostgreSQL, the HTTPS wallet fixture, and the
disposable OpenBao plugin; it includes authenticated/anonymous paths and
the wrong-sender fault. The separate renewal HTTP test also passed, but it
does not exercise this composed graph. The first Windows attempt stopped at
the missing `python3` command before reaching DIDComm; rerunning with the
supported `MARTY_DIDCOMM_TEST_PYTHON` override passed. Test-owned database,
migration-probe and OpenBao containers were removed. This is strong local
source/runtime evidence for this Canvas test path, not the complete Canvas
matrix, hosted CI or exact packaged service-image qualification. Keep this
batch in the broad UI feature PR.

2026-10-08 Canvas renewal signing-custody batch: the packaged renewal
acceptance path now creates a non-exportable Ed25519 key in the disposable
OpenBao Transit mount, reads only its public key for the DID document, and
signs dynamic JWT input through a separate Transit sign-only token. The
shared named signing peer no longer holds an `ed25519_dalek::SigningKey`.
The composed-delivery controlled issuer now uses the shared public signing
JWK constant rather than deriving it from a private test key. The disposable
Canvas OpenBao bootstrap enables both DIDComm and Transit in host and
PostgreSQL-namespace modes. A local disposable instance confirmed Ed25519
key creation with `exportable=false`, Transit signing with the scoped token,
and HTTP 403 on key metadata read by that token. The published Canvas Rust
test target compiled with Rust 1.97.1; rustfmt, diff check and Python
bootstrap syntax passed. Clippy with warnings denied reached an existing
duplicate-module inclusion of `remote_integration_secret.rs`; a diagnostic
run allowing that one lint passed, but the strict Clippy gate remains open.
The published database/process renewal gate has not run on this assembled
head, so live end-to-end signing behavior is not yet qualified. The
composed-delivery test still writes `sender_x25519_private_key` into its
policy; migrate that separate authcrypt fixture to remote references before
claiming Canvas K8 custody closure. Keep all corrections in the single UI
feature PR.

2026-10-08 Canvas scoped-signer acceptance follow-up: an ignored-by-default
Rust test now exercises the actual `RemoteIssuerSigner` against the disposable
Canvas OpenBao instance. It creates a managed Ed25519 Transit key, verifies
a live signature using the returned public key, and requires HTTP 403 when
its sign-only token attempts key metadata read. The test passed locally on
Rust 1.97.1 with the owned `marty-openbao-didcomm:local-audit` image; the
container was removed afterward. The existing published Canvas CI runner
now selects and executes this exact test after starting its one shared
disposable backend, avoiding a new job/image build. `bash -n`, Python
bootstrap syntax and scoped diff whitespace passed. This proves the signer
helper and token boundary, not the full packaged renewal/database path;
hosted CI has not run this head.

2026-10-08 Canvas strict-Clippy correction: the published schema target
loaded `remote_integration_secret.rs` twice, once from the status runtime
fixture and once from the issuance process fixture. The status fixture now
uses the one parent-owned module. Rust 1.97.1 Clippy on the exact published
schema target passes with `-D warnings`, with no lint exception. The
earlier duplicate-module diagnostic above is resolved for this target;
other targets still require their assembled-head checks.

2026-10-08 UI verification test-custody batch: the native verification
service no longer creates an Ed25519 issuer key to sign its VCDM test or a
P-256 issuer key to sign its VDS-NC test. Both paths now verify committed
public signed examples in `rust/services/verification/tests/fixtures/`;
the resolver's compressed P-256 normalization test uses a fixed public
point and checks exact output coordinates. The service's direct
`ed25519-dalek` dev dependency was removed. On Rust 1.97.1, all 67
verification-service library tests passed, Clippy for library and tests
passed with warnings denied, and both touched sources passed rustfmt check.
The workspace lockfile was regenerated offline to match the current broad
manifest diff. This closes these three issuer-key test constructors only;
canvas renewal and other service fixture custody still require review.
Keep this batch in the single UI feature PR and rerun the assembled-head
matrix after Core adoption.

2026-10-08 broad-PR boundary review: keep the remaining UI verification
fixtures (`credentials_compat/native.rs` Ed25519 VCDM and P-256 VDS-NC),
canvas renewal issuer signer, and any other issuer-owned test signing in the
single UI feature PR. Replace deterministic issuer signatures with public
signed vectors, or use the disposable remote signer where the test must prove
live signing. Classify holder, device, and ephemeral session keys separately;
do not delete those tests merely because they construct keys. Run focused
local tests after each fixture batch, then run the full local regression and
security/quality review on the assembled PR head. Avoid opening small PRs or
re-running hosted CI for intermediate fixture fixes.

The Core KMS-only bindings graph still enables P-256 ECDSA signing features
through SSI verification crates. This is a *source/dependency review gate* for
the broad Core PR, not proof of an exported local signer. Preserve ES256
VCDM/Open Badges verification while identifying the minimal verification-only
replacement boundary. Accept an ElevenID fork only if exact-artifact review
shows signer capability actually remains reachable or the stronger no-signer
artifact policy requires it; a manifest-only feature removal would silently
lose verification. The local Windows wheel's public Python API scan and 24
wheel-backed tests do not close this graph finding. Record the decision and
evidence on the same Core PR before UI pins its final reviewed SHA.

2026-10-08 Core wheel-symbol review: the local release build retains
`target/release/_marty_rs.pdb`, but its searchable names are dominated by
native AWS-LC symbols; exact-byte checks found no `ssi_jws`, `ssi_crypto`,
`SigningKey`, or `VerifyingKey` names. Absence of these strings is not a Rust
call-graph or dead-code proof. A first-party source scan found no direct
`ssi_jws::sign`, `ssi_crypto::SecretKey`, or SSI key-generation call in the
inspected Core crates, but the SSI verification dependencies still enable
their coupled signing features. Keep the artifact/reachability gate open;
neither the PDB nor this narrow source scan qualifies a KMS-only release
artifact. The Core feature PR and final UI pin remain pending.

2026-10-08 Credentials compatibility retirement checkpoint: the unreferenced
`rust/marty-rs/src/mdoc/issuance.rs` file still contained a PEM private-key
issuer signer even though `mdoc/mod.rs` did not compile it. That obsolete
source is removed. The mdoc evidence tests no longer instantiate a local
P-256 `SigningKey` merely to derive public device coordinates; they use the
public P-256 generator point. The Python Rust adapter's `RustMdocIssuer`,
`get_mdoc_issuer`, `PreparedMdoc`, and `issuer_key_pem`-accepting methods were
also retired; the presenter request helpers remain. Repository search found
no in-repo callers of those retired issuer exports. All 25 `marty-rs` library
tests, strict Clippy for library/tests, five focused Python custody tests,
Python import/export check, Ruff, targeted rustfmt and diff whitespace passed.
These are local source checks on the Credentials feature branch, not a
published wheel, full Python suite, native consumer cutover, or hosted CI.
Other compatibility adapters still advertise old local-key operations and
require consumer/data qualification before the Credentials PR can land.

2026-10-08 Credentials Python adapter retirement follow-up: the direct Rust
adapter and the nested SpruceID adapter no longer offer local key-manager or
issuer classes, singleton getters, or issuer factories. Their old methods
called removed `generate_p256_did_jwk` and `create_verifiable_credential`
native exports. The nested factory now creates only wallet and verifier
helpers; an explicit retired Multipaz selection fails closed instead of
falling through to SpruceID. Repository search found no in-repo consumers of
the removed key-manager/issuer names. Wallet and verifier helpers remain
importable. Fifteen focused custody/native-boundary tests passed, including
runtime export and fail-closed checks; Ruff and diff whitespace passed on the
touched files. This is another source-level Credentials branch increment, not
consumer qualification or the assembled broad PR review. The remaining
Python persistence key-manager wrappers and native artifact boundary still
need review before the feature branch can be offered for landing.

2026-10-08 Credentials persistence/port follow-up: both duplicate SQLAlchemy
key-manager wrappers and their key-pair tables were removed; these were able
to store JWK key material and expose local `generate_key`. The obsolete
Python `IKeyManager` and `ICredentialIssuer` ports and package exports were
retired with their only in-repo consumers. Credential wallet persistence,
wallet/verifier ports, holder `KeyPair` data type, and direct Multipaz
fail-closed test remain. A repository Python search found no remaining
references to the retired key-manager/issuer port names except absence
assertions. Twenty focused port/custody/native-boundary tests passed, plus
Ruff and diff whitespace checks on touched source. This does not yet prove
the full Python suite, built native wheel, or UI consumer qualification.

2026-10-08 Credentials broad Python regression checkpoint: `pytest tests/
packages/tests/ -q` with the two CI-excluded local-binding modules ignored
completed with 1,730 passed, 29 skipped, 200 subtests passed, and 11 failed.
Eight failures are in remote SD-JWT/JWT-VC issuance tests: the installed
`marty_rs` binding rejected the service's prepare-call argument shape (for
example, SD-JWT expected at most 12 positional arguments but received 13).
This is an artifact/API alignment gate: rebuild and install the reviewed
Core wheel, then rerun those tests before changing service semantics. Two
failures assert the Core revision across `Cargo.toml`, CI and
`release/dependencies.json`; the branch pins `a5cb567...` in manifests/CI
while release metadata records `7d501aea...`. Align all three only after
the final hardened Core commit and artifacts are qualified. One CORS
discovery-contract assertion got `Vary: Origin` where the contract expects
the four preflight request dimensions; investigate the installed Starlette
version and test runtime against the declared `starlette>=1.7.0` dependency.
None of these failures touches the removed Python key-manager/issuer adapter
surface directly. They remain open for the broad Credentials feature PR.
The local Python 3.12 test interpreter imports `marty_rs` from global
site-packages; its inspected SD-JWT/JWT-VC signatures omit the
`issuer_public_jwk_json` argument present in the hardened Core source at
`marty-bindings/src/remote_credential.rs`. Its installed Starlette is 1.0.0,
below this repository's declared minimum 1.7.0. Treat those local failures
as stale test-environment evidence until the pinned artifacts and dependencies
are installed; do not weaken the remote signing API to match that wheel.

2026-10-08 Core exact-link investigation: built `marty-bindings` in release
mode with `--no-default-features --features kms-only,extension-module` and a
Windows linker map using Rust 1.97.1. The map is preserved as
`artifacts/kms-core-bindings-link-map-2026-10-08.map` in the workspace (SHA-256
`b659000a1b4fcf4c468f0599387dd62979ddb3b486628151a450f53a4e690111`).
The corresponding local `_marty_rs.dll` SHA-256 is
`24c7a6b58db086f80fbb11e28cda9d9c5ddb2a521f93b13b253e2fdb780348d8`;
this is diagnostic build evidence, not a published wheel or release pin.
The production `cargo tree -e features,no-dev` excludes
`marty-crypto-test-support` but still enables `p256/ecdsa` through SSI. In
the linked map, `ssi_jws::decode_verify` remains, while the top-level
`ssi_jws::sign_bytes`/`encode_sign` entries present in its `.rlib` are not
listed as linked functions. The map also retains `ssi_jwk::ECParams`<-
`p256::SecretKey` and `<-k256::SecretKey` conversions and a P-256
`SecretKey::public_key` path. The `marty-verification::vcdm`
`CaptureMessageSigner` and SSI Data Integrity generic signing machinery are
linked to construct canonical bytes, but the capture implementation accepts
no private key and returns a placeholder for later remote completion.
The linked secret-key conversion code is nevertheless incompatible with a
strict private-key-free cryptography artifact claim. This closes the earlier
PDB-only uncertainty in favor of an actual artifact finding: split or
replace the SSI JWK/verification feature boundary (potentially a reviewed
ElevenID fork) while preserving ES256 VCDM/Open Badges verification, then
rebuild and repeat the map and behavior checks before accepting Core or
pinning its final SHA in UI/Credentials. Keep TLS rustls/AWS-LC signer
symbols classified separately as session/server transport capability; they
do not prove credential issuer signing.
Source follow-up narrows the replacement scope: `ssi-jwk` 0.4.0's
`secp256r1` feature unconditionally includes `JWK::generate_p256`, private
SEC1 parsing, and `ECParams`/`p256::SecretKey` conversions;
`ssi-jws` 0.5.0 calls those conversions from its coupled `sign_bytes` path;
`ssi-verification-methods` 0.3.0 exposes key-taking `sign_bytes` methods
under the same curve features. The upstream P-256 0.13 and locally cached
0.14 manifests both combine ECDSA signing and verifying under `ecdsa`.
Thus a P-256 manifest-only feature edit is insufficient. A reviewed
verification-only SSI fork or replacement must gate the private JWK,
JWS/method signing implementations together, retain public-key decoding and
VCDM/Open Badges verification, and preserve the keyless remote Data Integrity
prepare path. Repeat the linked-map audit on the rebuilt exact feature set.

2026-10-08 local SSI fork proof, not a release pin: cloned the current
`spruceid/ssi` monorepo at `d7593b911ee4b15365adb5b352d3631bef2aaa3b`
into workspace `ssi-kms-hardening-20261008`, branch
`security/verification-only-kms-20261008`. Its JWK/JWS/verification-method
crate versions match Core's locked versions and the inspected JWK/JWS source
matches the published registry sources. An experimental
`local-key-operations` feature now gates JWK key generation, private
multicodec import, and EC secret-key conversions in `ssi-jwk`, and the
key-taking `ssi-jws::sign_bytes` implementation. With the feature absent,
local JWS signing fails closed while public ES256 JWS verification passes.
`did-ion` required a third change to gate its `Sidetree::generate_key`,
`create`, and `recover` operations because `ssi-dids` depends on `did-ion`
unconditionally. The fork's public-only JWK and JWS integration tests passed
(two each), and `ssi-verification-methods` compiled with Ed25519/P-256
public support. This is a feasibility slice, not accepted code: old upstream
private-key tests still need retirement or public-vector replacement, direct
secret-taking methods in other SSI crates need review, and an opt-in local-key
feature is not itself a final no-private-key source policy.

Applied only these three crates to Core through local Cargo config, leaving
the checked-in Core manifests and lockfile unchanged after the experiment.
The existing ElevenID `ssi-jwt` security fork remained selected. KMS-only
`marty-bindings` check and release build passed. In the baseline Windows
link map, nine linked `ssi-jwk` text symbols contained `SecretKey` and five
`ed25519-dalek` symbols did; the experimental map has zero of each while
retaining `ssi_jws::decode_verify` and the 55 keyless
`marty-verification::CaptureMessageSigner` text entries. The experimental
map is preserved as
`artifacts/kms-core-bindings-ssi-experiment-link-map-2026-10-08.map`
(SHA-256 `18d04138b47ecc90b72f5c2a2b969ce0e42ecdbc0e86ae79b1ce086977708d98`),
and the local DLL hash is
`c6d3f789e267583c24aca3a9753f7be7488570c904a9466b1230a7894e5e14f07`.
With that local patch, 11 runnable VCDM and 24 Open Badges library tests
passed; 10 VCDM and five Open Badges tests were ignored because they require
marked disposable OpenBao signers. Before the broad Core PR, remove/replace
the remaining private-key tests and capabilities in the fork, run the live
tests, review the fork and full graph for feature loss, pin a reviewed
immutable fork revision, repeat the artifact audit and consumer checks, and
then adopt the final Core SHA in UI/Credentials. Do not treat this local
experiment as qualified custody or a published artifact.
Follow-up in the same local fork replaced JWK crate private fixture/generation
tests with public RSA, Ed25519, P-256 and multicodec evidence and removed the
Ed25519 private-DER test. Its eight library tests and two public-only
integration tests pass; the JWS public-only integration tests also pass (two).
The JWS crate's older local-signing unit tests and other upstream SSI
private-key tests have not yet been retired or replaced, so the user-requested
test-custody cleanup remains open in this fork. Targeted rustfmt and diff
whitespace checks passed. Core's checked-in lockfile was restored after the
experiment; no local path patch or unreviewed fork revision is pinned.

- [Core KMS implementation PR 308](https://github.com/ElevenID/marty-core/pull/308)
- [Core production crypto API removal PR 315](https://github.com/ElevenID/marty-core/pull/315)
- [Core audited boundaries PR 318](https://github.com/ElevenID/marty-core/pull/318)

- [DIDComm deferred work](https://github.com/ElevenID/marty-credentials/blob/e109b6c/docs/rust-migrations/didcomm-kms-outstanding.md)
- [Integration secret deferred work](https://github.com/ElevenID/marty-credentials/blob/e109b6c/docs/rust-migrations/integration-secret-secure-storage-outstanding.md)
- [BYOK preservation and contract hold](rust-migrations/marty-ui-worktree-cleanup-inventory-2026-09-07.md)

2026-10-08 broad dependency-batch checkpoint: the local SSI verification-only
experiment now removes the five private-key sign-and-verify unit tests from
`ssi-jws` and replaces their supported ES256, ES384, and RS256 verification
coverage with public-key and fixed-signature vectors. The RSA vector derives
from RFC 7515 Appendix A.2; the ES256/ES384 vectors were already present in
the upstream test suite. ES256K and recoverable/Keccak verification still need
public vectors before calling test-custody parity complete. The explicit
no-local-signing failure test remains. With the isolated three-crate local
patch, four JWS public-only integration tests passed and its library target
compiled. This is still an uncommitted local experiment, not an ElevenID fork,
product pin, feature PR, or exact release artifact.

Continue batching by dependency boundary: prepare one reviewed SSI fork change,
then one broad Core feature PR, one broad UI native/integration PR pinned to
reviewed Core, and one broad Credentials retirement PR after native
qualification. Keep local corrections on each branch and run hosted CI at
reviewed dependency and assembled feature heads, with required merge-queue
checks retained. The remaining fork review
must remove or permanently disable opt-in local signing/private-key paths,
audit JWK DER and optional algorithms, preserve supported public verification,
and repeat the exact Core artifact/link-map and consumer tests before opening
the Core PR.

2026-10-08 SSI ASN.1 boundary review: the local fork still let JWK's RSA and
Ed25519 ASN.1 conversion accept private fields with `local-key-operations`
disabled, and exposed private-key conversions under ordinary `rsa`, `ring`,
and `ed25519` features. The experiment now returns a dedicated fail-closed
error for private ASN.1 input, compiles private DER structures and private
conversions only behind the local-key feature, and tests rejection using
empty sentinels rather than stored keys. Three JWK public-only tests and four
JWS public-only tests pass. The exact Core KMS-only bindings graph passes
`cargo check` with the three local SSI patches; the alternate `ring` JWK
feature set and opt-in compile also pass. Core's checked-in lockfile was
restored after the local patch experiment. This closes a source-level gap but
does not yet prove the rebuilt release DLL/link map or complete the fork's
optional-feature/private-path review. No product dependency is pinned yet.
Follow-up also gates private RSA multiprime and Ed25519 DER helper types and
encoders; the eight public-only JWK library tests and the opt-in compile pass
after that change. The opt-in implementation remains a final-policy finding,
not an accepted production fallback.

2026-10-08 SSI JWS source-policy correction: the local fork no longer contains
JWK-backed signing implementations in `ssi-jws`; `sign_bytes` always returns
`LocalSigningDisabled`, while the signer trait remains available for remote
implementations. Its private-key documentation example was removed. The old
JWS feature name currently remains inert solely because `did-ion` forwards
it; it cannot re-enable signing. Four JWS public-only tests pass both without
and with that feature selected, and the patched Core KMS-only bindings graph
passes `cargo check`. Core's lockfile was restored afterward. A source review
found that `did-ion` still compiles `create_existing`, `update`,
`recover_existing`, and `deactivate` methods that call the separate
`ssi-jwt::encode_sign` path through its transaction registry. Those mutation
methods must be removed or replaced with remote signing before this fork can
be reviewed as a complete no-local-authority dependency. DID resolution must
remain intact. No fork pin, PR, or release qualification is claimed.

2026-10-08 Sidetree follow-up: the local `did-ion` patch now removes its
`DIDMethodRegistry` transaction implementation, local key generation,
`create`/`recover` helpers, and `update`/`recover_existing`/`deactivate`
methods that previously called `ssi-jwt::encode_sign`. The now-unused
`ssi-jwt` dependency and JWS local-key feature were removed. Public-key
`create_existing` construction, DID parsing/resolution, and verification of
fixed signed Sidetree operations remain. Five `did-ion` library tests pass;
the patched Core KMS-only bindings graph passes `cargo check`; four public
JWS vector tests still pass. This narrows the local fork to resolver and
verifier behavior, but a full dependency graph and release link-map audit,
remaining JWK private-feature removal, and downstream consumer review remain
required. The Core lockfile was restored after the local patch check.

2026-10-08 verification-only SSI source and artifact checkpoint: the local
`ssi-jwk` patch now physically removes its local-key feature, Ed25519/P-256/
P-384/secp256k1 key generation and private imports, RSA/Ed25519 private DER
types and encoders, and private-key conversion implementations. Private DER
input fails closed. The optional Aleo and BBS source modules still contain
private-key operations; neither feature appears in the exact patched Core
KMS-only bindings feature graph, so this is an artifact-scope finding rather
than a claim that every optional SSI build is KMS-only. Public JWK tests
(eight library plus three public-only), four JWS public-verification tests,
five Sidetree signed-operation verification tests, and the patched Core
KMS-only bindings check pass.

The Windows release bindings DLL was rebuilt with the final local three-crate
patch and linker map `artifacts/kms-core-bindings-ssi-final-link-map-2026-10-08.map`
(SHA-256 `e1fe74714499578b5eaf49642dc0b6dab15453d50dd71aa333ea2cdeda753ff6`);
the `_marty_rs.dll` SHA-256 is
`ce4210cc59904dd6ab5fa1a885b34ea42aa3e475b5a7a844d2c636abb42befba`.
Compared with the unpatched release map, linked `.text` symbols containing
`ssi_jwk` and `SecretKey` fell from 9 to 0, `ed25519_dalek` secret/signing
symbols from 5 to 0, while `ssi_jws::decode_verify` remains 2 to 2.
`marty_verification::CaptureMessageSigner` remains 55 to 55 and still requires
source-level review; a linked-symbol search alone cannot prove absence of
every private-key path. This is a local experiment, not a pinned ElevenID
dependency, PR, hosted CI result, or qualified distributable. Core's
checked-in lockfile was restored after all local patch commands.

Source review of the 55 linked `CaptureMessageSigner` symbols in
`marty-verification/src/vcdm.rs` classifies them as a keyless SSI canonical
message capture adapter. It accepts only EdDSA with no protocol transform,
stores the prepared message once, and returns a 64-byte zero placeholder so
SSI can serialize the proof configuration. The completion path replaces that
placeholder with the remote signature and verifies the resulting proof against
the public key before returning a credential. This explains why those symbols
remain in the KMS-only artifact; they do not by themselves indicate a local
private-key signer. The intermediate prepared envelope contains a deliberately
invalid placeholder proof and must not be exposed as an issued credential.

2026-10-08 JWK input-boundary follow-up: after the release-map experiment,
the local `ssi-jwk` patch also removed the unused deprecated `JWTKeys` private
wrapper and rejects deserialization whenever an EC/OKP/RSA private parameter
or symmetric `k` parameter is present. The rejection test uses only empty
sentinels, not a key fixture; four JWK public-only tests pass. With this
newer source, patched Core VCDM tests pass 11 (10 live-OpenBao cases ignored),
and Open Badges tests pass 24 (5 live-OpenBao cases ignored). The map and DLL
hashes in the preceding checkpoint predate this deserialization change and
must be rebuilt at a reviewed, pinned fork revision before artifact acceptance.
Public Rust struct fields can still hold private JWK parameters when directly
constructed; source/API review must decide whether to remove those fields or
prove they are unreachable from the product's production roots. The optional
Aleo/BBS modules also remain outside the measured Core feature graph.

2026-10-08 JWK Rust-construction review: consumers in SSI's DID/Tezos code
construct `ECParams`/`OctetParams` with public fields, so changing those
field types or visibility would expand the dependency patch beyond the three
isolated crates. The local JWK patch now also rejects serialization of any
directly constructed private EC/OKP/RSA parameter or symmetric `k` value;
`Display` prints a fixed prohibition marker instead of key material. Tests
use empty sentinels and show deserialization, serialization, DER encoding,
and private multicodec import fail closed. A legacy symmetric-key thumbprint
unit case was removed as incompatible with the KMS-only source boundary;
eight remaining JWK library tests and five public-only tests pass. Four JWS
public-verification tests, five Sidetree signed-operation tests, and the
patched Core KMS-only bindings `cargo check` pass after this change. Public
fields remain as source-level compatibility for SSI verifier types but no
local signing implementation consumes them, and the JWK parser/serializer
rejects private values. Full fork review and a rebuilt exact release artifact
are still pending; the prior map is not evidence for this latest source.
The full local `cargo test` targets (including documentation tests) now pass
for `ssi-jwk` with public EC/RSA/Ed25519 features (8 unit, 5 public-only),
`ssi-jws` with ES256/ES384/RS256 (4 public-only, 1 doc test; 1 existing
ignored doc example), and `did-ion` (5 signed-operation verification tests).
These are focused dependency tests, not downstream release qualification.
At the latest JWK serialization head, patched Core VCDM tests pass 11 with
10 live-OpenBao cases ignored, and Open Badges tests pass 24 with five
live-OpenBao cases ignored. Core's lockfile was restored after those checks.
Source searches of Marty Core and UI native Rust code find no direct
`DIDION`, `SidetreeClient`, or `DIDMethodRegistry` consumer; Core DIDComm
documentation explicitly excludes ledger-based `did:ion`. That supports
retiring the transitive SSI Sidetree transaction API for this product build
without a known supported consumer loss. It does not replace a full assembled
PR consumer review.

2026-10-08 grouped feature-PR execution update: carry this work as four
substantial dependency-ordered PRs, one per repository boundary. (1) The
ElevenID SSI fork PR removes local key authority in the JWK/JWS/did:ion graph
while preserving public verification and DID resolution. (2) The Marty Core
PR includes the reviewed SSI revision, KMS-only cryptographic APIs, issuer
test-custody cleanup, and exact wheel/link-map evidence. (3) The marty-ui PR
combines native Issuance, Signing Keys, Flow, Canvas, OpenBao Go extension,
integration-secret custody, BYOK, deployment, CI selection, and acceptance
updates at one assembled head. (4) The Credentials PR retires obsolete Python
and Rust issuer custody after the native consumer and data cutover is proven.
Batch corrections locally within each PR; run focused local checks during
development, then a full assembled-head regression/security/quality review
before invoking hosted CI. Required PR and merge checks remain mandatory.
This grouping is to avoid repeated CI on small intermediate PRs, not to waive
coverage or release gates.

The SSI dependency change has been transplanted onto the existing
`ElevenID/ssi-elevenid` fork at base `93e812aa68f5ea9576bc7599995d085f673a46c4`
in local branch `security/verification-only-kms-elevenid-20261008`. Fork-specific
`ring` 0.17.14 updates were preserved. The current staged batch spans JWK,
JWS, did:ion and follow-on verifier/test consumers; there is no commit,
push, PR, or product pin yet.
With the fork-based local patch, JWK's eight library and five public-only tests,
JWS's four public-only and one documentation test, and did:ion's five
signed-operation tests pass. JWK's `ring` feature check and Core's exact
`marty-bindings` KMS-only `cargo check` pass. Core's checked-in lockfile was
restored after the local dependency check. The fork's `build.yml` runs hosted
build/lint on PRs to main and skips draft PRs; prepare the full reviewed batch
before opening a ready PR. Remaining SSI gates include complete optional
feature/source audit, supported public-verification parity, downstream
consumer review, and a release linker-map rebuild at a pinned revision.

2026-10-08 dependency-wiring correction: self-review found that the initial
isolated three-crate test patch had changed SSI internal workspace dependencies
to registry versions. That supported the narrow Core experiment but would
mix patched and registry SSI identities in the fork's own workspace. The
fork-based branch now restores its internal workspace dependencies and keeps
only the intentional removal of did:ion's `ssi-jwt` dependency. Its focused
JWK, JWS and did:ion tests still pass with local SSI workspace crates. A
fresh Core check against that real wiring failed on duplicate SSI types:
Core's existing separately pinned `ssi-jwt-elevenid` and registry verifier
crates resolve different `ssi-claims-core`/JWK identities from the patched
fork. Do not use the earlier successful isolated Core check as evidence for
the final dependency arrangement. The broad Core PR must adopt a coherent
SSI source graph, including the existing JWT security fix, before its
bindings check, behavior tests, and release map are repeated. Core's
checked-in lockfile was restored after the failed experiment. Targeted
Clippy with warnings denied passed for the three changed SSI crates after
two small quality fixes.

The fork-wide `cargo check --workspace --offline` found one EIP-712 method
that still constructed a secp256k1 secret key from a JWK. Its JWK-backed
signer now fails closed with an explicit remote-signer diagnostic; public
signature recovery and account verification remain. The full workspace
`cargo check` then passed. A workspace test compile found private-key
generation in SD-JWT key-binding and did:jwk fixtures. The former redundant
local sign-roundtrip was removed while the existing signed public KB-JWT
verification vector remains; the did:jwk roundtrip now uses a fixed public
P-256 JWK and its private-input rejection case uses an empty `d` sentinel.
These changes are part of the same SSI fork PR, not separate CI batches.
Another `cargo test --workspace --no-run` exposed further VC, did:ethr,
did:pkh and root example/test signing fixtures; that run also hit a Windows
`link.exe` insufficient-disk-space error while linking many targets in
parallel. Full-workspace test-custody conversion and test qualification
remain open. The fork source currently passes rustfmt and diff whitespace
checks. Focused did:jwk tests pass six of six. SD-JWT's nine library tests,
including signed public KB-JWT verification, pass; two decode integration
tests still deserialize a private JWK and invoke local signing, so they fail
under the new boundary and need fixed signed public vectors. Further VC and
DID issuer-style fixtures require the same review before a PR is ready.

2026-10-08 coherent SSI graph checkpoint: a local Cargo patch now sources
all 17 SSI crates used by Core, including `ssi-jwt`, from the same
`ElevenID/ssi-elevenid` worktree. With this arrangement, Core's
`marty-bindings` check passes and `marty-verification --lib` passes 280 tests
with 72 opt-in tests ignored. The previous duplicate-type failure was caused
by patching only three workspace crates while keeping the separate JWT fork
and registry verifier crates. This is local dependency evidence only: before
landing, pin one reviewed SSI fork revision across the actual Core graph,
confirm the prior JWT security fix survives, run the exact wheel/release-map
and live-provider suites, and restore Core's lockfile after experiments. The
lockfile was restored after these checks.

The SD-JWT issuer and KB signed vector now lives in one shared fixture used
by both key-binding verification and decode tests. The decode cases no longer
deserialize a private JWK or invoke local signing. All nine SD-JWT library
tests and both decode integration tests pass. Its three `full_pathway` tests
still generate fresh disclosures and use a local JWK signer; they require a
remote signer or equivalent fixed signed cases while retaining reveal and
retention assertions. A `cargo check --workspace --tests --offline` inventory
avoided the Windows link failure and identified remaining compile-time local
key generation in VC JOSE/COSE (four sites), did:ethr (one), did:tz (five),
did:method:key (six), and did:pkh (three), plus runtime private-key fixtures
not caught by compilation. Convert these within the same SSI feature batch,
then rerun test selection and review before opening its PR.

The shared SD-JWT fixture was checked by decoding its issuer payload: it
contains public `cnf.jwk` coordinates without a private `d` parameter. The
fork's `ssi-jwt` manifest also retains the ElevenID removal of the unused
`serde_with` dependency. The full fork test-target compile inventory is
saved at `artifacts/kms-ssi-fork-test-check-2026-10-08.log`; it is a failing
inventory, not a passing gate. Rustfmt and staged diff checks pass at this
checkpoint. No fork branch has been pushed and no hosted CI has run.

2026-10-08 did:key public-resolution fixture batch: four shared public JWK
fixtures (Ed25519, P-256, P-384 and secp256k1) were derived from reference
coordinates with all private fields omitted and parsed back to confirm their
field sets. The did:key `fetch_public_jwk` coverage moved to a focused
integration target, preserving generation, resolution and public-key equality
assertions without private-key generation. All four tests pass with the P-384
feature enabled. The did:key issuer proof tests still use local signers and
remain open; this public-resolution result does not qualify them. Keep these
fixture changes in the same broad SSI fork PR.

2026-10-08 did:key signed-vector conversion: an isolated checkout of the
unmodified ElevenID SSI base generated the existing deterministic Ed25519,
secp256k1 and P-256 proof cases once. Only their public JWKs and complete
signed VCs were copied into the hardening branch as fixed fixtures. The
reference commands passed and their logs are preserved at
`artifacts/kms-ssi-vector-did-key-ed25519-2026-10-08.log` and
`artifacts/kms-ssi-vector-did-key-ec-2026-10-08.log`; the reference checkout's
temporary print edits were then restored. The fork's three local DID:key
private-key issuance/signing tests were removed and replaced with one shared
verification helper that checks DID derivation, each exact JWS, valid
signature, and rejection after issuer tampering. Four public-resolution and
three signed-vector cases pass; the five did:key library resolution tests
also pass. The three new public JWK fixture field sets were checked to
exclude `d`. This preserves the supported verification assertions without
shipping local signing code in those tests. Other SSI signer tests and the
full workspace test gate remain open in the same broad dependency PR.

2026-10-08 VC JOSE/SD-JWT signed-envelope conversion: the separate clean
ElevenID SSI reference checkout ran its seven library tests and recorded four
public P-256 JWKs plus complete signed enveloped VC/VP objects. The command
log is preserved at `artifacts/kms-ssi-vector-vc-jose-cose-2026-10-08.log`;
temporary reference print edits were restored afterward. The fork's four
local-JWK signing roundtrips were replaced by one integration target that
parses each fixed envelope, decodes its JOSE or SD-JWT payload, and verifies
the signature against the corresponding public JWK. Four integration tests
and the remaining three COSE library tests pass; the four new public JWK
fixture field sets were inspected to exclude `d`. This removes four
more compile-time private-key test constructors without dropping verification
or envelope-decoding coverage. Full fork workspace `cargo check` passes.

Review also found that `SdJwtVp::sign_into_enveloped` labeled its VP result
as `EnvelopedVerifiableCredential` despite using a VP SD-JWT media type and
documenting a presentation. The broad SSI batch now returns
`EnvelopedVerifiablePresentation`; the fixed VP envelope and verifier test
cover the corrected type. There are no public deployments requiring old
envelope-type compatibility. The latest fork-wide test compile still fails
on did:ethr, did:tz, and did:pkh local-key test constructors; VC JOSE/SD-JWT
and did:key no longer appear in that compile-error inventory. Those remaining
fixture conversions and runtime private-key test audits are next.

Focused Clippy with warnings denied now passes for `did-method-key` and
`ssi-vc-jose-cose` across all targets (with P-384 enabled). A one-line
`ssi-eip712` redundant-reference fix was needed under the local Rust 1.97
lint toolchain. Rustfmt and staged-diff checks pass. No fork PR or hosted CI
has been opened; the remaining DID and SD-JWT full-pathway test work still
belongs in this one large fork feature PR.

2026-10-08 broad-PR execution decision: keep the existing four repository
feature PRs as the delivery units. Accumulate the SSI verification-only and
public-vector work in one fork PR; take one coherent fork revision into the
Core PR; assemble native Rust services, OpenBao Go extension, deployments and
acceptance in one UI PR; retire the obsolete Credentials paths in one
Credentials PR. Review each assembled branch for feature parity, security,
DRY design and quality, run focused local checks during development, and run
the full required gate on the assembled head before a ready PR. Avoid pushing
small intermediate changes just to trigger hosted CI; do not skip required
release and merge checks.

The did:ethr local-signing credential/presentation test has now been converted
to six fixed signed vectors plus one public-only JWK. Both recovery and
EIP-712 suites preserve valid credential and presentation verification,
exact signature assertions, and wrong issuer, wrong key, altered signature and
wrong holder rejection. The two new public-verification integration tests
pass. The vectors were produced by the unmodified fork-base reference test
and captured at `artifacts/kms-ssi-vector-did-ethr-2026-10-08.log`; the
temporary reference instrumentation was restored. This remains in the same
SSI fork feature batch. did:tz, did:pkh, SD-JWT full-pathway and remaining
runtime private-fixture audit still block the fork-wide test gate.
The latest fork-wide test-target compile inventory is
`artifacts/kms-ssi-fork-test-check-2026-10-08-4.log`: did:ethr is cleared;
remaining reported constructors are in did:tz (five), did:pkh (three), and
the root `tests/send.rs` Send-future test (one). Other runtime signer tests
will need the same public-vector or remote-signer review after compilation
advances. This inventory failed as expected and is not a passing workspace
gate.

2026-10-08 did:tz public-vector conversion: the unmodified fork-base test
produced signed tz2 (secp256k1 recovery) and tz3 (P-256 Blake2b) credentials,
wrong-key credentials and presentations, plus the existing tz1 negative case;
capture is `artifacts/kms-ssi-vector-did-tz-2026-10-08.log`. Temporary
instrumentation in the reference checkout was restored. The fork branch now
uses public-only JWKs and fixed signed vectors in all nine did:tz tests,
retaining valid VC/VP verification and wrong issuer, wrong key, altered proof
and wrong holder rejection for tz2/tz3. The tz1 historical invalid-signature
case stays negative, with local signing removed; its public DID derivation
fixture no longer has `d`. All nine tests pass and did:tz all-target Clippy
passes with warnings denied. The Tezos-only feature combination exposed three
conditional-field Clippy warnings in common Data Integrity options; scoped
annotations explain why struct updates are needed when EIP-712 is combined.
Rustfmt and staged diff checks pass. The next workspace test-target inventory,
`artifacts/kms-ssi-fork-test-check-2026-10-08-5.log`, no longer reports
did:tz errors. It still fails on did:pkh's three local key constructors and
the root `tests/send.rs` constructor; runtime private signer fixtures remain
to audit. This is progress inside the one broad SSI fork PR, not a separate
CI batch.

The root Send-future type check now uses a public P-256 JWK and a stub with
the remote signer trait shape. It still proves that constructing the Data
Integrity signing future is `Send`, and it never performs a signature or
holds a private JWK. `cargo test --test send --no-run` passes and the specific
`data_integrity_sign_is_send` test passes. Running the whole `send` target
exposed two independent v1/v2 VC tests that still deserialize private JWKs
and locally sign, so that full target fails until those tests are converted.
The optional P-384/BBS cases in that target also need explicit fixture or
remote-signer review. Do not treat the compile-only type check as a passing
root test suite.
Follow-up in the same root test target: the unmodified reference checkout
captured signed Ed25519 VC v1, P-256 VC v2 and P-384 VC v2 vectors in
`artifacts/kms-ssi-vector-root-vcdm-2026-10-08.log`, and temporary source
instrumentation was restored. The fork tests now verify those fixed signed
credentials through DID resolution and reject a substituted issuer. The
complete `send` target passes four tests with `secp384r1` enabled, and
warnings-denied Clippy passes for that target. The optional BBS test in the
same file still generates a local secret and remains open for the optional
feature audit; the all-feature target has not been qualified.

2026-10-08 did:pkh full matrix conversion: the clean ElevenID fork-base
checkout passed its original 12-case signing/verification matrix and emitted
the public JWK, valid signed VC, wrong-key signed VC and valid signed VP for
each case. The immutable capture is
`artifacts/kms-ssi-vector-did-pkh-2026-10-08.log`; temporary reference
instrumentation was restored. The fork branch replaced its two local signer
helpers and matrix test with one 12-case public-verification fixture covering
Ethereum recovery, EIP-712, personal-signature and typed-data forms, Tezos
Ed25519/P-256 forms, Solana, Bitcoin and Dogecoin. The replacement asserts
case identity/chain and DID derivation from a public JWK, valid VC/VP
verification, and wrong issuer, wrong key, altered VC/VP signature and wrong
holder rejection. All 12 cases pass, and the fixture's 12 public JWKs were
checked to exclude `d`. A separate DID-generation library test still had an
unused Ed25519 private `d`; removing it preserved that test. All three
remaining did:pkh library tests pass, as does warnings-denied all-target
Clippy. Rustfmt and staged diff checks pass.

`cargo +1.97.1 check --workspace --tests --offline` now passes for the full
SSI fork (log `artifacts/kms-ssi-fork-test-check-2026-10-08-6.log`). This
clears the compile-time local-key constructor inventory, but does not prove
that all runtime tests or optional features pass, nor that the fork is
universally free of local-key operations. Runtime private-fixture and
optional-feature review remain inside this same large SSI feature PR.

2026-10-08 SD-JWT full-pathway conversion: the clean fork-base checkout
passed all three original tests and captured four signed SD-JWT examples
(regular claims, array claims, and both nested concealment pointer orders)
in `artifacts/kms-ssi-vector-sd-jwt-full-pathway-2026-10-08.log`; its
temporary instrumentation was restored. The fork tests now read those fixed
issuer/disclosure vectors and a public-only P-256 JWK, retaining full
cryptographic verification, disclosure reveal, selective retention, array
item retention, nested clearing, and the malformed inner-only disclosure
rejection. The first nested pointer order is now verified explicitly too.
All three pathway tests and the complete `ssi-sd-jwt --tests` selection pass;
warnings-denied all-target Clippy, Rustfmt and staged diff checks pass.
This removes the known SD-JWT runtime private-key fixture without creating
a separate PR or CI batch. Other fork runtime/optional-feature tests still
need audit.

2026-10-08 optional BBS root-test conversion: the clean fork-base checkout
passed `bbs_2023` and emitted a public BLS12381G2 JWK plus its signed base
credential (`artifacts/kms-ssi-vector-root-bbs-2026-10-08.log`); temporary
instrumentation was restored. The fork test now parses those public-only
fixtures, derives the same selective proof, verifies the derived credential,
and asserts the selected `foo` claim remains while `bar` is concealed. The
base BBS proof itself is not directly verified by this library path (it
returns `InvalidSignature`); the original test likewise verified the derived
proof. With BBS and P-384 enabled, all five root `send` tests pass, and
warnings-denied Clippy passes for that target. This removes that optional
test's local BLS key generation, but does not qualify every BBS feature or
implementation module. The first candidate run exhausted local disk while
compiling, before tests; the disposable reference Cargo target was safely
cleaned (12.0 GiB), then the candidate run passed. Source branches and vector
evidence were preserved.

2026-10-08 runtime-fixture audit follow-up: the `ssi-tzkey` Ed25519 and
secp256k1 self-signing tests now verify their already asserted Tezos
signatures with public JWKs and reject a changed message. All six crate
library tests pass. The `ssi-jwt` documentation's private-JWK local-signing
example was removed; its public verification example remains.

The clean fork-base `did:web` test emitted its signed VC at
`artifacts/kms-ssi-vector-did-web-2026-10-08.log`; temporary instrumentation
was restored. The fork `did:web` test now uses that fixed VC while retaining
local web DID resolution, exact signature, valid verification and wrong
issuer rejection. All three did:web library tests pass. The clean fork-base
zcap delegation/invocation roundtrip similarly emitted signed delegation,
invocation and wrong-invoker delegation at
`artifacts/kms-ssi-vector-zcap-2026-10-08.log`; temporary instrumentation
was restored. The fork test now parses those three public-verification
fixtures, checks them against the expected claims and verification-method
references, and retains valid delegation/invocation, tampering and wrong
invoker rejection. All three `ssi-zcap-ld` library tests pass. Rustfmt,
staged diff checks and the full fork test-target compile pass at
`artifacts/kms-ssi-fork-test-check-2026-10-08-7.log`.

Security audit finding: `ssi-cose` still implements local `CoseKey` secret
decoding, secret encoding/key generation and `CoseSigner` signing, with test
cases that materialize secret keys. This is outside the JWK/JWS fail-closed
surface implemented so far and contradicts a universal KMS-only claim.
Review the production COSE/API graph and replace or remove local authority
while preserving supported public verification before the SSI PR is ready.
Warnings-denied `ssi-zcap-ld` Clippy currently fails in `ssi-cose` under its
feature set because `CryptoRng`/`RngCore` are unused when COSE key-generation
features are off. Do not paper over that warning while local COSE custody
remains unreviewed. No hosted CI or fork PR has been opened.

2026-10-08 CI batching decision: keep one broad feature PR per repository
(ElevenID SSI fork, Marty Core, native UI/OpenBao extension, Credentials),
including related API removal, fixture conversion, docs, security review and
regression checks in that PR. Use local targeted and workspace verification
while assembling each batch; defer hosted CI until a coherent feature branch
is ready for review. Do not split COSE or remaining optional-feature cleanup
into small PRs merely to obtain earlier CI feedback. Before each PR, audit
the full diff for local secret-key authority, lost verification coverage,
unsupported algorithms, cross-repository pin consistency and deployment
instructions. This batching reduces CI runs, but each PR remains blocked on
its own passing checks and review rather than bypassing them.

The clean fork-base COSE signature tests passed for Ed25519, secp256k1,
P-256 and P-384, each tagged and untagged. Their signed COSE objects and
public-only COSE keys were captured at
`artifacts/kms-ssi-vector-cose-signature-2026-10-08.log` and copied to
`crates/claims/crates/cose/tests/fixtures/signed-cases.json` on the fork
branch. The fork branch now uses those vectors to verify all eight cases and
reject signature tampering; it also roundtrips the eight public keys and
rejects a COSE `d` parameter without storing actual private values in the
test. It removes COSE secret decode/encode/generation and the `CoseKey`
signer implementation. The generic `CoseSigner` interface remains available
for remote signers. The original VC/VP COSE signer tests also emitted signed
envelopes and public COSE keys to
`artifacts/kms-ssi-vector-cose-vc-2026-10-08.log`; temporary reference
instrumentation was restored. The fork replaces those tests with one shared
public-key VC/VP verification test. `ssi-cose` library tests and doctests
pass with Ed25519, secp256k1, P-256 and P-384 enabled; the COSE VC/VP test
passes; warnings-denied COSE/VC Clippy and full fork test-target compile pass
(`artifacts/kms-ssi-fork-test-check-2026-10-08-8.log`). The previously blocked
`ssi-zcap-ld` Clippy now passes after COSE's feature-off import issue was
removed and an independent derivable `Default` in its test was corrected.
Rustfmt and staged diff checks pass. This COSE work is staged inside the
same SSI feature batch; no hosted CI, fork commit or PR yet.

Next SSI fork gate: audit optional Aleo, which still exposes
`generate_private_key_jwk`, private-JWK parsing and local `sign` in
`crates/jwk/src/aleo.rs`, plus its tests and `examples/genaleojwk.rs`.
Determine the public verification surface to preserve, then remove those
local authority paths and private test fixtures in the same fork PR. Audit
remaining examples and feature combinations, run broader runtime tests, and
review the complete staged diff before a commit or hosted CI run.

2026-10-08 optional Aleo follow-up: the clean fork-base checkout passed its
original Aleo sign/verify test and emitted a public Aleo JWK plus signed
`asdf` message at `artifacts/kms-ssi-vector-aleo-2026-10-08.log`; temporary
instrumentation was restored. The fork now removes Aleo local key
generation, private-JWK parsing, JWK-backed signing and its private fixture
and obsolete generation example. Public address decoding and verification
remain, with a fixed public-only vector asserting valid signature, changed
message rejection and constructed private-parameter rejection. The
`AleoMethod2021` local signing entry point is removed; its verification
method remains. The data-integrity suite's pre-existing unsupported signing
path now returns `UnsupportedAlgorithm` rather than panicking. The Aleo
verification method no longer reports a malformed public input as an invalid
secret key. The targeted Aleo test, root `ssi` all-target Aleo check,
warnings-denied Aleo crate Clippy, Rustfmt, staged diff check and full fork
workspace test-target check pass (`artifacts/kms-ssi-aleo-root-check-2026-10-08.log`,
`artifacts/kms-ssi-fork-test-check-2026-10-08-9.log`). These changes remain
staged inside the large SSI feature batch; no hosted CI, fork commit or PR.

Next SSI gate: root examples `issue.rs`, `present.rs`,
`issue-status-list.rs` and `issue-revocation-list.rs` still read private JWK
fixtures and invoke local signers. Their runtime behavior fails under the
fork's private-key deserialization policy even though example targets
compile. Replace their execution path with a remote signer boundary or
public verification examples before deleting the remaining private root
fixtures. Other unused private root fixtures and commented references must
also be audited. A compile-only check is insufficient to qualify these
examples or a universal keyless claim.

2026-10-08 optional BBS custody removal: the existing bbs-2023 baseline
serialization test passed before modification with `bbs,w3c` enabled. The
fork now removes `ssi-bbs` secret-key export, local signing and key
generation; removes BLS12381G2 JWK secret-key generation and conversion;
and removes local BBS signing through generic JWK and Multikey signers.
Public BBS JWK conversion explicitly rejects a directly constructed
private parameter. The bbs-2023 test no longer contains a private key: a
fixed signature from its existing expected proof exercises the signer
boundary, and the test checks the 64-byte header, 14-message batch digest
and exact serialized proof. It does not claim remote KMS custody. A new
public-only JWK test covers public roundtrip and private-parameter rejection.
All six `ssi-data-integrity-suites` BBS library tests, the JWK test, and all
five root `send` tests with BBS/P-384 enabled pass. Warnings-denied Clippy
passes for the affected BBS/JWK/verification-method/suite crates; Rustfmt,
staged diff check and full fork workspace test-target check pass. Evidence:
`artifacts/kms-ssi-bbs-tests-2026-10-08.log` and
`artifacts/kms-ssi-fork-test-check-2026-10-08-10.log`. The work is staged in
the existing broad SSI feature batch; no hosted CI, commit or PR yet.

Further SSI custody audit is still required: some direct cryptographic
signing implementations (for example, Multikey's Ed25519 `SigningKey`
implementation) and private-root examples remain. The generic JWK signer
now has no BBS signing branch, but its wider trait exposure should be
reviewed against a fully KMS-only API, not treated as proof by search alone.

The follow-on source audit found a deeper production API gap: `ssi-crypto`
still exports `SecretKey` with generation and `AlgorithmInstance::sign`,
and verification-method implementations still accept direct Ed25519/P-256
signing keys and generate local keypairs. These are independent of JWK's
fail-closed serialization policy. The next SSI work must trace their callers
and retire local authority at the cryptographic and verification-method
layers while preserving public verification and the generic remote signer
contracts. The fork is not yet universally KMS-only.

2026-10-08 lower `ssi-crypto` custody removal: source inventory found no
in-repository callers of its exported `SecretKey`,
`AlgorithmInstance::sign`, or legacy Ursa BBS/BLS keypair generation beyond
the crypto crate itself and a claims-core error conversion. The fork now
removes that secret-key enum and its constructors, local signing method,
legacy BBS module and signing dependencies, and the unused conversion. Root
`bbs` feature selection now uses the maintained `ssi-bbs` verification and
derivation path without enabling the legacy `ssi-crypto/bbs` feature. Public
`PublicKey` parsing/verification and hashing remain. The four `ssi-crypto`
all-feature tests pass; warnings-denied all-target Clippy passes for
`ssi-crypto` and `ssi-claims-core`; full fork workspace test-target check
passes; root all-target compile with BBS, Aleo and P-384 enabled passes;
`cargo check --locked --offline -p ssi-crypto`, Rustfmt and staged diff check
pass. Logs: `artifacts/kms-ssi-fork-test-check-2026-10-08-11.log` and
`artifacts/kms-ssi-root-optional-check-2026-10-08.log`. This remains staged
in the same SSI feature batch; no hosted CI, commit or PR yet.
The locked root `ssi` BBS dependency tree contains neither legacy Ursa nor
`pairing-plus` after this removal.

This removes the generic crypto crate's direct local secret-key API. It does
not prove the full fork is KMS-only: method crates still expose direct
Ed25519/P-256 signing key generation and signing, and root examples still
depend on private JWK fixtures. Those callers and their runtime tests are
the next removal and fixture-conversion gate.

2026-10-08 direct verification-method custody removal: the fork now removes
Ed25519VerificationKey2018's raw `SigningKey` signer,
Ed25519VerificationKey2020's local keypair generator and raw-key signing,
EcdsaSecp256r1VerificationKey2019's raw `p256::SecretKey` signing, and
Multikey's local Ed25519 keypair generator and direct `SigningKey` signer.
The public-key constructors and verification implementations remain. The
existing JWK-backed sign methods still compile but ultimately fail closed
through `ssi-jws`; their wrapper API and generic `SingleSecretSigner` /
`LocalSigner` boundary need removal in the next pass. The unused
`rand_core` feature dependency was removed from verification-methods.
Full fork workspace test-target check passes
(`artifacts/kms-ssi-fork-test-check-2026-10-08-12.log`), warnings-denied
all-target verification-methods Clippy passes with Ed25519, P-256, BBS and
Aleo enabled, and all five root public `send` tests pass with BBS/P-384
(`artifacts/kms-ssi-root-public-send-2026-10-08.log`). Rustfmt and staged
diff checks pass. No hosted CI, commit or PR yet.

Private-fixture audit: the fork removed four unused private JWK JSON files,
one unused private RSA DER file, and a fully commented-out DID document test
file whose stale references named private fixtures. The public RSA DER file
used by the active `ssi-jwk` test remains. The private RSA and Ed25519 root
JSON fixtures still referenced by the four issuance/presentation examples
remain until those examples are converted; the remaining fixture inventory
must be checked again after conversion.

2026-10-08 generic signer boundary: `ssi-verification-methods-core` no longer
implements `MessageSigner` for `JWK`; downstream code therefore cannot use a
JWK directly as that remote-capable signer interface. The default
`MessageSigner::sign_multi` and legacy `SigningMethod::sign_bytes_multi`
return `TooManyMessages` rather than panicking when handed an unsupported
batch. Full fork workspace test-target check and warnings-denied core
all-target Clippy pass. This is staged in the same large SSI feature batch,
without hosted CI or a separate PR.

The next SSI sub-batch must retire `SigningMethod`, `MethodWithSecret`,
`SingleSecretSigner` and `LocalSigner` together with JWK-backed method
implementations. Three active Data Integrity suite signature fixtures still
contain `secretKeyMultibase`; convert them to fixed public signed vectors and
remote-shaped deterministic signer probes while keeping their expected output
checks. Root and status-list issuance examples still consume private JWK
files; convert their runtime path or replace with public verification examples
before deleting the last private root fixtures. Compile-only success does not
qualify those example behaviors. Keep the SSI changes together as one broad
feature PR and batch corrections locally before hosted CI.

2026-10-08 Data Integrity vector conversion: the two active
`ecdsa-rdfc-2019` signing fixtures no longer carry a private multikey. Their
test signer returns the fixed signature from the W3C expected proof and
asserts the selected verification method, requested ES256/ES384 algorithm,
and exact SHA-256 digest of the prepared signing message. The tests retain
exact generated-output comparison;
the corresponding public verification tests remain. Before conversion, both
signing tests failed because private multikey-to-JWK conversion was disabled;
after conversion, all four RDF canonicalization signing/verification cases
pass with P-384 enabled. Warnings-denied all-target Clippy and Rustfmt pass
for the changed crate. This test signer demonstrates the remote-shaped
request/response boundary; it is not evidence of KMS custody.

At this intermediate checkpoint, the same nine-case suite had eight passes and one failing
`ecdsa-sd-2023` signing case. That fixture still has both an issuer private
multikey and a second proof-scoped private key. Source inspection found
`ecdsa_sd_2023/signature/base.rs::generate_proof` locally creates a P-256
secret when an option is absent, decodes the option's private multikey when
present, and directly signs every non-mandatory RDF line. This is a separate
production custody path below the outer signer interface, not merely a test
fixture issue. Define and implement a remote proof-scoped key creation/signing
capability that returns its public key and signs those lines without exporting
the private key; route the suite's outer signature and the proof-scoped
signatures through that capability. Then convert the SD fixture to public
vectors, remove its private test options and local generation/signing code,
and run the full nine-case suite. Do not suppress the failing signing case or
claim ECDSA-SD issuance is KMS-only before this is done.

2026-10-08 ECDSA-SD fork boundary implemented: `MessageSigner` now has a
`sign_proof_scoped_p256` request/response capability whose default is an
explicit unsupported error. Both the algorithm adapter and AnySuite adapter
forward the call. The ECDSA-SD base-proof implementation no longer generates
or decodes a local P-256 private key and no longer signs RDF lines locally;
it requests remote proof-scoped signatures and a SEC1 public key, verifies
signature count and every returned signature against its corresponding RDF
line, then uses the returned public key for the outer issuer signature. The
private `keyPair` signature option was removed from both specific and
AnySuite options. The active ECDSA-SD signing fixture now contains only public
proof data and fixed signer responses, with pinned digests for all 14
proof-scoped lines and the outer issuer message. All ten suite cases pass,
including a new negative case that corrupts a proof-scoped signature and
proves rejection. Full fork workspace test-target check, targeted
warnings-denied all-target Clippy, Rustfmt and diff checks pass. This remains
in the single broad staged SSI feature batch, without hosted CI or PR.

The fork now exposes the necessary boundary but does not itself implement
remote custody. Before accepting ECDSA-SD issuance, the Core/UI remote signer
must implement proof-scoped P-256 key creation and per-line signing in a
scoped OpenBao operation, prove no private bytes cross the plugin boundary,
and verify lifecycle, authorization and crash/restart behavior. The existing
OpenBao HAIP P-256 code only generates persistent ECDH-ES decryption keys;
its `haip/decrypt` route is not a signing route and cannot be counted as this
capability. The default unsupported error fails closed until a qualified
implementation is wired. The broader SSI local signer wrapper/API removal and
private root example conversion remain open.

2026-10-08 Multikey local-authority retirement: after the ECDSA-SD test and
options conversion, the fork's `MultikeyPair` type had no callers. That public
type still accepted `secretKeyMultibase` and converted it to a JWK, so it and
its pair-only conversion error were removed. The generic `SigningMethod<JWK>`
implementation for `Multikey` was also removed; the `AnyMethod` local signer
dispatcher no longer routes Multikey through it, including the multi-message
case. Public Multikey parsing, JWK conversion, byte verification and the
ECDSA-SD public proof path remain. Full fork workspace test-target check and
warnings-denied all-target verification-methods Clippy pass; Rustfmt passes.
This is staged with the same broad SSI feature batch, without a separate PR
or hosted CI. Remaining direct JWK-backed method signers, local wrappers and
private examples still need removal before the SSI fork can be described as
KMS-only.

2026-10-08 generic local signer API retirement: the fork no longer exports
`SingleSecretSigner`, `LocalSigner`, `MethodWithSecret`, or `SigningMethod`.
Ten remaining JWK-backed `SigningMethod` implementations and ten direct
verification-method `sign`/`sign_bytes` helpers were removed. The generic
`Signer` and `MessageSigner` interfaces remain for external KMS providers,
including the ECDSA-SD proof-scoped request. The four root issuance and
presentation examples and the VC custom-credential signing example were
deleted because they generated or read local private keys and could no longer
run under the fork's private-key denial. Their checked-in signed public output
fixtures remain for verification coverage. The status-list sample retains
read and unsigned-create behavior; its private-key JWT-signing command and
`--key` create path were removed. Root README and crate documentation now
describe the remote signer contract, and the last two private root JWK fixture
files were deleted. This intentionally removes obsolete local-key sample
flows; production remote issuance capability still needs Core/provider
qualification, not an inference from sample removal.

The broad change passes fork workspace all-target compile and warnings-denied
all-target Clippy for the affected verification, status, VC and root crates.
The ten Data Integrity suite cases still pass, including ECDSA-SD signing and
bad proof-scoped signature rejection. Root doctests pass after running the
JSON-LD VC verification example on an explicit 16 MiB thread stack; its
default Windows test-main stack overflowed in a local run. The retained
status-list CLI `create` command produced a valid unsigned
BitstringStatusListCredential. All five public root `send` signed-vector tests
pass with BBS/P-384 enabled. No hosted CI, commit or PR yet; keep this in the
single large SSI feature PR. The next source audit found remaining private
Tezos signing in `ssi-tzkey` and private-key construction in did:tz tests,
plus stale dids documentation referring to `JWK::generate_p256`; these need
conversion before making a universal KMS-only claim.

2026-10-08 Tezos verification-only batch: `ssi-tzkey` no longer parses an
`edsk` secret into a JWK or exports `sign_tezos`; its unused Ed25519 signing
dependency was removed. Public `edpk`, `sppk`, and `p2pk` parsing and Tezos
signature verification remain. A prefix-rejection test and all seven tzkey
unit tests pass. The three did:tz signed JSON Patch tests now consume fixed
JWS fixtures generated from the clean ElevenID baseline. No secret Tezos keys
or local signing remain in those tests; they still exercise the service patch
behavior for tz1, tz2, and tz3, and all five did:tz unit tests pass. The two
`ssi-dids` examples now use a public P-256 JWK from a remote provider rather
than `JWK::generate_p256`; all six doctests pass. Warnings-denied all-target
Clippy for the three affected crates, Rustfmt and diff checks pass. Keep these
changes in the single broad SSI fork PR, then audit the rest of the fork and
downstream Core for remaining local-key authority before a universal KMS-only
claim. The planned grouped delivery remains one substantial PR per repository:
SSI fork, Core, UI native/OpenBao, and Credentials retirement. Batch local
corrections and self-review before triggering each repository's hosted CI;
required PR, security, and release gates remain mandatory.

2026-10-08 UCAN/JWS external-signer follow-up: the fork removed `JwsSigner`
for `JWK` and the `JwkWithAlgorithm` adapter, which were still public
local-key signer shapes even though direct JWS signing already failed closed.
UCAN payload issuance and revocation now request signatures asynchronously
through the existing `JwsSigner` provider contract instead of accepting a
private JWK. The UCAN issuance header takes the provider's algorithm and key
reference. The general JWS signer path rejects a non-public JWK returned as
header metadata before asking the provider to sign. Four UCAN unit tests,
three JWS public-only tests, JWS doctests, fork workspace all-target check,
warnings-denied all-target Clippy for JWS/UCAN/root, Rustfmt and diff checks
pass. A fixed signer unit test checks the prepared UCAN bytes and response
plumbing; it is not live KMS custody or a cryptographic signature acceptance
test. Keep this in the staged broad SSI fork PR. The remaining SSI direct
legacy JWS signing functions and other local-key references still require
inventory and consumer review before a fork-wide KMS-only claim.

2026-10-08 legacy JOSE API retirement: the SSI fork no longer exports direct
JWK-based `ssi-jws` byte, compact, custom-header, or detached signing helpers,
nor `ssi-jwt::encode_sign`. The disabled-local-signing error and its obsolete
fail-closed test were removed with those APIs. Remote JWS signing through
`JwsSigner`, public JOSE/JWT verification, and detached
prepare/complete operations remain. A commented-out Solana local-wallet
signer example was also deleted. Source search found no active callers in the
fork or current Core/UI Rust trees; the fork's workspace all-target check,
JWS/JWT/UCAN unit tests and doctests, warnings-denied all-target Clippy for
JWS/JWT/UCAN/Data Integrity suites, Rustfmt and diff checks pass. This is a
source-level dependency checkpoint, not a downstream linked-product proof.
Pinning the reviewed fork in Core and validating exact bindings/release
artifacts remain necessary before describing the product as KMS-only.

2026-10-08 cryptography storage-boundary review: the SSI multicodec crate no
longer implements import/export for `p256::SecretKey`; public P-256 codec and
private-codec rejection remain. The JWK public Rust parameter structs now use
unit presence markers for every forbidden EC, RSA, OKP and symmetric secret
field. They cannot contain private bytes through those fields even when a
caller constructs a JWK directly. JSON deserialization still rejects private
parameter names and serialization still rejects a set marker; Core's
presence-based denial checks stay compatible. The standalone RSA `Prime`
private-material type, no-longer-relevant zeroization `Drop` code, symmetric
thumbprint path, stale private-key errors, and unused JWK randomness
dependencies were removed. Public JWK thumbprints and public verification
remain. An empty symmetric JWK is classified non-public, so it cannot
masquerade as public signer metadata. Expanded rejection coverage includes
`d`, `p`, `q`, `dp`, `dq`, `qi`,
`oth`, EC/OKP `d`, and symmetric `k`. JWK optional Aleo/BBS/P-384 tests pass,
as do the standard public-only tests, fork workspace all-target check, and
warnings-denied all-target JWK/multicodec Clippy. This is staged in the same
large SSI fork feature batch.
The complete SSI fork `cargo +1.97.1 check --workspace --all-targets
--all-features --offline` also passes after this storage-boundary change;
this broad compile includes optional Aleo, BBS, ring, COSE and DID crates.

The Core consumer probe exposed an incoherent *temporary* local patch: its
17 SSI replacements left registry `ssi-cose`, `ssi-claims` and other crates
linked against the hardened `ssi-crypto`, failing because the old registry
COSE crate expects `ssi_crypto::SecretKey`. A new disposable full-fork patch
artifact at `artifacts/kms-ssi-elevenid-full-local-patch-2026-10-08.toml`
lists all 41 fork workspace packages. With that patch, Core
`marty-oid4vci` and `marty-bindings` checks pass, and
`marty-verification --lib` passes 280 tests (72 intentionally ignored).
The `marty-bindings` dependency tree under the full patch has no selected
registry `ssi-*` or `did-*` package; unused optional fork patches are expected
warnings. This checks the local source graph, not the published artifact.
Each diagnostic probe's Cargo.lock edits were restored; Core remains clean.
The Core probes used `cargo +1.97.1 check --offline -p marty-oid4vci`,
`cargo +1.97.1 check --offline -p marty-bindings`, and
`cargo +1.97.1 test --offline -p marty-verification --lib`, each with
`--config C:/Users/maree/OneDrive/Glthub/marty-workspace/artifacts/kms-ssi-elevenid-full-local-patch-2026-10-08.toml`.
The full local patch is **not** a product pin or release proof. Before the
broad Core PR, use a reviewed fork commit and coherent source pin across the
complete production graph, run exact bindings/release artifact checks and
consumer tests, and record the linked versions. No hosted CI or feature PR
has run for this batch yet.

2026-10-08 full SSI runtime checkpoint: the fork's all-feature workspace test
selection now passes locally with exit code zero: `CARGO_PROFILE_TEST_DEBUG=0`
and `CARGO_INCREMENTAL=0 cargo +1.97.1 test --workspace --all-features
--offline --no-fail-fast --quiet -j 2` completed 98 test targets, zero failed,
and three tests ignored by their own configuration. The immutable passing log
is `artifacts/kms-ssi-full-workspace-test-nodebug-rerun-2026-10-08.log`.
The prior `artifacts/kms-ssi-full-workspace-test-nodebug-2026-10-08.log`
recorded 97 passing targets and one RDF vector-test failure. That failure
first exposed an uninitialized pinned `crates/rdf/canonicalization` submodule;
after checkout it exposed CRLF line endings in its expected vectors on
Windows. The staged `ssi-rdf` test now normalizes expected vector line endings
at comparison, with no change to RDF production code or submodule contents.
The targeted RDF test and complete rerun pass. A separate fixture scan found
no JWK objects with private fields in fork `tests` or `crates` JSON fixtures;
source search found no active local `SigningKey`, `RsaPrivateKey`, `SecretKey`,
or `Keypair` implementation in the fork's Rust source/test trees. These are
review inputs, not proof of live remote custody, product artifact linkage, or
release readiness. The SSI fork batch remains staged and uncommitted; Core's
full local patch remains diagnostic rather than a durable source pin.

2026-10-08 SSI fork PR checkpoint: after the full runtime pass, the complete
fork `cargo +1.97.1 clippy --workspace --all-targets --all-features --offline
-j 2 -- -D warnings`, Rustfmt, and staged diff checks passed. Review of
removed source confirmed the deleted `ssi-crypto` signature code was local
private-key signing, BBS public verification remains, and the deleted
`dids/core/tests/document.rs` contained only commented-out obsolete tests.
`DOWNSTREAM.md` was corrected to describe the current optional Aleo/BBS
boundary. The 182-file broad SSI batch is committed as
`61ba3dcffa9937ea24261a232dc01f5b28f3221c`, pushed to
`security/verification-only-kms-elevenid-20261008`, and opened as
[ElevenID/ssi-elevenid#9](https://github.com/ElevenID/ssi-elevenid/pull/9).
This is one feature PR for the fork; it is open, not merged or release-qualified.
Core now has an in-progress manifest change replacing the temporary local
patch and prior separate JWT fork with 41 package patches pinned to this exact
revision. Consumer checks and lockfile graph review must pass before that Core
pin can be called durable.

2026-10-08 first SSI hosted PR check and Core pin follow-up: Core's candidate
manifest and lockfile now resolve 33 selected SSI/DID packages to the same
published fork revision `61ba3dc` with no registry SSI/DID package in the
lockfile. `cargo +1.97.1 check -p marty-bindings -j 2` passed, and the locked
offline `marty-verification --lib` run passed 280 tests with 72 ignored. This
is a real git-source consumer probe, still subject to the SSI PR's final SHA
and Core artifact qualification. The first SSI PR #9 hosted run has a failed
workflow-policy check because `dependency-health.yml` review dates expired;
its old Ursa exception was also stale because that package is absent from the
current source and lockfile. A local follow-up removes the stale record and
reviews the remaining dates. Build, Clippy, WASM and examples passed in the
first hosted build job; rustdoc failed on stale did:ion links left after local
creation API removal. Local doc review found another stale Aleo link and
multicodec reference links; fixes are being batched before a single follow-up
push. The hosted each-feature job is still running. Do not treat the first
PR check set as passing or the Core pin as final yet.

2026-10-08 K10 database-scope clarification: the user added explicit removal
of every private-key table and said no migration scripts are
needed. The current Credentials candidate already deletes the two duplicate
SQLAlchemy `KeyModel` definitions for the `keys` table, their `jwk_json`
column, and key-manager reads/writes. The current candidate's remaining
Credentials persistence models list holders, credentials, verification logs,
trust registry and ZK challenges, with no `keys` model. A first pass over the
native UI SQL found `device_registration_keys` stores `public_key_der`, key
ID/version and state, while `organization_service.api_keys` stores a hash and
prefix; these are not issuer private-key tables. This is a source inventory,
not yet a fresh-database schema or row-level proof. Before closing K10,
enumerate every clean-install DDL/ORM root across the grouped repositories,
inspect generic JSON key fields for prohibited private material, then create
empty test databases with the candidate artifacts and introspect tables and
columns. Remove any residual private-key table definition at its source;
do not add DROP/ALTER/data migration scripts or a compatibility read path.

2026-10-08 K10 Credentials clean-install correction: inventory found that the
historical Alembic chain still created `issuance_service.issuer_signing_keys`
with `encrypted_jwk_json` and later dropped it. Both private-key-specific
revisions have now been removed from the candidate, and their three children
were linked directly to the preceding non-key revisions. The generated
issuance runtime-surface manifest and its reviewed digest/count were updated;
the migration graph now has one head (`issuance_event_owner`) and 46 revisions.
Thirteen focused boundary/surface/migration/ORM tests passed and Alembic `ScriptDirectory`
walked the 46-revision graph. No new migration script was added. This proves
that this historical creation path is gone, not yet that every assembled
service database and artifact is free of private-key tables or columns.
The corrected chain also reached `issuance_event_owner` on a disposable fresh
PostgreSQL 16 database after adding the minimal organization-table prerequisite
used by an existing template backfill. The resulting `issuance_service` has
30 base tables, none with `private`, `key`, or `jwk` in the table name. Column
introspection found public JWKS, key digests/idempotency hashes, client-secret
references and the expected encrypted integration-secret value; no column
named for private-key storage. The exact Alembic output is in
`artifacts/kms-k10-credentials-fresh-alembic-2026-10-08.log`; the disposable
database was removed. The separate fresh SQLAlchemy metadata test creates
exactly the five remaining wallet/verification tables in SQLite and no `keys`
table. The remaining Credentials wallet adapter ORM defines only a
`credentials` table. Self-review found a nested adapter duplicating the same
`CredentialModel` and `SQLAlchemyCredentialWallet`; the current Credentials
candidate now re-exports the canonical adapter instead. The nested and
canonical paths share identical `Base`, model and wallet class objects, and
the 14 focused migration/custody tests plus Ruff pass. The separate broader
five-table `models.py` metadata had one unused, unconstrained
`selective_disclosure_keys` JSON column. No source read or write uses it; the
candidate now removes it from the clean-install ORM and asserts its absence
in the fresh SQLite metadata test. The focused custody tests and Ruff pass
after this correction. Remaining model JSON fields still need data-flow
review. Full
assembled platform migrations, row-level payload
review and release-artifact introspection remain K10 acceptance gates.

2026-10-08 K10 Core public-key store review (local commit `cb025fe`): Core's SQLite
`open_badge_keys.document_json` is a public verification-method field, but its
direct `store_open_badge_key` path did not apply the private-material admission
rule already used by governed trust-package writes. The candidate now rejects
private/symmetric material before serialization or insertion, using the shared
Rust classifier; the classifier also recognizes snake-case private-key names
and nested symmetric JWKs. The new direct-write test proves rejection leaves
zero rows and a subsequent public key is stored. The complete
`marty-secure-storage --lib` suite passed 50 tests with one pre-existing
ignored test, and `marty-types --lib` passed 19 tests. Targeted all-targets
Clippy passed with warnings denied, and the locked offline
`marty-bindings` consumer check passed at the current candidate pin. This closes one generic
JSON storage gap; the remaining database JSON fields and actual product write
paths still need K10 review.

2026-10-08 SSI PR #9 local CI correction: the full fork workspace test run
with default features disabled passed 98 test targets after the root signing
doctests were feature-gated. The exact hosted per-feature command is running
locally before the batched follow-up commit/push; the first hosted check set
remains red until that corrected head is published and checked.
The first 72 local per-feature variants passed, then the `ssi-data-integrity`
no-default-feature integration test failed to compile because its shared
proof-scoped fixture referenced `ecdsa_sd_2023` outside the `w3c` +
`secp256r1` gate. The helper now gates that vector branch without restoring
local signing; all 16 single-feature variants of `ssi-data-integrity` pass.
The remaining 99 workspace variants then passed with already-qualified crates
excluded, completing the exact CI each-feature matrix in local batches. The
`ssi-jwk` test-module feature gate also removed an otherwise
repeated unused-import warning; no-default and P-256 focused tests passed.
The later hosted `cargo-rdme` step was preflighted locally and found the README
stale: the source docs' remote-signer wording had diverged, and a malformed
Data Models heading had been copied literally. The source heading/grammar and
generated README were corrected; `cargo rdme --check --no-fail-on-warnings`
now passes. `cargo deny check bans licenses` and all-feature root doctests
also pass. Final warnings-denied rustdoc and workspace Clippy passed before
the batched fork push.

2026-10-08 SSI fork correction publication: warnings-denied all-feature
workspace rustdoc and workspace Clippy passed, along with formatting, diff,
README generation and dependency bans/licenses. The reviewed 12-file
follow-up commit `584a0d1e2f6a80f92a8483151f6cc6b78b021ad1` was pushed
to existing ElevenID SSI PR #9. Its second hosted build, policy and
each-feature checks are pending; do not treat the PR as qualified yet. Core's
41-entry patch manifest and lockfile are being repinned from `61ba3dc` to this
new immutable revision, with a locked git-source consumer check in progress.
The locked `marty-bindings` consumer check has now passed at `584a0d1`, and
lockfile inspection found 33 selected SSI/DID packages all sourced from that
one fork revision with no registry SSI/DID package. The second hosted
workflow-policy check passed; hosted build/lint and each-feature checks remain
pending. The Core verifier rerun passed 280 active tests with 72 ignored,
and the pin is now clean local Core commit
`2a2bf261393061488255cdb1f040c5ebab5b1938`. This commit retains the
older dedicated `linked-data` dependency ref and existing isomdl patch;
all 41 SSI/DID patch entries point to one fork revision. Do not open or land
the broad Core PR until the fork's hosted build and feature checks pass and
the remaining Core regression/security review is complete.
SSI PR #9 then passed all required hosted build/lint, workflow-policy and
each-feature checks and was merged with merge commit
`8d3314c4d235af0fc781933a0a1797da8ac4960d` at 2026-10-08T19:44:34Z.
The Core pin deliberately remains on its locally qualified immutable PR head
`584a0d1`, which is reachable through that merge. The dependency fork is
landed; this does not by itself qualify the Core, UI or Credentials PRs.
The broad Core branch then merged the single new `origin/main` CI-selector
commit (#354) without conflict, reaching clean local head
`33ac1ccd28a9cfefa94997843133991f58b14a89` (0 behind main). The
upstream selector's 10 Python tests pass on this assembled head. Its new
cross-package JWK fixture edge remains present for the broad PR matrix.
The assembled Core head also passes the verification feature-boundary and
release-contract checks, plus their 6 and 78 Python unit tests. The newly
selected `marty-crypto` JWK vector integration test passed all five tests at
the pinned fork head; this is a targeted regression gate, not yet the complete Core PR
matrix or published-artifact proof.
The post-repin Core workspace test selection (all crates except the native ZKP
and bindings lanes, with `test-fixtures`) ran against `584a0d1` and the merged
current-main CI selector. Its first run exposed the test-only JWK boundary
case described below.
That first full selection found one `marty-oid4vci` test still deserializing
a private-shaped JWK to then assert batch-input rejection. The hardened fork
now rejects it at deserialization, so the test now asserts that earlier
fail-closed boundary while retaining its positive public JWK input assertions.
The correction is Core commit `d56c3fe`; its focused test passes. The exact
full workspace selection was repeated with a captured process exit of 0 and
no reported failures in
`artifacts/kms-core-584a-workspace-final-2026-10-08.log`. Native ZKP and
bindings remain separate qualification lanes. No production signing or
fallback behavior was restored.

2026-10-08 K10 assembled source inventory: across current UI Rust service SQL
and migration sources, the key-named persisted tables found are
`device_registration_service.device_registration_keys` (public DER, public
key identifier, version/state) and `organization_service.api_keys` (prefix,
SHA-256 hash, scopes/state). The notification webhook schema contains a
Transit ciphertext envelope and four-character hint, not a private key.
No private-key or JWK-bearing column was found in the currently enumerated
native service DDL. This is source-level evidence only. The assembled fresh
PostgreSQL database, every legacy initialization entrypoint, JSON payload
writes and shipped release artifacts still need K10 qualification before
calling the product database free of private-key storage.
2026-10-08 K10 Credentials JSON-write correction: the Canvas LTI platform
probe previously persisted a fetched `lti_jwks_json` after checking only that
`keys` was nonempty. Candidate commit `a6c80de` now rejects private JWK
fields and PEM private-key markers anywhere in that document before the
probe result reaches the platform write path. The private-field policy is
shared by the existing registered-client, readiness and Rust-integration
public-JWK checks, removing duplicate lists. Public JWKS extensions remain
accepted. Ruff and 134 focused Canvas/client-auth tests passed, including
new direct private-field and nested/PEM rejection cases. This closes one
specific JSON ingress; other JSON-bearing writes and assembled row-level
inspection remain open K10 work.
Follow-up commit `5d29f4b` also detects JSON-encoded private JWKs in JWKS
extension strings, bounds recursive inspection, and preserves ordinary public
extensions. Ruff and the same 134 focused tests passed after that correction.
2026-10-08 native signing-keys DID review: the leased DID publication path
serialized its assembled document directly to Redis, bypassing the generic
document `save` guard. The current UI candidate now rejects private material
in both the existing DID document and the assembled result inside the shared
builder used by leased and ordinary publication. A new public-positive and
private-existing negative test passed; the full signing-keys library passed
135 tests with 8 ignored, and warnings-denied Clippy passed on Rust 1.97.1.
This is a local uncommitted UI candidate paired with the broader document/
HTTP change; live leased-Redis and assembled artifact qualification remain.
2026-10-08 K10 full signing-keys package review: the first package run exposed
two golden vectors that still supplied private JWK fields and expected silent
stripping. The candidate fixtures now use public positive inputs and explicit
private rejection inputs. The ignored Redis document round trip likewise
proves private publish/update/DID requests are rejected before successful
public writes, and now requires a loopback DB >=13 plus nonce sentinel.
`update_jwks_document` rejects private JWK update fields rather than silently
ignoring them. The four golden-vector tests passed, the full non-default
signing-keys package suite passed, warnings-denied Clippy passed, and both
document Redis tests passed against a disposable Redis 7 container removed
afterward. The existing CI Redis lane now includes those two ignored tests.
These are local UI candidate changes; hosted CI and assembled release
qualification remain.
The next consumer check ran the native `marty-issuance-service --lib`
selection on Rust 1.97.1 with no default features: 564 passed, 8 ignored,
0 failed. This confirms the current local signing-keys boundary does not
break issuance's library-level behavior; integration, packaged-process and
database evidence remain separate gates.
2026-10-08 Core PR #355 third-run CodeQL timing: the hosted Rust `Analyze`
job passed on head `f5ca93c`, and code-scanning alert #260 now reports its
most recent instance as `fixed`. The separate aggregate `CodeQL` check run
113532936281 failed at 20:45:49 UTC before Rust analysis finished (about
20:53 UTC), retaining the previous high-alert annotation. Treat the PR check
as failing until a refreshed aggregate check passes; once the remaining
hosted jobs complete, request a targeted refresh if available or batch a
follow-up head update with other required corrections. Do not dismiss the
alert or treat current analysis as a passing PR check.
The targeted GitHub check-run rerequest endpoint returned HTTP 404 for this
CodeQL check, so it did not refresh. A later Core head update is still needed
to produce a new aggregate check once the remaining jobs have been reviewed.
All remaining third-run functional jobs, including Fast Rust Preflight,
Affected Rust Tests, Native ZKP and the aarch64 wheels, then passed. With
alert #260 already fixed by the Rust analysis, an empty Core head update
`d41d87c` was pushed solely to obtain a fresh aggregate CodeQL check; no
source correction was batched because the reviewed third-run source had no
other failing required check. The new hosted result remains pending.
The device-registration write path calls Core's
`validate_device_public_key`, which parses canonical PKCS#1 RSA public DER,
rejects other DER shapes, and binds the claimed key identifier to its public
JWK thumbprint before storing it. This strengthens the public-only reading of
that table beyond its column names. Core's SQLite `open_badge_keys` schema is
a verification-method document store with a direct-write private-material
guard; its generic `config` table currently has no application writer in the
crate beyond schema-version handling. Continue reviewing other JSON-bearing
tables and all direct repository entrypoints before closing K10.
2026-10-08 persisted DSC result review found a narrower local PEM-only
check on Redis-backed issuance attachments. It missed JSON-encoded private
JWK material while the service already had a bounded recursive detector
covering private JWKs and nested JSON strings. UI commit `e775b8603`
uses that shared detector on both the attachment and the public result,
removes the duplicated PEM-only check, and extends the existing Redis
commit test to reject an encoded private JWK in the attachment and a direct
private JWK in the result before a valid public certificate commit succeeds.
The exact ignored test passed against a disposable Redis 7 instance on
loopback database 13 with Rust 1.97.1; rustfmt and scoped diff checks passed.
This strengthens the runtime data-flow proof but does not yet establish a
complete assembled database inventory.
The next issuer-profile storage review found `ProfileStore::put` accepted
arbitrary JSON with matching tenant and ID, and read validation only checked
tenant scope. UI commit `f76b57f1a` now applies the same recursive
private-material detector on writes and reads, failing closed for nested
JSON-encoded private JWKs while admitting public JWKs and managed references.
That commit also checkpoints the already-prepared tenant/profile binding
validation and its test. The focused storage test passed; the full
`marty-signing-keys` library selection passed 134 tests with seven ignored
on Rust 1.97.1. Service-level Redis/write tests and assembled schema checks
remain required for K10 closure.
The signing document audit then found that `sanitize_public_jwk` silently
discarded private JWK fields and generic Redis document save/read/mutation
paths did not reject private material at the storage boundary. The local UI
candidate now rejects private JWKs from provider/publication inputs, rejects
private-bearing documents on read and write across holder, DID, JWKS and
certificate paths, and preserves public projection of key references and
non-secret metadata. Four old tests that assumed scrubbing of private-key
payloads were changed to require rejection while retaining their positive
public-key/relationship assertions. The full signing-keys library suite
passes 134 tests with eight ignored; an additional ignored document-storage
test passed against disposable Redis 7 on loopback DB 13, covering public
write/read and private write/read rejection. Warnings-denied Clippy for
`marty-signing-keys --lib --no-default-features` also passed on Rust 1.97.1.
This change is local in the
large UI feature branch and not yet an assembled product/release proof.

2026-10-08 Core local quality gate: `cargo +1.97.1 fmt --all -- --check`
and the full branch `git diff --check` pass. Warnings-denied all-target
Clippy across the same non-ZKP, non-bindings workspace selection passed with
captured exit 0 in
`artifacts/kms-core-584a-clippy-selected-2026-10-08.log`. The initial
all-workspace Windows Clippy attempt could not build the native ZKP crate
because the local MSVC environment lacks OpenSSL and zstd headers; this is
recorded in `artifacts/kms-core-584a-clippy-2026-10-08.log`. The required
Linux ZKP/bindings lanes and hosted Core CI remain to be qualified on the
final broad PR head.
The Core advisory/yank gate also passed locally with
`cargo deny --locked --all-features check advisories --deny yanked`.
Regression review of removed signer-based CAVP integration tests found that
public-only ECDSA verification tests now cover P-256, P-384 and P-521,
including wrong-key/cross-curve cases; public-only RSA vectors cover all
supported PKCS#1 and PSS hash combinations, tampering, wrong key and
cross-scheme rejection. The exact selected workspace test pass exercised
these replacements. The local-signing round trips were intentionally
retired, not restored as production APIs. Continue the full assembled
regression/security/quality review before publishing Core's grouped PR.
The separate Core bindings test lane passed 50 active tests with five ignored
under `USE_ZK_MOCK=1`; the ZKP mock package test lane also exited 0. The
exact `marty-oid4vci` KMS-only issuer and verifier no-default feature profiles
both compile at the same SSI pin. These checks do not replace the Linux native
ZKP security lane or exact wheel inspection.
Core grouped draft PR #355 was opened on the locally qualified, clean head
`d56c3fe52f195f7e8cc157fa03898efb5a89f701` so its full diff and hosted
Linux lanes can be reviewed together. It remains draft while the remaining
regression/security/quality review and hosted findings are resolved; opening
the draft does not waive the plan's complete-review or final-head merge gate.
Initial hosted policy, license metadata/inventory, workflow quality and
Python/actions CodeQL jobs passed; other jobs were still running at this
checkpoint.

2026-10-08 Core PR #355 first hosted findings (immutable failed job logs in
`artifacts/kms-core-pr355-verification-aarch64-fail.log`,
`artifacts/kms-core-pr355-zkp-native-fail.log`, and
`artifacts/kms-core-pr355-preflight-fail.log`): the aarch64 Python
verification wheel failed because `marty_crypto::ocsp::build_ocsp_request`
had been removed while the public OCSP Python binding still called it.
The unsigned request builder remained, so local Core commit `f85592b`
restores the thin public-data wrapper and tests that it matches the builder
using public certificate vectors. The exact Python wheel feature profile
compiles, the local Python verification wheel builds, the focused OCSP test
passes, and warnings-denied Clippy passes for the wheel profile. This is a
feature-preservation fix, not a private-key signing exception.
Both Fast Rust Preflight and Native ZKP Security Boundary reached the live
remote-issuer test script, then failed linking a `marty-bindings` test binary
with undefined CPython symbols. The script used the package's default
`extension-module` feature for three ignored binding tests. Commit `f85592b`
adds `--no-default-features` to those test invocations, matching the separate
CI bindings lane and retaining the same test bodies. Follow-up local commit
`9b15904` also selects `kms-only` on those three calls; the exact binding
test target compiles with that feature profile on Windows. Shell syntax, formatting
and diff checks pass; the hosted native lanes must pass on the updated PR
head before this finding is closed. These corrections were batched with the
subsequent TLS finding before the next hosted run.

2026-10-08 Core PR #355 first full hosted run finished: Affected Rust Tests,
all four per-language CodeQL analyses, and the other listed passing jobs
passed. The aggregate CodeQL gate failed on high alert #260
(`rust/cleartext-transmission`) in the test-only OpenBao Transit helper.
The helper transmitted a scoped bearer token over loopback HTTP, even though
the reported taint source was synthetic public certificate fixture data.
The correction uses OpenBao's documented `-dev-tls` mode, retrieves the
generated CA from the disposable container, pins it in both Rust test clients
and curl, and reconstructs a literal HTTPS loopback origin after validating
the marked URL. It does not disable TLS verification or dismiss the alert.
The disposable runner's five live remote status tests passed on Windows via
WSL with that CA, and the remote issuer integration target compiled with its
exact KMS-only feature selection. Shell syntax, Rust formatting and diff
checks passed. OpenBao's pinned image required `-dev-listen-address=:8200`
for TLS; numeric IP bind addresses failed listener initialization in the
local probe, while the empty-host bind plus Docker's loopback port mapping
served a CA-verified `https://127.0.0.1` endpoint. The isolated probe
container and CA were removed after validation.
The OCSP, binding-test profile, and TLS corrections were pushed together to
Core draft PR #355 at `6fbe674` (`f85592b`, `9b15904`, `6fbe674`). Hosted
checks and CodeQL alert resolution on this exact head remain pending. The
previous failed logs and alert remain review evidence.
The second hosted CodeQL analysis on `6fbe674` again produced high alert
#260 at the scoped Transit `.post` URL, despite the endpoint now being
CA-verified HTTPS. This is a static-analysis visibility problem at the
dynamic `self.base` URL, not evidence that the TLS run sent plaintext. A
local correction stores the validated port and uses a literal HTTPS
loopback origin at the signing request. The five live status tests passed
again with that construction. Keep the alert open until a new hosted
analysis verifies resolution; the second run's Fast Rust Preflight and
Native ZKP Security Boundary were still running at this checkpoint.
Later on the same `6fbe674` hosted run, Native ZKP Security Boundary,
Affected Rust Tests, all four per-language CodeQL analyses, all four
aarch64 Python wheel jobs, and the other required completed jobs passed.
Only Fast Rust Preflight remained in progress at the live disposable
OpenBao step; the aggregate CodeQL check still failed on alert #260.
The literal-HTTPS follow-up is local Core commit `f5ca93c` and has not
triggered another hosted run yet, so no CodeQL resolution is claimed.
Fast Rust Preflight's disposable non-exportable OpenBao signing step then
completed successfully on `6fbe674`; its Clippy step was still running.
Fast Rust Preflight subsequently passed, including strict Clippy, the
OID4VCI WASM serial fallback contract and EUDI trusted-list client. Thus
the second hosted head's only failing required check was aggregate CodeQL
alert #260. After all other checks finished, the local literal-HTTPS
correction `f5ca93c` was pushed as the next single Core PR #355 update.
CodeQL resolution and all required checks remain to be requalified on
that exact new head; no earlier green check is attributed to it.

2026-10-08 Credentials consumer qualification at Core candidate 0.2: local
Windows Core `marty_rs` and `marty_verification_py` wheels built and loaded
from an isolated target, not from globally installed 0.1.60 extensions.
The full Credentials Python suite then passed 1,750 tests with three failures;
one was the global Starlette 1.0.0 falling below the declared `>=1.7.0`
transport contract. With Starlette 1.7.0 installed only in that isolated
target, the exact suite passed 1,751 tests with two failures, 29 skips and
200 passing subtests. Both remaining failures assert that published release
dependency metadata and CI still point to the earlier Core release commit.
The locally built Windows verification wheel successfully created an
unsigned DER OCSP request from public certificate fixtures, and both wheel
modules omit the sampled retired issuer-key and local crypto exports. These
are local wheel checks; Linux/aarch64 and final release-wheel behavior still
require hosted and exact-artifact proof.
Do not change those expectations or claim release qualification before
reviewed Core artifacts are actually published and pinned. The second
suite log is
`artifacts/kms-credentials-core02-python-suite-qualified-env-2026-10-08.log`.

2026-10-08 Credentials retirement self-review: the candidate deletes the
old Behave feature tree and its Makefile targets along with local-key issuer
steps. Those feature files also named supported verifier behaviors (tampered
W3C VC and SD-JWT rejection, selective presentation, Open Badge status and
trust, mDoc/ZK verification). The old tree is not invoked by the candidate
CI or Python dependency manifest, but deleting it still requires a behavior
coverage map before the Credentials PR can be called regression-reviewed.
Core already has KMS-backed SD-JWT/JWT-VC issuance and verification tests,
including altered signatures, wrong public keys and subset disclosure in
`marty-oid4vci/tests/remote_issuer_live_kms.rs`, plus structural checks in
`sd_jwt_vc_conformance.rs`. Core also has authenticated Open Badge status
negative tests and native ZK lanes. This is partial replacement evidence,
not proof for every removed scenario; map the remaining Open Badge,
cross-format, lifecycle and ZK cases to qualified native tests or add them
before merging the Credentials retirement PR.
The candidate Core head `6fbe674` passed both focused replacement suites
locally with the KMS-only issuer/verifier/wallet feature selection:
`sd_jwt_vc_conformance` (6/6) and `remote_jwt_vc_boundary` (6/6).
These prove preparation, selective-disclosure structure, and refusal of
private or mismatched issuer metadata; they do not alone replace the deleted
service-level Behave scenarios.
2026-10-08 deleted-Behave review checkpoint: the removed Credentials feature
files contain 20 digital-identity, 14 Open Badge, 14 SD-JWT, 15 W3C VC and
3 ZK scenarios. Current Core tests directly name OID4VP nonce replay,
tampering, audience/expiry rejection and required-ZK-predicate fail-closed
behavior in `marty-oid4vci/tests/oid4vp_conformance.rs`; the live remote
issuer suite names verified subset disclosure and mDoc issuance. Core's
Open Badge status tests name authenticated clear status, revocation,
suspension, wrong key/untrusted issuer and stale status-list rejection.
Native UI has credential signing and PostgreSQL lifecycle tests plus managed
OID4VP policy tests. This is a coverage map by inspected test entry points,
not a claim that each deleted scenario is equivalent or that those suites
have all passed on final artifacts. In particular, cross-format
interoperability, Open Badge endorsement/X.509 trust, mDoc ZK success and
failure, and service-level multi-format revocation still require assertion-
level mapping and, where absent, new native tests before K7 closure.
The older note above that `marty-verification/tests/open_badges_conformance.rs`
still generated issuer keys is superseded on the current Core PR head. That
suite now verifies previously signed public vectors for OB2/OB3, structure,
wrong key, expiry, hashed recipient, verification-method variants and unsigned
status rejection. A direct KMS-only run of the registered integration target
passed 12/12 on `f5ca93c`. This closes that specific test-custody item; the
remaining Open Badge endorsement/X.509 and cross-format service assertions
still need their own mapping.
2026-10-08 K7 test-custody audit found another active local-key fixture in
Credentials `tests/unit/test_canvas_lti_routes.py`: `_TestToolJwtSigner`
generates and signs with an RSA private key for dynamic Canvas client
assertions and deep-link responses, and `_private_rsa_jwk` generates keys for
negative and public-JWKS cases. Native UI's
`canvas_lti_tool_signing_behavior.rs` covers DID/tenant/method binding and
failure paths with a mocked signature provider, while
`managed_key_create_live_contract.rs` uses a mock Transit backend for the
LTI key-purpose route. Neither is a real remote RS256 assertion-sign-and-
verify replacement. Retire those Python private-key fixtures using public
negative vectors and an opaque unit signer, and add a disposable real
OpenBao-backed LTI assertion-sign/verify acceptance proof before calling
test-side custody and Canvas behavior fully preserved.
2026-10-08 K7 follow-up: Credentials commit `496926d` removes RSA key
generation and local signing from the Canvas route test fixture. The unit
double now binds the dynamic JWT input, public key identifier and a public
key marker without pretending to prove RS256. Its malformed-private-JWK
negative vectors contain only a rejection marker, not usable private key
parameters. Eighty focused Canvas tests passed and Ruff's F rules passed;
the file has unrelated pre-existing Ruff E402/UP017 findings. The UI
candidate's existing disposable OpenBao RSA test now also signs a Canvas-
shaped compact-JWT input remotely, verifies it against the provider's public
JWK, and rejects a tampered input. That exact ignored test passed against a
scoped-token disposable OpenBao 2.5.2 container, which was removed after the
probe. It is added to the existing OpenBao CI lane. This establishes real
cryptography plus separate route-binding coverage, while a packaged Canvas
route-to-OpenBao end-to-end proof and release artifact qualification remain.
The complete Credentials Python suite initially exposed three review-gate
failures caused by the shared private-JWK constant move and source line shifts
in the frozen issuance-surface manifest, in addition to the two known Core
release-pin failures. Commit `bcba5a4` updates the language-neutral Canvas
forbidden-field contract to the shared policy, changes the test to inspect
that policy directly, and regenerates the surface manifest. The old and new
surface contracts are identical after removing only source `line` metadata;
route count remains 95. The full suite then passed 1,751 tests, skipped 29,
and passed 200 subtests with only the two known release-artifact tests
deselected. Those tests still need the final published Core pin and remain
explicitly unresolved, not waived.
The broad Credentials retirement candidate was checkpointed locally as
`4051dd4` on `security/remote-kms-retirement-20261007`: 69 files changed,
including local issuer-key adapter/test removal, no-private-key clean-install
revision graph, native owner selection, one Core 0.2 source pin, and CI graph
checks. The branch had a clean diff check and 19 focused custody/native
boundary tests passed with Python 3.12 immediately before the commit. This
is a local candidate, not a qualified PR or release artifact; its Core pin
still needs the final reviewed Core head, full coverage mapping, and
published release metadata before the known two metadata assertions can pass.
The committed retirement source scan then found a remaining exported
`KeyPair(jwk_json)` type and dead wallet/adapter methods accepting that raw
holder key, plus a disabled mDoc method accepting `device_key_pem`.
Credentials commit `2076e52` removes those obsolete contracts, exports and
forwarders while preserving credential storage, verification helpers and
mDoc disclosure-request presets; supported holder presentation and offer
redemption remain owned by the canonical native wallet flows. A repository
Python source scan found no remaining `KeyPair`/`KeyAlgorithm` consumers or
private-key-shaped adapter/port parameters. Twenty-two focused port/custody/
native-boundary tests, Ruff, and diff checks pass. This does not replace the
remaining full consumer and final artifact qualification.
The complete Credentials Python suite was then repeated with the isolated
Core 0.2 wheels and qualified Starlette 1.7.0 target after commit `2076e52`:
1,751 passed, 29 skipped and 200 subtests passed. The same two release
metadata assertions failed because the published Core release metadata and
CI revision have not yet been updated to the final artifact. No new failure
or import regression appeared from removing `KeyPair` and the dead wallet
methods. The immutable log is
`artifacts/kms-credentials-core02-python-suite-no-raw-wallet-2026-10-08.log`.

2026-10-08 Core PR #355 CodeQL review at `d41d87c`: the Rust analyzer
reported alert #261 (`rust/cleartext-transmission`) at the test-only
`ScopedTransitSigner::request_signature` URL expression. The signer sends
synthetic certificate/revocation fixture bytes in an HTTPS POST body to
`127.0.0.1`; the URL includes only the random, non-secret Transit key name.
`DisposableOpenBao::from_marked_env` verifies the HTTPS loopback endpoint,
disposable marker and generated CA certificate; the reqwest client pins that
CA and disables proxies. The Transit key is created non-exportable and the
scoped token has sign-only policy. This is not a cleartext transmission. Alert
#261 was dismissed as a false positive with that rationale; the prior alert
#260 remains fixed, the aggregate CodeQL check `113540624614` now passes,
and the PR head has no open code-scanning alerts. Fast Rust Preflight job
`113540261467` subsequently passed, as did CI Gate. All current hosted
checks on the Core PR head pass, but the PR is still draft and requires review;
there is no Core merge or release claim yet.

2026-10-08 K10 Organization JSON-store review found that the internal
settings patch accepted arbitrary JSON and `save_organization_on` persisted
it directly to `organizations.settings`. The UI candidate now moves the
bounded private-material detector from signing-keys into one shared Rust
crate, reuses it in signing-keys, rejects private JWK/PEM and encoded/nested
material in Organization application updates and direct PostgreSQL writes,
and fails closed when reading a poisoned settings row. Public JWKs and remote
key references remain accepted. The shared, Organization and signing-keys
package suites passed with no failures; warnings-denied all-target Clippy
passed. A disposable PostgreSQL 16 repository round trip proved the rejected
write leaves the prior settings unchanged. The container was removed. This
is part of the broad uncommitted UI feature candidate; other generic JSON
stores still need review, as do assembled schema/artifacts. Follow-up review
found `audit_events.changes` and `audit_events.metadata` could persist arbitrary
JSON. The same repository-level policy now guards both write and read paths;
the disposable PostgreSQL 16 contract rejects nested private JWK data in
either column while retaining the one legitimate audit event. Organization
format and warnings-denied all-target Clippy pass after that correction.

2026-10-08 K10 shared policy and Trust Profile review: the policy now also
detects `private_jwk`/`private_pem` field names and `rsa_d` in JWK-shaped
objects, and offers a map API so Organization settings checks do not clone
the whole JSON object. The policy and Organization suites and warnings-denied
Clippy pass after this adjustment. Trust Profile's eight PostgreSQL save
methods now check their complete serializable records before SQL; all eight
row readers apply the same check after decoding. This covers imported
verification keys, public certificate records, trust rules and their generic
metadata. A direct repository test proves a synthetic private imported JWK
is rejected before any database connection; public JWK and remote-reference
values pass the policy. The full Trust Profile package suite and all-target
warnings-denied Clippy pass. These are uncommitted UI candidate changes; a
fresh assembled PostgreSQL schema, other services' generic JSON stores and
exact release-artifact behavior remain K10 gates.

2026-10-08 K5 Core consumer pin advance: all seven workspace Core dependencies
in native UI `rust/Cargo.toml` and the issuance service's direct
`marty-emrtd-issuance` dependency now use the green Core PR #355 head
`d41d87cc2ef8eeaddbb9d659c2ac5642f7a0ce82`. The CI graph verifier's
exact expected source was advanced with the pin; its nine unit tests pass.
The actual `cargo +1.95.0 metadata --locked --format-version 1` output
passes that verifier, and the lockfile contains eight Core crates at that
one revision with no old `a5cb567` or `bdbd151` Core source. The six
no-default-feature library suites (signing-keys, issuance, Flow, Gateway,
Verification and Trust Profile) pass 969 active tests with 17 ignored;
those six packages also pass locked `cargo +1.95.0 check` on the CI toolchain.
This is a local, broad UI candidate pin to a green draft PR head, not a
merged Core release or final shipped-artifact qualification. Credentials
has since advanced to the same Core candidate revision; its published
release metadata is still unreconciled.

2026-10-08 K5/K7 Credentials exact-Core adoption: commit `ab0e3e8` changes
all five direct workspace Core dependencies, six resolved lockfile Core
packages, both CI Core checkouts and the locked-graph verifier to PR #355
head `d41d87cc2ef8eeaddbb9d659c2ac5642f7a0ce82`. The mdoc digest
semantics integration test now declares its actual `python` feature
requirement, so a no-default-feature test run skips it and the default run
passes all three cases. The actual full locked Cargo metadata passes the
Core KMS graph verifier; 21 focused release-workflow tests pass with the
published-manifest assertion deselected. Diff whitespace review passes.

Two locally built Windows ABI3 wheels from that exact Core worktree were
installed into an isolated Python target for Credentials qualification:
`marty_rs-0.2.0-cp311-abi3-win_amd64.whl` (SHA-256
`47aca5146506774245b8b619196ab2fc48620fa470a2383c75252092ab156743`)
and `marty_verification_py-0.2.0-cp311-abi3-win_amd64.whl` (SHA-256
`db68a9af91a8a713c5e461f4d3d61efcd67a8758db52d038d68859adbaf481bf`).
The first full Python run produced 1755 passed, 29 skipped, three failures
and 200 subtests passed. Two failures correctly show the still-published
`release/dependencies.json` points at older Core artifacts; the third was a
Canvas LTI sync-status assertion (`queued` versus observed `succeeded`) that
passed in isolation. A full rerun excluding only the two release-manifest
gate tests passed 1756 tests, skipped 29, deselected two and passed 200
subtests. Preserve both logs at
`artifacts/kms-credentials-d41-python-suite-2026-10-08.log` and
`artifacts/kms-credentials-d41-python-suite-qualified-2026-10-08.log`.
This qualifies the local Windows wheel pair for the tested Python behavior;
it does not establish published wheel provenance, Linux image behavior or
the release-manifest boundary. Keep the manifest gate failing until exact
reviewed artifacts are published and pinned. Investigate the Canvas timing
flakiness if it recurs in hosted CI.

2026-10-08 K10 Deployment Profile JSON-store correction: its PostgreSQL
repository accepted arbitrary `environment_config`, `update_policy` and
lane `metadata` JSON, and persisted the complete profile and lane records
without a private-material check. The broad UI candidate now applies the
shared Rust private-material policy before both PostgreSQL and in-memory
profile/lane saves and after both PostgreSQL row decoders. A direct repository
test proves nested private JWK and JSON-encoded private PEM fields are
rejected before attempting a database connection, while public JWK and
remote-reference metadata remain accepted. The Deployment Profile package
passes six library and nine integration tests; all-target Clippy passes with
warnings denied on Rust 1.95. This is not yet an assembled PostgreSQL or
shipped-artifact proof. Other generic JSON repositories remain to review.

2026-10-08 K10 Presentation Policy storage correction: `PolicyRecord` is the
canonical converter for PostgreSQL writes and reads. It now applies the
shared Rust private-material policy to the current `policy_document` and
all three legacy JSON fields before persistence and before decoding a row.
This rejects a poisoned legacy column even when the current document is
otherwise valid. A regression test covers JSON-encoded private JWK in a
current policy and private material in both current-row and legacy-row
columns. The complete Presentation Policy package suite (50 tests) and
all-target warnings-denied Clippy pass on Rust 1.95. The UI candidate is
still uncommitted as one broad feature; fresh assembled database and
published artifact checks remain open.

2026-10-08 K10 Compliance Profile JSON-store correction: its `payload`
JSONB includes rule parameter maps and previously had no private-material
admission check. Both PostgreSQL and in-memory repository saves now reject
private payloads through the shared Rust policy; the PostgreSQL row reader
rejects a poisoned payload before deserialization. A direct repository test
proves a nested private JWK is rejected before database access and a remote
reference remains accepted. The Compliance Profile package passes five
library and eight integration tests; all-target Clippy passes with warnings
denied on Rust 1.95. This remains part of the uncommitted broad UI candidate;
an assembled fresh-database and shipped-artifact proof is still required.

2026-10-08 K10 Flow JSON-boundary correction: Flow's key-name-only context
check missed private JWK parameters such as `d` and JSON-encoded private
fields. It now retains its precise path errors for known names and applies
the shared Rust policy as a fallback. PostgreSQL's common definition,
instance and artifact validators and row decoders apply the same policy;
callback payloads and application-event plans are checked on write/read.
The in-memory repository also checks direct definition, instance, artifact,
finalization callback and planned-event writes through one shared helper.
A direct PostgreSQL repository test rejects a private JWK before connection;
in-memory tests prove rejected context and artifact payloads are not stored.
The Flow package's full library/integration test run passed, and focused
tests plus all-target warnings-denied Clippy passed after the shared-helper
and callback changes on Rust 1.95. This remains uncommitted in the broad UI
feature candidate. Other persisted JSON fields and an assembled database
inspection remain open.

2026-10-08 K10 disposable PostgreSQL follow-up: PostgreSQL 16 backed the
existing Presentation Policy and Flow integration contracts in separate
databases; both passed. Flow's first invocation used an arbitrary database
name and failed its explicit `marty_atomic_test` isolation assertion before
executing the contract; the rerun with that required name passed. Applying
Flow's clean-install `0001_flow_schema.sql` to a third disposable database
created seven `flow_service` tables: application-event receipts, callback
outbox, definitions, instance artifacts, instances, nonce consumptions and
schema versions. Information-schema inspection found no private-key-named
table or column among them; its 16 JSON columns were inventoried, including
definition, instance, artifact and callback fields guarded above. Presentation
Policy's fresh database contained only `presentation_policies`, with public
policy metadata/document columns and no private-key-named table or column.
The disposable PostgreSQL server was removed. This is per-service schema and
runtime evidence, not the required assembled cross-repository schema or
published-artifact proof.

2026-10-08 K10 Notification JSON-store correction: notifications' `data`,
subscriptions' `filter_config` and webhook outbox `payload` could persist
caller-controlled JSON. One shared Rust repository guard now rejects private
material before in-memory and PostgreSQL writes, including direct repository
calls. PostgreSQL row readers check the raw JSON before converting it, so a
poisoned field cannot be silently discarded. A direct repository test proves
a nested private JWK is rejected before database access and a remote
reference remains accepted. The Notification package suite and focused
outbox tests pass; all-target warnings-denied Clippy passes on Rust 1.95.
This remains part of the uncommitted broad UI candidate. Notification's
disposable PostgreSQL contract and the assembled database/artifact checks
are still separate gates.

2026-10-08 K10 Notification live storage qualification: the existing
`postgres_integration` contract passed against fresh PostgreSQL 16 and a
separate disposable OpenBao dev instance with a non-exportable
`aes256-gcm96` Transit key. The test migrated the clean schema, created a
webhook, wrapped its signing secret remotely, persisted an outbox event and
verified idempotence. Direct information-schema inspection found seven
`notification_service` tables and six JSON columns; no table or column was
named for private-key storage. The one webhook endpoint row held a `vault:`
secret envelope and a four-character hint, and the old plaintext `secret`
column was absent. The disposable PostgreSQL and OpenBao containers were
removed. This proves the tested service boundary, not the full assembled
platform or exact published artifact. The prior note that this disposable
contract remained open is superseded by this passing run. A subsequent
row-reader cleanup removed duplicate JSON decoding; the complete Notification
package and strict Clippy passed, and the live PostgreSQL/OpenBao integration
contract passed again against fresh disposable services after that change.

2026-10-08 self-host bundle regression review: the local test must use the
pinned standalone Docker Compose 5.4.0 executable, as hosted CI does; the
default `docker compose` invocation cannot satisfy the test's explicit
standalone renderer contract. With that executable, the remaining extracted
bundle failure exposed a stale synthetic environment: the issuance-native
Compose file now requires `BAO_ADDR` for `DIDCOMM_KMS_ADDR`, but the fixture did
not supply it. The bundle fixture now supplies a synthetic address, requires
the DIDComm OpenBao token mount and forbids the retired integration-secret
master-key file. The adjacent Canvas self-host acceptance fixture and its
container-recovery check now use the same DIDComm token mount. All 24
`marty-selfhost-bundle` tests pass with the pinned renderer; the focused
Canvas container-recovery test passes. These are source/fixture checks, not
the still-required shipped-image and assembled-runtime qualification.

2026-10-08 Canvas acceptance fixture cleanup: the base runtime renderer's
closed input set and the renewal/Kubernetes test specs no longer require or
inject `INTEGRATION_SECRET_MASTER_KEY`. The Kubernetes fixture's synthetic
secret map likewise no longer provisions that retired local key. The base
Compose model gate passes all 12 selected models plus required-directory
negatives, and the Canvas acceptance target recompiles and passes its focused
container-recovery test. The Linux-only rendered renewal and published-image
runtime acceptance cases remain release gates; this Windows compile and
configuration proof does not substitute for them.
The two renderer/renewal obligation Python suites also pass (101 tests) with
the retired input removed. The machine's default Python lacks pytest, so this
run used an isolated `uv` invocation with pinned pytest and PyYAML.

2026-10-08 K10 Credential Template JSON-store correction: its template,
wallet-registry and delivery-destination JSON columns were not checked at the
repository boundary. The PostgreSQL store now applies the shared Rust
private-material classifier to serialized JSON before writes, including
`compliance_profile` and `claim_projection_policy`, and to raw JSON read from
rows before typed deserialization can discard an unknown private field. The
package suite, package formatting and all-target warnings-denied Clippy pass.
The live repository contract passed against a fresh disposable PostgreSQL 16
database: a nested private JWK was rejected before a template row existed,
while normal template, wallet and destination round trips succeeded. Direct
schema inspection found four `credential_template_service` tables
(`credential_templates`, `delivery_destinations`, `wallet_registry`, and
`rust_schema_versions`) and no table or column named for private-key storage.
The disposable database was removed. This is one service's clean-install
evidence; assembled platform schema, other JSON stores and exact release
artifacts remain K10 gates.

2026-10-08 K10 Auth and Device Registration review: Auth's
`audit_logs.event_metadata` is assembled only from fixed server fields by its
current writer; `session_history.device_info` is not written by that repository.
Its TLS private-key files remain transport credentials, not database key
custody. Device Registration's `preferences` JSON and public-key columns have
broader direct-repository write paths. The PostgreSQL repository now rejects
private material in preferences before connection/write and before row
deserialization, and uses Core's public DER/key-ID validator on direct saves,
rotations and row reads. A direct-repository test proves private PEM in
preferences and non-public key bytes are rejected before database access.
The complete Device Registration package and warnings-denied all-target Clippy
pass. Its clean-install/live repository contract passed against disposable
PostgreSQL 16, then passed again after the write-path DRY refactor. The fresh
schema has four tables (`alembic_version`, `device_key_transitions`,
`device_registration_keys`, `device_registrations`); its key columns are public
DER, key ID, version/state and timestamps, with no private-key-named table or
column. The disposable database was removed. Auth's closed writer provenance
and Device Registration's per-service test do not replace assembled-platform
or shipped-artifact K10 qualification.

2026-10-08 K10 shared classifier self-review correction: the first Rust JSON
guard recognized `private_key` only at the start of a field name. A generic
document could therefore have carried the retired
`sender_x25519_private_key` member through a guarded JSON store. The one shared
policy now recognizes private-key/JWK/PEM, secret-key and PKCS#8 tokens
anywhere in normalized field names; focused vectors cover prefixed DIDComm and
issuer names. An affected-package local run across the shared crate and ten
consumer services completed with exit 0; tests that require separately
provisioned OpenBao/Redis backends remained explicitly ignored. The shared
crate passes formatting and all-target warnings-denied Clippy. This closes
the identified classifier bypass in source; assembled runtime and shipped
artifact checks remain open.

2026-10-08 grouped UI feature checkpoint: the 267-file native/deployment
candidate is now one local feature commit, `2b8198fc2`, on
`security/remote-kms-hardening-20261007`. It includes the K10 service guards,
the remote DIDComm and integration-secret paths, Go OpenBao extension,
reference-only BYOK surface and deployment changes. The four generated
Windows `%SystemDrive%` cache databases were excluded from staging; all newly
added self-host example token files contain explicit `CHANGE_ME` placeholders.
The staged diff had no whitespace errors, and locked Cargo metadata passed the
production Core/isomdl feature-boundary checker and its nine focused tests.
The shared classifier's prefixed-field fix passed one combined local test run
across its crate and ten consuming service packages with exit 0. Some live
OpenBao/Redis tests in that selection were explicitly ignored without their
disposable backends. The Core PR #355 remains draft and review-required with
all current hosted checks green; Credentials is locally committed at
`ab0e3e8` and has no PR yet. The UI commit is local only, with no UI PR or
hosted CI run yet. This checkpoint makes the broad change reviewable but does
not close K8/K9/K10 or the release-artifact gates.

2026-10-08 UI PR checkpoint: the grouped UI branch was pushed and draft
ElevenID/marty-ui#1192 opened against `main` at head `e7bf0cb55` (the broad
feature commit is `2b8198fc2`; the later commit records its local evidence).
The PR is open and review-required. The first GitHub read returned no checks
yet, so hosted CI has not been counted as passing. Keep corrections in this
same broad PR and batch local fixes before its next hosted run to limit CI
cost. Core #355 is the upstream dependency; Credentials has no PR yet.

2026-10-08 UI integration checkpoint: PR #1192 could not form a test merge
against the newer `main` (`809f093a6`), which split Canvas worker acceptance,
changed CI selection, and tightened the passport image gate. The branch now
has a local merge commit `01942fb70` resolving 11 textual conflicts. The
resolution retains remote OpenBao acceptance setup, the new Canvas timeout
tier, the Canvas worker package split, and all three CI selector outputs
(`openbao`, `planner_only`, `rollback_test_only`). The combined Python suite
finished with 410 passed, 1 skipped, and 2 stale selector expectations; both
corrected expectations passed on a focused rerun. Earlier stale expectations
for the scoped KMS probe and renamed passport gate were also corrected.
`cargo +1.95.0 check --locked` passed for Credential Template, Issuance,
Canvas acceptance, and Canvas worker acceptance. Targeted Rust formatting,
locked metadata, the frozen self-host Compose model comparison, and staged
whitespace checks passed. The `%SystemDrive%` cache artifacts remain untracked
and excluded. The merge and tracker update still need to be pushed; hosted UI
CI and review have not yet passed. Do not mark K8/K9/K10 complete from these
local integration checks.

2026-10-08 UI first hosted CI review: the merged branch was pushed at
`6fae2fc92` and PR #1192 ran its broad workflow. UI tests, protocol contract,
security scanning, Rust supply chain, Python lint, Passport PostgreSQL, and
MIP lifecycle passed. The run found integration failures in dependency review,
the standalone Rust probe lock, the OpenBao snapshot-recovery startup race,
strict Rust lint, native release contracts, and Canvas Kubernetes runtime
composition. The local correction batch upgrades the Go OpenBao plugin to
`golang.org/x/crypto` 0.56 on Go 1.26, refreshes the standalone locked probe,
waits for initialized OpenBao API before snapshot unseal, removes duplicate
Rust test-module loading and Clippy warnings, refreshes exact Core provenance
and Compose bind expectations, and keeps native Kubernetes signing traffic on
the Gateway route while retaining the legacy direct service route. The local
plugin image build, Go tests/vet, live Raft recovery, strict Rust lint, Rust
release-evidence unit tests, locked Rust probe check, and 217 focused Python
contract tests passed. These corrections are still local and need a single
batched push and hosted rerun; Rust service images and Rust analysis from the
first run were still in progress at this checkpoint. Core #355 remains green,
draft, and review-required. Credentials is locally qualified against the Core
candidate but has no PR; its release metadata and coverage mapping remain
open. No K8/K9/K10 or shipped-artifact gate is closed yet.

2026-10-08 UI CodeQL follow-up: the first run completed Rust analysis but
raised two high-severity findings at
`rust/services/issuance/src/integration_secret_kms.rs` where the client sends
an integration secret and API key to a configured HTTP Signing Keys endpoint.
This is a real transport-boundary issue: supported Compose and Kubernetes
configurations currently use private-network HTTP for the shared Signing Keys
URL. Resolve it with an authenticated TLS transport for integration-secret
operations and matching deployed endpoints/trust roots, while preserving the
separate signing routes and synthetic acceptance behavior. Do not suppress the
alert or switch the existing HTTP URL to HTTPS without a serving endpoint.
The local CI-correction batch does not yet resolve this finding and remains
un-pushed to avoid another broad run before the transport change is ready.

2026-10-08 Credentials main-line reconciliation: `origin/main` has since
landed Python issuance and SDK retirement (#311 and #312). The Credentials
KMS branch merged that main line at `591deb1`, accepted deletion of the
retired Python source/tests/workflows, and retained its KMS-only Rust binding
changes. The CI wheel job was reconciled to build both distributions from
Core PR #355 head `d41d87c`, with a locked graph verifier; no two-revision
verification compatibility pin remains. The merged Rust Python-feature check,
native-feature test build, graph verification, source-boundary tests, YAML
parse, and staged whitespace check pass locally. The Python extension test
requires a built wheel and the combined post-merge release suite still needs
qualification. The branch is local, unpushed, and has no PR. Its old 106-file
diff is no longer representative of the net main-line change; review the new
Rust/contract/CI diff before opening the grouped PR.

2026-10-08 UI image-job follow-up: all Rust service images built in the first
hosted run, but the Issuance smoke step failed before printing service logs:
Docker inspect found no `8005/tcp` mapping after the test container exited.
The smoke harness needs to report an early container exit, and the packaged
runtime failure needs local reproduction or captured logs before the next
hosted run. This is separate from the CodeQL transport finding.

2026-10-08 UI image-job local reproduction: Docker built the exact current
Issuance target (`rust/services/Dockerfile.ci`, `marty-issuance:kms-local`) and
the packaged-image smoke script passed twice against disposable PostgreSQL
and the synthetic remote-secret service. The first hosted failure therefore
has no locally reproduced service-startup cause. The smoke harness now waits
briefly for the published port mapping and prints Issuance and remote-service
logs if the container exits or never receives one; this makes a remaining
hosted-only failure diagnosable. It has not yet passed on the new PR head.

2026-10-08 integration-secret transport implementation in progress (local,
unpushed): CodeQL's two high alerts are a real plaintext/API-key
HTTP path, not a false positive. A separate Rust TLS listener has been added
to Signing Keys on configurable port 8018 with paired PEM certificate/key
configuration; its HTTP listener denies integration-secret routes. Issuance's
remote envelope client now accepts HTTPS only, disables redirects, verifies
the TLS peer, and can load a trusted CA PEM via
`INTEGRATION_SECRET_KMS_CA_FILE`. The API and Canvas worker use the shared
`KmsIntegrationSecretCipher::from_environment` constructor with
`INTEGRATION_SECRET_KMS_URL`. A unit test completed a real certificate-
verified TLS encrypt/decrypt round trip. The Signing Keys package and
Issuance package compile with the locked graph; an integration fixture
compiles with a TLS test server. This is not yet deployable: Compose, K8s,
runtime smoke/process fixtures, and live OpenBao recovery must supply the new
URL and trust root; supported certificate provisioning/rotation needs a
documented and tested path; the HTTP-route denial needs a live assertion.
Do not push this partial transport change or claim CodeQL fixed until those
surfaces and a hosted rerun pass. Use distinct certificates and keys for
transport TLS versus non-exportable KMS application keys.

2026-10-08 TLS deployment follow-up (local, unpushed): the transport code is
committed at `ee05e0f37`. Self-host Compose now provisions separate Signing
Keys server certificate/key secrets and mounts the existing workload CA on
Issuance and Canvas worker clients. Kubernetes templates and the deploy script
now create a separate server TLS Secret plus a CA-only client Secret; the
closed Rust renderer checks their exact URLs, paths, ports, mounts, and service
mapping. The self-host Compose model suite passes all five cases. Twelve of
thirteen Kubernetes renderer tests pass locally; the remaining CLI-fixture
test invokes `envsubst`, which is unavailable in this Windows environment and
must run on Linux/hosted CI. A live middleware test confirms that the HTTP
listener refuses both integration-secret routes. The packaged Issuance smoke
harness now generates a disposable CA and separate server certificate,
supplies only the CA to the client, and runs the synthetic service over TLS.
The current `marty-issuance:kms-tls-local` image passed this smoke. Rustls
correctly rejected an initial test certificate marked `CA:TRUE` as an end
entity; the corrected leaf has `CA:FALSE` and `serverAuth`. The Canvas worker
image-startup suite passed all 16 direct and file-backed cases against the
same image and TLS synthetic service. The beta workload-identity issuer and
disposable passport certificate issuer now produce a Signing Keys server leaf
with DNS SAN `signing-keys`; the disposable chain passed `openssl verify
-verify_hostname signing-keys`. These deployment and harness edits remain
local and unpushed. Development Compose certificate provisioning, other process
fixtures, live OpenBao recovery, certificate rotation, and hosted CodeQL
remain open.

2026-10-08 development TLS follow-up (local, unpushed): the self-host and
Kubernetes transport batch was committed at `7adde88bd`. Base Compose and
the native overlay now mount a generated Signing Keys TLS leaf/key only on
Signing Keys, and the CA only on native Issuance and Canvas worker. The
ignored `.dev-integration-secret-tls` directory is provisioned by
`scripts/ensure-dev-integration-secret-tls.py`; its CA signing key is removed
after leaf issuance. The helper verifies DNS SAN `signing-keys`, server key
pairing, chain, and remaining validity; issue, idempotence, simulated renewal,
and loopback IP-SAN generation passed locally. The beta deploy runner invokes
it after plan-only exit under its deployment lock. All 12 base native Compose
models, the conformance and DIDComm Compose gates, 81 passport provisioning
tests, 275 passport model/ownership tests, and 37 local beta runner tests pass.
The coordinated live PostgreSQL/Raft recovery probe passed with an actual
Signing Keys TLS listener and CA-pinned Rust integration-secret client: its
write phase encrypted through OpenBao, then the read phase recovered the same
row after OpenBao Raft snapshot and PostgreSQL restoration. The probe also
passed live DIDComm authcrypt after rotation, VC-API holder-proof cleanup, and
Flow HAIP checks on their existing routes. Two issuer tests verify leaf
issuance, renewal, no retained CA signing key, and DNS/IP SAN scoping. These
are local disposable runtime results; hosted CodeQL, development Compose
end-to-end runtime, operator certificate rotation, and release artifact
qualification remain open.

2026-10-08 grouped TLS push and CI follow-up: UI PR #1192 now has head
`d9240b8fd` with the dedicated TLS transport, deployment wiring, development
certificate issuer, and live coordinated recovery proof. The new hosted run is
in progress. Its dependency review found `google.golang.org/grpc` 1.78.0 in
the OpenBao DIDComm plugin graph; upstream GHSA-hrxh-6v49-42gf lists versions
below 1.82.1 as affected. Locally upgraded the plugin to 1.83.1, ran `go mod
tidy`, and passed `go test ./...` in the Go 1.26 container. Hold this correction
for a batched UI push after reviewing the remaining hosted findings. The
Credentials candidate also removes WASM `generate_p256_key` and
`generate_ed25519_key`, but the authenticator web wallet calls them from
`SpruceIdPlatformServiceWeb.createDid` and `generateKeyPair`. Its
`create_verifiable_credential` wrapper has no active Dart call site. Review
and preserve the wallet's holder-key capability without restoring server-side
issuer private-key APIs before opening the grouped Credentials PR.

2026-10-08 UI hosted Rust follow-up: the same PR run failed strict Signing Keys
Clippy because its new HTTP-route denial test module preceded
`shutdown_signal`. Moving the test module to the end of the file passed local
`cargo +1.97.1 clippy --locked -p marty-signing-keys --bin
marty-signing-keys --tests -- -D warnings`. The hosted Canvas and contracts
jobs both failed compiling the shared TLS integration-secret test fixture
because the two Canvas acceptance crates lacked `rustls`, `axum-server`, and
`rcgen` dev dependencies. Those dependencies are now declared, with `rcgen`
centralized in the workspace manifest; `cargo +1.97.1 test --offline -p
marty-canvas-acceptance -p marty-canvas-worker-acceptance --no-run` passes
locally. These fixes are local until remaining hosted jobs complete, then
will be pushed together with the gRPC advisory correction.

2026-10-08 UI broad-contract and CodeQL follow-up: the pushed TLS PR run
reported one new high CodeQL alert at the integration-secret HTTP send because
the request endpoint inherited a dynamic URL scheme. The local correction now
constructs each endpoint from a literal HTTPS origin, copies only the
validated host/port/path, and retains constructor HTTPS validation,
`https_only(true)`, disabled redirects, and peer verification. The focused
certificate-verified integration-secret round trip passed both tests locally;
hosted CodeQL must confirm the alert clears. The release-contract job also
found 23 failures and 63 errors from frozen Compose/Kubernetes/beta fixtures
that predated the TLS deployment changes. Updated the exact self-host signer
cert/key and client CA inventory, Kubernetes signer/native/Canvas mounts and
ports, beta physical-provider TLS inventory, developer TLS setup for clean
beta CI checkouts, Kubernetes secret publication harness, and the standalone
Rust probe's current patch graph. The combined affected Python suite now
passes 376 tests with two skips; Ruff checks and focused Rustfmt checks pass.
The broad hosted job, packaged images, and release artifacts still require
confirmation on a new PR head. Keep these local corrections in one batched
push after the remaining current-run jobs finish.
The updated Issuance library also passes local `cargo +1.97.1 clippy
--locked -p marty-issuance-service --lib -- -D warnings`; focused Rustfmt
passed for the modified Issuance and Signing Keys files. The old-head plugin
and service-image jobs remain live at this checkpoint.

2026-10-08 additional consumer and security review: the Credentials WASM diff
removes four names referenced by the authenticator's web interop:
`generate_p256_key`, `generate_ed25519_key`, `create_presentation`, and
`create_verifiable_credential`. The first two are called by the exported
`SpruceIdPlatformServiceWeb.createDid`/`generateKeyPair` path; the latter two
appear in wrappers without a direct Dart call site found in the current
authenticator tree. Core's KMS-only wallet exposes public-key proof
preparation/completion but no local holder-key generator, so simply restoring
the removed Credentials implementation would reverse its private-key surface
retirement. Preserve this as an explicit cross-repo wallet compatibility gate
and design an opaque wallet/device key operation before releasing the new WASM
artifact. The upgraded Go OpenBao plugin also passed `go vet ./...` in the Go
1.26 container. Both old-head hosted image jobs were still live when checked;
do not infer success from their elapsed time.
Authenticator call-graph follow-up: no current Dart view or service calls
`SpruceIdClient.createDid`, `SpruceIdPlatformServiceWeb.generateKeyPair`, or
the WASM `createPresentation`/`createVerifiableCredential` wrappers. The
visible credential-selection presentation path uses
`spruceIdClientExtendedProvider` and `createPresentationSDK` through its
platform service. Thus the removed WASM exports are an exposed API/consumer
compatibility risk, not yet evidence of a regression in the active wallet
presentation flow. There are no public deployments and no compatibility
requirement, but final wallet qualification must show the active path and
the new WASM artifact still initialize and work; do not reintroduce raw-key
exports solely to satisfy dormant wrappers.
Packaging check: `marty-authenticator`'s production Flutter Dockerfile copies
only Flutter's built web output; the explicit `local_wasm_overrides/marty_rs`
asset copy appears in its web-test Dockerfile, while `web/index.html` loads
`marty_wasm_loader.js` from that asset path. No product Dart call site for
the four retired raw-key WASM methods was found. This weakens the claim that
their removal breaks an actively shipped wallet feature, but does not prove
the browser build works; test the exact authenticator artifact and its active
presentation path before closing wallet preservation. The removed methods
remain retired in the Credentials candidate.

Hosted old-head checkpoint: the UI OpenBao DIDComm plugin image job completed
successfully, including coordinated live integration-secret recovery after
PostgreSQL and OpenBao Raft restoration. This is acceptance evidence for the
TLS transport at PR head `d9240b8fd`, although the dependency advisory and
other known check failures at that head still require the local correction
batch and a new hosted run. The service-image job remains in progress.
The old-head Rust service-image job subsequently completed successfully,
including the packaged Issuance smoke and Canvas worker startup gates. Its
full PR check set ended with 22 successful, seven failed, and one skipped
check; the failures are dependency review, Canvas/contracts compilation,
strict Rust lint, release contracts, and CodeQL, all addressed in the local
grouped correction batch. Push that batch once, then evaluate the new head.

2026-10-08 grouped correction checkpoint: pushed the compiled/tested batch to
UI PR #1192 at `888e7949b`. The new hosted run is in progress. Dependency
review immediately found a separate high-severity gRPC-Go advisory,
GHSA-2v4p-qf9q-27wj, affecting the batch's 1.83.1. Upstream identifies 1.83.2
as patched. Locally upgraded the OpenBao plugin to 1.83.2 (and its required
`golang.org/x/net` 0.58.0), then passed `go test ./...` and `go vet ./...` in
Go 1.26. Keep this local until the rest of the hosted results are known and
combine any corrections in one push. The Credentials WASM target check could
not compile locally because the Windows environment lacks `clang` for
`cc-rs`; that is an environment limitation, not evidence of a Rust source
failure. Qualify the target with a suitable compiler or hosted artifact build.
The Linux Rust 1.97.1 WASM check exposed an actual Credentials feature-graph
failure: its workspace-wide `marty-verification/icao-client` enabled LDAP,
Tokio, and `mio` on `wasm32-unknown-unknown`. The Credentials candidate now
enables `icao-client` only for native/Python features, retaining the LDAP
client there while omitting it from browser builds. The corrected dependency
graph excludes `mio` on WASM and retains `ldap3` on native Python; a Linux
`cargo +1.97.1 check --locked -p marty-rs --no-default-features --features wasm
--target wasm32-unknown-unknown` passed. This proves source compilation, not
the exact wasm-pack artifact or authenticator browser flow.
Linux `wasm-pack build --locked --target web --no-default-features --features wasm`
subsequently passed for the Credentials candidate. It produced a 5,151,231-byte
WASM artifact with SHA-256
`268511f350ffefbd174358674c9090cbbeb325b2c54226941eb41f19e53621ae`;
the generated TypeScript exports exclude the retired local-key methods. This
qualifies the web package build but not its browser consumption or presentation
flow.

2026-10-08 second UI hosted run at `888e7949b`: CodeQL Rust, strict lint,
security scanning, and Python lint passed. Dependency review found the separate
gRPC 1.83.1 advisory; the local 1.83.2 correction above remains unpushed.
The Canvas lane failed a Linux-only Kubernetes composition proof because its
closed synthetic secret map used `OPENBAO_SERVICE_TOKEN` as a key, while the
source Signing Keys manifest references `SIGNING_KEYS_OPENBAO_TOKEN`. Corrected
that test fixture and reran the exact Linux Rust proof successfully with its
2x2 marker. The contracts lane failed five Issuance executable smoke tests:
the dedicated PostgreSQL database was initialized with only the old four-table
OID4VCI fixture, and KMS-only startup now verifies the integration-secret
table. CI now initializes that database through the production Rust `migrate`
command. The release-contract lane passed 6,169 tests with 19 skips except for
one Linux Compose projection difference: it omitted explicit
`bind.create_host_path: false` on three authcrypt mounts. The model gate now
accepts only that missing JSON field for those exact mounts after verifying
the source profile declares false and the synthetic policy directory and
checked-in plugin config exist. The local targeted Compose suite passes 66
tests. This does not claim Compose runtime enforcement; upstream tracks a
Compose 5 issue where `create_host_path: false` can be ignored, so supported
deployment must validate bind sources before `up`. Packaged image and live
plugin jobs remain active at this checkpoint.
The exact CI smoke setup was verified locally in an isolated PostgreSQL 16
container: after creating empty upstream Organization and Credential Template
catalogs, the production Rust Issuance `migrate` command succeeded, and all
six `executable_smoke` tests passed against that database. The disposable
container was stopped. The source profile still declares no host-path
creation; upstream Compose issue
https://github.com/docker/compose/issues/13602 documents why that directive
alone cannot serve as an operator-side missing-path preflight.
The exact generated Credentials web package also initialized with Node 24 via
`initSync` over the compiled WASM bytes. `get_version()` returned `0.1.79` and
`health_check()` returned status `ok` with credential-offer and verification
features. This is a package-load check, not the authenticator browser flow.
Credentials preflight review found a stale CI assertion that still required
isomdl `issuer-local-signing`, directly contrary to the KMS-only dependency
guard. Changed it to reject that feature in native, Python and WASM graphs;
the current Python graph selects only isomdl `issuer-planning` and
`presentation-verifier`, and the pinned-Core KMS graph check passes locally.
Credentials `cargo +1.97.1 fmt --all -- --check`, native and Python feature
checks, and a local ABI3 wheel build pass. The Windows wheel was 9,466,128
bytes (SHA-256
`c34e5dad6d517383628aca377d6f12f93ea76d0bb0a37d63e2a0cce9eb6ceb3e`);
after installing it to an isolated target, the six focused Python Core/KMS
surface tests passed. The generated wheel was removed from the worktree after
qualification. Hosted cross-platform and exact publish-artifact gates remain.
UI Rust Service Images completed successfully at `888e7949b`; the live OpenBao
plugin image job was still active at this checkpoint.
The live OpenBao plugin image job subsequently completed successfully at
`888e7949b`, including packaged plugin verification, self-host Raft,
snapshot export/recovery, and coordinated Rust integration-secret recovery
after PostgreSQL and Raft restore. The complete hosted run ended with 24
successes, five failures, and one skip; the fifth failure is the aggregate CI
gate reflecting the three corrected lane failures, while the separate
dependency-review advisory is addressed by the local gRPC 1.83.2 patch.
Push the combined corrections once and re-evaluate the exact new head.
The UI correction batch was pushed as PR #1192 head `81ab5df4d`; its new
hosted run is underway. Credentials was pushed as one broad feature branch
and opened as draft PR #313 at `c5329260`, based on current `main` with no
behind commits. Its hosted Rust, WASM, Python-wheel, dependency and security
checks are queued. Keep both PRs draft until all required checks, cross-repo
wallet compatibility, and exact release-artifact gates are satisfied.

2026-10-08/09 grouped PR qualification follow-up: Credentials PR #313 head
`c5329260` exposed two CI assumptions after raw-key retirement. Fast Rust
Preflight's inverse `cargo tree -i sd-jwt-rs` selector is ambiguous because the
resolved graph has sd-jwt-rs 0.7.1 and 0.8.0. The local correction checks the
complete locked feature tree for each native, Python, WASM and full-WASM
surface; all four tree checks pass locally and none selects the forbidden
isomdl local signing or sd-jwt-rs acceleration/mock features. Its Nextest job
also treated the deliberately empty native binding unit-test suite as an
error. The local correction uses `cargo test --lib` and retains `cargo test
--doc`; both pass with zero Rust tests while dedicated Python/WASM behavior
jobs remain. These changes are committed locally as `99e0cc0` and have not
yet been pushed, so hosted requalification is still required.

UI PR #1192 head `81ab5df4d` passed the prior Release Contract correction
except for one stale assertion expecting the old OID4VCI SQL fixture in CI;
the current dedicated smoke database is seeded through the production Rust
Issuance `migrate` command. The corrected assertion passes its 11-test local
suite. The contracts lane found a standalone Canvas worker test still
expecting startup without remote integration-secret KMS configuration. Its
replacement requires a nonzero startup with `InvalidConfig` when that
configuration is absent. The existing PostgreSQL-backed worker process tests
retain real remote KMS and signal coverage; the replacement itself requires
Linux hosted qualification. UI `main` advanced with the additive Canvas
worker diagnostic lane (#1194), making this PR unmergeable until reconciled.
Merged current `main` locally, resolved the one CI workflow conflict while
preserving the diagnostic lane and KMS fixture environment, and passed 213
focused workflow/contract Python tests plus YAML step-shape verification.
The merged UI head `cf87ca204` remains local until the current hosted jobs
finish, allowing any additional fixes to be batched into one push.
An existing locally built `marty-issuance:kms-tls-local` image confirmed the
new worker assertion's failure mode: with a signing-only API token and no
remote integration-secret KMS URL, the actual worker exits 1 with
`Error: InvalidConfig`; this is image behavior for an earlier candidate, and
the source test still needs the new hosted run.

K10 static DDL pass at these candidate heads: the UI SQL migrations' key-named
tables are `device_registration_keys` (public DER/KID and lifecycle metadata)
and `organization_service.api_keys` (prefix and hash), while
`organization_integration_secrets` stores a remote opaque envelope. No
private-key table declaration appeared in the current Credentials DDL/ORM
search. The checked-in `contracts/issuance-runtime-surface.json` still records
historical Python `issuer_signing_keys` revision names and paths; those
revision files are absent from the current runtime migration directory, so
the snapshot is historical metadata rather than an executable clean-install
table creator. This static inventory does not replace the pending assembled
fresh PostgreSQL schema and runtime-write audit.

Credentials PR #313 correction `99e0cc0` is pushed. Its new hosted native
preflight, Rust tests and Clippy pass; the pinned-Core wheel build from the
previous head also passed and installed wheels whose exported surfaces reject
retired local DIDComm and symmetric-key methods. The new Python unit job found
one test asserting the removed Nextest command; the local `fef8da1` correction
requires the current Cargo native test command and its focused suite passes.
The local full unit collection showed five additional failures only because
this worktree retains 100 ignored `.pyc` files under the retired
`services/issuance` directory; `git ls-files services/issuance` is empty and
the hosted fresh checkout passed those tests. WASM and local binding jobs
remain live; hold `fef8da1` for any further findings before pushing again.
The UI OpenBao image job passed at `81ab5df4d`, including coordinated
integration-secret recovery; its Canvas lane is still building the published
selfhost image. The local UI merge/correction head remains unpushed pending
that last result. A local full Windows release-test run was interrupted after
slow progress around 12%, so it is not acceptance evidence; the 213 focused
workflow/contract tests and the prior hosted 6,169-pass release run remain
the relevant evidence until the new hosted head is checked.
Credentials PR #313 was pushed again at `fef8da1`. Its corrected Python job
passed on a clean hosted checkout. Remaining new-head Rust/WASM/binding jobs
are still in progress, and this is not yet an all-checks-green result.
The full Credentials PR #313 head `fef8da1` hosted rollup subsequently
completed with 19 successes, one intentionally skipped scorecard and no
failures. This includes KMS-only feature preflight, Rust compile/test and
Clippy, Python retirement and unit gates, WASM, local Marty Python binding,
Core wheel, dependency/security checks and aggregate CI. It remains a draft
because exact published artifacts and authenticator browser integration are
still outstanding; green branch CI alone does not satisfy K7/K9.

2026-10-08/09 UI Canvas hosted follow-up: PR #1192 head `81ab5df4d`
completed with 25 successful checks, three failing lanes and their failed
aggregate gate. Release Contract Tests had one obsolete fixture assertion,
and the Rust contracts lane had a standalone worker test expecting startup
without remote KMS; both have locally tested corrections in the unpushed
batch. The Rust Canvas lane passed its 110-test worker parity suite but seven
packaged base/Kubernetes composition and renewal cases timed out waiting for
the Issuance health endpoint. The retained CI child diagnostics report the
health failure, not the process stderr. Source review found two deterministic
fixture defects affecting those cases: the synthetic integration-secret KMS
requires `test-remote-secret` while the packaged Issuance process was given a
different Signing Keys internal token; and the exact rendered Compose and
Kubernetes child environments retained deployment-only integration-secret
KMS URL/CA locations. The local correction aligns the shared internal token
with the synthetic remote peer and overlays only the owned HTTPS KMS URL and
CA file while preserving the closed rendered configuration model. Its input
validator rejects non-HTTPS, non-owned, embedded-credential and missing-CA
values. Focused Python renderer/renewal tests pass (106), the Canvas Rust
contract test executable compiles with Rust 1.95, rustfmt and diff checks
pass. This is a diagnosed candidate fix, not yet hosted Canvas acceptance;
push the grouped UI batch and inspect all exact-head gates before claiming
K8/K9/K10 qualification.

2026-10-08/09 K10 existing-database read-only catalog audit: the running
`marty-selfhost-prod-postgres-1` database still has the historical
`issuance_service.issuer_signing_keys` table with an `encrypted_jwk_json`
column, although its row count is zero. The running `elevenid-beta-postgres-1`
database has no table or column matching the private-key/JWK storage markers
used in this audit. Both still have legitimate public/hashed-key and opaque
integration-secret tables. These are existing local stacks, not the new
candidate's assembled fresh schema. No row value was read and neither stack
was changed. The self-host table demonstrates that deleting the clean-install
definition does not remove historical physical storage from an existing
database. With no public deployments and no removal migration scripts by
user direction, supported KMS-only cutover must use a separately qualified
fresh database/rebuild for this local stack and verify the old table is absent
before release; do not count a source-only schema search as deployed K10 proof.

2026-10-08/09 exact UI PR #1192 run `37871998969` exposed one Rust contracts
assertion in `marty-release-evidence`: `actual_cli_arguments_bounded_input_and_real_envsubst_model`
still expected `kubernetes-native-issuance validate` to succeed with only a
mutable image reference and no explicit enable flag. The production CLI now
selects native issuance by default and correctly rejects that input. The
local test correction requires a nonzero exit, no output, and the fixed
refusal message; it leaves production code unchanged. The adjacent parser,
environment, and immutable-image policy test passes locally with Rust 1.95;
rustfmt and diff checks pass. The Linux envsubst-backed assertion itself
requires hosted requalification. Hold this correction with any remaining
Canvas/release/image findings for one grouped push, rather than restarting
the ongoing 40-minute CI run.
The built Windows `kubernetes-native-issuance validate` CLI also confirmed
this exact negative input exits 1 with no stdout and the fixed configuration
refusal on stderr. The UI Release Contract Tests lane later passed at
`543b9a96c`; Rust contracts remain the one completed failing lane while the
Canvas, OpenBao plugin image and service-image lanes continue.
Core PR #355 is green at `d41d87c`, its description now reflects the final
KMS-only implementation and passed Native ZKP/WASM/wheel checks, and it was
marked ready for review. Its branch protection requires one approving review;
no approval is recorded yet. Credentials PR #313 remains draft with 19 green
checks at `fef8da1`; its description was updated to distinguish passing
branch CI from the outstanding authenticator and published-artifact gates.

2026-10-08/09 K10 candidate Rust Issuance fresh-schema audit: built the
`marty-issuance-service` binary from the current local UI candidate and ran
its `migrate` command against an isolated, ephemeral PostgreSQL 16 database
with only the minimal upstream Organization and Credential Template catalogs
seeded. The migration created 31 `issuance_service` tables. A read-only
catalog inventory confirmed `to_regclass('issuance_service.issuer_signing_keys')`
is null: the historical private-key table is absent from this fresh candidate
schema. The key-named table inventory found
`organization_integration_secrets`, whose `encrypted_secret_value` is the
opaque integration-secret ciphertext, not an issuer signing-key table. The
scratch container was stopped without touching either running local stack.
This qualifies only the candidate Issuance migration on a fresh database;
the assembled release schema, runtime writes, and self-host cutover still
need K10 proof.

2026-10-08/09 authenticator consumer pin audit: the current
`marty-authenticator` `origin/main` Rust manifest and lockfile still pin seven
Marty Core packages to `56cc26c`, predating the hardened Core PR head
`d41d87c`. Its active Rust source uses `marty-oid4vci` wallet issuance and
presentation operations, plus verification, mdoc, ZKP and biometrics APIs.
The Credentials WASM branch's green checks therefore do not prove the
authenticator's actual browser artifact or Rust bridge has adopted the
hardened Core. Before K5/K7/K9 closure, qualify an isolated authenticator
consumer against the hardened Core and new WASM package, then update its
production pin if that application is included in the KMS-only release.
Do not restore the retired raw-key exports merely to satisfy dormant web
wrappers; prove the active wallet flow instead.

UI PR #1192 run `37871998969` subsequently passed both `Rust Service
Images` and `Test OpenBao DIDComm plugin image` at pushed head `543b9a96c`.
The plugin job includes the coordinated PostgreSQL and Raft recovery probe.
Canvas remains live, while the known Rust contracts test correction is held
locally for one grouped push after Canvas finishes.

The isolated authenticator Core-pin probe first failed dependency resolution:
its old `isomdl-elevenid` revision provides `isomdl` 0.2, but hardened
`marty-iso18013` requires 0.3. Matching Core's reviewed isomdl and SSI fork
patches and updating the locked `aws-lc-rs` selection to 1.18.1 resolved that
graph conflict. The hardened Rust bridge is now compiling in the separate
authenticator consumer worktree; no authenticator PR or release claim follows
from dependency resolution alone.

Authenticator probe follow-up: Cargo's locked inverse graph exposes a second
old Core path through `marty-sync` pinned to Marty Verifier `8d410be`; that
Verifier revision still depends on Core `56cc26c`. It selects a second
`marty-oid4vci`/`marty-verification` 0.1.61 graph, old `isomdl` 0.2 and
`ssi-claims-core` 0.1.3 beside the new Core 0.2 graph. The resulting mixed
SSI build reports missing `ssi_crypto::SignatureError`/related APIs after
the KMS-only fork removed local signing. This is a real consumer-integration
gap, not a reason to restore those APIs. Qualify and update the Verifier
`marty-sync` dependency to the hardened Core graph, or replace that dependency
with a shared supported policy-sync component without feature loss, before
claiming authenticator adoption. The isolated authenticator worktree contains
diagnostic manifest/lock edits only and has not been published.

An isolated Verifier root probe using Core `d41d87c` reaches a concrete
manifest incompatibility before compilation: `src-tauri` dev-dependencies
request the removed `marty-verification/local-key-operations` and
`marty-crypto/sod-builder` features, and `marty-sync`'s optional demo-fixture
path requests them too. Cargo validates these feature names even for the
selected `marty-sync` build and rejects `sod-builder` on hardened Core 0.2.
Verifier's current `origin/main` still pins an older Core
`08a0d43`; simply advancing the authenticator's `marty-sync` revision to
Verifier main would leave a mixed old/new Core graph. Treat Verifier and
authenticator as explicit downstream consumer work, preserving verifier and
wallet capabilities while removing obsolete local-signing fixture paths.
The probe changes are isolated and uncommitted; the three primary feature
PRs remain the immediate landing path.
Source review narrows the Verifier impact: the `sod-builder` call is in
`src-tauri/tests/emrtd_conformance.rs` and the local Core key generator is in
`src-tauri/tests/open_badge_conformance.rs`; the optional `marty-sync`
`demo-fixtures` module also creates local Ed25519 keys and SODs. Yet
`src-tauri/Cargo.toml` lists those features under `[dev-dependencies]`, not
normal production dependencies. This is a test/optional-fixture migration and
dependency-resolution gap; it is not evidence that the Verifier production
binary selects local-key features. An aligned Verifier change would replace
those fixtures with public vectors or remote-custody fixtures while retaining
their conformance assertions.

2026-10-08/09 UI PR #1192 run `37871998969` completed with the known Rust
contracts test failure plus three Canvas database-contract failures; service
images, OpenBao plugin recovery, release contracts, strict lint, CodeQL and
the other applicable checks passed. Canvas ran 142 passing and three failing
tests in its main isolated group, plus a separate 110-pass worker group. The
retained child stderr proves both base-profile failures were caused by the
renderer checking `docker/openbao-didcomm-dev.hcl` inside an exact-owned
container whose source allowlist omitted that tracked file; it was not a
missing PR file or a KMS process failure. The local fix adds exactly that
regular file to the closed mount allowlist and updates its cardinality guard.
The focused Rust allowlist/completion test passes locally.

The third Canvas failure was the packaged self-host loader. Its child failed
before completing the packager operation, so cleanup correctly retained the
synthetic scratch. Reproducing the same bundle model on Windows with the
standalone Compose executable exposed the stale exact-secret set in
`resolved_selfhost_runtime`: `issuance-native` now mounts the
`workload_identity_ca_cert` for HTTPS integration-secret KMS, but the model
still expected the earlier six secrets. The local correction includes that
CA secret and maps `INTEGRATION_SECRET_KMS_CA_FILE` to its mount. All six
`marty-selfhost-bundle --test executable_bundle` cases pass locally after the
correction, including actual package/extract/render and negative guards.
Windows' default Docker CLI could not discover its Compose plugin under the
packager's intentionally cleared environment, so the local reproduction used
the installed standalone `docker-compose.exe`. These are diagnosed candidate
fixes; Linux hosted Canvas and the full exact-head PR gate must pass after
the single grouped push.
Targeted Rustfmt for the two touched acceptance crates and `git diff --check`
pass. Workspace-wide Cargo fmt on the Windows long path could not launch
rustfmt (`os error 206`), so the targeted check is the local formatting
evidence; hosted Rust lint remains the exact-head gate.

The isolated Verifier probe now passes `cargo +1.97.1 check --offline -p
marty-sync` against Core `d41d87c` and the reviewed SSI/isomdl fork pins after
removing the obsolete feature requests from its dev-dependency and optional
demo-fixture declarations. The normal Verifier Tauri application also passes
`cargo +1.97.1 check --locked --offline -p marty-verifier -q` in this isolated
worktree. Neither check qualifies Verifier tests or the authenticator wallet;
the old local-signing fixture tests still need migration.

The UI correction batch was pushed once as PR #1192 head `473b46dd1` after
run `37871998969` completed. New CI run `37875662633` is active; 17 jobs
have passed at the observed checkpoint, with contracts, Canvas, OpenBao
plugin, service images and release contracts still live. Do not claim the
Canvas candidate fixes or exact-head gate passed before those jobs finish.
An isolated Verifier follow-up now has a local public-only Open Badge test
candidate derived from Core's reviewed signed vector; its test executable
is still compiling, so validity and wrong-key behavior remain unverified.

Verifier consumer continuation (supersedes the pending Open Badge test
qualification above): the isolated `marty-verifier` app check passes at the
hardened Core/SSI/isomdl graph. Its four signed OBv3 tests no longer generate
or store an Ed25519 private JWK: they consume the reviewed Core public-only
signature vector, with a document-store public key substitution for the
negative case. The copied vector's SHA-256 matches Core's source fixture
(`252ef1a1c2488f46f0cb7c83fe98b09664a90c6461ae0e8ca8d78166fe24743c`).
All 25 `open_badge_conformance` cases pass on Rust 1.97.1, and targeted
Rustfmt passes. This is isolated, uncommitted Verifier candidate work; the
eMRTD and optional demo private-key fixtures, complete test suite, and
authenticator integration remain.

UI run `37875662633` surfaced one early Release Contract Tests failure:
6,187 Python tests passed, but a newly merged `main` worker-only CI
classification test expects a record without the `openbao` field. The KMS
branch's conservative classifier includes `openbao: false` for those worker
test-only changes, so the exact-record assertion in `main` is stale only in
the PR merge graph. `origin/main` has one new commit, `f4926bb4d` (#1195),
since the UI branch's last main merge. After the other live new-head lanes
finish, merge that commit and update the test to assert the explicit false
OpenBao lane in the same grouped follow-up. The other long jobs were still
live at this checkpoint; do not infer their outcome from this single failure.

UI run `37875662633` Rust contracts subsequently failed the authenticated
Gateway managed-key route acceptance: the first authorized create returned
409 instead of 200. The production Signing Keys service now rejects KMS key
metadata unless OpenBao explicitly reports a non-exportable, non-imported key
with plaintext backup and deletion disabled. The Gateway test's synthetic
Transit read response omitted those four booleans, so its generated key was
correctly classified as invalid. The local correction adds only the OpenBao
metadata to that fixture; it does not loosen the production custody check.
Targeted Rustfmt and `git diff --check` pass. The exact ignored Gateway
acceptance case now passes locally with Rust 1.95 against a separately
launched disposable Redis database 13 carrying its ownership sentinel; that
container was stopped after the test. The case still needs hosted
requalification. The Release Contract classifier expectation was also
corrected locally after merging current `main`; all 139 tests in its file
pass. Hold both corrections until the still-running Canvas, plugin-image, and
service-image lanes finish, then send one grouped PR update.

Verifier consumer test sweep: `cargo +1.97.1 test --locked --offline -p
marty-verifier --tests --no-run` found two remaining Core-local-key test
callers: the eMRTD integration suite uses `cert_builder`, `keygen`, and
`sod_builder`; one Tauri verification unit test creates a CSCA certificate.
The latter now consumes the reviewed public-only Core eMRTD vector instead.
The copied JSON fixture has the same SHA-256 as Core
(`944a97005ed646adb995fb847f5ac7eeeb8da14afd0c4d40fa15006498b42e40`),
and the targeted governed-CSCA unit case passes with Rust 1.97.1. Verifier
workspace Rustfmt and diff checks pass. The eMRTD suite still requires
public-vector/remote-custody migration with its multi-DG coverage preserved;
the full Verifier test compile remains red until that is done. This consumer
work is isolated and uncommitted, with no Verifier PR yet.

UI run `37875662633` later passed both `Test OpenBao DIDComm plugin image`
and `Rust Service Images`. Canvas remains live at this checkpoint. The two
known failed lanes have local corrections and are held for the grouped push.
UI `main` then advanced through `fb93db737` (#1196), adding an exact checkout
root rejection case to Canvas worker startup attestation. The KMS branch
merged it locally without conflicts. The focused new test passes on Windows
with Rust 1.95 (`marty-canvas-worker-acceptance`, one executed case); this
merge is held with the same correction batch while Canvas remains live.

UI run `37875662633` completed with three failed lanes and the aggregate
gate: Release Contract and Rust contracts are the two locally corrected
expectations above. Canvas's isolated database suites executed 144 passing
cases and one failure, `selfhost_public_image_loader_isolated`; its separate
worker suite passed 110. The selfhost child reached `correct:create` and
stopped with an incomplete native-create operation. The rendered
`issuance-native` Compose model mounts the new
`workload_identity_ca_cert`, but the loader's synthetic secret writer still
created only its previous six files. The local correction writes an existing
public test CA certificate to that seventh exact-owned path and checks the
writer's file set against the packager's closed `issuance-native` mount set.
The focused Canvas Rust test passes with Rust 1.95; targeted Canvas and
selfhost Rustfmt plus diff checks pass. This is a source-diagnosed candidate
fix to a Docker create failure, not yet a passing Linux public-image test.
The complete prior run has stopped, so push the accumulated UI corrections
together and require exact-head requalification.
The grouped correction batch was pushed to UI PR #1192 at exact head
`f798dcde61729d5e8e221882484533e410d4d4d0`, including the current
`main` merge and the Release Contract, Gateway managed-key metadata, and
packaged Canvas CA fixture corrections. New hosted CI run `37879061558`
started for that head. The previous failed run `37875662633` and its logs
remain immutable evidence; no new-head gate is claimed yet.
The isolated Verifier consumer candidate is now committed on its separate
branch at `981a2de`. It pins hardened Core and the reviewed SSI/isomdl graph,
removes unavailable local-key feature requests from dev/optional manifests,
and replaces Open Badge and one governed-CSCA test with public-only vectors.
The normal app and `marty-sync` checks, 25 Open Badge conformance cases, and
the governed-CSCA unit case passed locally. Full Verifier test compilation is
still blocked by its eMRTD suite's removed local certificate/SOD builders;
there is no Verifier PR or authenticator qualification yet.
Verifier all-features consumer check at `981a2de`: `cargo +1.97.1 check
--locked --offline -p marty-sync --all-features -q` fails because the optional
`demo-fixtures` modules still import removed
`marty_verification::dtc::sign_dtc_json` and Core-local certificate/key/SOD
builders. The default production `marty-sync` and Tauri app checks do not
select this optional path. Do not call the Verifier feature graph qualified
or silently discard the existing demo behavior; replace those generators
with public signed vectors or authorized remote-custody fixture generation
and then re-run the complete feature/test graph. No local private-key
fallback should be restored.
The same Verifier consumer source inventory found `marty-sync/src/usb.rs`
unit tests constructing an Ed25519 `SigningKey`, while its normal runtime
path verifies signed trust packages. Replace the test signer with a public
signed package vector or a remote-custody fixture without dropping replay,
signer-identity and signature-negative coverage. The app's process-local
keyring is a separate offline verifier data-at-rest boundary and is not
evidence of credential signing-key custody; audit its scope explicitly
before applying the KMS-only cutover to that desktop storage design.
Verifier consumer follow-up `0e43a26`: the `marty-sync` USB signature test
now consumes two deterministic signed **public** package vectors plus a public
Ed25519 key, instead of constructing a `SigningKey`. It retains the valid
signature, declared-wrong-signer, payload tamper and transition tamper
assertions. The focused case passes, and the full default `marty-sync` suite
passes 35 tests (one intentionally ignored) with Rust 1.97.1; workspace
Rustfmt and staged diff checks pass. These historical vectors intentionally
test signature/policy semantics, while package time validity remains covered
by a separate fixed-clock test. The optional demo fixture generators and
eMRTD conformance suite remain unqualified.
UI PR #1192 exact pushed head `f798dcde6` run `37879061558` has now
passed `Release Contract Tests`, including the corrected OpenBao classifier
expectation. Rust lint/packaging and the feature-regression probe also
passed. Rust contracts, Canvas, OpenBao plugin image and service images
remain live at this checkpoint; do not claim those gates yet.
Verifier eMRTD consumer correction `1a53fa6`: the app-layer conformance
suite now loads immutable signed public SOD/CSCA vectors for one, two and
five data groups, verifies every requested DG byte against its vector, and
uses an independent public CSCA for wrong-anchor rejection. The historical
generator ran only in a disposable, detached pre-hardening worktree and was
restored there after emitting public artifacts; no private key or generator
source was committed to the hardened consumer branch. All 25 eMRTD cases
pass on Rust 1.97.1, preserving single/multi-DG, tamper, SOD signature and
chain assertions. The full `marty-verifier --tests --no-run` graph now
compiles with the hardened Core pins. Workspace Rustfmt and diff checks pass;
the full test execution, optional demo-fixture feature and authenticator
wallet integration remain separate gates. No Verifier PR yet.

Verifier's full default `marty-verifier --tests` run subsequently passed: its
six executed targets reported 58, 0, 24, 25, 26 and 25 passing cases, with no
failures. This does not qualify the optional `demo-fixtures` feature or the
authenticator graph.

UI exact-head run `37879061558` passed Release Contract, authenticated
Gateway Signing acceptance and other fast lanes, but the Rust contracts lane
failed in `managed_config_resolve_does_not_revive_retired_tuple_binding`.
The assertion expected HTTP 200 for an unscoped `legacy-shared-key` in a
managed LTI profile; the hardened live resolver correctly returned 404. The
test now requires 404 and zero KMS reads, and passes against disposable Redis
with Rust 1.95. The plugin-image lane independently passed packaged plugin
storage and live Raft snapshot export/recovery, then failed in the Rust
integration-secret coordinated-restore probe while starting OpenBao after a
forced Raft snapshot restore. Its Docker helper previously suppressed stderr;
local correction reports bounded Docker stderr and gives the final restored
process a distinct name to avoid a possible `--rm` container-removal race.
The full local coordinated-restore reprobe passed on Windows against disposable
Docker PostgreSQL, Redis and OpenBao: Rust signed/holder, DIDComm, Flow and
integration-secret tests passed before the PostgreSQL/Raft restore, and the
final Rust secret read passed afterward. The original hosted Docker failure
had no diagnostic stderr, so the exact hosted cause is still unproven. The UI
Canvas lane remains live; hold these corrections for a grouped PR update and
require exact-head hosted requalification.

UI run `37879061558` has completed with three failed lanes. The Canvas lane
passed 145 isolated database cases and failed one packaged selfhost loader
case after `correct:await-health`; its separate worker target passed 111.
The previous CA-file correction let the native container create and start.
Source review identified the next real dependency: Issuance now performs a
remote integration-secret encrypt/decrypt proof before health, while this
isolated packager fixture removed service dependencies and had no reachable
HTTPS Signing Keys endpoint. The test harness now starts the existing
synthetic remote-secret fixture on the owned Docker bridge gateway, generates
ephemeral transport TLS for that fixture, verifies its encrypt/decrypt route,
mounts the matching public CA, and points only the isolated Compose copy at
that endpoint. This is **packaging behavior only**, not KMS custody evidence;
the separate live OpenBao/PostgreSQL/Raft restore probe remains the custody
proof. The focused HTTPS fixture test and exact secret-mount inventory case
pass locally with Rust 1.95; Linux packaged startup awaits exact-head CI.
The Rust contracts and plugin-image corrections were already validated
locally, so send all three lane fixes in one grouped UI PR update.

The grouped UI fixes were pushed at exact head `1e770acb0`; CI run
`37882379709` is active. Its Rust Lint and Packaging lane found a Clippy
`duplicate_mod` error because the Canvas test included the shared
remote-secret fixture directly while its existing `issuance_process` module
already included the same source. The local correction reuses that canonical
module path; focused `cargo +1.95.0 clippy --locked --offline -p
marty-canvas-acceptance --test canvas_published_schema_contract -- -D warnings`
passes. Hold this correction until the still-running contracts, plugin,
Canvas and image lanes complete, then batch any additional findings.

Verifier consumer optional-demo recovery is in progress on the isolated
branch. Public signed DTC and two-DG eMRTD artifacts were generated in the
disposable pre-hardening checkout with validity through October 2036; that
checkout's generator source was restored afterward. The hardened branch now
consumes only those public vectors, validates the trust-package signature and
current expiry, verifies the DTC chain and eMRTD trusted/tampered outcomes,
and removes `marty-crypto`, `rcgen`, `getrandom` and `const-oid` from
`marty-sync`'s optional demo graph. No private-key fields occur in the copied
artifacts or the hardened sync/Verifier source inventory. The locked optional
`marty-sync` suite passes 38 cases (one intentionally ignored). On final
Verifier candidate `7888ea9`, the locked/offline `marty-verifier --all-features`
check, its complete all-feature test graph (65, 0, 24, 25, 26 and 25 cases),
and all-target/all-feature Clippy with warnings denied pass. The complete
default Verifier test graph previously passed as well. Self-review of the
consumer diff found no remaining local issuer signing or optional demo key
generation; the only `ring::hmac::sign` use is for a verifier-local liveness
challenge. These public demo vectors remain synthetic and time-bounded.
Verifier draft PR [#154](https://github.com/ElevenID/marty-verifier/pull/154)
groups all four consumer commits and depends on the hardened Core PR #355.
Its first exact-head CI run completed with 17 successful checks and one
skipped check, with no failures; PR #154 is ready for review. Core PR #355
remains its dependency and still requires an approving review.

The isolated Authenticator consumer candidate now pins Verifier `marty-sync`
to PR #154 head `7888ea9` alongside hardened Core `d41d87c`. Its resolved
lockfile has no references to the old Core `56cc26c` or old Verifier
`8d410be`; Cargo's duplicate graph shows the sync crate and bridge sharing
the same hardened Core and SSI graph. The native Windows `marty-zkp`
Longfellow C++ build failed before a Rust bridge verdict; an explicitly
debug-only `USE_ZK_MOCK=1` Rust integration check is running. This does not
qualify a production ZK artifact or browser wallet flow, and no Authenticator
PR is open yet.

UI run `37882379709` also exposed a CI-runner artifact-selection failure in
the Rust contracts lane after its database and live Gateway tests had passed:
the database runner found two executable hashes for the same
`document_storage_contract` target, because a later focused Cargo invocation
rebuilt it with a different feature set. The runner now resolves singleton
contract executables from the exact workspace Cargo artifact manifest rather
than counting every executable left in `target/debug/deps`. Bash syntax and
diff checks pass locally. This is a CI selection correction, not a change to
the signing-document contract itself; hold it with the local lint correction
until the still-running Canvas, OpenBao and image lanes finish.

Authenticator follow-up source audit found a broader local-key surface beyond
the Rust dependency graph. The web Dart `MartyWasm` interop still exposes
`generate_p256_key`, `generate_ed25519_key` and a raw issuer-JWK credential
creation call, although the hardened Credentials WASM branch removes those
exports. `SpruceIdPlatformServiceWeb.createDid` and `generateKeyPair` call the
removed key generators. The native `SpruceIdPlatformService` exposes the same
channel methods; iOS `W3CMethodHandler.createDID` and `PKIMethodHandler`
generate `KeyManager` signing keys, while Android's
`SpruceIdHandlerRefactored.createDid` calls SDK `generateSigningKey` and reads
the signing key's JWK. These handlers are callable even where no current view
invokes them. The Authenticator consumer PR must remove these local-key
methods from reachable production channel routes and Dart/WASM wrappers,
preserve public DID resolution/verification and the active wallet issuance and
presentation flows, and verify that no native or browser path can mint or
export a private signing key. Do not interpret the hardened Rust dependency
pin or a green bridge compile as whole-application KMS-only proof.
The Android handler also creates a default SDK signing key at initialization
and uses its `Signer` for OID4VCI proof of possession; its credential-signing
route can create another key on demand. iOS `SignerAdapter` can generate an
SDK signing key too. These are active holder-wallet integration paths, not
just dormant wrappers. A KMS-only Authenticator release therefore needs a
remote-custody holder proof implementation or an explicit removal of those
wallet operations, followed by native and browser flow tests. Keep this gap
open until the actual platform signer call graph is denied or remote-backed.

UI run `37882379709` has now passed its packaged OpenBao DIDComm plugin
image lane, including the coordinated PostgreSQL/Raft integration-secret
restore probe that failed without diagnostics in the previous run. The Rust
service images lane also passed. Rust lint and database-contract CI selection
fixes remain local for the next grouped push; the Canvas public-image lane
is still building its packaged image.

The Authenticator short-target Windows debug build reached the Rust bridge
after avoiding a vendored OpenSSL long-path compiler failure. It found six
Core API incompatibilities: four ZK-prover symbols were gated by Core's
explicit `prover` feature, one `HashMap::get` call needed a borrowed claim
name, and `WalletEngine::create_proof_jwt` no longer exists. The mechanical
ZK feature and borrow corrections are local and are being rechecked. Core's
replacement `prepare_proof_jwt` returns a public-JWK-bound signing input for
an opaque external signer; it does not create a JWT. Authenticator has no
remote-custody completion at that bridge boundary. The current generated Dart
binding has no non-generated Dart caller, but the Rust export is reachable.
Replace or remove that export only after designing the remote holder signer
contract and validating the actual OID4VCI wallet flow; do not silently
reinterpret a signing input as a complete proof JWT or restore local JWK
signing.

The Rust bridge export `wallet_create_proof_jwt` has no non-generated Dart
caller and cannot satisfy its contract after Core removed local signing. It
has been removed in the isolated Authenticator candidate, rather than left
as a misleading or silently failing API. Regenerate the Flutter Rust Bridge
2.13 bindings and confirm the native/web consumer still builds; this does
not address Android/iOS SDK signers or add the future remote holder proof.

UI run `37882379709` is complete. The Canvas lane passed its packaged public
selfhost image, KMS fixture probes and isolated database suites; the OpenBao
plugin restore and Rust service-image lanes also passed. Only Rust Lint and
Packaging (`duplicate_mod`) and Rust contracts (duplicate executable hash in
the CI runner) failed, plus their aggregate gate. Both corrections are
already locally validated and grouped for one push to PR #1192. The next
exact-head run must turn those two lanes green before UI is ready for review.
The grouped fixes and tracker updates were pushed as UI PR #1192 head
`cf2f701fe`; exact-head CI run `37885206206` has started. Do not infer
qualification from the prior head's passing Canvas/OpenBao/image lanes;
require all required checks on this exact commit.

Potential DRY basis for the remaining Authenticator holder proof: UI Signing
Keys already has a Rust `OpenBaoHolderProofProvider` for the internal VC-API
Gateway bridge (`/internal/vc-api/holder-proof`). It creates a non-exportable
ephemeral Ed25519 Transit key, signs the OID4VCI proof JWT, verifies the
result and deletes the key. This is **not yet** an Authenticator mobile API:
it has an internal trust boundary and one-request ephemeral holder identity,
while the native wallet may require stable holder keys and device-scoped
authorization. Evaluate reuse or extraction of its Rust proof logic and
define authenticated remote holder key lifecycle before replacing Android/iOS
SDK signers. Do not expose the internal route directly to devices.

Authenticator isolated candidate now compiles its Rust bridge with hardened
Core and Verifier pins using a short Windows build target and debug-only ZK
mock. Enabling Core's `marty-zkp/prover` feature and borrowing the claim name
resolved five bridge errors. The unused `wallet_create_proof_jwt` export and
its stale Rust/Dart/native/web binding entries were removed; no non-generated
Dart caller referenced it. The pinned Flutter Rust Bridge 2.13 generator
could not finish locally because `ffigen` requires a real Flutter SDK, which
is absent here. A hand-pruned generated diff remains provisional; the actual
Flutter 3.44.6 codegen CI job must regenerate and compare it before any
Authenticator PR can be qualified. Android/iOS
SDK holder signing is still an active KMS-only release gap.

At UI PR #1192 exact head `cf2f701fe`, Rust Lint and Packaging has completed
successfully. This confirms the duplicate-module correction; the contracts,
Canvas, OpenBao restore and image lanes remain live in run `37885206206`.
The same run's Release Contract Tests lane found two stale source assertions
in `test_issuance_rust_candidate.py`: they searched for the old executable
globs removed by the manifest-based CI resolver. Its other 6,196 tests
passed. The two assertions now require the new resolver calls and retain the
OID4VCI-migration-before-transaction ordering check. Both focused tests,
Ruff and diff checks pass locally. Hold this correction until the still-live
contracts, Canvas, OpenBao and image lanes finish, then group any further
findings in one push.

The exact-head Rust contracts lane has since progressed past the database
contract groups and into authenticated Gateway Signing acceptance, indicating
the manifest-based executable selection cleared its previous duplicate-hash
stop. Wait for the lane's final result before claiming it green.

Authenticator isolated commit `3b67547` now checkpoints the hardened Core and
Verifier sync pins, enabled ZK prover feature, corrected claim lookup and
retired unused local holder proof bridge export across Rust/Dart/C headers.
The Rust bridge compiles and all 36 library tests pass with the short Windows
target and debug-only `USE_ZK_MOCK=1`; Rustfmt and diff checks pass. This is
not a production ZK build, generated-binding equivalence proof, mobile
signer replacement or Authenticator PR. The local 2.13 generator was tried
twice but cannot complete its `ffigen` pass without the Flutter SDK; a
version-only shim was discarded and the tracked generator config restored.
The same isolated Authenticator checkpoint also passes locked/offline Rust
Clippy for the bridge library with warnings denied. Cargo reports unused
fork patch entries as resolver notices; there is no Rust lint failure.

The Rust contracts lane at UI head `cf2f701fe` now selects the manifest-built
`document_storage_contract` binary, clearing the earlier duplicate-hash
failure. It exposed a separate CI fixture mismatch: the selected test requires
a loopback Redis database numbered at least 13 and a matching disposable
nonce guard, while the shared database runner supplied Redis database 0.
The next grouped UI change seeds a fresh guard in database 14 before the
contracts group and passes the nonce to the runner; only the document contract
is scoped to database 14. A focused source contract verifies those CI wiring
invariants, and its test, Ruff, Bash syntax and diff checks pass locally.
This correction still needs an exact-head CI run. The Release Contract Tests
source-assertion fix is in the same local batch; the current OpenBao restore,
Canvas image and Rust image lanes should finish before the batch is pushed.

Further Authenticator production-surface inventory found a web custody violation in
`lib/services/spruce_platform_service_web.dart`: `generateKeyPair` calls the
local WASM P-256 generator and returns its JWK under both `publicKey` and
`privateKey`. A direct isolated call to the checked-in WASM confirms both its
P-256 and Ed25519 generated JWKs contain the private `d` parameter (only
parameter names were printed). Thus the web DID creation and key-generation
returns exposed private material. The conditional web WASM wrapper also exposes Ed25519 generation,
raw-JWK credential issuance and raw-JWK presentation signing. Native Android
`PresentationSignerAdapter.kt` signs through device `KeyManager`; iOS
`SignerAdapter.swift` similarly operates on device keys. These paths are not
remote KMS-only. Replace or retire their exported signing/generation surfaces
as part of the Authenticator consumer cutover, and prove web/native wallet
capabilities against authenticated remote holder custody before qualifying
that consumer. Do not treat the Rust bridge pin or mock ZK pass as this proof.

An Authenticator candidate follow-up now makes web `createDid` and
`generateKeyPair` fail closed with a remote-KMS-required error, removing those
direct application return paths. The checked-in WASM still exports local
generation and raw-JWK signing functions, and the remote holder flow is not
implemented. Do not qualify or ship the Authenticator consumer from this
intermediate fail-closed change; rebuild or remove the raw-key WASM surface
and restore DID/key workflows through authenticated remote custody first.

The Authenticator follow-up additionally removes the Dart WASM wrapper's
local key-generation, raw-JWK credential-signing and presentation-signing
methods from both web and non-web stubs, and replaces the loader's wildcard
global export with an explicit public/verification method list. JavaScript
syntax and reference/diff checks pass; Flutter/Dart verification is unavailable
locally. The checked-in WASM module itself still includes raw-key exports.
`web/marty_wasm_loader.js` requests it under `/assets/packages/marty_rs/`, but
the present `pubspec.yaml` does not declare that package; actual web release
packaging and fetchability remain unverified. This narrows application access
but is not the required final artifact boundary.

UI run `37885206206` subsequently completed `Test OpenBao DIDComm plugin
image` successfully, including the coordinated PostgreSQL/Raft restore lane,
and `Rust Service Images` successfully at pushed head `cf2f701fe`. Canvas
public selfhost image qualification remains live. The Release Contract Tests
and Rust contracts failures on this head are addressed by local commits
`f90161397` and `0c7370c7a` respectively; neither is a hosted pass until the
next exact-head run completes.

Before that hosted retry, the ignored Rust `document_storage_contract` binary
was exercised locally against a fresh disposable Redis 7 container on a
random loopback port, database 14, with a freshly seeded matching nonce guard.
Its real certificate/JWKS/DID/slug round-trip passed (1 passed, 0 failed);
the container was removed. The full 12-test release-contract source file also
passes locally. This validates the fixture choice and contract behavior, not
the workflow wiring on a hosted runner.

UI run `37885206206` has now passed the Canvas lane's public selfhost image
build, host/namespace KMS fixture probes and isolated database suites. Its
OpenBao plugin image, service images and Rust lint also passed. All substantive
lanes are terminal; only Release Contract Tests and Rust contracts failed on
the known assertions/Redis fixture corrected in the local grouped batch.
The aggregate CI Gate was still queued at this checkpoint. Push the grouped
batch once, then require a new exact-head rollup before claiming UI PR #1192
qualified.

Grouped UI correction head `d2b56df78` has been pushed to PR #1192. CI run
`37888791629` was queued for that exact head. The previous run
`37885206206` was superseded/cancelled while its aggregate CI Gate was queued;
its substantive lane results and two failure logs remain preserved. Do not
interpret the cancelled rollup as qualification or as a new Canvas failure.

Authenticator web artifact replacement candidate: rebuilt the
`marty-credentials` `marty-rs` WASM crate at exact PR #313 head `fef8da1`
with hardened Core `d41d87c`, `--locked --release --target
wasm32-unknown-unknown --no-default-features --features wasm`, then generated
web bindings with `wasm-bindgen 0.2.127`. The generated module has public
protocol/verification exports only; direct Node loading, health check,
credential-offer wire check and JS/raw-WASM forbidden-export audit passed.
The Authenticator candidate replaces its tracked raw-key `marty_rs` module
with those generated artifacts under `web/marty_rs`, changes the loader to a
relative URL, and adds a web-build artifact audit to the existing Flutter test
job. A simulated copied web directory passes the audit. Actual Flutter web
build/packaging and the native Android/iOS KMS-only holder flows remain due;
the Authenticator candidate is not release-qualified or pushed.

Authenticator local commit `1307612` records that replacement. Its generated
WASM artifact SHA-256 is
`c7cf660e4fa82824938b69cd0b4b6e5e17d6fa52ef37a34718b075ca9d91db39`;
the generated JS SHA-256 is
`618b641e96fe338ee7e5971e0c50aab0744291ce9f6a53241ebcc2e7390bff35`.
The checked-in copies match the exact generated files. The Node audit passes
against both `web` and a simulated copied web root, checks the public export
allowlist, rejects raw key operation names in JS and WASM exports, and exercises
health and credential-offer behavior. The Flutter test workflow now builds
`lib/main_document.dart` for web and runs that audit on `build/web`; this
hosted job has not run for the isolated Authenticator branch.

Web verification self-review found `SpruceIdPlatformServiceWeb.verifyJWT`
called `verify_jwt_claims`, whose new Credentials WASM source explicitly
validates structure and claims without checking the cryptographic signature.
The Authenticator candidate now fails closed for web JWT and SD-JWT
verification, removes the Dart wrapper call and excludes that helper from the
loader's global allowlist. The binary still contains the claims-only helper,
and web cryptographic verification is unavailable. Restore it through a
public-key/trust-aware verification route with forged-signature negatives
before shipping the web consumer; do not treat the public-only WASM swap as
complete wallet feature preservation.

K10 database guard follow-up: the existing Rust Issuance migration PostgreSQL
contract now queries `information_schema` after applying the service migration
and rejects `issuer_signing_keys`, private-key-named tables and private JWK/key
columns in `issuance_service`. It adds no migration script. The test compiled
locked/offline and passed against a fresh disposable PostgreSQL 16 container
on a random loopback port; the container was removed. An initial local run
passed the new schema queries but tripped its pre-existing narrow 1798–1800
second token-expiry timing assertion. A diagnostic failure message was added;
the second full run passed. This proves the targeted Issuance schema contract,
not the assembled product database or the historical selfhost table cleanup.
Hold the Rust test change for the next grouped UI push after current exact-head
run `37888791629` has exposed any further findings.

UI run `37888791629` Release Contract Tests failed one source-shape assertion
after 6,200 tests passed (19 skipped):
`test_canvas_published_preflight.py` compared the entire isolated database
workflow step to the pre-disposable-Redis shell block. The test's exact
expectation now includes the contracts-only nonce guard before the existing
worker/canvas branch, preserving its full-gate invariant. Its focused pytest,
Ruff and diff checks pass locally. Rust Lint and Packaging passed on this
head; Rust contracts, Canvas, OpenBao and images remain live. Group this
source-assertion correction with the K10 schema guard and any further live
lane findings before the next push.

With CI's `PYTHONPATH=packages` plus the repository root locally, all 6,208
Python release tests collected. A full Windows run reached the Canvas Bash
shell-harness cases at roughly 12% and advanced too slowly to serve as a
practical full-suite gate; it was stopped deliberately. This is not a full
local pass. The exact corrected workflow assertion passes in isolation, while
the hosted Linux run established 6,200 passing tests and the one known source
assertion failure. Re-run the complete hosted release lane after the grouped
correction rather than extrapolating from the interrupted Windows run.

The new Issuance PostgreSQL migration contract also passes targeted locked,
offline Rust 1.95 Clippy with warnings denied. The first disposable database
run's narrow expiry assertion is retained with a diagnostic message; the
subsequent clean disposable PostgreSQL 16 run passed the entire selected
migration test. Both runs exercised the new private-key schema checks before
the expiry assertion.

At UI head `d2b56df78`, run `37888791629` has now passed `Run safe Rust
contract groups concurrently`, the hosted step that executes the selected
signing document Redis contract with the new guarded database-14 fixture.
Rust Lint and Packaging and Rust Service Images also passed. The Rust
contracts job continues through later checks; do not call the entire lane
green until it terminates.

The same `d2b56df78` run subsequently completed Rust Service Tests
(`contracts`), Rust Service Tests (`canvas`), Rust Lint and Packaging, and Rust
Service Images successfully. The Canvas result includes packaged public
selfhost and isolated database suites; the contracts result includes the
guarded Redis document test, gateway and live Signing Keys contracts. Release
Contract Tests remains the sole failed lane observed so far because of the
known exact workflow-text assertion fixed locally. The OpenBao plugin image
restore lane remains live and must finish before the grouped follow-up push.

The OpenBao DIDComm plugin image job also completed successfully at
`d2b56df78`, including the coordinated PostgreSQL/Raft restore probe. All
substantive lanes are now terminal; Release Contract Tests is the only failed
one, and the aggregate CI Gate is queued. Push the single grouped follow-up
containing the corrected workflow assertion and real Issuance private-key
schema guard, then require a fresh exact-head CI rollup.

Grouped UI follow-up `f9317b67a` is pushed to PR #1192, and CI run
`37891713276` is queued for that exact head. Its result is pending. The prior
`d2b56df78` run finished with only the release source-assertion lane failed;
the native, Canvas, OpenBao and image lanes passed on that prior head.

PR #1192's draft description has been refreshed around the current grouped
native/deployment behavior, exact prior-head hosted evidence, Core/Credentials
dependencies and remaining release gates. This metadata edit did not change
the commit head or restart CI. The PR remains draft while run `37891713276`
and artifact/cutover qualification are pending.

Test-boundary inventory follow-up: active Canvas published-worker Python
reference oracles still seed a synthetic `INTEGRATION_SECRET_MASTER_KEY` in
`run_canvas_worker_rest_oracle.py` and
`run_canvas_worker_startup_oracle.py`. They are isolated historical parity
fixtures, not native production configuration, but they are still executable
test code. Do not infer KMS-only test completeness from the production graph.
After the native published-process parity gate is qualified, replace or retire
these raw-key reference executions and preserve only non-executable frozen
evidence needed for review. Keep rejection tests that supply synthetic
private-material markers to prove fail-closed behavior.

Credentials artifact checkpoint: downloaded the exact retained
`core-python-Linux` artifact from green PR #313 CI run `37870545663` at head
`fef8da1`. It contains `marty_rs-0.2.0-cp311-abi3-linux_x86_64.whl`
(SHA-256 `adeb13256b0a39f1b6ae99ecb065f700c9c92ff0c6e2f9ee1cf21b36656e5b58`)
and `marty_verification_py-0.2.0-cp311-abi3-linux_x86_64.whl`
(SHA-256 `f4b75ce07d916a66c8182df88e27f5afa381b92da3ec8aa46a1ad1635c5e7d11`).
Both installed without network dependencies into a disposable glibc Python
3.12 container. Import and callable public OID4VCI/Open Badge verification
exports passed; retired local DIDComm, symmetric-key, local generation and
Open Badge issuer exports were absent. The container was removed. This is
pre-release branch artifact evidence, not proof of the final published wheel
or Authenticator browser/mobile integration.

Core Python test custody follow-up: `marty-verification/python/tests/test_dtc_external_signing.py`
still held a fixed private PEM and locally signed DTC payloads. In the Core
hardening worktree, replace this with a pre-signed public ECDSA vector plus
the public key, and fix the DTC ID and creation date so the canonical payload
is stable. The positive external-signature assembly and tampering rejection
tests both pass (`2 passed`); Ruff and `git diff --check` pass. This local
test-only correction is not yet on Core PR #355. Batch it with any remaining
Core follow-up before one hosted CI rerun and coordinate downstream exact
revision pins. Do not count the current green Core PR head as including this
test cleanup.

The first public DTC vector was generated against an older installed
`marty_verification` 0.1.60 binding, which hid a canonical payload difference.
That vector was corrected using a local `maturin develop --locked` build of
the current Core 0.2.0 source with the repository's full Python feature set.
The Core conformance selection now passes all 10 tests: production KMS
surface, DTC external signing and tamper rejection, MRZ, and eMRTD. The
test-only Core local commit is `e9a0495`; it remains unpushed for the next
grouped Core follow-up and downstream pin coordination.

Credentials/Auth public verification boundary follow-up: a self-review found
the Credentials Python `verify_jwt` and WASM `verify_jwt_claims` exports only
parsed claims, while the WASM `extract_credentials_from_vp` export returned
credential objects from an unverified VP JWT. There were no repository callers
of these functions beyond the unused Authenticator wrapper method. Local
Credentials commit `5eaedab` removes all three misleading exports and adds
a Python public-API guard while retaining Core-backed `verify_vcdm_jwt`.
WASM release build from this source passed, Python `marty-rs` Clippy with
warnings denied passed, and the locally built Python extension passed six
production-surface/Core-boundary tests with `verify_jwt` absent.

Local Authenticator commit `bb0d90e` removes the unused Dart VP extraction
wrapper and global loader export, replaces the tracked WASM/JS bindings with
the artifact built from Credentials `5eaedab`, and makes its artifact audit
forbid both unverified JWT exports in JS and raw WASM. The Node public-artifact
audit and JS syntax check pass. The new WASM SHA-256 is
`806f2d0a0e9516525bc1dccab145b88db8e2cb54d7b6756f6189b3566d1d2eac`;
generated JS SHA-256 is
`54e5e73ed2b0f42d9a00980a1e1d17bb2ca8993f5f51cd3bca3835aa5ec32775`.
Credentials `5eaedab` has now been pushed into grouped draft PR #313; its
new exact-head hosted CI/artifact result is pending. Authenticator `bb0d90e`
remains local and unpushed while its wallet feature gaps are addressed. Web
cryptographic JWT/SD-JWT verification and mobile KMS-backed holder flows
remain required before Authenticator can be shipped.

UI exact-head run `37891713276` at `f9317b67a` has now passed Release
Contract Tests, Rust Lint and Packaging, and Rust Feature Regression Probe.
At this checkpoint 18 jobs passed, four long jobs were still running:
OpenBao plugin image with PostgreSQL/Raft restore, Canvas tests including
public selfhost image, Rust contracts including live Signing Keys Redis,
and Rust Service Images. No failure has been observed on this head. Require
terminal aggregate CI Gate before qualifying PR #1192.

Credentials PR #313 description now distinguishes its green prior head
`fef8da1` from the new unverified-export retirement head `5eaedab`.
Exact-head CI run `37893495477` and organization/license policy runs are
queued or in progress; Open-source policy has passed. Require the new CI
artifact and exact-head checks before promoting this PR or rebuilding the
Authenticator artifact for release from a published Credentials revision.

Authenticator native self-review found that the iOS JWT, PKI and W3C channel
extensions returned placeholder JWTs/signatures, unconditional verification
success, a fabricated DID/credential result, or local `KeyManager` key
creation. Local Authenticator commit `c6415b9` removes these placeholder
implementations and makes the affected channels fail closed with explicit
remote-KMS or cryptographic-verification errors. Source/diff checks show no
remaining private-key generation, placeholder signature, or unconditional
`valid: true` in those three handlers. Swift/iOS compilation was unavailable
on this Windows host, so this commit is not a mobile qualification. The
Android `SpruceIdHandlerRefactored` still generates device-local signing keys
and uses them for issuance/presentation; that is an active blocker, not an
accepted KMS-only holder implementation. Preserve the unshipped Authenticator
branch until both platforms use remote custody and wallet features are
requalified.

UI run `37891713276` has now passed the OpenBao DIDComm plugin image lane,
including its coordinated PostgreSQL/Raft restore, and the Rust contracts
lane. At this checkpoint 20 jobs passed and only Canvas's public selfhost
image build and Rust Service Images remained live. The aggregate CI Gate
still requires terminal results. Credentials exact-head CI `37893495477`
has six passing jobs and four active build/test jobs, with no failure yet.

Further iOS review found mDoc and wallet channel methods also returned mock
sessions, fake age/ID/X.509 verification, fabricated mDoc responses, and
storage success without persistence. The unreferenced iOS
`W3CMethodHandlerRefactored.swift`/`SignerAdapter.swift` pair still compiled
device-local key generation/signing code. Local Authenticator commit `2f79125`
removes that unused pair and the mock mDoc/wallet implementations, with
explicit errors at all prior channel method names. A source comparison
confirmed the five affected iOS channel dispatchers still recognize the
same 44 method names (7 JWT, 4 PKI, 13 W3C, 12 mDoc, 8 wallet), now failing
closed where no real operation exists. No local signing-key generation,
placeholder response, or unconditional verification success remains in
`ios/Runner/SpruceID`; `git diff --check` passed. This is source-level
containment, not restoration or compiled iOS acceptance. Real mobile
remote-KMS holder, mDoc session, and persistent wallet implementations
remain mandatory before the Authenticator branch can ship.

Credentials PR #313 exact head `5eaedab` now has 19 successful checks and
one intentionally skipped check; CI run `37893495477` completed all 11 jobs
successfully, including WASM, local Marty Python binding, Python retirement,
Rust and Python tests, security, and aggregate gate. Its only retained run
artifact is `core-python-Linux`, containing the pinned Core wheels; the
Credentials wheel built in the local-binding job is not retained. The hosted
checks prove the branch CI, but a publishable Credentials wheel and its API
export audit still require release-artifact qualification. Keep PR #313 draft
for coordinated Core/UI and browser/mobile cutover gates.

Android Authenticator containment follow-up: local commit `cae6bd5` removes
the default signing-key creation from `SpruceIdHandlerRefactored.initialize`.
All 20 existing channel method names remain in its dispatcher, but DID/VC,
OID4VC/VP, mDoc, SD-JWT and unqualified wallet storage routes now return
explicit remote-KMS, trusted-verification, session, or persistent-wallet
errors; advertised DID methods/credential formats are empty until real
implementations exist. A source comparison found no dispatch-name loss and
no local key generation in initialization; `git diff --check` passed. The
old private Android helper methods and signer adapter are still compiled
behind unreachable private paths, and Android compilation is unavailable
here. Remove those paths and implement/requalify remote holder signing plus
wallet/session behavior before shipping. This is fail-closed containment,
not completed Android KMS custody.

Authenticator desktop audit also found local signing-key generation in
`macos/Runner/SpruceIdSupport.swift`; this surface has not been changed or
qualified by the mobile containment commits. The final consumer gate must
cover every shipped platform (including macOS if it remains supported),
remove the now-dead Android signer code, and restore real remote signing,
verification, wallet persistence and mDoc sessions before enabling release.

UI exact-head run `37891713276` has advanced to 21 passing jobs; Rust
Service Images is now green. Only `Rust Service Tests (canvas)` remains live,
currently building the public selfhost image. No exact-head failure has
appeared; the run and aggregate CI Gate are not yet terminal.

The Android containment was then tightened in local Authenticator commit
`0a2396b`: the unreachable SDK key-manager/signing helper code and
`PresentationSignerAdapter.kt` were removed, along with the no-op
initialization claim. `ChannelRegistry` still registers the same channels,
and a source comparison confirmed all 20 previous Android method names
remain in the dispatcher with explicit fail-closed responses or empty
capability lists. A scan of active Android Kotlin app sources found no
`KeyManager`, `generateSigningKey`, `signPayload`, or `Signer` call; diff
checks pass. Android/Flutter compilation is unavailable locally and has not
run in hosted CI for this unpushed branch. This removes the old local signing
surface but does not restore functional remote holder signing, wallet or
mDoc capabilities; release remains prohibited until those are implemented
and tested.

macOS Authenticator containment now matches the mobile boundary. Local
commit `30764df` removes the single-file macOS mock `KeyManager`, fabricated
JWT/PKI/W3C signatures, unconditional verification, mDoc sessions and
wallet success responses. It retains all five previous channel names and
all 30 method names with explicit fail-closed errors. Source comparison,
forbidden-marker scan and diff checks passed. macOS/Swift compilation is
unavailable locally and the branch has not been pushed to hosted CI. The
goal still requires actual remote holder signing, trusted verification,
wallet persistence and mDoc sessions across every supported platform;
these fail-closed channel stubs must not be marketed as feature parity.

The repository also contains `local_plugins/pi-authenticator-legacy` with
Android keystore private-key signing helpers. This plugin is absent from
the root `pubspec.yaml`/`pubspec.lock` and active
`lib`/`android/app/src/main` references in the current Authenticator
worktree, so it is not evidence of a shipped key path. Retire or archive the
unused plugin after a release graph audit rather than accidentally pulling
it into a KMS-only package.

After the Android/macOS edits, the Authenticator candidate still passes its
Node public-WASM artifact audit and loader syntax check. A targeted scan of
active Android app Kotlin, iOS `Runner/SpruceID` Swift and macOS `Runner`
Swift sources found no `KeyManager`, `generateSigningKey`, `signPayload`,
placeholder signature/response markers, or unconditional verification
success in those paths. This is a source audit only; compiled mobile/desktop
artifacts and real wallet behavior are still unqualified.

Local Authenticator commit `274ffaf` adds a fast CI source guard to the
existing Flutter Test workflow. It scans active Android handler, iOS
SpruceID and macOS runner sources for SDK local key-manager/signing calls
and placeholder or unconditional-success responses, and rejects an accidental
root `pubspec` dependency on the retired legacy plugin. The guard and Node
syntax check pass locally. This guard preserves the source boundary while
the branch is under construction; it does not prove compiled mobile/desktop
artifacts or restore wallet functions.

Remote-holder feasibility check: Signing Keys already exposes
`/v1/signing-keys/holder-keys`, but its request only registers a device and
credential's **public** JWK; it does not create or sign with a remote holder
private key. `/internal/vc-api/holder-proof` creates a one-request ephemeral
OpenBao Ed25519 proof for the Gateway VC-API organization flow and deletes
that key after use. Neither endpoint is an authenticated, durable
device-scoped Authenticator signing API. Do not wire the mobile wallets to
either as if they solved remote holder custody. The replacement needs a
device-authorized create/reference/sign/rotate/revoke contract with public
verification projection and recovery semantics, followed by end-to-end
wallet and mDoc qualification.

The grouped Authenticator candidate is now pushed at exact head
`274ffaf5d6b2e15b2b615ae8324df117f3ab2f7b` as draft PR #57. Its PR
description makes the fail-closed scope, upstream Core/Credentials/UI pins,
local evidence and remaining remote-holder/wallet/browser gates explicit.
Hosted Flutter Test run `37895163573`, Flutter Build `37895163276`, Rust
Bridge Codegen `37895163219` and policy/quality runs have started or queued;
none is qualified until terminal. Keep PR #57 draft and do not release the
feature-reduced candidate. The current UI run `37891713276` remains live in
the Canvas isolated database contract step with 21 earlier jobs passing.

Authenticator PR #57's first hosted Flutter Test run `37895163573` passed at
`274ffaf`. The quality lanes exposed two specific corrections: the Flutter
formatter wants a multiline `UnsupportedError` in
`spruce_platform_service_web.dart`, and `dependency-health.yml` had a stale
`2026-10-01` review date for `permission_handler`. Both are corrected locally
but intentionally unpushed while Android/iOS and bridge checks finish, so
the next push can batch any further CI findings. The dependency review now
records the 2026-10-09 upstream 13.x compileSdk 37 requirement against the
app's current compileSdk 36, with review due 2026-10-23; it no longer asserts
that Android SDK 37 is unavailable without current evidence. This remains a
tracked dependency exception, not a KMS feature qualification.

At Authenticator PR #57 head `274ffaf`, Flutter Build run `37895163276`
completed successfully for both unsigned Android APK and iOS configuration.
This gives a hosted Android compile and iOS project/configuration check for
the fail-closed native edits; it does not compile the iOS Swift runtime or
prove functional KMS wallet behavior. Rust Bridge Codegen run `37895163219`
is still generating bridge surfaces. The local quality correction is committed
as `91bac10` and remains unpushed pending that result.

UI PR #1192 exact-head CI run `37891713276` finished successfully: all 23
jobs passed at `f9317b67a`, including the Canvas isolated database and native
timeout/TLS parity suites. This qualifies that PR head's hosted checks, but
the pending Core repin will require a new exact-head run; no release artifact
or product cutover is implied.

Core PR #355 now carries commit `e9a0495`, which replaces a private-key DTC
Python test signer with a fixed public signed vector. The previous local
binding tests passed. Hosted checks on the new head are still running; its
Organization Quality lane failed because two dependency-health review dates
expired on 2026-10-08. A local correction re-reviewed RustCrypto RSA release
tracking and the Affinidi TDK source, updates those reviews to 2026-10-23,
and passes YAML parse/diff checks. It remains unpushed until the other new-head
Core checks finish so findings can be batched.

Verifier PR #154 has a pushed Core `e9a0495` repin at `4e40ba0`; its hosted
checks completed successfully at that head, including CI, organization
quality, license compliance and open-source policy. Local UI and Credentials manifests, lockfiles and
graph guards also pin `e9a0495`, and their full locked KMS metadata checks
pass. Authenticator's first naive direct repin produced two Core revisions
because `marty-sync` still came from Verifier's prior head. Its local
`marty-sync` dependency now points to Verifier `4e40ba0`, and full locked
metadata resolves exactly one Core source across ten Core packages. Do not
ship or claim graph closure until the final Core correction SHA is repinned
through all four consumers and the hosted/artifact gates pass.

Authenticator PR #57 Rust Bridge Codegen run `37895163219` failed only at its
generated-file freshness check: `frb_generated.dart` and `frb_generated.rs`
held an obsolete content hash. The CI-generated exact diff changes both
constants to `1509900566`; that correction is local. The exact generator
version 2.13.0 was installed locally, but generation cannot run without a
Flutter/Dart SDK on this Windows host. The next hosted run must prove these
generated files match current bridge source. Local locked bridge tests are
running after the unified Core/Verifier repin; the first parallel C++ build
failed before test execution, so a single-job retry is being captured.

The single-job Windows bridge retry also stopped before Rust test execution:
vendored OpenSSL `openssl-sys` failed under MSVC with `C1083: Cannot open
compiler generated file: '': Invalid argument` in the long worktree target
path. This is a local build-environment/path failure, not passing bridge
validation. The exact-head hosted Linux bridge lane must provide the decisive
compiled behavior evidence after the final repin and generated-hash fix.

The grouped final-Core repin is now pushed across the existing PRs. Core PR
#355 head `6855721d7e863682f18fad613ec46f9f4975e33e` carries the
review-date correction; Core CI `37897508392`, release wheel preflight
`37897508412`, and organization quality `37897509053` are queued or running.
Verifier PR #154 head `19431ecc5a4562934e6c6108567cec7167997c0b`
has a full locked Cargo metadata pass against that Core source; new CI run
`37897580679` is queued. UI PR #1192 head
`5d26b11e3f7db07645bbca2d8d7eb3538e937c84` has local locked KMS graph
and diff checks passing; its new exact-head run has not yet appeared.
Credentials PR #313 head `7b065b0875ae3a15a71149f7925ea192eb96826c`
passes the local locked KMS graph guard; CI `37897657865` is queued.
Authenticator PR #57 head `77dda21592de0f5214aca0fb0d81ff12619f2044`
contains the Flutter formatting/dependency-date fixes, exact generated hash
from the prior hosted diff, final Core pin and Verifier `19431ec` pin. Its
locked metadata resolves one Core source; mobile custody and public WASM
source audits pass. New Flutter Test `37897669658`, Flutter Build
`37897669670`, and Rust Bridge Codegen `37897669694` are queued. All those
new-head hosted outcomes remain unqualified until terminal.

Main advanced while UI PR #1192 was in review and GitHub reported its head
conflicting, suppressing the new PR check run. A local merge reconciles four
conflicts: the Rust workspace member list retains KMS key-material policy and
deployment-profile crates while adopting the new selfhost-acceptance crate;
the KMS remote-secret HTTPS fixture and synthetic secret mount test now live
with the extracted selfhost target; the Canvas runner retains disposable
OpenBao cleanup and all three parallel target logs; and its Python fake-shell
expectation covers the extra KMS signer calls plus the third target. The
untracked generated `%SystemDrive%` directory remains untouched.

After that merge, Rust 1.95 compiled both `marty-selfhost-acceptance` and
`marty-canvas-acceptance` test executables. The selfhost target lists twelve
tests, and its real disposable HTTPS remote-secret fixture passed locally.
The full Canvas preflight fake-shell suite passed **222 tests** in a local
Linux container with GNU `tail` and `jq`; Git Bash on Windows timed out in
the phase-log relay, so that Windows result is not acceptance evidence.
Additional Windows structural suites passed 134 tests, one skipped and 298
subtests, and the selfhost runtime model/registration suites passed 30 tests.
The final Core `6855721` locked graph guard still passes after the merge.
Hosted exact-head CI and full packaged/native acceptance remain pending after
merge commit `14f115ecc46eb31d22672359265090d75cd0349a` was pushed. UI PR
#1192 now reports `MERGEABLE`; CI run `37899481669` and security/quality
workflows are queued for that head.

Authenticator Rust Bridge Codegen run `37897669694` passed at `77dda21`,
confirming the generated hash and native bridge behavior on hosted Linux.
The quality lane still found a Dart formatting difference. Dart SDK 3.12.2,
the version bundled by CI's Flutter 3.44.6, formatted the web file; a
project-wide `dart format --output=none --set-exit-if-changed` then reported
zero changes. That correction is pushed in Authenticator PR #57 head
`1a3bb7389615e0e10b4b5c8c5f25b17be2998b4c`; require its new CI result.
Core `6855721` organization quality and release wheel preflight passed,
while its main CI remains active. Verifier `19431ec` has green exact-head CI.

Core `6855721` main CI run `37897508392` subsequently completed successfully,
including its native ZKP boundary and aggregate gate. A further Python test
audit found `test_native_key_conversion.py` still generated a private P-256
JWK through a forbidden production API merely to test public conversion.
Core PR #355 head `4cc1c9f` now reads its canonical public P-256 vector and
uses only a synthetic private-field marker for the rejection case. Both
focused Python tests pass locally; Ruff lint/format and `git diff --check`
pass. New hosted checks for that test-only head are pending. Downstream
consumers remain pinned to `6855721`, whose production implementation is
unchanged by this test correction; do not repin solely to induce four more
CI runs. Core review approval is still required.

The five grouped PR descriptions now cite current heads, completed evidence,
and open release gates. Authenticator final-head Flutter Test, Android/iOS
Flutter Build and Rust Bridge Codegen passed; Flutter Quality remains live.
UI merged-head CI is live, not yet a packaged/native release qualification.

The self-host migration-image qualifier previously checked successful startup,
idempotent notification schema migration, Redis KMS registry seeding, and the
non-exportable OpenBao notification key, but did not inspect the resulting
PostgreSQL schema. Its candidate now queries the disposable catalog after
each migration run and refuses `issuer_signing_keys`, private-key/JWK/secret-key
table names, and private-key/JWK/key-material column names. It returns
`private_key_storage: absent` only after both read-only checks pass. The
seven local qualification tests pass, including a new failure-and-cleanup
case. Ruff and diff checks pass. An isolated PostgreSQL 16 container verified
the SQL returns no hits for public JWK and opaque integration-secret fields
but detects a synthetic `issuer_signing_keys.encrypted_jwk_json` table and
column. This protects the migration-image schema only; the separate native
Issuance migration, assembled release schema, runtime writes, and clean
self-host cutover still require their own evidence.

Authenticator PR #57 head `1a3bb73` has now passed every applicable hosted
check, including Flutter Quality, Flutter Test, Android build, unsigned iOS
configuration, generated Rust bridge, CodeQL and policy. It remains draft:
these checks prove the current fail-closed containment builds, not working
remote holder signing or wallet feature parity.

K10 assembled-schema follow-up: the separate
`docker-compose.passport-supported-disposable.yml` on this KMS branch still
starts `issuance-migrations` from a pinned Credentials issuance image and
executes `manage_migrations.py upgrade` through
`scripts/passport_supported_issuance_migrate.sh`. That historical Alembic
owner can reintroduce the retired issuance private-key table, so a clean
Rust Issuance migration alone does not qualify the full passport stack.
Draft UI PR #1203 (`codex/passport-postgate-rust-only-20261009`, published head
`cb10f9248`) already changes the same stack to run both the one-shot migrator
and runtime from the signed Rust services image and deletes that Python shell
entrypoint. Its exact-head checks are mostly green; Canvas remains live.
An exploratory local merge of its published head into the KMS branch exposed
13 conflicts across KMS custody mounts, native release selectors, Kubernetes
guards and their tests. The merge was aborted cleanly without pushing or
altering either PR. Reconcile the reviewed Rust-only owner once PR #1203 is
qualified or landed, preserving the KMS custody changes; then run the
assembled fresh-database catalog and runtime-write audit against that exact
combined stack. The newly added self-host migration-image catalog check is
useful defense but cannot substitute for this combined proof.

The published Rust-only issuance PR #1203 head `cb10f9248` subsequently
passed all 23 CI jobs. Its head was merged into the local KMS integration
candidate with the KMS custody mounts, TLS secret wiring, Gateway signing
route and native deployment guards preserved. The 13 textual conflicts were
resolved explicitly; the obsolete Python issuance-image test was removed
because its validator is retired by the Rust-only release gate. Focused
overlap tests passed 401 cases. Thirty changed root Python test files then
passed 1,133 tests with four skips. The other changed Canvas deployment test
file could not finish locally: the combined 31-file run passed 303 cases
before an import of the uninstalled external `marty_common` package stopped
the run; hosted CI
must cover that environment. Five changed whole-model scripts passed. Rust
release-evidence tests passed 14 of 15 locally; the remaining test requires
`envsubst`, unavailable in this Windows shell. Direct Rustfmt on changed
files, Python compileall, Bash syntax and diff checks passed. The local
merge remains unpushed while the previous UI CI run is live. It is not yet
an assembled fresh-database, runtime-write or published-artifact proof.

This Rust-only branch also carries a `merge_issuance_heads` to
`issuance_event_owner` bridge for existing beta data. It is not needed for a
fresh KMS-only database and needs an explicit no-migration review before the
combined candidate can be considered the user-requested clean cutover.

2026-10-09 K10 merged-source fresh Issuance check: built the combined
`marty-issuance-service` binary and ran `migrate` against an isolated PostgreSQL
16 database with only the required upstream organization and credential-template
catalogs seeded. It created 31 `issuance_service` tables and 10 Rust migration
ledger entries, with no Alembic table, `issuer_signing_keys` table, or columns
named `private_key`, `encrypted_jwk`, `secret_key`, or `key_material`. The
`organization_integration_secrets` table remains for opaque encrypted
integration-secret ciphertext; its name is not evidence of private-key storage.
The first read-only `verify-owned-schema` run exposed a fresh-install bug: it
unconditionally queried the absent historical Alembic table. The local
integration correction now checks Alembic only when that table exists; the
rebuilt verifier passed against the same fresh database. This is candidate
source and one-owner database evidence, not the assembled stack's full schema,
runtime-write, or shipped-image qualification. The verifier correction and
merged Rust-only head remain local until the prior UI CI run finishes.

The combined Rust Issuance schema validation now rejects retired private-key
tables and key-material columns in its owned schema, in both migration and
read-only startup verification paths. Against a fresh disposable PostgreSQL 16
database, `migrate` and `verify-owned-schema` passed; adding a synthetic
`issuer_signing_keys.encrypted_jwk_json` table made verification fail, and
removing it restored success. Adding only an `encrypted_jwk_json` column to
`issued_credentials` likewise made verification fail; removing it restored
success. This prevents an existing schema with private-key storage from being
accepted silently. The separate release-image qualifier checks all service
schemas; full assembled-stack and image qualification remain outstanding.

The aggregate beta acceptance collector now queries the live PostgreSQL
container for private-key tables and columns after checking the exact Rust
Issuance migration ledger. It reuses the self-host release qualifier's catalog
query, so a signed aggregate deployment cannot be accepted if another service
reintroduces retired key storage. Its negative fixture injects
`issuer_signing_keys.encrypted_jwk_json` and fails; all 17 focused collector
tests pass locally. This adds a full-database acceptance gate but is not yet a
successful run against the combined signed release artifacts.

Self-host Rust-only integration review found that the retained `issuance`
HTTP alias runs the same Rust binary as `issuance-native`, whose startup
unconditionally verifies remote integration-secret custody, but the alias
lacked `INTEGRATION_SECRET_KMS_URL` and its CA file. The alias also retained
DIDComm capability without the dedicated remote token binding. The compose
candidate now gives both Issuance processes the same scoped DIDComm KMS
endpoint/token and TLS integration-secret KMS endpoint/CA mounts. The frozen
whole-model self-host checker enforces these exact additions, and all five
model cases plus 147 focused Python tests pass locally. Packaged runtime and
exact-head hosted qualification still need to prove this wiring in an image.

The same review found the passport disposable `issuance-native` Rust process
had no integration-secret KMS URL/CA, and its `signing-keys` service had no
TLS integration-secret listener. The stack now mounts its already staged
short-lived `signing-keys` certificate/key and CA, enables the TLS listener,
requires both HTTP and CA-verified HTTPS health, and waits for signing-keys
health before Rust Issuance starts. The protected compose model and live
ownership checker now enforce the exact KMS URL, TLS files and mounts.
Negative binding tests and the full related group pass: 217 tests, one skip.
This is model evidence; actual signed-image startup remains to be exercised.

UI PR #1192 published head `14f115ecc` completed CI run `37899481669`
successfully, including the final Canvas database contract job. The grouped
local KMS/Rust-only head still needs its own hosted checks after one push.

The grouped KMS/Rust-only branch was pushed once at `aadcc39cf` after the
older run finished, and UI PR #1192's description now describes the merged
Rust owner, KMS/TLS custody and remaining gates. Its exact-head CI run is
`37904347088`; CodeQL Rust, CodeQL Actions, open-source policy and organization
quality runs were also created at that SHA. At first observation, policy had
passed, Actions CodeQL was in progress, and the other runs were queued. Do
not infer release qualification from the earlier `14f115ecc` checks.

The separate Rust-only Issuance PR #1203 subsequently advanced from the
already integrated `cb10f9248` to `8341eca92`. Its five newer commits remove
retired Credentials-image CI/SBOM and release gates, update the public stack
lock and release promotion, and bind the Kubernetes services image to the
exact attested reference. Its latest exact-head CI is still running, with
several jobs green and no failures at first review. Do not close #1203 or
assume those newer release-gate changes are in UI PR #1192; reconcile them in
one later grouped KMS batch after both active heads are qualified, preserving
the KMS TLS/custody additions and reviewing the final diff for feature loss.

The newer PR #1203 head `8341eca92` merged into the local KMS branch without
textual conflicts in merge commit `d97f5822f`. The 18-file incoming delta
removes retired Credentials-image CD/SBOM/CI requirements, rejects that image
in the Rust-only stack, binds the Kubernetes services reference to the exact
attested image, and observes Gateway DID-web consumers in the affected-Rust
planner. No KMS custody/TLS files changed in this merge. The nine directly
changed test files passed locally: 298 tests, one skip, 316 subtests. The
staged diff and merged tree were checked for conflict markers and whitespace.
The local merge remains unpushed while both the current KMS and Rust-only PR
exact-head CI runs finish; its replacement release gates still require
assembled/artifact qualification and a rollback-path review.

Release-gate self-review of that delta: the removed `--previous-manifest`
comparison in CD related to an earlier public stack image and cannot qualify
the first KMS-only cutover. This matches the superseding custody decision above:
no public deployment or compatibility window is being preserved, and rollback
to an old local-key artifact is outside KMS-only acceptance. The removed
Credentials-image provenance/SBOM checks are paired with rejection of any
retired Credentials issuance component or external OCI image in the Rust-only
stack manifest/lock, plus exact attestation binding for the native services
image. This review does **not** satisfy the requested rollback gate: a clean
KMS-only artifact, PostgreSQL snapshot and OpenBao Raft restore must still be
exercised together and rechecked for custody and behavior.

Test-custody follow-up: the Canvas LTI public-JWKS exporter test still generated
two RSA private keys solely to derive public PEM. It now reads two existing
public-only RSA certificate fixtures, projects their public keys and asserts
the two exported moduli differ across Transit versions. All seven focused
tests and Ruff pass. The broader private-key-name scan found only synthetic
rejection markers and TLS/certificate-device proof test key generation in the
sampled UI paths; this narrow correction is not an exhaustive test-custody
closure claim. It remains local until the current hosted UI run finishes.

A repository-wide search of test-named Python files for
`generate_private_key`, `Ed25519PrivateKey`, `X25519PrivateKey`, and
`private_bytes` found remaining generation in the common gRPC TLS fixture and
passport issuer/certificate-chain tests. Those tests exercise certificate
creation or PKI verification, rather than an application signing-key custody
path. Keep their cryptographic test material isolated from product key storage
and do not use this source scan as proof of shipped KMS-only custody.

2026-10-09 grouped CI handoff: Rust-only Issuance PR #1203 exact head
`8341eca9291742c8f6a79054e4c5303b7841cc60` completed CI run
`37904023691` successfully, including the long Canvas isolated database
contract job. The prior KMS UI head `aadcc39cf9d03ecd67b8ca1e7db57e9e5ad6add2`
also completed CI `37904347088` successfully, including OpenBao plugin image,
coordinated PostgreSQL/Raft recovery, and Canvas. At both exact heads,
`gh pr checks` reports 29 passing and one intentionally skipped check, with no
pending or failing checks. The local combined release-gate/public-fixture batch
was held until both were terminal to avoid overlapping CI cycles. This clears
the prior-head CI gate for one grouped push; it does not qualify the new head
or the assembled release artifact.

The grouped release-gate/public-fixture batch was pushed to UI PR #1192 at
`8215f28af12ceff678ca99b2745a3336cef423d4` after both prior heads passed.
Its description now names the retired Credentials image, exact services-image
attestation binding, test evidence and remaining KMS-only rollback boundary.
The new CI run is `37908090888`; Open-source policy passed while the main CI,
CodeQL and organization quality runs were queued or active at first check.
Do not transfer the earlier head's green result to this combined head. The
local tracker follow-up is held for a later grouped push to avoid restarting
CI for a documentation-only correction.

2026-10-09 Authenticator retired-source cleanup: the root Flutter
`pubspec.yaml`/lock and active `lib`, Android, iOS, macOS and CI source graph
had no reference to `local_plugins/pi-authenticator-legacy`; only a README
cleanup note referenced it. That unused plugin nevertheless retained Java
`SecretKeyWrapper` private-key loading/signing and Swift private-key import
code. With no public deployment or migration requirement, the Authenticator
candidate removes its 89 tracked files and the stale README note. A wider
scan found an unreferenced `AppDelegate.swift.original` backup containing
local signing-key calls, plus an unreferenced Python Flask backend pair that
accepted private JWKs and could emit fabricated fallback signatures. These
three files are removed too; the existing CI source guard now refuses all four
retired paths. Repository references to their identifiers are gone outside
the guard, `git diff --check`, Node syntax, and the custody guard pass. Flutter
is not installed locally, so hosted source/build checks are still needed
after a grouped Authenticator push. This removal does not implement remote holder
signing, trusted verification, wallet persistence or mDoc sessions; PR #57
remains draft and must not be released as feature complete.

Remote-holder ownership trace for the next implementation: Gateway authenticates
Bearer sessions and forwards trusted `x-user-id` to Device Registration;
Device Registration owns active user/device records, public DER key versions,
and its PS256 registration/rotation challenge. Signing Keys' existing
`holder-keys` route only stores a supplied public JWK, while its internal
VC-API holder-proof route creates a one-request OpenBao key and deletes it.
Neither establishes a durable device-owned KMS signing reference. The current
Authenticator Dart service surface delegates signing to platform channels and
does not expose a Gateway session-backed holder-signing client. Implementing
remote holder signing therefore needs a new authenticated client and a server
contract that checks user, organization and active device ownership before
scoped KMS create/sign/rotate/revoke; merely replacing a platform method with
the current public-JWK registration or ephemeral VC-API proof would leave the
wallet unable to sign or would bypass device authorization. Review the
Device Registration PS256 proof key's own custody against the KMS-only policy
before reusing that proof as authorization for remote signing.

Implementation seam: Signing Keys already centralizes managed OpenBao Transit
`create_managed_openbao`, `read_managed_openbao`, `sign`, and
`rotate_openbao` with an active, non-exportable public-metadata check. Reuse
that Rust adapter for durable holder keys rather than copying the one-request
VC-API provider's direct Transit calls. Add a scoped key-reference and
deletion/revocation operation, but keep those internal until Device
Registration's trusted Gateway identity, organization membership, active
registration and device-binding checks authorize each operation. Persist only
reference/version/public metadata; never a JWK `d` member, PEM private key or
raw Transit token. The current registration challenge verifies a PS256 device
key but does not itself prove KMS custody of that key, so accepting it as the
holder-signing authorization proof would need separate qualification or a
replacement device-bound session mechanism.

2026-10-09 holder lifecycle Rust foundation: `marty-signing-keys::kms` now has
an internal managed OpenBao delete operation. It validates the managed
provider, origin URL, mount/key-reference path components and token, enables
Transit deletion, then deletes the key. If the final delete fails after
permission changes, the existing active-custody metadata check rejects that
key for further managed signing until cleanup is retried. The VC-API ephemeral
holder-proof provider now reuses this operation and one service-config builder
for normal, failed-create and stale-key cleanup, removing duplicate direct
Transit deletion code. A mock Transit test proves config-before-delete,
rejects path traversal before any request, and prevents delete after config
failure. The Signing Keys library suite passed 135 tests with eight ignored,
targeted warnings-denied Clippy and direct Rustfmt passed, and the diff is
clean. The new operation is internal only; it neither authorizes a user/device
nor persists a durable holder reference. The local disposable
`probe_integration_secret_coordinated_restore.py` then completed against real
OpenBao, PostgreSQL and Redis: the scoped VC-API holder proof signed,
verified and deleted its ephemeral Transit key with the refactored path;
DIDComm rotation, Go plugin integration, HAIP Flow, and both pre/post-restore
Rust integration-secret reads passed. The probe removed its labeled Docker
containers and volumes. Device authorization, durable holder references,
wallet functionality and signed-image acceptance remain open.

Holder API boundary review: `marty-device-registration` currently derives its
HTTP identity solely from `x-user-id`, then checks active organization
membership. Gateway supplies that header after authenticating and authorizing
the public request, but the Device Registration service itself has no
cryptographic caller proof on that HTTP header. Its deployment also has no
Signing Keys internal client URL/key today. A new private-key signing route
must therefore not simply be added to the Device Registration HTTP router:
direct service access could forge a user header and turn KMS into a signing
oracle. Establish an authenticated Gateway-to-service identity assertion or
revalidate the Bearer session in the service, then check active registration,
user and organization before handing a scoped reference to Signing Keys.
Signing Keys must accept only internal authenticated holder operations; the
mobile client must never receive an OpenBao token. The current clean-install
Device Registration schema has only public device-key records and transition
history; any durable holder metadata must remain reference/public-only, with
no private-key table or removal migration. This is an implementation gate,
not an authorization mechanism already present in the candidate.
Gateway's current `requires_gateway_service_token` list omits Device
Registration, although the service-token override exists for other Rust
services. Device Registration receives `GRPC_SERVICE_TOKEN` for its outbound
membership client, but does not authenticate inbound `x-service-token`. A
holder signing API needs a dedicated Gateway-to-Device Registration credential
or equivalent signed identity context, with public caller headers stripped
before injection; reusing the broadly shared gRPC token alone would give
every holder of that token signing-authority reachability.

2026-10-09 local Gateway-to-Device Registration boundary candidate (not yet
published): the Rust Gateway reads a dedicated
`DEVICE_REGISTRATION_GATEWAY_KEY` and injects it only on routes owned by
Device Registration. The service requires that key on all `/v1/devices`
routes before reading `x-user-id`; health routes remain separate. The
configured key must be at least 32 bytes and differ from the shared gRPC
token and Gateway signing/issuance credentials. Development, beta, self-host
and Kubernetes bindings now name a separate secret; self-host and Kubernetes
deployment catalogs/templates include it. The Device Registration behavior
full suite passed 12/12, including missing and forged token rejection, and
Gateway's library suite passed 151 tests with one ignored. The deployment catalog's
five unit checks and Ruff passed after accepting both existing placeholder
spellings in the template assertion. Warnings-denied Clippy passed for both
Rust service packages and all targets. Deployment model checks and
an actual Gateway-to-service probe remain to run before publishing. This
credential authenticates the Gateway as caller; it does not by itself
authorize a holder signing request or establish durable device-owned KMS
keys. The current public device registration API will require a coordinated
deployment of both services so direct callers receive 401.

The first broader acceptance run exposed a missing disposable passport
Gateway secret mount: its model verifier correctly rejected the rendered
stack. The candidate now stages a distinct disposable key, mounts it in the
protected passport Gateway, and checks that binding and live ownership.
The repaired provisioning/model/ownership suites pass 249 tests with two
skips; 16 compose-deployment and Gateway/Device Registration cutover tests
also pass. This correction is local and held with the larger UI batch while
the previous published head's Canvas CI job is still running.

The preceding published UI head `8215f28af` then completed exact-head CI
`37908090888` successfully. After the affected tests and static checks above,
the seven-commit grouped batch was pushed to draft UI PR #1192 at
`167c5e7e4b9e4cd55f1571156746bd13eef26629`. The PR description now names
the holder-key cleanup, dedicated Device Registration caller credential,
paired deployment wiring, and still-open durable holder/wallet release gate.
The new CI run is `37913136390`; Open-source policy completed successfully
while CI, CodeQL and organization quality were queued or active at first
inspection. Do not transfer the prior head's green result to this new head.

Further local Rust DRY follow-up: the ephemeral VC-API holder proof now creates
its non-exportable Ed25519 key through `kms::create_managed_openbao` and uses
the returned public/custody metadata directly, removing its duplicate raw
Transit create request and redundant metadata read. Error cleanup still
attempts remote deletion after an uncertain create; successful proof paths
delete the key before returning. Signing Keys' library suite passed 135 tests
with eight ignored; warnings-denied Clippy passed. The disposable coordinated
restore probe passed against real OpenBao, PostgreSQL and Redis after this
refactor, including holder-proof verification/deletion, DIDComm rotation, the
Go extension, HAIP and integration-secret reads before and after restore.
This remains a local follow-up held for the next grouped UI push.

Device proof design gate for durable holder signing: the current Gateway
session identity carries a user and tenant, but the searched Rust Gateway/Auth
runtime has no device-bound session claim. The existing Device Registration
challenge verifies a PS256 public key supplied by the device; using that as
the new signing authorization would preserve an app-held private key and
conflict with strict KMS-only custody. The Authenticator client currently has
OID4VCI access-token handling but no Gateway session-backed holder-signing
client. A revocable, server-issued device credential paired with the user
session could bind a registration without an app-held private key, with the
explicit limitation that theft of both bearer credentials grants signing until
revocation. A stronger device-possession factor may be preferable, but must be
evaluated against the KMS-only requirement before implementation. No public
holder-signing route is enabled until this choice and its enrollment/revocation
semantics are settled and tested.

Latest UI CI `37913136390` exposed two packaging-guard omissions on the
published `167c5e7e4` head: the frozen self-host model comparator did not yet
classify the paired Device Registration secret as an owned security addition,
and the Rust packaging workflow's synthetic beta Compose environment omitted
the newly required key. The local correction checks that the self-host secret
is mounted exactly once to Gateway and Device Registration and nowhere else,
and adds a distinct synthetic value to the packaging job. The full
`test_selfhost_native_owner_compose.py` script now passes its default, empty,
custom and missing-input renders plus frozen-model comparison. This is a
correction for the current CI failure, not an exact-head hosted pass; wait for
the remaining jobs to finish and batch any further findings before repushing.

The same published-head CI subsequently exposed three more fixtures tied to
the dedicated Device Registration credential. The Canvas Kubernetes runtime
composition proof used a synthetic `marty-secrets` map without that key; the
Gateway executable smoke setup omitted it and failed before reaching its
intended Redis checks; and repository release checks included a beta physical
Compose render, a Flow self-host render and Kubernetes secret setup fixtures
without distinct values. Local follow-up now supplies a unique synthetic key
in each fixture while preserving the new fail-closed production checks. The
targeted Python suite covering the beta selector, Flow render, Kubernetes
secret setup and self-host model passed 157/157; the Gateway executable smoke
tests passed 3/3. The Linux-only Canvas composition proof still requires
exact-head hosted confirmation. These corrections remain local pending the
rest of published-head CI and full local release-suite results.

Published-head UI CI `37913136390` has now terminated with five failed
worker lanes plus the aggregate gate; the OpenBao DIDComm plugin image lane
finished successfully, including its coordinated PostgreSQL/Raft recovery
step. The five failed lanes map to the dedicated-credential fixtures described
above. No failed evidence was rerun or discarded. The next hosted run must use
the correction head and independently prove all gates; the former green
prior-head run and the passing OpenBao lane do not qualify that new head.

After publishing correction head `8f7d6bec4`, UI PR #1192 gained a merge
conflict with `main` commit `859030f8e`, which splits published Flow
acceptance into `marty-flow-acceptance`. An isolated review worktree resolves
the four textual conflicts by retaining both workspace members, the KMS
encrypted-envelope feature, the new Flow test owner and the owned OpenBao
cleanup path. The split Flow acceptance crate also imports the KMS branch's
shared HTTPS integration-secret fixture, so its manifest and lockfile need
`axum-server`, `rustls` and `rcgen` test dependencies. This was caught by a
combined Canvas/Flow no-run compile; after adding the three dependencies both
targets compiled. Focused Canvas preflight, Flow-owner and Canvas compile-scope
Python checks passed 38/38. The merge is prepared locally, not published;
first preserve the exact-head `8f7d6bec4` CI result, then publish the merge
as one grouped correction and qualify its own exact head.

The new `8f7d6bec4` CI run `37915227632` contract lane later found one more closed-model fixture:
`marty-selfhost-bundle` expected Gateway's former three secret mounts and did
not recognize `DEVICE_REGISTRATION_GATEWAY_KEY_FILE`. The prepared merge now
requires the fourth dedicated mount, maps the file selector to that mount and
explicitly forbids the raw credential in the rendered owner environments.
All six extracted-bundle executable tests pass locally against Docker Compose
5.4.0, including swapped dedicated-key mount and raw-key negative controls.
Warnings-denied Clippy passes for the changed self-host bundle test package.
This is local evidence;
the current published CI run and the future merge head remain separate gates.

Exact-head UI CI `37915227632` terminated with two worker failures and the
aggregate gate. The contract lane failed `marty-selfhost-bundle`'s closed model
on the missing Gateway secret. The Canvas lane passed its Kubernetes renewal
proof, public image build, DIDComm KMS fixture and other published database
groups, then failed `selfhost_public_image_loader_isolated` before emitting a
packaged runtime stage. Source inspection shows that child preflight invokes
the same `selfhost_prepared::qualify` closed model; this makes the omitted
Gateway secret the likely common cause, although the Canvas child suppressed
its precise preflight error. Local bundle tests exercise that preflight and
pass 6/6 with the correction; the next exact-head hosted Canvas lane must
confirm the inference. The OpenBao plugin and coordinated PostgreSQL/Raft
recovery, Rust service images, release contracts, Rust lint/packaging, security
scanning and other completed CI lanes passed on `8f7d6bec4`. Preserve this
failed run as immutable evidence; merge reconciliation and the closed-model
fix are grouped into the next UI PR head.

2026-10-09 fresh-only Issuance migration review (local commit `f444c8d16`,
unpushed): Rust
Issuance still accepted historical `merge_issuance_heads`/`issuance_event_owner`
Alembic databases and shipped a 72-line bridge, despite the fresh KMS-only
cutover requirement and absence of public deployments. The local candidate
removes that bridge and its release ledger/file inventories; `migrate` and
read-only `verify-owned-schema` now reject any historical Issuance Alembic
table. The native 0001-0008 schema migrations remain because the current
product uses their tables and constraints. Focused native-migration and
aggregate-acceptance/fence-authority Python tests pass 65/65; the Rust
Issuance library test target compiled and warnings-denied Clippy passed.
This batch is **not publishable yet**: the older fenced beta
native installer assumes an existing Issuance schema, applies only post-baseline
SQL, and would no longer produce a database accepted by the fresh-only Rust
verifier. Replace or retire that installer and its protected release path as
one coherent clean-database cutover before pushing the bridge removal. Do not
count local tests of the SQL inventory as proof of assembled-stack behavior.

The existing Rust contract CI lane already creates a dedicated empty
PostgreSQL database and executes the built Issuance `migrate` binary. The
local follow-up extends that lane to run the read-only Rust
`verify-owned-schema` command and a shared catalog inspection over every
service schema. The inspector reuses the self-host private-key table/column
query and rejects an Issuance Alembic ledger. Against a new disposable
PostgreSQL 16 container, the rebuilt binary migrated and verified successfully,
the inspector passed, and the ledger had exactly nine entries (baseline plus
0001-0008). Injecting `issuer_signing_keys.encrypted_jwk_json` made the
inspector fail; after removing it, injecting an Alembic table made both the
inspector and Rust read-only verifier fail. The disposable container was
stopped. A second disposable PostgreSQL 16 database with only a historical
Issuance Alembic table proved the rebuilt `migrate` command rejects the old
lineage without creating a Rust ledger; its container was also stopped. This
is direct clean-install evidence for the candidate source and
new gate, not yet a hosted exact-head or released-image result. The old
fenced beta installer remains the explicit replacement/retirement dependency.

Release-path audit of that dependency: `prepare_passport_beta_native_migrations.py`
generates SQL that locks already-present `issuance_service.physical_document_jobs`
and Flow tables, then creates a Rust ledger claiming the baseline. It does not
run the signed Rust Issuance binary or create the clean baseline. The routine
`Passport Fence PostgreSQL` CI lane exercises the fence and synthetic native
receipt using `SELECT 1`, not the real 0001-0008 bundle; the optional frozen
schema replay requires an external dump and is skipped without it. Consequently
green fence/receipt tests cannot authorize the clean KMS-only release. The
successor gate must run the exact signed services image's Rust `migrate` and
`verify-owned-schema` commands on a fresh disposable database, check the
entire assembled catalog and behavior, and bind that evidence to the release
artifact. Retire the old beta installer and its acceptance/rollback claims
only after that successor covers the supported passport flow. This audit is
the reason the local bridge-removal commits remain unpushed.

2026-10-09 signed-image successor candidate (local, unpushed): the disposable
self-host migration qualifier now requires both an immutable migrations image
and immutable Rust services image. In one isolated Compose project it runs
the released migration image twice, then invokes Organization, Credential
Template and Issuance one-shot `migrate`/`verify-owned-schema` commands from
the same services image; it checks for Alembic state and private-key table or
column names across the assembled database after each pass. Exact-image,
closed-model, replay and cleanup tests pass 8/8; the rendered Compose model
has no host ports or production mounts. A cached signed pair from main
revision `78039a29` failed at native Issuance because its migration image
did not create the Credential Template catalog. That is a valid rejection of
an older pair, not qualification of the new source head. The probe cleaned
up its disposable project.

The real upstream-schema follow-up found a product bug obscured by CI's
hand-made text-ID Organization fixture: the native Organization schema uses
UUID IDs, but the fresh Issuance application-template seed bound the Marty
organization ID as text, producing PostgreSQL `uuid = text` error `42883`.
The candidate parses that constant as a UUID for the Organization query and
replaces CI's synthetic tables with actual one-shot Rust Organization and
Credential Template migrations. A fresh disposable PostgreSQL 16 run of all
three rebuilt binaries now passed `migrate`, `verify-owned-schema`, and the
KMS catalog inspector **twice** (idempotent), yielding 47 tables in those
three service schemas and nine Issuance ledger entries. The container was
stopped. This is direct local source-binary/DB evidence; signed new-head image
and full assembled product release gates are still pending.

Follow-up validation: 32 focused migration/aggregate Python tests and 45 CI
owner/Issuance source-contract tests passed after the workflow switched to
real upstream Rust binaries. The disposable image qualifier's eight tests,
including actual Compose rendering and failed-native-step cleanup, pass.
Warnings-denied Clippy passed for all three changed Rust binaries. The
published UI `a957f5da6` CI run `37919254810` passed its OpenBao plugin,
Rust image, Rust contract, release contract and other jobs, but failed the
Canvas job before its database contracts: Flow's executable listed ten tests
while the runner's exact owner inventory expected nine. The tenth was the
ignored OpenBao scoped signer probe inherited through a shared Issuance
fixture by both Flow and Canvas. The local follow-up moves only its test
registration into Canvas while retaining the OpenBao signing and denied-read
proof, so Flow again owns exactly nine and Canvas retains the scoped probe.
The later fresh-only source and selector corrections are not in that run and
remain unpushed; no exact-head UI qualification can be claimed from it.

2026-10-09 release-gate follow-up (local, unpushed): `cd.yml` now runs the
disposable self-host qualifier against both exact signed release-image digests
and pinned PostgreSQL, Redis and OpenBao images. It verifies the image
attestations against protected main, requires two successful fresh native
schema/idempotence passes, stores the qualification artifact, and binds its
SHA-256 digest as a required `native_schema` gate in the release transaction.
The transaction rejects a release with only the earlier public-stack and
verifier gates. Its 69 focused release/qualifier tests pass and the workflow
parses as YAML. This source-level result does not yet prove that a newly built
pair passes the gate. The historical fenced beta installer and protected
receipt path still assume a pre-existing Issuance schema; retirement of that
path remains necessary before the fresh-only source batch is publishable.
The direct stale path is `run-passport-beta-native-db-gates.ps1` invoking
`prepare_passport_beta_native_migrations.py` to emit post-baseline SQL and a
synthetic Rust ledger. `prepare_passport_beta_aggregate_handoff.py` imports
that same preparer, and `run-passport-beta-aggregate-deploy.ps1` consumes its
receipt and executes `passport-beta-rust-owner-transition.sql`. These are
manual protected beta operator paths rather than steps in the stack `cd.yml`
release workflow, but they remain executable and their acceptance scripts
still trust their receipts. Retire this whole old-schema path and its claims
together; deleting only the SQL bridge would leave a misleading operator
entrypoint. The supported fresh self-host and disposable passport routes must
retain their native Rust migration and passport behavior.

Local retirement stage after this audit: the three manual beta mutation
entrypoints (`start-passport-beta-db-maintenance.ps1`,
`run-passport-beta-native-db-gates.ps1`, and
`run-passport-beta-aggregate-deploy.ps1`) have been reduced to terminal
diagnostics, including the resume entrypoint. The native SQL preparer and
aggregate handoff reject before protected-source or Docker reads, and the
aggregate Compose CLI exits before a saved-plan verification can bypass that
guard. Obsolete operator-order and SQL-stream tests were removed; a regression
test asserts that the three PowerShell files contain no executable operation
after their parameter blocks. The old `Passport Fence PostgreSQL` CI lane was
removed from the aggregate gate, which now has 17 planned jobs; the Rust
contract lane retains real fresh Organization, Credential Template and
Issuance database migrations and schema verification. Focused affected suites
passed 78/78 and 66/66 (17 disposable tests skipped on Windows), the CI-gate
rehearsal and terminal-entrypoint tests passed 12/12, and workflow YAML parses.
This is still an intermediate source change: historical Python SQL builders,
receipt consumers and manual beta acceptance workflows remain in the tree and
need cleanup/replacement before the grouped PR is publishable. No protected
beta host or signed new-head image was exercised by these tests.

The follow-up removed `build_sql`, `checked_migrations`, image SQL reads and
`stage_sql` from the historical beta native-migration module, together with
its disposable SQL-bundle tests. Its remaining `prepare()` is a terminal
error; `checked_receipt()` remains temporarily because read-only historical
maintenance/aggregate modules import it. Focused maintenance, aggregate,
fence-authority and retired-operator tests pass 87/87; release-transaction,
qualifier and CI-gate tests pass 32/32. This removes the old bundle assembly
capability, but does not yet retire every historical receipt consumer or beta
workflow. Supported fresh Rust schema paths remain the release target.

Grouped UI draft PR #1192 was updated from `a957f5da6` to exact head
`daa74b80ee9423030f97e11b2a204655c8b863f1` with the eight local
fresh-schema, signed-image gate, Canvas owner, and beta retirement commits.
Before publication, 309 relevant Python tests, Ruff, the compiled Canvas and
Flow test inventories, and local fresh PostgreSQL migration/verification
checks passed; Flow lists exactly nine cases. The new exact-head CI run is
`37924336922` and was queued at the last observation. The PR remains draft;
this is a qualification request, not release approval or signed-image proof.

Remaining beta-workflow audit after disabling the old operator: the
`passport-beta-*`, `passport-python-deletion-cutover`, and
`passport-rust-predeletion-acceptance` dispatches all target the dedicated
`passport-beta-wsl2` runner. They cover prerequisite, preliminary, deployed
candidate, final acceptance, demo publication, soak, and old-writer drain
lineage. Their aggregate readers still query
`passport_cutover.native_migration_receipt`; merely deleting the SQL emitter
does not invalidate a pre-existing receipt. The newer `passport-supported-*`
workflows rehearse disposable infrastructure, managed certificates and Rust
provisioning, while the current supported consumer workflow uploads a blocked
receipt. They do not yet replace every old beta publication/soak claim. Keep
those old claims out of KMS-only release qualification and remove or replace
the dispatches together with their receipt validators after mapping the
required supported passport acceptance behavior; no old receipt is evidence
of a clean fresh-schema cutover.

Release artifact source check: `services/Dockerfile.migrations` copies only
`rust/services/issuance/migrations` and `rust/services/flow/migrations` into
the migrations image's passport-native directory; it does not copy the retired
Python SQL preparer or protected beta PowerShell entrypoints. The deleted
Issuance Alembic bridge is therefore absent from this candidate image input.
This source inspection is narrower than an exact digest filesystem inspection
and does not replace the new signed-image qualification gate.

The first grouped UI CI run for `daa74b80e` is still active. Its Release
Contract Tests job failed 15 of 6,128 cases: 14 parametrizations expected the
former single-package Issuance Bookworm build, and one Flow-only selector test
omitted the newly reported `openbao: false` field. The build now deliberately
includes Organization and Credential Template binaries for the fresh-schema
qualification. Local commit `2300b503e`, after merging current `origin/main`,
updates the assertions to require all four binaries and the OpenBao selector;
71 base-runtime fixture tests, all 141 CI-workflow performance tests, Ruff and
`git diff --check` pass. This fix is local and not part of the published run.
Keep the failed run as evidence; inspect its four unfinished OpenBao, Rust
contract, Rust image and Canvas jobs before batching the next PR update.

Authenticator follow-up remains local for the eventual grouped consumer PR:
`a3c4038` removes unused local-key source trees, and `1bb9db2` removes the
unreferenced `errorMissingPrivateKey` translation from all eight ARB locales.
All eight files parse as JSON and the mobile/desktop custody source guard
passes. Neither cleanup supplies durable remote holder signing or wallet
feature parity; do not publish the Authenticator branch as a KMS-only wallet
on the strength of those source removals.

Local UI bootstrap cleanup: the `flow-response-envelope-marty-aes256`
Transit key was still provisioned by the Python migration/bootstrap runner,
the OpenBao initializer, and the disposable passport checker, with service
policy allowing encrypt/decrypt. The runner explicitly described it as a KEK
for per-flow private-key envelopes. A repository-wide source search found no
runtime reader or writer for that key. The candidate removes its creation,
authorization and disposable requirement while retaining purpose-bound
OID4VP request signing and the separate integration-secret envelope. The
focused OID4VP, supported OpenBao, infra-rehearsal and webhook suites pass
24/24; broader beta selector, local release runner and Signing Keys cutover
checks pass 167/167 with two Windows skips. Ruff and diff whitespace checks
pass. This is source-level dead-key
retirement, not proof that all other secret classes or released images satisfy
the KMS-only boundary.

The published UI run `37924336922` is now terminal. Its Canvas job passed
after the public self-host image build and isolated database contracts;
OpenBao, Rust contracts and Rust image jobs also passed. Release Contract
Tests had the 15 previously identified stale source/selector assertions, and
the downstream CI Gate therefore failed. This failed run remains immutable
evidence, not a green qualification for the corrected local head. The local
branch then merged the next `origin/main` Flow selection refinement without
conflict.

Core test-custody follow-up is local at `4abe1f2`: removed raw X25519/P-256/
P-384 secret import/export helpers that existed solely under `cfg(test)` and
their private-scalar vectors. Generated ephemeral ECDH, ECIES and mDL session
tests remain. The `marty-crypto` `ecdh,kdf` unit suite passes 36/36, its
compile-fail documentation checks pass 5/5 (one unrelated example ignored),
and warnings-denied Clippy and Rustfmt pass. This does not change production
Core APIs or replace the live OpenBao DIDComm decryption proof. Core PR #355
and every downstream pin still point to its prior published head until this
local correction is grouped into a deliberate cross-repository update.

Grouped UI draft PR #1192 was pushed at exact head
`a47fb79425d63f842df286b81300dc1e4233fe4d` after the terminal
`daa74b80e` run. Its PR description now reflects the fresh schemas, signed
image gate, retired beta SQL entrypoints, dead flow-envelope key, and still
open passport/wallet acceptance. After merging the latest main Flow-owner
refinement, a combined local run passed 424 focused Python checks with two
Windows skips; Ruff and `git diff --check` passed. New exact-head CI run
`37929521793` was queued immediately after the push; CodeQL and organization
quality runs were active. This is a new qualification request, not an accepted
release or a replacement for the immutable failed run.

Credentials packaging recheck: PR #313 head `7b065b0` has green exact-head
CI `37897657865`, including `Local Marty Python Binding`, `Core Python
Wheels`, WASM, Rust tests, and `Python Retirement Guard`. Its root
`pyproject.toml` is named `marty-credentials-test-harness` and explicitly
selects no Python runtime package for the root wheel. The CI builds the local
`rust/marty-rs` extension and two exact pinned Core KMS-only/verification
wheels instead. The remaining artifact question is whether those canonical
native wheels and the browser consumer behave correctly when published and
installed in the supported product, not whether a root Credentials runtime
wheel can be produced.

Holder authorization working assumption, pending user preference: use a
revocable server-issued 256-bit opaque device credential together with the
authenticated Gateway user session. Store only its SHA-256 digest and scope it
to an active registration, exact user and organization, with bounded expiry.
Theft of both bearer credentials permits signing until revocation; no
device-held asymmetric private key is introduced. The first local Rust
foundation is `marty-device-registration::holder_credential`: it returns the
bearer only at issuance, denies any registration carrying the old PS256 public-key
projection, and rejects wrong token, user, organization, registration,
expiry, revocation and inactivity. Its library suite passes 4/4 and
warnings-denied Clippy passes. This module is **not wired to an HTTP route or
persistent repository**, and does not create, authorize or sign with a durable
KMS holder key. Complete transactional credential rotation/revocation,
reference-only key persistence, authenticated Device Registration-to-Signing
Keys operations, Gateway session binding and mobile/web wallet behavior
before calling this accepted custody.

2026-10-09 local holder-credential durability follow-up: the Rust Device
Registration fresh schema now has a digest-only `device_holder_credentials`
table scoped to registration, user and organization, with a single-current
index, bounded lifetime and revocation constraints. A repository rotates the
current digest in one PostgreSQL transaction under the registration row lock;
explicit revocation and device deactivation revoke it. The credential lookup
returns only digest and scope metadata. A disposable PostgreSQL integration
test passed issuance storage, authorization, rotation, wrong-scope rejection,
transaction rollback on duplicate ID, explicit revocation and deactivation
revocation. This is local, unpushed evidence. It does not establish an
authenticated enrollment route, a durable KMS holder key, holder signing or
wallet acceptance; those remain release blockers.

2026-10-09 holder enrollment security review: the current native Device
Registration `register` path accepts a keyless registration under an
authenticated Gateway session with no device challenge; the challenge is
required only when a PS256 public key is supplied. Therefore the proposed
session plus server-issued bearer is revocable and KMS-compatible, but its
initial enrollment does not independently prove control of a particular
device. A stolen Gateway session could register and receive a fresh bearer.
Do not expose holder signing on that basis alone. The cutover needs an
explicit enrollment and rotation authorization decision (for example,
step-up user authentication or an independent device pairing ceremony),
while keeping the actual holder signing key generated and retained in KMS.
Signing Keys currently offers only public-JWK `holder-keys` registration,
and the VC-API holder-proof path creates and deletes a one-request OpenBao
key. Neither is a durable holder signer. The next implementation must pair
a registration-scoped, reference/public-only key ledger with authenticated
Device Registration-to-Signing Keys create/sign/revoke operations and must
reject arbitrary provider references at that boundary. The published UI run
`37929521793` is still live: 19 of 21 jobs completed without a failure;
OpenBao integration-secret recovery and Canvas public image build are active.

2026-10-09 local durable holder-key reference work: native Device Registration
now has a fresh-schema `device_holder_keys` ledger containing only a
registration/user/organization/purpose, OpenBao reference and version, and
public Ed25519 or P-256 coordinates. It contains no JWK blob or private key
column. The Rust projection accepts only active non-exportable provider
metadata, validates the public coordinates and binds the reference to the
organization hash. PostgreSQL binding locks the registration, rotates the
current purpose entry atomically and revokes entries on deactivation. The
Device Registration library and integration suite passed 16/16, including
fresh PostgreSQL migration, reference rotation and rollback. Synthetic
provider metadata in these tests proves storage behavior only, not live KMS
custody. OpenBao's [Transit sign API](https://openbao.org/docs/next/api/secret/transit/)
documents `key_version`; the local Signing Keys adapter now selects the
matching public-key version, sends a positive explicit version for signing
and rejects a response tagged with another version. Its focused regression
test passes. The ledger and adapter are local, unpushed, and not connected to
an enrollment/signing route. Provisioning compensation, remote revoke,
dedicated service authentication, a live versioned OpenBao signature, and
wallet behavior remain required. UI CI `37929521793` remains live with
20/21 jobs complete and no failure; Canvas is still active.

Holder namespace/policy review: the first local ledger draft used
`holder-*`, which the shipped signing-keys-managed OpenBao policy cannot
create. The corrected reference generator binds the organization digest and
purpose to the existing `cred-holder-*` and `cred-presenter-*` namespaces;
fresh PostgreSQL constraints enforce the same purpose-to-prefix mapping.
Only those two namespaces now permit deletion after an explicit
`deletion_allowed=true` config update, while the issuer namespace still
denies both. The live disposable policy probe with `--rust-adapter` passed
after this correction, including positive holder/presenter deletion,
negative issuer deletion and the Rust version-pinned signing proof. Remote
deletion is still not called by Device Registration deactivation; a durable
cleanup/compensation path remains required before acceptance.

2026-10-09 live OpenBao version follow-up: the guarded
`python scripts/probe_signing_keys_openbao_policy.py --rust-adapter` run passed
against disposable pinned OpenBao and scoped service credentials. Its Rust
managed-key test created a non-exportable P-256 key, rotated it, recovered
the version-one public JWK after rotation, and obtained a version-one Transit
signature through the newly pinned adapter. The probe also completed its
existing six-prefix ACL, provider HMAC, tenant and managed-profile route
checks. This is real remote signing/version evidence, but the durable holder
ledger has not been connected to the provider, an authenticated signing
route, or a wallet. Review found that a pinned public JWK paired with the
provider's latest version could be stored as a false binding; the Rust
holder-key projection now requires `selected_version` to equal
`latest_version` when first binding a new key. Rotation later uses a new
ledger record instead of silently relabeling an old public key.

2026-10-09 exact-head UI qualification update: draft PR #1192 head
`a47fb79425d63f842df286b81300dc1e4233fe4d` completed run
[`37929521793`](https://github.com/ElevenID/marty-ui/actions/runs/37929521793)
successfully. Its CI Gate, Release Contract Tests, OpenBao DIDComm plugin
image, Rust service contracts/images/Canvas, feature-regression probe,
supply-chain and other required jobs passed; PR CodeQL, dependency review
and workflow-quality checks also passed. This qualifies that published head
only. The local credential/key ledger and version-pinned adapter commits are
not included, and green CI does not substitute for the remaining holder
wallet/signing, passport cutover or release-artifact acceptance gates.

2026-10-09 local managed holder service boundary: a shared Rust reference
crate now derives purpose-, organization- and registration-bound OpenBao names
for holder and presenter keys; the fresh Device Registration schema enforces
the same 128-character reference shape. Signing Keys has a separate internal
create/sign/revoke router guarded by a dedicated Device Registration service
credential, rather than the broad internal signing credential. The provider
accepts only EdDSA or ES256, checks reference scope before contacting OpenBao,
requires a positive pinned version and exact matching public JWK for signing,
rejects private material and noncanonical or oversized signing input, and
uses the existing managed OpenBao adapter for key lifecycle. The route is
currently disabled until its distinct credential is provisioned. Its local
unit tests passed, and the guarded disposable OpenBao probe passed actual
non-exportable holder key creation, version-pinned signing, and remote
revocation under scoped policy. The Device Registration client, durable
provisioning compensation and deactivation cleanup, enrollment authorization,
Gateway session binding, public signing route and wallet acceptance remain
open. Do not present this as end-to-end holder custody yet.

2026-10-09 local remote holder-deletion follow-up: fresh Device Registration
schema now includes a reference-only deletion queue. Replacing a holder key or
deactivating a device commits local revocation and queue insertion in the same
PostgreSQL transaction; a failed replacement rolls both back. A Rust worker
uses the dedicated Device Registration-to-Signing Keys credential, retries
failed revocations after a bounded delay, and marks completion only after the
remote service confirms key absence. The Signing Keys revoke operation is
idempotent after OpenBao deletion and verifies absence through the managed
key lookup and scoped inventory before reporting success. A fresh disposable
PostgreSQL plus HTTP test passed rollback, deactivation, failed-call retry and
completion behavior; the disposable OpenBao probe passed repeated revocation.
The worker is enabled only with its paired origin and credential, which are
not yet provisioned in supported deployment profiles. Remote creation and
signing are also not yet called by Device Registration, and provisioning
compensation remains open. The HTTP retry test proves scheduling behavior;
the separate OpenBao probe proves actual remote deletion. Neither is an
end-to-end wallet acceptance test.

2026-10-09 local holder creation compensation: Device Registration and Signing
Keys now share the strict Rust holder-key request/scope contract. Device
Registration has one dedicated client for create/sign/revoke, reused by its
cleanup worker. Before a remote create, the repository reserves the scoped
reference in a fresh-schema provision ledger. Binding public KMS metadata
requires that live reservation in the same transaction that retires the old
key; an expired, failed or interrupted unbound reservation is eligible for
the remote cleanup worker. The internal provisioner checks the exact user,
organization and active keyless registration, reserves, calls Signing Keys,
validates non-exportable public metadata and binds it; on an ordinary error it
accelerates cleanup, while a process crash still leaves the original durable
deadline. Fresh PostgreSQL tests passed reservation-required binding,
rollback, stale-provision cleanup and a disposable dedicated-client create
call. This client and provisioner have no public enrollment route yet. The
test create service returns synthetic metadata, so live combined Device
Registration-to-Signing Keys-to-OpenBao behavior still needs acceptance.
The Device Registration client and binding projection also reject private
material anywhere in returned metadata, rather than checking only the
projected public JWK.

2026-10-09 local supported-profile holder credential wiring: a new cataloged,
non-placeholder, at-least-32-character Device Registration-to-Signing Keys
credential is mounted only on those two services in self-host Compose and
resolved from one Kubernetes Secret key in the two corresponding Deployments.
Device Registration receives the internal Signing Keys origin; beta and
development Compose use paired values, with beta requiring an explicit
credential. Kubernetes and local beta setup reject reuse of the device
Gateway or gRPC credential. Self-host operator examples and secret inventory
include the new file. The self-host whole-model ownership check passed, base
Compose rendered matching service values, Kubernetes manifests resolved the
same secret reference and expected origin, 24 Kubernetes secret-helper tests,
61 Device Registration/Signing Keys/beta-profile tests and 85 local beta
release/physical-provider tests passed. Canvas's Kubernetes acceptance test
compiled with the new secret model, but the direct Windows run stopped in its
preparation stage because `envsubst` is absent; no Canvas runtime acceptance
is claimed from that compile. These are local configuration checks. The real
operator secret has not been provisioned, and the public holder enrollment
authorization, signing route and wallet acceptance remain open.
The standalone `scripts/check-selfhost-production.py` invocation currently
fails before its checks because it imports the absent `packages/marty_common`;
qualify or retire that old Python preflight as part of the supported release
path rather than treating this configuration pass as a complete cutover.

2026-10-09 local combined holder lifecycle acceptance: the guarded Signing
Keys OpenBao policy probe now starts disposable pinned PostgreSQL alongside
OpenBao and runs a Rust Device Registration integration test through the real
Signing Keys HTTP router. It creates a keyless registration, reserves and
binds a non-exportable Ed25519 key using only public metadata and a scoped
reference, signs with the stored OpenBao key version, and independently
verifies the signature against the returned public JWK. Deactivation drives
the real retry worker; the test then requires both a 404 on remote key read
and absence from the scoped OpenBao key inventory. The full disposable probe
passed with that stronger assertion. This proves the internal combined
service/DB/provider lifecycle on a local source build. It does not authorize
public enrollment or signing, exercise the wallet, prove packaged-image
deployment, or supply the actual operator service credential; those gates
remain open.

2026-10-09 local internal signing authorization: Rust Device Registration now
has one internal `HolderSigner` path that checks a digest-only device bearer,
live user/organization/registration scope and the current public-only key
record while holding the registration transaction lock through the bounded
Signing Keys call. Credential rotation and device deactivation acquire that
same lock, so they cannot revoke midway through this signature operation.
The guarded disposable PostgreSQL/OpenBao test passed actual remote signing,
rejection of an invalid bearer, rejection of the rotated-out bearer, signing
with the replacement bearer, rejection after deactivation and remote deletion.
The test uses PostgreSQL time for bearer issuance because Windows and the
disposable database clock can differ; any production bearer issuance endpoint
must likewise use database time or a verified clock-skew policy. This is an
internal service boundary only. Public enrollment/pairing authorization and
wallet use are still unimplemented and must be qualified before exposure.

2026-10-09 local clock-safe bearer issuance: the PostgreSQL credential
repository now owns one internal `issue_for_registration` operation. It locks
the live registration, enforces the caller's user/organization scope, reads
PostgreSQL `clock_timestamp()`, creates the one-time random bearer, and
atomically revokes the old digest and stores the new digest before returning
the bearer. The old externally supplied-record `replace` path and issuance
share the same locked insert helper, including the lifetime/revocation schema
checks. The guarded disposable probe passed both the live OpenBao holder
lifecycle (including wrong-scope refusal and credential rotation) and the
existing PostgreSQL credential-durability tests. There is still no public
issuance route; its caller authorization policy remains a release gate.

2026-10-09 wallet pairing/product-path audit: UI `WalletSetup` currently
generates an eight-character `Math.random` pairing code and QR content in the
browser, offers a `Simulate Pairing` button that marks success without a server
exchange, and treats the first returned device registration as a paired wallet.
The vendor onboarding step calls `/wallet/pairing/generate` and polls status,
but no Rust Gateway or service route owns that path in the inspected source.
Authenticator's `credential_selection_view.dart` still calls
`generateSecureKeySDK` for presentation signing before creating a presentation.
These paths cannot count as KMS-only wallet acceptance. Replace them together
in the grouped feature PR with server-issued one-time pairing state, a
device-bound revocable bearer, Remote Signing Keys references, an Authenticator
remote-signing client, and a status projection that requires actual paired
remote custody. Remove the simulated success and local signing-key generation
when the complete path is wired; retain independent-wallet OID4VCI/OID4VP
transport. Enrollment authorization must include the selected session/step-up
policy and be tested against replay, wrong user/organization, expiry and
revocation before any public signing route is exposed.

2026-10-09 local server-owned pairing ticket foundation: Rust Device
Registration now has internal memory/Redis pairing-ticket repositories using a
256-bit random one-time token, a SHA-256-derived Redis lookup key, a maximum
five-minute TTL, user/organization scope and atomic Redis redemption. Neither
the raw token nor any private key is persisted. A guarded disposable Redis
test verified the sentinel, digest-only key/value inventory, TTL and exactly
one winner from concurrent redemptions; its unit and Clippy checks passed, and
the full OpenBao/PostgreSQL/Redis probe passed with this new test included.
This is not a public pairing API or a completed wallet flow. The ticket may
only be issued after Gateway session and selected step-up authorization, then
redeemed with a server-created keyless registration, remote holder and
presenter keys, one-time device bearer delivery, real paired status and
Authenticator remote signing. Remove the browser simulation and local SDK
signing-key path in that grouped cutover.

2026-10-09 self-host operator preflight repair: `make selfhost-prod-check`
still invokes `scripts/check-selfhost-production.py`; it was unusable because
two imports pointed at the removed `marty_common` Python package. The script
now requires the supported exact `selfhost-production` migration profile and
sets its operator error-hint ID to match the Rust presentation-policy catalog's
seeded OpenBadgeLogin ID. Its `--help` and direct profile validation load, the ten
targeted Canvas/self-host preflight tests pass, and Python compilation/Ruff
pass. This restores the preflight command's importability; it is not evidence
of a healthy live self-host deployment or of the remaining wallet cutover.
The same preflight now rejects a holder Signing Keys credential shorter than
32 UTF-8 bytes or equal to the Device Registration Gateway, gRPC or Issuance
service credential, without printing secret contents. Its focused synthetic
secret-file test passed; real operator secret provisioning and live deployment
qualification remain open.

2026-10-09 Device Registration PS256 retirement stage: the public
`/v1/devices/challenge` route is removed, and registration/update requests
carrying device-held signing-key fields are rejected before proof processing.
Both memory and PostgreSQL repository saves also reject a supplied device key
projection. The service's native diagnostics now advertise keyless registration
instead of the retired `device_authentication` capability. Its behavior suite
no longer creates RSA private keys; it verifies keyless CRUD, Gateway service
authentication, challenge-route unavailability and old-key input refusal.
Four Rust behavior tests, seven library tests, five Python cutover tests,
all-target Clippy and the full disposable OpenBao/PostgreSQL/Redis probe passed.
This closes the public old-key route but does not yet remove dormant internal
PS256 challenge/rotation methods, public-key projection columns, transition
tables or Core device-auth fixtures. Remove those in this same grouped feature
batch after keeping the KMS holder signing and notification behavior green.

2026-10-09 Device Registration key-history retirement: the Rust service now
uses keyless registration CRUD without PS256 challenge/rotation modules or
device-key projection fields. The fresh PostgreSQL baseline no longer creates
`device_registration_keys`, `device_key_transitions`, or the associated
registration columns, and startup rejects a database that still has that
retired schema. No upgrade script is supplied because this is a fresh-only
deployment cutover. Registration input rejects old key fields, including
unknown preference fields, and repository saves reject embedded private-key
material. The fresh-schema custody check is included in the disposable
OpenBao/PostgreSQL/Redis probe. This is source and local integration evidence;
Core device-auth fixtures, public wallet pairing/signing, and operator
deployment qualification remain open.

2026-10-09 retired Core registration proof removal: Core branch
`security/remote-kms-fixture-20261007` commit `7c50d31` removes the
device-registration PS256 challenge verifier, Python bindings, contract and
RSA-generating fixture. The distinct mdoc DeviceAuthentication verifier and
its tests remain intact. Native diagnostics now identify that retained
capability as `mdoc_device_authentication_verification`, rather than the
ambiguous old `device_authentication`. The `marty-verification` and
`marty-bindings` test suites, native diagnostics test and all-target Clippy
passed locally. The unused UI copy of the old challenge vector is also
deleted in the grouped UI branch. These changes are local branch evidence;
Core PR/publication, consumer repin and exact-artifact qualification remain.

2026-10-09 production-root Core repin: Core PR #355 now publishes the
`7c50d31` head. UI branch commit `fa3080c22` pins every workspace Core crate,
including Issuance, to that revision; full Rust workspace `cargo check`,
Device Registration tests and the disposable OpenBao/PostgreSQL/Redis holder
lifecycle probe passed on the repin. Credentials PR #313 now publishes
`daf1164`, with all Core crates pinned to `7c50d31`; its native check,
25 library tests and all-target Clippy passed. Verifier PR #154 now publishes
`206f80e`, similarly pinned to one Core revision; `marty-sync` check and its
35 focused tests passed. Authenticator's direct Core pin has been updated,
and its `marty-sync` pin now targets Verifier `206f80e`, removing the older
transitive Core revision from the lockfile. Authenticator's Windows bridge
build is still under investigation after vendored C++/OpenSSL compiler failures;
the graph repin is not yet qualified or published. These consumer PRs remain
open, and exact release artifacts and wallet acceptance remain required.

2026-10-09 consumer CI correction: Credentials PR #313 head `daf1164`
passed Rust tests, Clippy, Python tests and security checks but its Fast Rust
Preflight rejected the new Core graph because `MARTY_CORE_REVISION` and the
graph guard still expected `6855721`; that made its CI gate fail. Commit
`6269324` updates the graph guard, CI wheel checkout and cache revision to
the full `7c50d31bf0b1d969f42f8cb1125995f1c99cb96c` hash; the exact
`cargo metadata --locked` graph check passed locally, and the corrective
head is published for a new hosted run. UI's equivalent guard was updated
and passed against its locked full workspace graph before the grouped UI
push. Core PR #355 hosted checks are green at `7c50d31`; Verifier PR #154
hosted checks are green at `206f80e`. Authenticator's first Windows build
against the unified graph reproduced the previously known MSVC OpenSSL
`C1083` long-path failure; a short isolated target-path check is in progress.

2026-10-09 exact-head consumer CI and UI main reconciliation: Credentials PR
#313 corrective head `6269324` now has 19 successful checks, including its
graph preflight and CI gate. Verifier PR #154 at `206f80e` and Core PR #355
at `7c50d31` are green. Authenticator PR #57 at `9a91130` has 12 successful
checks, including Android, unsigned iOS configuration, Flutter tests and
generated Rust bindings; its Cargo metadata resolves one Core source. Local
Windows checks did not prove a bridge build: the original long target hit
MSVC OpenSSL `C1083`, and a short isolated target exposed missing
`openssl/sha.h`/`zstd.h` plus C++ `sbb`/`adc` intrinsics in the local ZK
toolchain. Those local failures remain evidence; the hosted Linux bridge lane
is the passed compile evidence, while wallet remote-signing acceptance is
still open.

UI PR #1192's grouped `2eb1223fd` push was blocked from checks by a newer
main conflict. The local merge preserves KMS-only DIDComm/OpenBao settings
and the fresh Rust Issuance ledger, while taking main's Canvas deadline and
deployment improvements. Main's `0000_merge_issuance_heads_bridge.sql` was
excluded because it would restore an Alembic upgrade path that the fresh-only
runtime rejects. The merged Rust workspace check, Issuance all-target Clippy,
394 affected Python tests, 47 physical-provider tests, two Canvas published
runner cases, three complete Compose model scripts, 55 migration/fence tests
and Bash syntax checks passed locally. The merged head was published as
`c31ad24b3` but is not yet qualified by hosted CI. Historical published-schema
Canvas fixtures still assert the old Alembic revision; retire or replace that test
producer with fresh Rust schema evidence before final release qualification.

2026-10-09 UI merged-head CI checkpoint: PR #1192 head `c31ad24b3`
started hosted CI `37952848950`. Its Rust Feature Regression Probe and Rust
Lint and Packaging jobs failed before compilation because the standalone
frozen probe lockfile still named Core `6855721` after the production graph
moved to `7c50d31`. Regenerating
that probe lockfile changed only the six Core source entries; local Cargo
metadata and `cargo fetch --locked --offline` pass with Rust 1.95.0. A local
frozen/offline build of the standalone probe then produced deterministic
canonical output accepted by `test_feature_regression_rust_probe.py`. This
correction was held locally until the other jobs finished so their findings
could be batched into one follow-up push. The failed jobs remain
immutable evidence, and this checkpoint is not a green hosted claim.

The same merged-head run's Release Contract Tests completed with 6,131
passing and five failing cases, all variants of one stale Kubernetes signing
environment inventory assertion. The 11th binding,
`DEVICE_REGISTRATION_SIGNING_KEYS_KEY`, is a dedicated service credential for
holder-key cleanup between Device Registration and Signing Keys, not private
signing material, and must remain for supported device behavior. The test now
requires that exact secret reference and all 31 tests in its file pass
locally. This correction is part of the batched CI follow-up.

The Rust Service Tests (contracts) lane also failed 10 cases because its
`kubernetes_native` exact signing template guard omitted that same live
service credential. The Rust guard now requires the same named Secret
reference. Local Windows execution passed 14 of its 15 tests; the remaining
shell/`envsubst` fixture cannot start because that program is absent locally.
Hosted Linux must still prove the full lane after the batched correction.

The Canvas Rust lane's resolved Kubernetes configuration proof failed at
`native::compose` for the same signing-template mismatch. The shared Rust
guard correction is the path to that model; hosted rerun remains required to
prove the full Canvas case. No private-key material was restored to make the
fixture pass.

The same exact-head OpenBao DIDComm plugin image job completed successfully,
including packaged plugin, storage, Raft HA/failover, snapshot and coordinated
Rust/PostgreSQL/integration-secret recovery probes. This is hosted backend
evidence at `c31ad24b3`, not yet whole-release qualification.

The Rust Service Images job also passed at `c31ad24b3`, including its
packaged Canvas worker startup gate. The first merged-head run finished with
22 successful checks, one skipped check, five substantive failures described
above, and the dependent CI Gate failure. The next grouped push will qualify
the standalone lockfile and both exact signing-template inventories together.

2026-10-09 UI correction head `c138f9528` was pushed to draft PR #1192 with
those three source fixes; the PR body now describes the current grouped scope,
local evidence and open wallet/release gates. Its exact-head CI run
`37955356572` passed the frozen Rust Feature Regression Probe. Rust Lint and
Packaging reached a later beta Compose render and failed because that job's
synthetic environment omitted the still-required
`DEVICE_REGISTRATION_SIGNING_KEYS_KEY` service credential. The local workflow
correction supplies a distinct synthetic value; executing the entire workflow
packaging-render script through Git Bash with the job's declared environment
passes. The remaining contracts, Canvas and release jobs are still live, so
this correction is held for one grouped follow-up push. The earlier failed
run and this new failure remain separate, immutable evidence.

2026-10-09 UI held-batch reconciliation: UI PR #1192 remains published at
`c138f9528` while its Canvas job `113904439586` is still running. That job
compiled its reusable Rust executables, built the public self-host image,
verified the no-local-passport-signing gate, built and probed the disposable
Canvas DIDComm KMS backend, and reached the isolated database contract suites.
The still-unpublished UI branch includes `a02ae3cd5` (the locally verified
beta packaging environment correction) and merge `10c28878c` of main
`953cf5294`, which added the base Compose verification-service binding. The
merged candidate passed 113 focused Python tests, one skip and 348 subtests,
plus the full CI packaging-render step under its declared environment. These
local checks do not qualify the eventual pushed head; wait for the Canvas
result so any final correction can share the next hosted run.

2026-10-09 UI Canvas terminal evidence: job `113904439586` in exact-head run
`37955356572` completed successfully at 16:40:35 UTC after the isolated
database contract suites and native Canvas operation/TLS parity. PR #1192
head `c138f9528` now has 26 successful checks, one skipped check and two
failures: the known Rust Lint and Packaging synthetic-credential omission and
its dependent CI Gate. No additional source correction was needed from Canvas.
Main remains `953cf5294` after a fresh fetch. The locally verified workflow
fix, latest-main merge and tracker corrections can be published together for
one new hosted run; the prior failed result remains immutable evidence.

2026-10-09 grouped UI qualification push: branch
`security/remote-kms-hardening-20261007` and draft PR #1192 now publish
`6cc8159a5a2e289dc0b51820b43a3fa35aded7a8`, containing the beta
packaging environment correction, merge of main `953cf5294` and the tracker
updates. The PR body was refreshed to distinguish the two earlier failed UI
runs, their passed OpenBao/Canvas/service-image evidence and the still-open
wallet and release gates. Exact-head CI run `37960926646` was queued after
the push; its result is not yet known. Do not treat the prior green lanes as
qualification of this new head.

2026-10-09 test-custody review finding: the Canvas published-worker Python
oracles still set a synthetic `INTEGRATION_SECRET_MASTER_KEY` in
`scripts/run_canvas_worker_rest_oracle.py` and
`scripts/run_canvas_worker_startup_oracle.py`. Those scripts launch the frozen
historical Python oracle image for parity, not a candidate Rust production
service, but they still exercise the retired local master-key configuration in
the acceptance graph. K8 review must either replace that oracle with public
expected behavior and live remote-custody Rust acceptance, or document and
isolate the frozen historical comparison so it cannot serve as custody proof
or ship in a product image. Preserve Canvas regression coverage when retiring
the oracle path. The exact-head Canvas pass does not close this finding.
Source packaging review narrows the exposure: the final `services/Dockerfile`
runtime stage copies Rust binaries, the service entrypoint and the secret
loader, but no `run_canvas_worker_*_oracle.py` script. That excludes the
historical oracle from this source-defined product image; an exact released
image filesystem check and replacement of the acceptance graph's local-master
oracle dependency remain open.

2026-10-09 K10 exact-image coverage expansion (local candidate): the
digest-pinned self-host migration qualifier previously ran only Organization,
Credential Template and Issuance native schema owners. Device Registration now
contains the fresh reference-only holder credential, key, provision and
deletion ledgers, so the qualifier must run it too. Its Rust binary now has
`migrate` and read-only `verify-owned-schema` commands. The disposable Compose
model and verifier command include it between Credential Template and
Issuance, and the model test rejects omission. Focused Python qualification
tests passed (8), Rust Device Registration library tests passed (6), and the
binary check compiled. On disposable PostgreSQL 15, the fresh-schema/runtime
custody test passed, followed by idempotent binary migration and the read-only
verification command; the resulting schema contained exactly the six expected
Device Registration tables, with no retired device-key tables. This is local
source evidence. The exact signed services image, all-database inventory and
runtime writes still require release qualification before K10 can close.

At published UI head `6cc8159a5`, hosted run `37960926646` passed Rust
Lint and Packaging, including the beta Compose render that failed at
`c138f9528`; the grouped synthetic service-credential correction is therefore
qualified for that lane. At this checkpoint 16 CI jobs had passed and five
long jobs (OpenBao plugin, contracts, release contracts, service images and
Canvas) were still live. The new Device Registration schema-qualifier change
above is local and is not included in this hosted result. Its targeted
all-target Clippy passed with warnings denied, and the actual disposable
Compose YAML command exactly matched the verifier's canonical native command.
The verification transaction now sets PostgreSQL `READ ONLY` before querying.
A second disposable PostgreSQL 15 run passed fresh migration and read-only
verification, then injected the retired `device_registration_keys` table;
the same verification command exited nonzero with the expected fresh-schema
error. The container was discarded after the probe.

2026-10-09 K10 assembled inventory artifact (local candidate): the
digest-bound self-host migration qualifier now captures every non-system
ordinary, partitioned, materialized and foreign table column (schema, table,
column name and SQL data type) after native and
legacy-migration image execution. It requires a nonempty, well-formed JSON
inventory, compares the two idempotent runs, and includes the complete list
in its version-3 result alongside the existing private-key name scan. The
focused qualifier tests passed (8), and the SQL query parsed against a fresh
disposable Device Registration database: six tables and 51 columns, including
the reference-only holder ledgers, with no retired device-key tables. This is
not yet the final assembled product inventory; only the exact signed-image
probe after merging can establish that evidence for all schemas.
The inventory and private-key name scan now use PostgreSQL catalogs, so the
probe sees non-system table definitions regardless of `information_schema`
visibility. On a separate disposable PostgreSQL 15 database, the catalog
guard returned no findings before injection and then reported both a
`private_key_cache` table and its `encrypted_jwk_json` column. No product
database was modified for this test.

2026-10-09 pairing authorization interface review: the Auth service session
record retains creation time and OIDC claims, but its current gRPC
`ValidateSession` response and Gateway `SessionIdentity` expose user and
organization only. Gateway therefore cannot currently prove a recent user
authentication event from the session it validates. Session creation time is
not a substitute for a fresh step-up. If the pairing policy requires step-up,
carry a verified authentication timestamp/assurance result through Auth and
Gateway, reject API-key identities, and enforce freshness before issuing a
pairing ticket. If an independent device ceremony is selected instead, prove
its user-presence binding and stolen-session resistance before adding public
routes. The existing ticket store and keyless registration alone do not meet
that authorization gate.

2026-10-09 local pairing step-up prerequisite: Auth's `ValidateSession`
contract now includes an optional Unix authentication time sourced only from
the nonce-validated, signed OIDC ID-token claims stored with the session. It
omits absent, nonnumeric, nonpositive and implausibly future `auth_time`; it
does not substitute session creation or activity time. The existing Keycloak
login request now sends `max_age=0` alongside its existing `prompt=consent
login` so the provider is explicitly asked for a new authentication event.
Gateway carries the optional timestamp only on session identities; API-key
identities never receive one. Auth's focused gRPC and OIDC suites passed
(four and five tests), and targeted formatting passed. Gateway's focused
test passed. Self-review found that credential-login callbacks could copy
validated claims from an account token exchange into a new session. That
exchange does not prove a fresh interactive login, so the callback now strips
`auth_time` while preserving other linked-account claims; its dedicated
regression test and the four-test credential callback suite passed. Both
Auth and Gateway all-target Clippy checks passed with warnings denied, and
their targeted formatting checks passed. This is a prerequisite, not a public
pairing
authorization: ticket issuance must still require a recent claim, correct
user/tenant membership and explicit step-up policy, with a wallet flow and
replay/expiry acceptance before exposing the route. Neither the Auth change
nor the previously local K10 schema-qualifier changes are in published UI
head `6cc8159a5` or its hosted CI run `37960926646`.

At the 17:03 UTC checkpoint, run `37960926646` had 20 successful jobs and no
failures; only Rust Service Tests (canvas) was still running. The OpenBao
plugin-image, Rust service contracts, service images, Rust Lint and Packaging,
release contracts and UI lanes had passed on the published head. Keep the
local candidate changes batched until that exact-head run is terminal.

2026-10-09 Gateway pairing policy candidate: the trusted Gateway identity
now has an explicit `permits_pairing_ticket` predicate. It accepts only a
session actor with a nonempty user ID and a validated OIDC `auth_time` no
older than five minutes and no later than current time. Missing, stale,
future and API-key values fail. The focused Gateway unit test and formatting
check passed. This policy is not yet wired to a public route or sufficient
on its own: the selected organization still needs active membership
authorization, the device service needs a Redis-backed issue/redeem runtime,
and the mobile wallet must consume the ticket and receive a remote-key-bound
credential. Current `ui/src/components/WalletSetup.jsx` still calls the
simulated pairing-code application helper, so no wallet cutover is claimed.
Keep this as one local batch in draft UI PR #1192 until the running head's
Canvas lane finishes and the complete routing and release checks are ready.

2026-10-09 published UI qualification: run `37960926646` completed
successfully for exact PR #1192 head
`6cc8159a5a2e289dc0b51820b43a3fa35aded7a8`, with 22 successful jobs
and no failed or skipped jobs. The Canvas lane passed its public image build,
isolated database contracts and native operation parity. This proves the
prior beta packaging correction and published head; it does not qualify the
locally committed Device Registration schema inventory or pairing changes.

2026-10-09 local pairing ticket issuance candidate: Device Registration now
offers `POST /v1/devices/pairing-tickets` behind its dedicated Gateway key,
requires an active user/organization membership and stores only the digest
of a five-minute single-use ticket in Redis. The response is `no-store`.
Gateway adds the route to its fixed manifest and, before forwarding, requires
a recently authenticated session, rejects API keys and stale/future claims,
checks the selected organization against live active membership and builds a
fresh trusted upstream context. Its full-router test proves missing/stale/API
key/wrong-tenant requests never reach the Device Registration upstream and a
forged `x-user-id` or service token is replaced. The Device Registration
behavior suite passed five tests, including token rejection, membership,
scope, one-time redemption and no-store; its binary compiled and its six
library tests passed. The Gateway focused full-router test and full library
suite passed (154 passed, one existing ignored). Gateway and Device
Registration all-target Clippy passed with warnings denied, as did targeted
formatting. This is issue-only; do not present the
QR to users or claim wallet completion until ticket redemption provisions
the remote holder key and credential under the registration and revocation
locks, with disposable OpenBao, PostgreSQL and Redis acceptance.

2026-10-09 local pairing redemption candidate: Device Registration now has a
dedicated Gateway-authenticated `POST /v1/devices/pair` route that consumes a
single-use Redis ticket, rechecks active membership, creates a server-owned
keyless mobile registration, provisions `holder_binding` EdDSA and
`presentation_signing` ES256 keys through the remote Signing Keys authority,
and returns only public JWKs plus a digest-stored, one-day device bearer.
The route rejects a missing Gateway service credential and unavailable KMS
enrollment; the focused six-test behavior suite passed. A guarded disposable
OpenBao/PostgreSQL/Redis probe passed the full HTTP redemption, ticket replay
rejection, both remote-signature verifications, credential rotation, and
deactivation/deletion lifecycle. It also passed the six managed-prefix and
provider HMAC checks. Device Registration and Gateway all-target Clippy passed
with warnings denied. These changes remain local to the grouped UI branch and
are not covered by published PR #1192 head or its successful 22-job run.
The signer now checks live active membership after bearer authorization and
before the remote call. The disposable lifecycle probe proved an unexpired
bearer cannot sign after membership is revoked, and the repeated all-target
Clippy check passed. Before wallet cutover, review compensation under failures,
expose an authorized remote signing path to the mobile wallet, replace the
wallet's local holder-key behavior and simulated pairing, and qualify the
exact signed image/release.

2026-10-09 local holder signing route candidate: Device Registration now serves
`POST /v1/devices/holder-signatures` only behind its dedicated Gateway key and
a digest-backed device bearer. It derives user and tenant scope from the stored
credential, checks the current active membership, holds registration and key
locks during the bounded remote call, and returns a version-pinned OpenBao
signature with `no-store`. Gateway exposes exactly this path without session
auth, forwards the bearer and its own service key, and strips forged client
user/tenant/service headers. Its full-router proof passed. The guarded
disposable OpenBao/PostgreSQL/Redis probe passed real HTTP EdDSA and ES256
signing and verification, ticket replay rejection, membership-revocation
denial, bearer rotation, deactivation and remote deletion. The seven-test
Device Registration behavior suite and Gateway library suite passed (156
passed, one ignored); both service all-target Clippy checks passed with
warnings denied. This remains local, beyond published PR #1192 head. The
Authenticator still uses local holder signing, the browser still simulates
pairing, and the final mobile credential renewal, bearer handling, user
presence, actual wallet-to-Gateway network path and signed release need review
and qualification before calling the wallet KMS-only.

2026-10-09 push-independent mobile enrollment correction: the Authenticator
has no FCM token acquisition path. Requiring one during KMS pairing would
block a wallet before notification consent. Device Registration now accepts a
mobile pairing request without `fcm_token`, stores SQL NULL in the fresh-only
schema, rejects malformed nonempty supplied tokens, and verifies the nullable
column at startup/read-only schema qualification. The disposable OpenBao and
PostgreSQL probe paired, signed, rotated and deleted a device with no push
token. Device Registration library and eight focused behavior tests passed,
and all-target Clippy passed with warnings denied. This local correction is
not in published UI PR #1192; mobile push enrollment and delivery still need
an independently consented integration.

2026-10-09 Authenticator local mobile pairing candidate on branch
`security/kms-hardened-core-consumer-20261008`: the Rust QR parser recognizes
only `marty://pair` with one 43-character ticket and a bare HTTPS API origin;
it rejects duplicate, unknown, insecure or malformed parameters. The Flutter
scanner asks the user to approve the displayed origin before sending the
ticket. A bounded, no-redirect HTTP client redeems the ticket without an FCM
token, accepts only the expected public-JWK response shape, and stores the
opaque device bearer and public metadata in platform secure storage. This is
not a KMS-only wallet cutover: the current SDK presentation path still signs
locally, bearer renewal and exact browser status are absent, and neither an
Android/iOS build nor a physical-device end-to-end run has passed. The local
Rust parser test is compiling; Flutter/Dart is not installed on this host, so
the mobile service tests and analyzer remain required CI/host gates.
The first local Windows Rust bridge test could not reach this QR assertion:
Longfellow ZK's native compile lacks `openssl/sha.h` on this host. A second
parser-only run used the repository's debug-only `USE_ZK_MOCK=1` setting to
isolate the QR logic, but Windows `openssl-sys` failed while compiling its
vendored OpenSSL before the QR test executed. Neither local run establishes
QR correctness, ZK custody, or release qualification. The Authenticator
candidate was committed locally as `9b8a5ad` without updating draft PR #57;
run its Rust parser, Flutter service tests, analyzer and mobile build in the
supported Linux/mobile toolchain after the grouped wallet changes are ready.
Browser pairing completion must be tied to this exact ticket. Listing an
arbitrary new or existing device is not proof that the scanned mobile app
received and stored its bearer. The next grouped UI work should issue a
separate browser-only status capability with the ticket, record a pending
registration after remote enrollment, and mark it complete only after the
mobile app acknowledges secure storage using its newly issued bearer. The
browser should poll that scoped status under its authenticated session, then
replace the local code generator and simulated completion. Review QR
shoulder-surfing/race behavior and require the user to approve the displayed
API origin on mobile; do not expose the bearer or status capability in logs.

2026-10-09 exact-ticket wallet confirmation candidate (local UI commit
`af613188e`, mobile follow-up commit `85efa95`; neither pushed yet):
Device Registration now persists a UUID pairing identifier separately from the
single-use Redis secret. The fresh schema records ticket issue, enrollment,
confirmation, and expiry without storing bearer or private key material.
Enrollment binds its registration to that exact identifier. General holder
signing fails before mobile confirmation; the pending device may only ask
remote KMS to sign the fixed challenge for its identifier. A current bearer,
active registration, matching user/organization, live membership, and an
Ed25519 signature verified against the stored public key are all required to
acknowledge. A lost acknowledgment response can
be retried with the same live bearer. A retrying expiry worker deactivates
unconfirmed registrations, revokes their bearer, and queues both remote keys
for deletion. Gateway exposes public bearer-only `POST /v1/devices/pairing-ack`
and keeps `GET /v1/devices/pairing-confirmations/{pairing_id}` session-bound;
Device Registration checks the user's live membership before returning status.
The browser now requests the server ticket, renders `marty://pair` with the
bare HTTPS API origin, polls only that identifier, and has no simulated
success button or arbitrary-device completion check. Mobile saves the bearer
to secure storage before calling the acknowledgment endpoint and offers a
retry if its response fails. This still does not migrate the wallet's
credential/presentation signer, renewal, or mobile network acceptance.

Local validation of this candidate: the guarded disposable
`python scripts/probe_signing_keys_openbao_policy.py --rust-adapter` passed
after the expanded test covered pending-sign denial, exact status, remote
acknowledgment and retry, EdDSA/ES256 signing, rotation, revocation, expiry
deactivation, and remote key cleanup. Device Registration behavior tests 8/8,
Gateway contract tests 15/15, Gateway public-ack/private-status route test,
all-target Device Registration/Gateway Clippy, UI wallet tests 11/11, and UI
TypeScript build check passed. Flutter/Dart is unavailable on this Windows
host, so the changed mobile parser/service tests, analyzer, and device build
remain unverified. The source changes are still local on both feature branches;
run exact-head hosted CI after the grouped wallet work is ready. This is no
release qualification and does not close the KMS-only wallet goal.

2026-10-09 Authenticator presentation-path review correction: Android
`SpruceIdHandlerRefactored` and iOS `W3CMethodHandler` currently return
`REMOTE_KMS_REQUIRED` for OID4VP signing/presentation operations. This is a
fail-closed stub, not evidence of functioning local presentation signing. The
Flutter completion wrapper nevertheless tried the mDoc channel whenever a
W3C channel call raised a platform exception, which could reinterpret an
authorization or signer error as a different protocol. The local mobile
follow-up now remembers the Rust-selected `oid4vp` versus `mdoc` route for a
bounded set of selection sessions and completes on that channel only; unknown
sessions fail closed. No mobile test or device build has yet qualified this
change. The Core Rust bridge has `wallet_build_and_submit_presentation`, but
the current caller is unused by the scanner and constructs a request with
empty `client_id` and `nonce`, so it is not suitable for SD-JWT key binding.
To close the wallet gate, wire a real Rust presenter from the secure credential
store and user selection into Core's verified SD-JWT preparation, a trusted
issuer-key resolver, the bearer-scoped Gateway ES256 signer, and
`submit_presentation_for_request` with the original request's nonce, audience,
state, and response mode. Preserve the separate mDoc session path and prove
both on mobile; add bearer renewal with lost-response recovery before release.

2026-10-09 holder bearer renewal candidate (local UI `328bdf3f0`,
Authenticator `e712ad4`; grouped PRs not yet updated): Device
Registration now offers bearer-only `POST
/v1/devices/holder-credential-rotations` through Gateway. A confirmed,
active registration and current organization membership are required. The
mobile app generates a fresh 32-byte capability using `Random.secure`, saves
it as `pending_credential` in platform secure storage before sending it, and
promotes it only after receiving the server's scoped expiry response. The
mobile client rejects noncanonical 32-byte base64url capabilities and
serializes pairing against in-flight renewal while coalescing concurrent
renewals, so a second request cannot overwrite the bearer installed by the
first. The
server stores SHA-256 digests only, locks the registration while revoking the
old bearer and installing the replacement, and recognizes an identical
old/new retry after a lost response; a changed replay is rejected. The
Authenticator records pairing as locally confirmed only after its exact-ticket
acknowledgment succeeds; renewal rejects an unconfirmed stored enrollment.
The presentation entrypoint checks and renews a confirmed paired bearer when
its expiry is within 12 hours. A device that stays offline past the one-day
bearer expiry still needs a user-approved re-pairing path or a proven
background renewal schedule; renewal at presentation time alone does not
guarantee uninterrupted wallet use. This does not yet make presentation
functional: the trusted-issuer and Rust remote-presenter work above remains.

The expanded disposable OpenBao/PostgreSQL/Redis probe passed with public
rotation, exact lost-response retry, changed-replay rejection, signing under
the replacement, and revocation/deletion. Device Registration behavior tests
8/8, Gateway contract tests 15/15, its public rotation forwarding test, and
all-target Device Registration/Gateway Clippy passed. Mobile unit test source
covers staged-storage retry, simultaneous calls, and rejecting renewal before
acknowledgment; the canonical bearer
Rust unit test passed. Dart/Flutter tooling is absent on this host;
run analyzer, mobile tests, and physical-device network acceptance on the
grouped PR before claiming release readiness.

2026-10-09 Authenticator presentation bridge review (local `afc7219`,
grouped PR not yet updated): the generated FRB
`walletBuildAndSubmitPresentation` entry point is unused by the scanner but
its Rust implementation reconstructed a request with empty `client_id` and
`nonce`, discarded `state` and `response_mode`, and submitted a VP without
issuer verification or holder key binding. The local Authenticator follow-up
retains the generated symbol for bridge compatibility but makes it fail closed
with `REMOTE_KMS_REQUIRED`; no presentation is submitted through it. The
replacement must parse the original request in Rust, validate the response
URI/mode and verifier audience, preserve nonce/state, select credentials from
secure storage, resolve trusted issuer verification keys under an allowlist,
run Core `prepare_verified_sd_jwt_presentation`, sign its exact input using
the bearer-scoped remote ES256 endpoint, complete the signature, and submit
through `submit_presentation_for_request`. Core currently parses these request
fields but does not itself enforce response URI/mode policy; the mobile
integration must do so before any credential disclosure. The physical-device
OID4VP and separate mDoc flows remain acceptance gates. Local `cargo fmt
--check` passed; the targeted Authenticator Rust test could not compile on
this Windows host because the Longfellow ZK C++ dependency cannot find
`openssl/sha.h`. Run the test and generated-bridge verification in hosted CI.

2026-10-09 mobile credential and issuer-trust source audit: Authenticator's
scanner calls `handleOID4VCOfferSDK`, which still invokes Android/iOS native
handlers that return `REMOTE_KMS_REQUIRED`; the existing
`WalletCredentialStore.store` has no production caller. The current mobile
wallet therefore has neither a functioning KMS-backed OID4VCI receipt path
nor a stored SD-JWT to present. Its Rust `trust.rs` is an IACA certificate
registry for mDoc, not an SD-JWT issuer key allowlist. Signing Keys exposes
organization-scoped managed issuer identity list/resolve APIs with public JWK
projection, but those identify the organization's own active issuer keys;
they are not by themselves a trust policy for external issuers. Do not treat
an unverified credential `iss`, verifier request, or arbitrary DID resolution
as authority to add a trusted key.

Wallet completion must include a user-approved OID4VCI receipt flow that
uses the paired remote holder key for proof JWT signing, stores the issued
credential only after issuer/holder binding and endpoint validation, and
records its trust provenance. Define an operator-governed issuer trust source
covering supported external issuers and managed local identities; deliver a
bounded, authenticated, organization-scoped public verification-key snapshot
to the paired device and refresh it on rotation/revocation. Feed only that
snapshot to Core's `SdJwtIssuerKeyResolver`, with exact issuer, `kid`, and
algorithm matching and a rejection path for stale or ambiguous keys. Then
wire the Rust OID4VP presenter to secure stored credentials and remote ES256
signing. Acceptance needs an issued credential received on Android and iOS,
verified issuer and `cnf.jwk`, a signed KB-JWT with original nonce/audience,
state-preserving submission, rotation/revocation denial, and physical-device
negative cases. The earlier mobile pairing and renewal probes do not prove
these gates.

2026-10-09 shared issuer resolver prerequisite (local Core `9abc621`,
unpublished grouped candidate): `marty-oid4vci` now exposes
`TrustedSdJwtIssuerKeys`, an explicit public-only resolver that matches the
issuer, optional protected `kid`, and JOSE algorithm exactly. Construction
rejects empty or duplicate identity tuples, private/malformed JWKs,
incompatible key families, and inconsistent JWK `kid`. The browser test wallet
uses this Core resolver instead of a separate local matching implementation.
Core's 14 SD-JWT presentation tests passed, including the new resolver's
successful verified preparation and negative cases; wallet-feature Clippy
with warnings denied and the test-wallet binary check passed. No mobile
issuer trust source is delivered yet. Publish/batch the Core feature before
repinning Authenticator to this revision, then wire only an authenticated,
operator-governed snapshot into this resolver. Do not treat the test-wallet
environment configuration as mobile trust provenance.

2026-10-09 authoritative wallet issuer trust source correction (local UI
`a8c3cffd0`, grouped PR not yet updated): the native Trust Profile service already owns operator-managed,
organization-scoped issuer relationships and public `verification_keys`,
including DID assertion-method pinning and registry freshness checks. Its
`/internal/v1/trust-profiles/{profile_id}` decision route includes this
material, so a new trust store or a Signing Keys identity-list proxy is not
the right source. The local service batch adds service-authenticated
`GET /internal/v1/trust-profiles/{profile_id}/wallet-issuer-keys`. It projects
only an explicitly selected active, compliant profile with
`CREDENTIAL_ISSUER` purpose and `SD_JWT_VC` support, then includes keys only
for current trusted relationships and non-revoked, valid issuers under the
profile's allowed/denied issuer and algorithm policy. Ambiguous key identity,
inconsistent JOSE algorithm, unsupported key family, or an empty result fails
closed. The response is public-key-only, `no-store`, and expires after one
minute. Trust Profile HTTP tests 8/8, surface tests 2/2, and all-target
Clippy with warnings denied passed locally. This is a service-only building
block: Device Registration still needs to bind an operator-selected profile
to the paired bearer organization, fetch this internal projection, and expose
a bounded public bearer endpoint; mobile must refresh it online for each
presentation and pass it through Core's strict resolver. No physical wallet
trust acceptance is claimed.

2026-10-09 paired wallet issuer trust binding (local UI `890ffde5d`, not yet
published in grouped draft PR #1192): Wallet Setup now loads active profiles
for the selected organization, requires a selected Trust Profile before issuing
a QR ticket, and passes that exact UUID through Gateway. Device Registration
requires active membership and fetches a fresh, service-authenticated,
size-bounded public issuer-key projection before issuing the single-use ticket.
The fresh-only Device Registration schema and durable confirmation row store
`trust_profile_id` alongside the user and organization; schema verification
requires that non-null column. No legacy migration or private-key table was
added. A new bearer-only `GET /v1/devices/wallet-issuer-keys` resolves the
profile from the confirmed pairing row rather than a mobile-supplied ID. It
requires a current digest-backed credential, active registration, matching
user/organization, live membership, and an unexpired non-revoked bearer;
it rechecks the bearer after fetching the snapshot. Gateway exposes that
fixed route, strips forged identity/service headers, and forwards only the
bearer under its own service credential. The returned public-only snapshot is
`no-store`, limited to 256 KiB and 256 keys, with exact profile/organization
and one-minute validity checks. Trust Profile revocation/status decisions are
refetched online, so a stale cached decision is not an authorization source.

Local validation: Device Registration 9 library and 8 behavior tests passed;
Gateway 159 library tests passed with one existing ignored test; all-target
Device Registration and Gateway Clippy passed with warnings denied; Wallet
Setup/use-case tests 4/4 and TypeScript build check passed. The guarded
disposable OpenBao/PostgreSQL/Redis probe passed, including HTTP ticket issue
with a selected profile, confirmed bearer snapshot read, cross-organization
denial, membership denial, bearer-rotation denial, and deactivation denial.
Base and self-host Compose model checks passed. This qualifies this local
server/UI boundary only. Authenticator still must fetch this snapshot through
the paired bearer for each presentation, enforce expiry and trusted issuer
resolution through Core, and finish actual OID4VCI receipt and OID4VP
presentation. The Core resolver is still local, mobile Dart/device acceptance
is absent, and grouped PR heads/exact release artifacts have not been updated
or qualified for this batch.

2026-10-09 four-hour checkpoint (09:13–13:13 MDT): Core resolver commit
`9abc621` is now published on draft PR #355; its new exact-head hosted CI is
still running. Verifier commit `ea91db5` is published on PR #154 and pins its
Core manifest and lockfile to that resolver; dependency-contract tests passed
locally and exact-head CI is running. A local Verifier `marty-sync` Rust test is
still in its first dependency build. The mobile Authenticator branch has six
additional local commits for pairing, renewal, session binding, and a
fail-closed legacy VP bridge. Its uncommitted Dart candidate fetches the
fresh bearer-scoped issuer-key snapshot and requests exact-input remote
signatures, with source tests; Flutter/Dart tooling is unavailable locally, so
those tests have not run. Its uncommitted Rust manifest and lockfile now pin
Core `9abc621` and Verifier `ea91db5`; the old Core revision is absent from
both. These mobile transport methods are not yet wired into OID4VCI receipt
or Core's verified OID4VP presenter. The grouped UI branch remains 25 local
commits ahead of draft PR #1192. Do not count any of these as physical-device
wallet acceptance or release qualification.

2026-10-09 continuation: Verifier's exact `ea91db5` local `marty-sync`
library run finished with 35 passed and one ignored; Verifier PR #154
exact-head CI still has Rust tests and Clippy in progress. Core PR #355
exact-head CI still has preflight and affected Rust tests in progress, while
its completed checks pass. Authenticator local commit `4a4cc92` groups the
paired bearer issuer-snapshot fetch and remote exact-input signing transport
with the single Core `9abc621` / Verifier `ea91db5` Rust graph. `cargo
metadata --locked --no-deps` passed; the old Core revision is absent from its
manifest and lockfile. Dart tests remain unrun without a local Dart/Flutter
SDK. A Rust snapshot-to-Core resolver adapter is under development and is not
yet called by a presenter. The Authenticator Rust test attempt reached the
Longfellow C++ build and emitted tool-execution failures; await its terminal
result before classifying the attempt. Neither transport nor resolver adapter
constitutes OID4VCI receipt, verified OID4VP, or physical-device acceptance.

2026-10-09 mobile resolver prerequisite: Authenticator local `be64bba`
adds strict Rust conversion of the paired public issuer-key snapshot into
Core's `TrustedSdJwtIssuerKeys` resolver. It requires a bounded JSON response,
non-empty organization, UUID profile, one-minute freshness window, 1–256
keys, and Core's public-JWK/algorithm/exact-identity validation. A disposable
isolated Rust harness importing the actual module and current Core source
passed both positive and negative tests (2/2); `cargo fmt --check` passed.
This adapter is not yet invoked by an OID4VP presenter. The complete
Authenticator Rust build and Dart/mobile checks remain outstanding.

2026-10-09 published dependency CI update: Core PR #355 at `9abc621` and
Verifier PR #154 at `ea91db5` now report passing exact-head CI gates and all
required completed checks (with only declared skipped jobs). Core's affected
Rust tests, Rust preflight, native ZKP boundary, and security checks passed;
Verifier's Rust tests, Clippy, frontend checks, dependency contract, and
security checks passed. These are dependency-branch checks, not validation of
the unpublished Authenticator/UI grouped heads or a physical wallet flow.

2026-10-09 Authenticator local Rust test terminal result: `cargo +1.95.0 test
--lib operations::issuer_trust::tests --locked` failed in the Windows native
dependency build before compiling the bridge tests. `marty-zkp` Longfellow C++
compilation reported tool-execution failures, and vendored `openssl-sys`
OpenSSL `nmake build_libs` exited 2. This does not contradict the isolated
actual-module resolver harness passing 2/2; it leaves full Authenticator Rust
validation for a suitable hosted/mobile build. Core PR #355 is mergeable but
branch protection reports `REVIEW_REQUIRED`, while Verifier PR #154 is clean;
both are still open. Do not bypass the Core review requirement.

2026-10-09 mobile verified-presenter candidate (local, unpublished): Rust now
has a short-lived, one-use SD-JWT presentation session that rechecks the
operator-governed issuer-key snapshot, verifies the credential and paired
holder public JWK through Core, preserves the parsed nonce/audience/state,
returns only the exact JWS signing input for the remote signer, verifies the
returned ES256 signature against the paired public key, then builds Core's
DCQL/Presentation Exchange response. A digest of the entire parsed request
is returned to Flutter and compared after reparsing before preparation, so a
remote request object changed after user approval is rejected. The isolated
actual-source Rust harness passed five tests, including the signed public
OpenBao vector, changed request state, and one-use invalid-signature denial.
This is not yet a full Authenticator build or a working mobile route.

The Flutter candidate now stages a user-selected stored SD-JWT, retrieves a
fresh issuer snapshot and paired public key after approval, calls Rust
preparation, requests remote exact-input signing, and requires the verifier
response to accept. Targeted pairing/transport Flutter tests passed 12/12.
Rust bridge generation on Windows failed twice during native vendored OpenSSL
`nmake`; a short-target-path generation run is still in progress. Generated
bridge output, full Flutter analysis, OID4VCI credential receipt, query
semantics review, and physical-device validation are outstanding. Core local
`1939d4a` gives VP submission a no-redirect, bounded-time HTTP client so a
VP token is not forwarded to a redirect target; its focused test and
wallet-feature Clippy with warnings denied passed. This correction is not yet
published to Core PR #355 or repinned in consumers.

2026-10-09 presenter self-review continuation: the local Authenticator
candidate now rejects DCQL `meta` and Presentation Exchange filters, optional
fields, ZK predicates, or format requirements it cannot enforce; unsupported
requests fail closed instead of presenting an arbitrary stored credential.
The isolated actual-source Rust harness still passes 5/5, including the
unsupported-metadata rejection. Dart analysis of the paired transport and
its tests reports no issues. Windows bridge generation succeeded with a short
Cargo target path, explicit LLVM path, and MSVC/Windows SDK C include paths.
The first intermediate bindings were invalid due to missing standard C
headers; the final generated bridge and presenter service pass Dart analysis
without issues. Targeted pairing/transport Flutter tests pass 12/12. Three
new tests prove legacy native credential-offer, VP, and ad hoc presentation
entry points now fail closed instead of calling local-key handlers. Those
screens cannot complete until remote-only issuance and presentation
replacements are wired; the underlying native handlers and other entry
points still require a full retirement audit. The isolated actual-source
presenter harness passed 5/5. Do not treat credential-query
matching, OID4VCI receipt, physical-device signing, or a released image as
qualified until their respective checks pass. The full Authenticator Rust
library check initially exposed an existing moved-value compile error in the
wallet-pairing QR parser; the local fix now passes `cargo check --lib --locked`
and `cargo clippy --lib --locked -- -D warnings` with a short target path and
mock ZK build. This is compile evidence, not a real-ZK or physical-device
qualification. In-crate presenter tests passed 2/2 under the mock ZK build,
covering changed request binding, the signed public OpenBao vector, and
one-use invalid-signature denial. The Windows linker emitted missing static
OpenSSL PDB debug-symbol warnings, but the test executable linked and passed.
Authenticator local commit `26bc34e` contains the verified SD-JWT bridge,
generated bindings, paired public-key read, strict one-use signing session,
legacy Dart route retirement, QR compile repair, and public-only fixture.
It has not been pushed to PR #57; keep the broad feature batch grouped until
remote-only credential receipt and the remaining native path audit are ready.
The next mobile implementation should receive pre-authorized OID4VCI offers
through Rust's offer/issuer-metadata/token APIs, fetch the issuer's fresh
Nonce Endpoint value (not currently exposed by the Authenticator bridge),
prepare Core's `openid4vci-proof+jwt` with the paired public P-256
`presentation_signing` key, obtain the exact-input ES256 signature from the
paired remote signer, verify the signature before requesting the credential,
then verify the returned SD-JWT against the fresh Trust Profile issuer snapshot
and holder binding before storing it in `WalletCredentialStore`. Preserve
configuration choice and transaction/deferred semantics or explicitly fail
closed until implemented; do not revive the native local-key offer handler.
The previously recorded Ed25519 `holder_binding` proof choice was wrong for
SD-JWT receipt: Core's verified presenter requires `cnf.jwk` to bind to the
paired P-256 presentation key. The distinct Ed25519 key remains scoped to
its own holder-binding use; do not rely on its proof to issue a credential
that the P-256 presenter cannot later use.

2026-10-09 Core and Verifier review checkpoint: Core `cd21cad` is published
on PR #355. It shares strict trusted-issuer and P-256 holder-binding
verification between SD-JWT receipt and presentation, exposes verified
receipt metadata for remote-only wallet storage, and uses one bounded,
no-redirect HTTP client for wallet token, credential, and VP requests.
Core wallet-feature library tests passed 151/151 (42 existing ignored),
strict Clippy passed, and the public-only receipt fixture rejects untrusted
issuers and mismatched holder keys. Hosted CI on this exact Core head is
running; PR #355 still requires review before merge. Verifier `cd059ce`
repins its Core graph to this head on PR #154; `marty-sync` tests passed
35/35 (one ignored), and its new hosted CI has not yet completed. The
Verifier repin changed only Cargo.toml and seven Core package sources in
Cargo.lock; unrelated generated schema files remain untouched. The
Authenticator PR #57 still has nine local unpublished commits so remote-only
receipt and native-path retirement can land as a broad feature batch.

2026-10-09 Authenticator remote-only receipt candidate: local commit
`de568f9` repins its Rust graph to Core `cd21cad` and Verifier `cd059ce`,
adds a one-use Rust pre-authorized OID4VCI receipt session, generated Flutter
bridge, and the QR offer-handler route. The Rust session keeps the bearer
token private, accepts only one advertised SD-JWT configuration with JWK
holder binding and ES256 proof support, rejects required key attestations,
requires HTTPS offer references and same-origin issuer credential/nonce
endpoints, and fails closed on batch or deferred responses. The paired
remote P-256 `presentation_signing` key signs the exact proof input; Rust
verifies the signature before requesting a credential and verifies the
issuer signature, `vct`, format, and P-256 `cnf.jwk` against a fresh paired
Trust Profile snapshot before returning it for secure wallet storage.
Local Rust `cargo check --lib --locked` and strict Clippy passed under the
mock-ZK build; four focused Rust receipt tests passed, generated bridge and
service Dart analysis found no issues, and 15 focused Flutter tests passed.
The generated bridge needed explicit LLVM, MSVC, and Windows SDK include
paths on Windows. This is still a local candidate, not a full mobile build
or physical-device KMS/issuer receipt acceptance. The old handler is replaced
for one-configuration pre-authorized SD-JWT offers; multi-configuration
selection, authorization-code/deferred issuance, transaction-code UI, and
remaining native credential paths require explicit qualification or retirement
before PR #57 is published. Core exact-head hosted checks and Verifier
`cd059ce` hosted checks passed; Core PR #355 still requires review. Review
Core wallet HTTP response-size limits during the native audit: the Rust
receipt boundary caps returned credential size, but Core currently parses
issuer HTTP JSON before that cap applies.

2026-10-09 native mobile path audit finding: Android's registered SpruceID
W3C/PKI/JWT/mDoc/wallet channels route holder signing to explicit
`REMOTE_KMS_REQUIRED` errors; iOS does the same for the corresponding W3C
and PKI operations. The Dart-only `spruce_id_sdk` channel used by
`initializeHolderSDK`, ad hoc signing, and related legacy SDK wrappers has
no Android or iOS registration in the inspected native registries. These
wrappers do not constitute a working fallback, but they still advertise
unsupported capabilities and need to be retired or replaced in the broad
Authenticator PR. `initializeSDK(enableAdvancedFeatures: true)` currently
calls the unregistered holder initialization route; inspect all public
callers and preserve any required non-signing wallet/session behavior before
removing this API. The QR SD-JWT route uses the verified Rust bridge and
does not traverse those native signing channels. This is a source audit,
not mobile artifact or physical-device acceptance.

2026-10-09 Core wallet HTTP bound review: local Core commit `735a11f`
replaces unbounded wallet response parsing with one streaming, size-limited
reader for credential offers, issuer and authorization-server metadata,
nonce, token, credential, presentation, and request-object responses. It
also rejects non-HTTPS, credential-bearing, or fragment-bearing by-reference
offer URLs before network access and stops copying arbitrary issuer error
bodies into token and credential errors. The presentation path now rejects
an oversized body even when the HTTP status is successful. A focused test
proves advertised oversize rejection; another proves chunked oversize
rejection; a third proves insecure offer references fail before fetch.
Wallet-feature library tests passed 154/154 (42 existing ignored), strict
Clippy and formatting passed. This commit is local and is deliberately held
for a grouped Core PR #355 update with downstream Core-revision repins;
published Core `cd21cad` remains the checked head. The 8 MiB credential
response bound preserves larger mDoc payloads while Authenticator applies
its tighter 1 MiB SD-JWT receipt limit after Core parsing. Physical-device
and real-issuer qualification remain required.

2026-10-09 Authenticator legacy channel retirement: local commit `07ea30a`
removes the unregistered `spruce_id_sdk` and credential-monitor channels from
the extended platform service. Their holder initialization, ad hoc key and
signing, batch/validation, capability, secure-channel, and monitoring methods
now fail explicitly instead of constructing `default-key` requests for a
nonexistent handler. `SpruceIdClientExtended.initializeSDK` initializes its
base service and, when advanced features are requested, requires an existing
confirmed remote holder pairing by reading only the pinned public P-256 key;
it rejects legacy local holder configuration. Targeted Dart analysis passed
with no issues, and the remote-only entry-point suite passed 4/4. This is a
local, unpushed Authenticator batch addition for PR #57. Other registered
W3C/JWT/mDoc/wallet channel entry points and the credential-selection view
still need a source and artifact audit; this commit does not qualify a mobile
build or physical-device wallet behavior.

2026-10-09 registered mobile wrapper audit: Android routes its registered
PKI, JWT, mDoc, wallet, and W3C method channels through a handler that
returns explicit custody/verification/storage errors for supported method
names; iOS JWT, mDoc, and wallet handlers likewise reject signing,
verification, session, and storage methods. Authenticator local commit
`a277df4` removes the remaining Dart `default-key` requests from the
extended service's SD-JWT, mDoc, and credential-refresh wrappers and makes
those unsupported methods fail before any native call. It also removes the
unused credential-selection view's local Ed25519 key creation and ad hoc
presentation attempt, replacing that action with a clear verified OID4VP
remote-holder requirement. Targeted Dart analysis found no issues, and the
remote-only entry-point suite passed 5/5. These local changes remain in the
grouped, unpublished PR #57 batch. The view itself is not referenced by the
current app routes, and other mDoc and wallet wrappers still need real
remote-only replacements or explicit product retirement; source inspection
does not qualify a native artifact or physical device.

2026-10-09 shared Core graph convergence: Core commit `735a11f` was pushed
to PR #355 after its local 154/154 wallet-feature library tests, strict
Clippy and formatting checks. Its new exact-head hosted CI is running;
the previous `cd21cad` head was green but is superseded. Verifier commit
`7cd9a54` repins six Core manifest entries and seven lockfile sources to
`735a11f`, passed `marty-sync` library tests (35 passed, one existing
ignored), and was pushed to PR #154 for exact-head checks. The Verifier's
unrelated generated schema changes remain untouched. Local UI commit
`c14deeed5` repins all eight native Core crates and the production graph
guard to `735a11f`; full locked Cargo metadata passed the KMS-only graph
checker. It remains local in the broad UI PR #1192 batch, which is still
published at green head `6cc8159a5`. Authenticator local commit `0966587`
repins its seven Core entries and Verifier to `735a11f`/`7cd9a54`, with only
manifest and lockfile changes. Locked no-deps metadata passed. The first
Windows Rust check failed while building vendored OpenSSL under the long
worktree target path, before bridge compilation. With the previously used
short target `C:\marty-kms-auth-target` and `USE_ZK_MOCK=1`, locked library
check and strict Clippy both passed. This is source-graph evidence under
the mock ZK build, not real-ZK or device qualification. No new published
downstream head or release artifact is qualified by these local checks.

2026-10-09 exact-head Verifier qualification: PR #154 at `7cd9a54`
completed its hosted checks successfully, including Rust tests, Clippy,
frontend checks, security audit, and CI Gate. Core PR #355 at `735a11f`
still has running checks with no failure reported at this checkpoint.
The local UI service check first stopped before compilation because the
host's default Rust 1.93 is below this workspace's Rust 1.95 minimum;
the explicit Rust 1.97.1 locked check of Gateway, Auth and Device
Registration passed. This toolchain mismatch is not a source regression;
the check does not replace full hosted CI or the real KMS release probes.

2026-10-09 UI local grouped-graph validation: with Rust 1.97.1 and the
new `735a11f` Core pin, strict all-target Clippy passed for Gateway,
Auth and Device Registration. Their locked library suites passed:
Gateway 159 passed/one existing ignored, Auth 3 passed, and Device
Registration 9 passed. Core PR #355 still has Fast Rust Preflight pending
at this checkpoint; its other reported checks have no failure. Do not
publish or qualify the broader local UI batch based on these three
library suites alone; native image, database, wallet and exact-head hosted
checks remain required.

2026-10-09 grouped publication and integration review: the 44-commit UI
batch was pushed to draft PR #1192 at `1fe2d3b9e`; Authenticator's
13-commit remote-only wallet batch was pushed to draft PR #57 at `0966587`.
Verifier PR #154 at `7cd9a54` and Core PR #355 at `735a11f` now have
green exact-head hosted CI gates; Core still requires protected-branch
review. UI's published head reported a merge conflict and no checks after
six new main commits. Local merge commit `624affb5a` resolves only two
Canvas preflight conflicts by retaining both main's serialized historical
worker probes and this branch's scoped OpenBao signer probe. `bash -n`,
diff hygiene and both focused full-mode preflight tests passed; the full
preflight test file is still running at this checkpoint. Do not count
the conflicted `1fe2d3b9e` head as qualified. Authenticator's first
Flutter quality job failed at `dart format` on three pairing files;
local commit `423674a` applies the same Flutter 3.44.6 formatter. The
full Dart format check is clean and 17 focused pairing/retirement tests
pass. The Android and generated-binding jobs are still pending; hold
the Authenticator correction for one grouped follow-up push.

2026-10-09 exact-head grouped CI triage: Core PR #355 at `735a11f` and
Verifier PR #154 at `7cd9a54` have green hosted CI gates; Core remains
blocked on protected-branch review. Authenticator PR #57 at `0966587`
passed Android, unsigned iOS configuration, build, and generated-bindings
checks. Its only failed source check was Flutter formatting, corrected and
pushed as `423674a`; that new head requires its own hosted checks.
UI PR #1192 at `bee21fa6c` passed four UI test shards, the MIP browser
gate, public protocol contract, Python lint, security scanning, and crawler
build artifacts. Its standalone Rust feature-probe lock retained old Core
`7c50d31`, causing both the probe and Rust lint/packaging jobs to fail at
locked `cargo fetch`. The local correction pins the six probe Core sources
to `735a11f`, and extends the production graph guard plus a regression test
to enforce the standalone lock. Locked probe fetch, boundary tests (10/10),
and the full locked workspace metadata boundary check pass locally. Multiple
independent UI image/test/supply-chain jobs failed while Docker Hub returned
unauthenticated HTTP 429 pull-limit responses; this is an external hosted
registry failure, not evidence of real KMS qualification. The reusable
workflow-quality job also failed while preparing its runtime image, with
image pull exit status 1. Release contract and Rust CodeQL jobs remain in
progress at this checkpoint. Keep the UI correction local until the remaining
checks are triaged, then publish it in one batch; do not mark PR #1192 or the
goal qualified on partial checks.

2026-10-09 full Canvas preflight regression result: the local merged-head
`tests/test_canvas_published_preflight.py` suite completed with 226 passed,
one skipped in 11m38s. This covers the combined historical serial workers
and scoped OpenBao signer probe after the merge conflict resolution; it does
not replace the pending hosted Canvas/image or live KMS acceptance gates.

2026-10-09 UI release-contract triage: the first hosted grouped head ran
6,141 release tests successfully, with four failures. Three were stale
assertions in existing cutover/classifier tests: Device Registration now has
12 contract routes after remote-holder pairing/signing/renewal, Gateway now
has 451 routes after the seven wallet proxy routes, and the CI classifier
returns the new `openbao` output. The corrected expectations passed their
three focused tests locally. The fourth failure was the independent live
registry-index check: Docker could not inspect the pinned Postgres digest,
matching the other Docker Hub pull-limit errors. Keep that availability gate
intact and rerun it when the registry is available. These corrections are
local and need exact-head hosted requalification after the current CI run.

2026-10-09 UI correction publication: grouped commit `c732eae85` was pushed
to PR #1192 after all prior source-bearing checks completed; its new hosted
run is in progress. The standalone Rust feature regression probe now passes
at this head. Image, service-test, supply-chain, Nginx and reusable workflow
quality jobs still fail before KMS execution while Docker Hub returns the
unauthenticated pull limit; these cannot be counted as acceptance evidence.

2026-10-09 live holder lifecycle audit: a dedicated ignored integration test
for registration, scoped remote OpenBao key provisioning, public-key and
signature proof, credential rotation, deactivation and KMS key deletion was
present but not invoked by the contracts CI lane. On isolated disposable
OpenBao and fresh PostgreSQL containers it passed end to end with a scoped
Transit token. A first run without global `BAO_TOKEN` exposed that the
managed-key missing check used a global token for its collection lookup even
when the operation carried an explicit scoped token. The local fix reuses
the operation's token for that lookup, retaining the public environment-token
inventory API; a focused regression test and strict Signing Keys Clippy pass.
The live test passed again against a third fresh database after this change.
A local CI addition runs the test in the existing contracts lane with a
dedicated fresh database, root-guard sentinel and scoped token; YAML and
shell syntax pass locally. This new gate is not yet hosted or released.

2026-10-09 Authenticator quality correction: formatting commit `423674a`
was pushed to PR #57 and the new head passed its format step, Android/iOS
configuration and build checks. Full hosted Flutter analysis then reported
four missing braces in the new remote wallet code. Local commit `e773596`
adds them; after localization generation, full `flutter analyze --no-pub`
reported no issues, and repository-wide Dart formatting reported no changes.
That correction remains local until the current generated-binding check
finishes, so the published head is not yet quality-green.

2026-10-09 exact-head UI recheck and registry feasibility: PR #1192 at
`c732eae85` passed the Rust feature regression probe and Rust lint/packaging
after the standalone Core lock correction. Release contracts now report
6,145 passed and one failure: the live pinned Postgres registry-index fetch;
all three stale source assertions are fixed. The container-backed jobs and
reusable quality workflow still fail at Docker Hub pulls. Docker's published
limit is 100 unauthenticated pulls per IPv4/IPv6 subnet in a six-hour window
(https://docs.docker.com/docker-hub/usage/pulls/). Read-only `buildx`
inspection confirmed that Public ECR's official-image mirror serves the same
reviewed digest for the pinned Postgres, Redis, Rust, Debian, Go and Nginx
images, but a registry switch would also touch shared quality workflow and
release image policy; no image provenance or CI requirement was weakened.
Wait for registry availability or implement a fully reviewed mirror change
across all affected owners before claiming the hosted artifact gates.
After the scoped-token correction, the complete Signing Keys library suite
passed locally (140 passed, eight intentional live-test ignores); the live
holder lifecycle was run separately against disposable services.

2026-10-09 Credentials graph convergence candidate: draft PR #313 remained
green at `6269324` but still pinned Core `7c50d31`; its body mentioned an
older revision. The local Credentials branch now pins its five direct Core
crates, six lockfile packages, Python-wheel CI source, and graph guard to
reviewed Core `735a11f`. Locked metadata passed the KMS-only graph guard,
and the local `marty-rs` library check, warnings-denied Clippy, and 25/25
library tests passed. This is not yet a pushed exact-head CI or wheel/browser
artifact qualification; keep #313 draft until the native graph and release
gates converge.

2026-10-09 Credentials publication: `f3ea65e` was pushed to draft PR #313,
and its description now names the actual `735a11f` Core pin. The new hosted
CI is running; do not treat the earlier green `6269324` head as qualifying
the repinned release graph.

2026-10-09 Authenticator exact-head quality review: PR #57 at `e773596`
passes Dart formatting, full Flutter analysis, and its 168 Flutter tests
(four skipped), but the existing 90% line-coverage gate reports 57.24%
(976/1,705 non-generated lines). The exact hosted LCOV artifact attributes
most misses to imported legacy Spruce platform wrappers: 316/343 lines
missed in the extended wrapper and 202/203 in the base wrapper; the new
remote-holder pairing service itself has 293/305 lines hit. Wallet credential
storage, web wrapper and liveness view account for further misses. Do not
weaken or exclude the gate solely to make CI green. Audit and retire old
local-key wrappers or add behavioral coverage for still-supported methods,
then rerun the exact-head gate. Physical-device and native wallet proof are
still required beyond Flutter test coverage.

2026-10-09 base mobile local-signing retirement candidate: local Authenticator
commit `8fee8c3` replaces eight legacy Dart-to-native signing/key-generation
paths (DID creation, VC signing, PKI generation/CSR/certificate signing,
JWT/SD-JWT issuance and mDoc response signing) with one fail-closed remote
KMS requirement. Android/iOS handlers already rejected these old channels;
this removes the Dart invocation route before native dispatch. A focused
negative test invokes each without private-key fixtures and passed 6/6,
full Flutter analysis found no issues, and the complete Flutter suite passed
169 tests with four skips. Local non-generated line coverage rose only to
60.42% (997/1,650), still below the protected 90% gate. Do not publish a
coverage workaround or claim the mobile PR ready; the remaining active
legacy wrapper and wallet-storage surfaces need retirement/replacement or
behavioral qualification without losing the verified remote wallet flows.

2026-10-09 verified wallet card-source retirement: local Authenticator commit
`a203fbe` removes the card provider's legacy Spruce native/web credential
source. The native handlers already reject that source, while the web wrapper
had accepted arbitrary unverified maps in memory. Both base and web platform
storage interfaces now reject writes, reads and deletes before dispatch; the
card list reads only receipts written by the Rust-verified OID4VCI completion
path. Deletion targets the credential ID and updates persistent receipt
storage before removing the UI card, so two cards with the same title no
longer disappear together. The focused same-title and fail-closed tests pass
(8/8); full Flutter analysis reports no issues, and full tests pass 171 with
four skips. Local non-generated coverage is 61.66% (1,113/1,805), still below
the protected 90% gate. This commit and the earlier `8fee8c3` remain local in
the grouped Authenticator PR #57 batch; do not push only to collect another
failing hosted coverage run. The active wallet credential store and other
supported UI paths still need behavioral coverage and native-device review.

2026-10-09 unsupported mobile channel retirement: local Authenticator commit
`9408df6` removes the extended Dart service's remaining platform dispatches
for mDoc presentation/session setup, SD-JWT presentation verification, and
wallet backup, restore, sync, import and export. Android's registered handler
does not implement these advanced methods; iOS rejects or leaves them
unimplemented. The OID4VP router now rejects the unsupported mDoc branch
before channel dispatch, and the verified Rust-backed SD-JWT path retains its
single-use session set and completion flow. Negative boundary tests pass
8/8, full Flutter analysis reports no issues, and the full suite passes
172 with four skips. Local non-generated coverage rises to 65.95%
(1,129/1,712), still short of the protected 90% gate; this is not mobile
artifact or physical-device qualification. The three Authenticator local
commits since published PR #57 head remain grouped and unpushed. Core PR
#355 and Verifier PR #154 retain green exact-head CI; Credentials draft PR
#313 at `f3ea65e` now has all exact-head hosted checks green, including the
local Python binding and WASM jobs. UI PR #1192 at `7f8ae9b9d` still has
container-backed/registry failures and its aggregate CI Gate is red; do not
count that head as qualified. Continue with behavioral tests and native
release/device verification before publishing or merging the mobile batch.

2026-10-09 assembled disposable schema gate: local UI commit `a1ba39ba2`
adds a read-only private-key catalog check to the protected passport Rust
producer after the fully assembled stack starts and again after its
representative route and durable Flow writes. It uses the existing shared
`PRIVATE_KEY_SCHEMA_QUERY`, targets only the producer's ownership-verified
disposable PostgreSQL container ID, and fails closed without returning row
values. The focused producer suite passes 13/13, Ruff and diff checks pass.
Against a new disposable PostgreSQL 16 container the gate accepted a clean
database, then rejected an injected `public.issuer_signing_keys` table with
`encrypted_jwk_json`; the container was removed. This is executable
acceptance wiring and a local SQL proof, not a signed-image result. The
protected producer still needs an exact released-image run and a final
assembled table/column inventory with JSON runtime-write review before K10
can close. The commit remains local in the grouped UI PR #1192 batch.

2026-10-09 exact-head UI hosted result: CI run `37994913688` for published
PR #1192 head `7f8ae9b9d` is terminal. Release Contract Tests passed 6,145
tests (two skipped, 363 subtests) and failed only
`test_reviewed_registry_indexes_are_available_now`: `docker buildx
imagetools inspect` could not fetch the pinned Postgres digest from Docker
Hub. Rust feature regression, Rust lint/packaging, public protocol, UI and
service tests, browser gate, Python lint, security and CodeQL passed at this
head. The container-backed Rust service tests, plugin image, Nginx, service
images and supply-chain action failed during image initialization/build; the
CI Gate consequently failed. The Organization Quality reusable workflow also
failed while preparing its image. These are not KMS acceptance results. The
reviewed Docker Hub digest and live registry-index requirement remain intact;
the next grouped UI push should run after registry availability recovers or
after a separately reviewed, provenance-preserving mirror change. Local
schema-gate/tracker commits after this head have not had hosted CI.

2026-10-09 mobile wallet orchestration qualification: local Authenticator
commit `ea7a152` introduces a typed, production-default Rust bridge port so
Dart receipt and presentation coordination can be tested without duplicating
cryptography or generating local private keys. Behavioral tests prove that a
Rust-rejected receipt is not stored, a completed Rust receipt reaches the
wallet, unsupported mDoc routing never parses/presents, and explicit
credential/disclosure approval is exact and single-use before remote signing.
The fake bridge exercises Dart orchestration only; it is not a KMS custody or
cryptographic acceptance proof. Full Flutter analysis is clean and the suite
passes 176 tests with four skips. Local non-generated coverage is 73.11%
(1,264/1,729), up from 65.95%, but remains below the protected 90% gate.
The commit remains local for a grouped Authenticator PR #57 push. Self-review
found the wallet card-state preference persistence still serializes Flutter
objects and addresses cards by title in one toggle path; repair and test it
before claiming wallet feature preservation or publishing the mobile batch.

2026-10-09 wallet preference self-review correction: local Authenticator
commit `b3f7c76` saves only versioned issuer ordering, verified receipt IDs,
and expired IDs in secure storage. Reload reconciles those preferences with
current receipts, so newly received credentials appear without restoring
stale credential copies. Reorder, expired selection, and deletion use receipt
identity; cards with the same title no longer share hide/unhide actions or
selection. The focused reload test proves issuer/card order, one-card expiry,
new receipt inclusion, and cross-issuer move rejection. Full Flutter analysis
has no issues; 177 tests pass with four skips. Non-generated line coverage is
77.04% (1,366/1,773), still below the protected 90% gate. This Authenticator
commit remains local and unpushed for the broad PR #57 batch; mobile-device
review and remote-KMS end-to-end acceptance remain open.

2026-10-09 presentation-definition coverage addition: local Authenticator
commit `70f0888` exercises the supported Presentation Exchange definition path
through credential selection, approved disclosure, and the remote-signing
bridge. It also proves filtered fields, duplicate claim requests, and
unsupported paths fail before signing. These are Dart orchestration tests
with a fake bridge, not cryptographic custody acceptance. Flutter analysis is
clean and the full suite passes 179 tests with four skips. Non-generated line
coverage is 79.30% (1,406/1,773), still below the protected 90% gate; the
commit remains local in the grouped Authenticator PR #57 batch.

2026-10-09 wallet receipt durability and UI deletion correction: local
Authenticator commit `537c547` removes the separate secure-storage receipt
index and writes one independently enumerable entry per verified wallet
receipt. Concurrent saves can no longer overwrite a shared ID index; reads
reject an entry whose embedded ID differs from its storage key, and clear
leaves unrelated secure-storage data intact. The expired-pass UI awaits
deletion, keeps its selection and reports a failure if the receipt delete
fails; a widget test confirms deleting one of two same-title expired passes
preserves the other. A storage read error now preserves already displayed
cards instead of replacing the wallet view with an empty list. Full Flutter
analysis passed and 183 tests passed with four skips. Instrumenting the new
widget test added previously unmeasured view code to LCOV, so the current
non-generated coverage ratio is 75.91% (1,494/1,968), still below the 90%
protected gate; this is not a source-coverage regression conclusion. The
source commit remains local for the broad PR #57 batch. Real platform secure
storage and device behavior remain to be qualified.

2026-10-09 grouped UI CI recovery reconciliation: the preserved
`codex/a6-dockerhub-mirror-20261009` branch's digest-preserving Docker Hub
cache work was cherry-picked into this KMS integration branch as commits
`984fdb5c4` through `5e5171e64`, with current KMS workflow conflicts
resolved in `1f6218f8a`. The retired beta fence test/job stayed removed;
the current Rust service job retains real Organization, Credential Template,
and Issuance migrations plus the fresh private-key schema verifier, now using
fixture container IDs started after mirror setup. The release-contract
allowlist still requires exact reviewed OCI digests and linux/amd64 indexes;
its live registry-index test passed locally through the mirror/canonical
selection. CI fallback policy tests passed (10; 17 POSIX-only skips), the
non-registry infrastructure policy tests passed (10), workflow-performance
tests passed (142), candidate-workflow tests passed (15), and the impacted
Canvas shell scenario passed (2). Ruff, Python compilation, Bash syntax and
diff checks passed. This is local CI wiring evidence, not an exact-head
hosted run or released-image K10 proof.

2026-10-09 grouped UI publication: the 18-commit local batch after
`7f8ae9b9d` was pushed to draft PR #1192 at exact head `8ee6790ba4eaa472892c2031874b6d50f3438b7d`.
Its new hosted CI run `37999429439` and Organization Quality run
`37999430821` were queued at observation; CodeQL and policy runs were also
queued. No hosted result is claimed yet. The prior failed run
`37994913688` remains immutable evidence and is not overwritten by this
push. The untracked `rust/crates/canvas-acceptance/%SystemDrive%/` path was
neither staged nor modified.

2026-10-09 K10 JSON storage self-review: after the published `8ee6790ba`
batch, the local branch adds a PostgreSQL catalog-driven scan of every
non-system JSON/JSONB table column to both the exact-image self-host
migration qualifier and the protected passport producer's pre/post runtime
write guard. It rejects named private-key fields and nested JWK objects that
contain both `kty` and private `d`, reporting only schema/table/column. A
disposable pinned PostgreSQL 15 probe accepted public JSON and rejected both
a nested private-JWK shape and a named private-key field; no key material was
generated. Focused tests passed (21, with one Windows `bash -n` stdin case
excluded because PowerShell supplies UTF-16), and Ruff passed. This new
guard was also exercised through the protected producer's actual PostgreSQL
command against a second disposable PostgreSQL 15 database: public JSON was
accepted and a named forbidden field caused a producer failure. Both owned
containers were removed after the probes. The source guard is local and has
not been published or run against a full
assembled product database. The exact-head UI CI run `37999429439` remains
in progress; at observation all completed jobs, including Nginx integration,
UI shards, service tests, security scanning and Rust supply chain, were green.
Organization Quality run `37999430821`, Open-source policy run
`37999429420`, and CodeQL Actions run `37999429505` have since completed
successfully at the same published head; CodeQL Rust and the main CI run
remain in progress.

2026-10-09 four-hour checkpoint and CI review: the published UI exact-head
run `37999429439` reached the Rust contract and release-contract jobs. Those
jobs failed on two stale inventories: the release-contract Python test
expected the pre-mirror GitHub Redis service ID, and the trust-profile crate
maintained a second HTTP-operation list that omitted the new wallet issuer-key
route already present in the canonical service surface and shared contract.
The local UI branch now uses the selected Redis fixture ID in the assertion
and removes the duplicate Rust list so the domain test reads the canonical
surface. The focused Python assertion passed locally, as did all six Rust
tests in the affected trust-profile domain and surface suites. The full
227-test Python file was stopped after its early checks ran slowly; the exact
changed assertion had already passed. These corrections, along with the JSON
storage guard, remain local for one grouped
UI PR #1192 push. The earlier hosted failures remain immutable evidence.

2026-10-09 mobile issuer-trust self-review: local Authenticator commit
`92b6dd0` recursively rejects private or secret fields hidden inside the
public JWK snapshot, including nested objects and lists. Full Flutter
analysis is clean; 183 tests pass with four skips. Current non-generated
coverage is 75.90% (1,493/1,967), below the protected 90% gate. This and
the preceding mobile wallet commits remain local for one grouped PR #57
update; live device, KMS custody, and end-to-end acceptance are still open.

2026-10-09 Canvas LTI public-metadata boundary review: the Core LTI probe
checked that a remote JWKS had keys but did not reject private JWK members;
the native Issuance service could then persist that external JWKS and the raw
OpenID configuration in JSON columns. Local UI changes now apply the shared
Rust key-material policy to both values in the common metadata probe before
all management and refresh persistence paths. A focused negative/positive
probe test passed, as did all three affected module tests. Local Core commit
`f8a8dc0` also rejects private material in discovered JWKS/configuration and
in direct LTI JWT verification input, with a redacted error; its `lti::tests` passed
10 with two disposable-OpenBao tests ignored, and warnings-denied library
Clippy passed. These changes are unpushed.
After the Core batch is published, repin all production consumers and replace
the temporary UI policy call with the Core canonical boundary to avoid
duplicating the same rule across repositories. The older database JSON guard
remains a defense and acceptance check, not the only runtime barrier.

2026-10-09 exact-head CI observation after local metadata guard: published UI
run `37999429439` is still live at `8ee6790ba`; Rust Service Images completed
successfully, as did separate CodeQL Rust run `37999429628`. Canvas Rust tests
and the OpenBao DIDComm plugin image job remain in progress. The release and
Rust contract job failures remain the two previously diagnosed stale checks;
their correction is local in `89cf4bdd0`. Local Core `f8a8dc0` and UI
`0acb63f5d` metadata guards have not had hosted checks or artifact proof.
UI Issuance warnings-denied library Clippy and all three affected probe tests
passed locally.

2026-10-09 Core/consumer pin convergence: Core PR #355 was updated to exact
head `bd6e4cc9a7e86d11aec53194899e074289f7b681`, including a direct LTI
verification regression test; its new hosted checks are running and its PR
description now reflects the current implementation. Verifier PR #154 was
updated once to `181763848cbab28d8d968cde903df84565fddb5b`, pinning that
Core head; all 35 local `marty-sync` library tests passed (one existing
ignored), its hosted checks are running, and its PR description was updated.
Generated Tauri schema edits in that local worktree were excluded. The UI
production and standalone feature-probe locks now resolve only Core
`bd6e4cc`; the exact graph guards and three affected Canvas LTI probe tests
passed locally. Credentials locally repins its manifest, CI wheel source,
lockfile and graph guard to the same head; the actual metadata graph check
passed, while its cold library build remains in progress. Authenticator now
pins Core `bd6e4cc` and Verifier `1817638`; the lockfile has exactly one Core
revision after the Verifier repin. Its Windows Rust library test did not reach
assertions because the bundled Longfellow C++ build failed in `marty-zkp`;
capture the compiler cause or use the required hosted platform build before
claiming this new graph qualified. UI, Credentials and Authenticator repins
remain local for grouped updates, and earlier green hosted heads do not
qualify them.

2026-10-09 Credentials and mobile graph checkpoint: Credentials draft PR
#313 is now published at `6097d55626964f4871cd5f07cff87cabe034280a`.
Its exact Core `bd6e4cc` metadata guard, 25/25 `marty-rs` library tests, and
warnings-denied library Clippy passed locally; its PR description reflects
the new pin, and hosted checks are newly running. Authenticator local commit
`b799533` pins Core `bd6e4cc` and Verifier `1817638`; locked Cargo metadata
and the lock inventory show ten Core packages at exactly one revision. The
attempted Windows Rust library test was stopped after the bundled Longfellow
C++ compiler failed, before any Rust assertions; this is not a passing
mobile-native test. PR #57 remains at published `e773596` with the 90%
coverage gate still open. The UI old-head CI run `37999429439` remains live
only in Canvas image build; its OpenBao plugin image and Rust Service Images
jobs have passed, and its two completed stale-contract failures are fixed
locally for the next grouped UI push.

2026-10-09 hosted-head and mobile coverage checkpoint: Core PR #355 at
`bd6e4cc9a7e86d11aec53194899e074289f7b681` has 22 successful and eight
skipped hosted checks; it is mergeable but requires protected review. Verifier
PR #154 at `181763848cbab28d8d968cde903df84565fddb5b` has 17 successful
and one skipped hosted checks. Credentials draft PR #313 at `6097d55` has 16
successful and one skipped check, with two binding jobs pending and no failures.
The full local Authenticator Flutter suite passed 183 tests with four skips;
new same-title receipt detail-action tests at local commit `9b85c77` passed
and analysis found no issues. Non-generated coverage increased from 75.90%
(1,493/1,967) to 78.44% (1,543/1,967), still below the protected 90% gate.
These mobile changes remain local. UI run `37999429439` is still live in its
Canvas database contract suites; do not cancel it with the grouped push yet.

Credentials PR #313 subsequently completed its two binding jobs and all
exact-head hosted checks: 19 success, one skipped, zero failures at `6097d55`.
The independent Windows Authenticator Rust test retry exposed a vendored
OpenSSL MSVC `C1083` compiler-output failure under the long OneDrive target
path, before Rust tests ran. A retry using `C:\mka` as a short junction to
the same target cache is running; do not treat either attempt as a Rust pass.
