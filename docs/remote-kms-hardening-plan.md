# Remote KMS hardening implementation and landing plan

Status: active qualification requirements. Updated: 2026-10-16 (America/Denver).

Owner: Codex working with the repository maintainer. This file is the canonical
cross-repository requirements and qualification tracker. Keep current decisions
and unresolved gates here; retain per-run output in ignored local directories
or CI artifacts. Completed checkpoint history belongs in Git. A merged library change alone does not complete
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
| K1 | Reconcile preserved branches; map every supported production binary, image, wheel, Cargo root and release pin; enumerate current signing/encryption paths and explicit secret-class exceptions. | Keep production-root and release-pin inventory current; qualify actual shipping graphs. |
| K2 | Prove backend support for non-exportable DIDComm sender agreement/authcrypt with actual recipient decryption; select the smallest shared Rust boundary and record supported provider scope. | Plugin-backed holder decryption and Raft proofs exist; published-image and supported-provider qualification remain required. Standard Transit alone does not provide X25519. |
| K3 | Implement DIDComm scoped/versioned references and remote operations; bind tenant, sender DID/key, recipient documents and frozen attempt inputs; preserve rotation, expiry, retries, replay, cancellation and unknown-outcome semantics. | Native scoped/versioned authcrypt is implemented; qualify retry/recovery and remote-only delivery in the exact released deployment. |
| K4 | Implement opaque integration-secret custody with remote-only startup and new writes; reject old AES-GCM envelopes and raw master-key configuration; prove tenant/purpose isolation, tamper rejection, restart, rotation, recovery and atomic repository behavior. | Remote envelope and restore implementations exist; qualify packaged startup, writes, rotation and recovery. |
| K5 | Adopt hardened Core across Rust services and fork pins; replace removed APIs and broad features; isolate fixtures and qualification binaries; eliminate compatibility crypto from production graphs. | Core #355, UI #1192 and Credentials #313 are merged; qualify exact signed consumer images. |
| K6 | Establish actual supported BYOK route/schema and tenant/certificate binding; integrate reference-only UX and server rejection of private material, preserving existing onboarding behavior. | Reference-only BYOK and scoped grants are implemented; real-provider, installed-image and device acceptance remain required. |
| K7 | Retire Credentials raw-key adapters, obsolete wheels and local private-key tests; prove native owner selection and published artifact behavior without old-data reads. | Credentials retirement landed in #313; inspect published native artifacts and qualify the installed cross-format journey. |
| K8 | Add production-root feature, forbidden-API, binding and artifact checks; exercise real remote operations and negative paths; complete all three self-review passes. | Source and CI checks exist; signed artifacts, real cloud providers and physical-device acceptance remain required. |
| K9 | Land grouped feature PRs through required checks; qualify exact release artifacts, clean KMS-only cutover and recovery; update durable evidence and close the goal only after acceptance below. | Consumer changes are merged. Use the current stack lock and protected release workflow; signed-digest, installation and cutover/recovery acceptance remain required. |
| K10 | Remove every private-key database table and secret-bearing key column from clean-install DDL, ORM metadata, initialization and tests. Add no migration scripts; prove the fresh database schema and runtime writes contain only public keys or scoped remote references where key metadata is needed. | Clean-schema probes exist; qualify signed images and representative runtime writes on a fresh installed stack. |

### Next qualification steps

1. Resolve the release coordinate and eligibility from the current
   [stack lock](../release/stack-lock.json), not a historical handoff command.
2. Require protected exact-head and full qualification gates before claiming
   four image digests; inspect signed artifacts after the release review.
3. Exercise the installed KMS-only journey across supported credential formats:
   issuance, tenant-scoped retrieval, presentation, verification, status and trust.
4. Complete real-provider/device acceptance and supported cutover/rollback.

### Grant invariants

Signing grants use origin-specific non-exportable HMAC keys, scoped mint/verify
policies and bounded, one-use Redis replay protection. Bind tenant, route,
operation, key, purpose, algorithm and exact payload before remote KMS use.
Do not substitute source-only or local-fixture success for installed acceptance.

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

## Current source status and evidence retention

The protected KMS consumer changes landed as UI #1192
(`62607e860e3fe57abef39e29dfb59ae1c8bbd2a8`) and Credentials #313
(`7ac622015a220992fbae84177a1518fec7b75849`). Core v0.2.2 is the
shared dependency. The source stack lock currently selects `marty-ui@1.1.258`
with `release_state: eligible`. The signed v1.1.250 bundle failed installed
startup and must not be used for cutover. Eligibility does not establish
signed-image, installation, provider/device or cutover acceptance. The earlier
v1.1.244/245 candidate handoff history is superseded; use the current lock and
release gates.

The dated implementation log and 14 local KMS probe receipts were retired from
the working tree. Their original contents remain recoverable at Git commit
`0ff6000f24e59feb3b5fea0fae0cb156ab545aaf`. New probe receipts belong in ignored
`artifacts/` or uploaded CI artifacts. Keep current test sources, supported
runbooks and unresolved acceptance requirements in the repository.

2026-10-17 v1.1.252 installed-qualification repair candidate: the signed release and prepared bundle passed publication and source-bound staging, but fresh 16 GiB workstation qualification remains unpassed. The exact installed runner rejected a 28-service closure because the Canvas worker explicitly disables its healthcheck; a diagnostic runner overlay passed closure and then found the audit helper still required a UUID DID suffix instead of the configured organization slug. The fixture's first public PKCE request returned 503 through the healthy gateway even though Auth returned 302 directly: the production `ReqwestUpstream::new` followed Auth's browser redirect toward `https://localhost` inside the gateway container. This v1.1.253 source-lock candidate groups the slug-bound scoped audit policy, disabled-healthcheck interpretation and Rust proxy redirect preservation with regression tests. The diagnostic overlays and reused-state HTTP probes are unqualified evidence only. A clean v1.1.253 release and fresh Raft-backed installed journey must pass before cutover.

2026-10-17 local-first v1.1.254 candidate: [integration PR #443](https://github.com/ElevenID/marty-integration-tests/pull/443) merged at protected main `5b3ec6a802a5e13201be8883741889405a86d146`. Its signed [v1.2.90 source release](https://github.com/ElevenID/marty-integration-tests/releases/tag/v1.2.90) passed its release workflow; the downloaded source archive, checksum and GitHub attestation agree on SHA256 `2dddf814b58d0214c41407c92eca331e54ff85ee30990c224fb3a82dccec589c`. [MMF PR #133](https://github.com/ElevenID/marty-microservices-framework/pull/133) merged through its protected queue at `c7181c86949fdb0fb415e52cee364c19615bcfc6`; its PR and merge-group suites passed. Review found that error normalization still dropped cookie-expiry fields; the same MMF PR fixed and tested that path before merge. The local UI candidate now pins these exact upstream sources, preserves multiple auth cookies, uses bootstrap-matched managed references for the fixture, audit policy and evidence verifier, supplies Presentation Policy's issuance API key file, and advances the release lock to v1.1.254. A small shared key-reference module avoids pulling the fixture's HTTP dependency into the audit-token helper. Local exact-dependency checks passed 167 Rust gateway library tests, Cargo check and fmt, and 163 relevant Python tests. The previously reused diagnostic stack completed the public issue/present/verify/revoke journey and live Raft custody checks, but it is not fresh signed installed qualification. The UI PR, full protected CI, signed v1.1.254 publication, fresh installed acceptance, cloud provider tests and physical wallet test remain pending. No production cutover is authorized by this evidence.
