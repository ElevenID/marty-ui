# Agent trust runtime milestone checkpoint

This integration advances the application work after Marty Protocol PR #38.
It reconciles the existing delegated-authority draft in Marty PR #1994 with
main at `f662bb326bd0a83eb8191dc002bc3db57ec08cc3`, including the accepted
Core JWT 11 dependency alignment. It preserves that existing lifecycle service
and Flow admission implementation. The application now includes candidate agent directory administration,
exact-terms organization approval, managed key-control enrollment and an opt-in
human lifecycle command host. Retained delegated use now includes authenticated
internal command transport, selected full-machine and nested JWT-VC verification,
durable machine-audit retention, concurrency-safe Flow finalization and managed
receipt signing qualified against disposable OpenBao/Redis. The next source-owner
slice adds explicit full-machine/MAP registration, concrete Trust Profile and
Issuance credential observations, and a named Organization machine-policy owner
with retained MMF evaluation. The current serving-path slice adds explicit
machine-use rights, a current exact-operation delegated-use policy owner,
certificate-authenticated transport and protected original request/proof ingress.
The explicit default-off serving executable now assembles these owners with
fourteen restricted database connections and readiness before mandatory mTLS
listen. Public delegated execution and production deployment remain gated.
The next consumer slice adds protected recovery of the exact original signed
receipt and a standalone verifier with separate fresh and historical evidence
types. Actual-executable startup/readiness qualification now has a disposable
OpenBao/Redis harness with explicit metadata wire fixtures.
The separate managed lifecycle gate replaces selected template/policy wire
fixtures with actual owner services, issues a fresh managed machine credential,
and joins protected HTTP use, request/receipt signing, recovery and independent
verification. Its privileged bootstrap and readiness-only reference fixtures remain
explicit. The current caller follow-on adds opt-in managed wallet routes and an
independent Rust transport that follows the returned request link and verified
signed response URI. Production deployment and general wallet interoperability
remain separate from this selected local qualification.

## Implemented in this application slice

| Milestone area | Deliverable | Qualification boundary |
| --- | --- | --- |
| M01 protocol adoption | Independently pinned optional protocol source, manifest and schema checks | Existing public MIP 0.5.0 and support levels remain unchanged |
| M01 runtime reconciliation | Delegation workspace integration and Flow persistence guards alongside current issuance-intent protections | Internal composition; no new public delegated route |
| M01 upgrade operations | Read-only database preflight, role separation checks and evidence-preserving upgrade/rollback procedure | No automatic reconstruction of missing historical evidence |
| M02 principal binding foundation | Strict Rust principal/runtime/key/session consistency checks, typed fingerprints and opaque validated output | Operational proof authentication remains separate; bounded enrollment proof is implemented by the separate purpose-specific adapter below |
| M02 directory and enrollment candidate | Tenant inventory, public-key history, immutable audit, authorized administration, retained signed-challenge enrollment and a local key-custodian signer | Managed entries start PROVISIONED; explicit key-control enrollment permits ACTIVE eligibility, with authority NOT_ASSESSED. Operational MAP, external host trust and suspended-identity resume remain separate |
| M03 approval candidate | Exact immutable terms, explicit human confirmation, durable recovery/withdrawal, independent current Organization authority and an opt-in executable | One configured organization and KEY binding; represented-subject SESSION establishment and broader authority profiles remain separate work |
| P03 application lifecycle commands | Atomic grant/journal/original-result persistence, opt-in human Gateway/host composition, exact producer confirmation and current Organization authorization rechecked after lock waits | Selected human organization/KEY profile only; the human executable and Gateway still reject START_USE and FINALIZE_USE |
| M02 selected machine authentication candidate | Concrete Core OID4VP verification, strict MAP/full-machine consistency, real nested JWT-VC issuer/holder verification, actual MMF machine-policy evaluation and append-only exact audit retention | Concrete source owners are now implemented below; live deployment and required attestation remain unqualified. SERVICE_ACCOUNT inventory and enrollment do not satisfy this gate |
| M02 full-machine source owner | Distinct Organization registry, explicit deployment MAP assignment, attributable human administration, immutable revision/key history, and exact retained source observations | Internal APIs only; no inventory promotion, public registration route, workload authentication or attestation claim |
| M02 credential authority source | Explicit nested JWT-VC Trust Profile authorization, current issuer/key and exact original Issuance artifact/status binding, separate retained source evidence | Concrete PostgreSQL owner composition; no SD-JWT widening, external issuer transport or public host enablement |
| M02 machine-policy source owner | Named Organization MACHINE_AUTHORIZATION policy, fixed context-only Cedar schema, immutable revisions, concrete MMF evaluation and retained source/evaluation linkage | General policy CRUD cannot write this type; domain/use authorization and public proof ingress remain separate |
| P03 retained use candidate | Original command claims, START_USE correlation, FINALIZE_USE PERMIT/DENY receipts, authenticated internal command router and immutable recovery; concrete Flow owner commits nonce/proof/result state on the supplied transaction while preserving bounded retrieval progress | Internal KEY-grant composition selected by the explicit host below; public wallet transport remains separate, and unresolved claims are never automatically retried |
| P03 machine-use access owner | Five independent rights administered against actual full-machine/deployment registration, current RBAC and immutable history; concrete command and ingress authorizer | Component access is separate from transport identity, cryptographic machine proof and Rifare business permission |
| P03 delegated-use policy owner | Dedicated exact-operation Cedar policy lifecycle, fixed schema, retained current observations and real MMF evaluation | Consumer domain attributes and EXTERNAL_PROFILE adapters remain independently owned |
| P03 authenticated request/proof ingress | Mandatory mTLS listener with exact leaf certificate binding; protected Flow request retrieval and immutable proof retention, durable one-sign request claims and original deadline checks through COMMIT | Selected by the explicit host; production CA/pin management and public wallet contracts remain unqualified |
| P03 explicit serving candidate | Default-off `marty-delegated-use` executable, fourteen actual restricted database identities, concrete local-owner and protected-provider assembly, bounded read-only readiness and mandatory mTLS before serving | Selected managed organization / full-machine / KEY / EXACT_OPERATION profile; production network, custody, roles and public consumers remain separate gates |
| Managed decision receipt candidate | Dedicated signing-grant origin, pinned remote key, strict transcript binding, independently verified signatures, OpenBao/Redis router/kernel qualification for Ed25519 and ES256, and selected ES256 HTTPS host lifecycle | Production custody, credentials and deployment remain pending |
| P03 original receipt delivery | Protected read-only recovery of exact FINAL_USE compact JWS bytes, current RECOVER_RESULT access checked around awaited reads, original response/digest/timestamps retained | Internal mTLS host; recovery preserves original evidence under current read access and supplies no renewed grant authority; no additional permission or migration |
| Independent receipt consumer | Standalone ES256/EdDSA verification with independently pinned trust, exact request context, retained original-byte digest and explicit clock/freshness policy | Sealed fresh/history evidence types; no service, database or Core dependency; public client packaging and business execution remain separate |
| P03 managed network lifecycle | Actual executable and mTLS use routes, real template/policy gRPC owners, fresh managed issuance, separate remote request/credential/receipt keys, exact recovery and independent consumption | Internal selected operation with privileged setup, in-process Issuance bootstrap and named readiness-only reference fixtures; no public wallet, production or Rifare execution claim |
| P03 managed public caller | Separately enabled mTLS command/request/direct_post/receipt routes, frozen-query association and independent Rust client with retained command identity and explicit TLS trust | Selected managed MachineCredential / KEY / exact-operation profile; no general wallet, production deployment, capability promotion or Rifare business execution claim |

The source pin is Protocol commit
`6126da7619e057be2ff58dd38a5d50f49891d1b3`, with source-pack manifest digest
`3d9fc9475050d80ea2e0a835a3c8cf801a642303a063fa4d3014485ceb6b8d37`.
The source checker does not execute upstream code. Its schema checks are
separate from semantic corpus tests and from production runtime qualification.

## Responsibility boundary

Marty owns identity and authority checks, immutable grants, trust evidence,
challenge/receipt state and recovery of its own committed outcomes. A recovered
grant snapshot is historical evidence; it does not restore expired or revoked
authority and does not authorize another business operation.

Rifare continues to own logical agent definitions, prompts and models, task and
runtime orchestration, domain/resource permissions, business state, budgets,
reservations, provider execution and business outcomes. No Rifare integration
should import private Marty Core code or read Marty storage. Public consumers
must use the selected Gateway contracts. The new administration candidates do
not authorize Rifare business execution; that integration still depends on the
qualified delegated-use contracts.

## Remaining application exit gates

The broader milestones are not closed by these libraries and candidate
administration paths. The next application packages still need:

- Deployment qualification of the implemented machine proof/MAP/Cedar and
  audited credential gates. Concrete full-machine/MAP, Trust Profile/issuer/key,
  Issuance status and machine-policy source owners now exist, with their own
  retained evidence and restricted connection checks. Required attestation,
  production service connections and production role qualification remain.
  Connection/grant aggregation and independent directory qualification remain
  separate. Enrollment key possession does not satisfy these operational checks.
- Broader approval/authority profiles and qualified represented-subject session
  establishment beyond the implemented human/organization KEY profile.
- Deployment qualification of the implemented default-off executable, its
  fourteen restricted connections, protected provider origins, mutual-TLS
  identity mapping and concrete current access/policy sources. Qualify production
  CA issuance/revocation and pin rotation. The human administration host does not
  accept machine use calls.
- Deployment of retained `START_USE`/`FINALIZE_USE`, the concrete same-database
  Flow owner and managed receipt signer with reviewed serving privileges,
  the implemented authenticated request/proof ingress, deployed signing-provider
  qualification beyond the passing disposable gate, and a separately reviewed
  pending-claim reconciliation design.
  Ordinary Flow finalization remains guarded.
- Production qualification of the optional managed caller host and independent
  Rust client, deployed integration of the independent verifier and explicit
  capability qualification. Human lifecycle commands,
  directory, enrollment and approval hosting are opt-in candidates.
- Rifare adoption of those public features after the corresponding runtime
  gates pass. This checkpoint changes no Rifare business execution behavior.

See [the optional protocol consumer contract](architecture/agent-trust-protocol-consumer.md),
[principal binding integration](principal-runtime-binding.md),
[the directory and approval candidate](agent-identity-and-approval-candidate.md),
[managed enrollment and human command hosting](managed-agent-enrollment-candidate.md),
[the retained delegated-use candidate](delegated-use-runtime-candidate.md),
[the delegation upgrade procedure](delegated-authority-upgrade.md), and
[the delegated-authority service](../rust/services/delegated-authority/README.md)
for the implemented contracts and their limits.

## Prior foundation validation

Validation is local, using Rust 1.95 and PostgreSQL 17.12 against the accepted
Core/JWT 11 dependency graph. Hosted GitHub Actions are not part of this work's
evidence.

| Check | Result |
| --- | --- |
| Protocol source consumer | 82 tests; 355 source files verified, 14 selected/transitive schemas, 26 positive and 26 negative schema fixtures |
| Principal binding consumer | 24 regressions and the opaque-output compile-fail doctest; complete external corpus of six valid and 30 invalid vectors |
| Delegated authority service | 122 service tests with PostgreSQL enabled, including atomic commands, expiry/clock bounds, reconnect recovery and the legacy-writer migration race |
| Database upgrade preflight | 42 live PostgreSQL tests, including role separation, drift, preserved history and the exact migrator checksum format |
| Flow compatibility | 97 selected tests, plus explicit PostgreSQL issuance-prerequisite and public-verification regressions |
| Accepted Core dependency boundary | 42 tests |

The final application tree contains locally authored synthetic examples. Exact
private protocol corpora are exercised only through explicitly configured,
independently verified external checkouts. After that fixture separation, the
new synthetic command digest case and external command corpus gate both passed;
production service code and database migrations were unchanged.

The selected default Flow run reported nine existing fixture-gated ignores.
Two relevant PostgreSQL gates were then executed explicitly and passed. The
remaining TLS/OpenBao, retention and separately fenced-role acceptance gates
remain outside this local integration evidence. Full workspace/UI qualification
and production runtime enablement are separate gates. Scoped formatting, diff
checks and the OSS boundary check passed; optional Clippy was not completed.

## Directory and approval validation

The next slice was validated locally against the same dependency graph. The
approval tests use PostgreSQL 17.12 and separate actual database roles; the
console uses synthetic responses and does not claim live browser qualification.

| Check | Result |
| --- | --- |
| Organization directory persistence | 11 tests, including current-permission revocation during a lock wait, hidden identity changes and eleven trigger/index/function drift cases |
| Organization HTTP administration | 4 tests, including authenticated persistence and current membership revocation |
| Organization permission catalog | 2 tests, including explicit approval exclusion from Access Administrator |
| Full delegated-authority service | 139 passed; the separately configured external private-protocol corpus gate remains explicitly ignored in this run |
| Approval host | All-targets compile and actual `marty-delegation-approval` executable build passed |
| Upgrade preflight | 58 live PostgreSQL tests passed; recognizes migration 0005, preserves historical approval evidence, rejects missing provenance and allows the bounded candidate producer privileges |
| Gateway | 311 library tests plus three executable smoke tests and one certificate contract passed; includes strict returned approval terms, current session/membership and actual HTTP redirect refusal; one Redis fixture gate remains ignored |
| Console, client, routes and navigation | 98 tests across five files; 25 focused new-feature tests cover exact-terms consent, original-result recovery, withdrawal, uncertain directory writes and pre-dispatch public-key validation |
| Application qualification profile | 26 files / 321 assertions passed; includes both new feature test files |
| Portable source and consumer compatibility | 87 source-closure/consumer tests and 14 export/restore tests passed; current 581-file map and historical 575-file map are selected by exact reviewed hashes, preserving the original 24-file/296-assertion package policy |
| Application build | Passed both with default feature selection and with both new console features selected |

Organization migration 0003 and Delegated Authority migration 0005 are new.
Organization 0001–0002 and Delegated Authority 0001–0004 retain their original
bytes and checksums. No protocol release, production rollout or public discovery
enablement is implied by this checkpoint.

## Recovery review and integration corrections

The directory/approval slice was recovered from uncommitted work after
`eef877dae846fbedbfbe57a337b586869ab80d82`. Parallel review completed the
Organization, Gateway and console paths while the approval/preflight boundary
was reviewed independently. The three recovered Gateway failures were incorrect
case-sensitive assertions against HTTP header names; the checks now require one
case-insensitive trusted-header match and continue to reject caller assertions.

The review also corrected actual integration gaps: migration 0005 was missing
from upgrade inspection, the consent role was required to read unrelated
lifecycle results, Organization readiness accepted inadequately defined guards,
Gateway source checks followed redirects, and malformed success responses could
allow a directory write to be resubmitted without inspecting its outcome.
Historical reviews, exact confirmation bindings and authority provenance now
have explicit preflight coverage; failed inspection never repairs evidence.
The portable application export now includes all six new feature/test files and
qualifies both test files. Existing source packages retain their exact historical
contract rather than inheriting the new test roster. This leaves package-manager
selection unchanged from the reviewed baseline; the local application tests and
builds above were run with Bun 1.4.4.

Public MIP remains 0.5.0. Support levels and discovery stay unchanged. Validation
ran locally; hosted Actions, production rollout and independent browser/issuer
qualification are not claimed. The subsequent enrollment/human-command slice is
described below. The later retained-use candidate implements the corresponding
machine gate, START_USE admission, FINALIZE_USE persistence and receipt-signing
boundaries. Their deployment and public consumer qualification remain required
before Rifare uses those paths for business execution.

## Managed enrollment and human command follow-on

The follow-on after `49000ea6725cc4adf03a1482fab2f692e036f960` adds a versioned,
purpose-specific ES256/Ed25519 key-control proof, retained Organization challenge
consumption and original-result inspection, a local Node key-custodian signer,
and the separate `marty-delegation-commands` executable. Gateway hosts both
surfaces only when their own feature switches are selected. No private key is
uploaded and neither surface authorizes a delegated business operation.

The command host uses restricted writer/evidence-reader/Organization-reader
credentials. It checks current actor permission again after command/grant lock
waits and rechecks the original grantor's authority during reinstatement. An
awaited source recheck cannot extend the original authorization or consent
lifetimes. Explicit recovery still needs current view permission and preserves
immutable historical results. Organization enrollment additionally serializes
with its current membership/key/lifecycle rows and uses deferred database guards
to reject expiry after later transaction waits.

Organization migration 0004 is additive; earlier Organization and all Delegated
Authority migrations retain their previous bytes. The proof/signing profile is
an application-specific enrollment contract, not a newly promoted protocol Flow,
MAP proof wire standard, or receipt format. Public MIP, protocol source pin,
capability discovery and qualification status remain unchanged.

See the [operator/API contract](managed-agent-enrollment-candidate.md),
[proof and signer contract](../rust/crates/principal-runtime-binding/docs/managed-enrollment-proof.md),
and [command host runbook](../rust/services/delegated-authority/COMMAND_HOST.md).

### Follow-on validation

The follow-on was validated locally with Rust 1.95, PostgreSQL 17.12 and Node
24.22.3. The earlier UI/source-package evidence above belongs to the previous
checkpoint; this follow-on adds API/operator surfaces and changes no console
source or portable application map.

| Check | Result |
| --- | --- |
| Principal binding and managed enrollment | 45 passed, including 17 enrollment cases, the complete explicitly selected pinned protocol corpus, and three compile-fail contracts; no ignored cases |
| Local signer and independent interoperability | 13 Node tests passed; Node-generated ES256/Ed25519 proofs are independently verified by Rust, and generated private keys are not retained in fixtures |
| Organization, full normal suite | 136 passed; 28 fixture-gated cases ignored in the normal run |
| Organization, explicit live PostgreSQL/HTTP/catalog suite | 36 passed with none ignored, including all 25 directory/enrollment PostgreSQL cases skipped by the normal run; three unrelated offline-audit PostgreSQL cases remain outside this evidence |
| Delegated authority, including command host | 150 passed with actual separate PostgreSQL roles; the separately configured external private command-corpus gate remains ignored |
| Gateway | 322 library tests, four real executable smoke tests and one certificate contract passed; one Redis fixture gate remains ignored |
| Read-only upgrade preflight | 58 tests passed against disposable PostgreSQL databases and roles |
| Command executable | Actual `marty-delegation-commands` binary build passed |
| Combined compilation and hygiene | All-targets compilation for principal binding, Organization, Gateway and Delegated Authority passed; scoped formatting across 44 changed Rust files, diff checks and OSS boundary passed |

These rows are separate verification views and overlap. The focused Organization
run includes ordinary HTTP/catalog tests also present in the full suite. The
Gateway executable smoke verifies live route selection and authentication
admission; it does not claim a deployment with live Auth and all upstreams.

Cross-review found and corrected missing enrollment route installation in both
Gateway executable route tables. The new binary smoke exercises directory,
enrollment and command selection with approval disabled. Live database tests
also exercise permission loss during lock waits, expiry after audit waits,
rotation/policy invalidation, exact historical recovery and atomic rollback.
The full Organization suite corrected its previously stale language-neutral
permission-count fixture to the actual 127-entry catalog and checks the five
new enrollment/lifecycle actions explicitly.

All eight previously published Organization/Delegated Authority migration files
retain their exact bytes. The lockfile adds references to existing workspace
packages only; package versions, sources and checksums are unchanged. The
commit uses `[skip ci]`, and no hosted workflow is manually dispatched.

## Retained delegated-use and machine gate follow-on

This section records the published `085d65c` baseline. The subsequent machine
audit, credential, internal HTTP, concurrency and live custody work is recorded
in the next section; historical gaps below describe that earlier checkpoint.

The follow-on after `0404d1100f34f1423c80c432c0cd63df60908f48` implements the
internal KEY-grant use composition. Durable original claims precede Flow
preparation or receipt signing. START_USE records the exact challenge and
retained verifier nonce; FINALIZE_USE records a completed PERMIT or DENY and its
signed receipt. Pending claims are retained without automatic retry or takeover,
and recovered results preserve their original evidence and timestamps.

The concrete Flow owner commits authoritative challenge, proof and consumption
state on the same connection as the use ledger, checking the immutable Flow
storage identity. It locks and compares current definitions, original instances
and immutable proof submissions, with fresh clocks and deferred expiry guards.
The result remains `EVIDENCE_ONLY`; Rifare owns domain execution and business
idempotency. No executable use host or public Gateway route is installed, and
the existing human command host continues rejecting use commands.

The machine adapter composes the actual pinned Core OID4VP verifier with the
selected MAP, full machine/key/runtime state and all required evidence ports.
The selected machine policy runs through the actual MMF Cedar engine. Missing
credential, attestation or policy requirements fail closed. Current Organization
SERVICE_ACCOUNT inventory is not converted into a full MachineIdentity; that
source and its provider qualification remain required. The proof digest now
commits the complete machine qualification audit record, but a consuming host
must still durably retain that record and the referenced evidence.

The receipt adapter uses an independently configured public-key pin and a
dedicated signing-grant origin. It verifies actual returned ES256 or Ed25519
signatures and rejects changed issuer/key/profile state. Signing Keys adds only
an explicit default-off receipt-origin selection; live OpenBao/AWS/Redis custody
qualification, credentials and executable composition remain separate work.

Delegated Authority migration 0006 and Flow migration 0005 are additive. Earlier
migration bytes, public MIP/support/discovery, the Protocol checkout and Rifare
execution behavior remain unchanged. The current contract and remaining gates
are in [the retained delegated-use candidate](delegated-use-runtime-candidate.md).

### Current follow-on validation

These local checks use the locked Rust graph offline. Focused and aggregate
rows overlap and must not be summed. Synthetic providers do not qualify live
credential issuers, attesters, source freshness or managed signing custody.

| Check | Result |
| --- | --- |
| Principal binding and enrolled/pinned Protocol coverage | 56 passed, zero ignored, including 10 new MAP cases and four compile-fail contracts |
| Selected machine proof/MAP/Cedar gate | 13 passed with actual Core VP crypto and MMF Cedar; one additional opaque service compile-fail doctest passed |
| Retained use ledger | 15 focused tests passed, including all 14 explicit PostgreSQL cases |
| OID4VP verifier-ID compatibility and retained ledger | 24 focused tests passed after preserving opaque verifier client IDs; includes the 15 ledger tests |
| Full delegated-authority service | 184 passed, zero failures or ignores, with PostgreSQL enabled and serialized; one separately configured external command-corpus test explicitly filtered |
| External command corpus | The filtered case separately passed against the clean pinned Protocol checkout |
| Read-only upgrade preflight | 101 live PostgreSQL tests passed |
| Managed receipt adapter | Six tests passed with actual ES256/Ed25519 signatures |
| Signing-grant library | 32 passed; three existing live provider tests ignored |
| Signing Keys library | 274 passed; 22 existing live/external fixtures ignored |
| Signing Keys executable | Targeted binary compilation passed |
| Concrete Flow transaction/proof integration | 10 passed, zero ignored; includes six new explicit PostgreSQL cases with actual Core/ES256 proof, signed PERMIT/DENY, post-sign rollback, source isolation, retrieval progress and deferred expiry |
| Broader Flow library | 92 passed; 13 fixture cases ignored in the normal run, including the six delegated-use cases and public-retention case executed explicitly |
| Existing Flow PostgreSQL regressions | Five passed across retained-data handling, physical-start/finalization/callback atomicity, issuance-prerequisite freshness and public HTTP retry/quota/cancel races; one separate fenced-role case remains ignored |
| Combined six-package all-targets compilation | Passed for Gateway, Flow, Delegated Authority, principal binding, signing grant and Signing Keys |
| Formatting and whitespace | Scoped Rust formatting and CRLF-aware diff checks passed |

The 184-test aggregate preceded the final verifier-client-ID correction. The
subsequent 24-test run covers the corrected ledger/OID4VP path, and the external
command corpus passed separately with its required pinned source configuration.
The focused Flow group repeats four normal-library tests and explicitly runs
six additional PostgreSQL cases. Public retention was also selected separately;
these seven cases cover seven of the normal library's thirteen ignores.
External TLS/OpenBao and separately provisioned fenced-role gates remain open.

Hosted Actions, production rollout, a live receipt provider and independent public
consumer qualification are not claimed. Public capability promotion still
depends on the remaining runtime gates above.

## Machine evidence and authenticated transport follow-on

This parallel follow-on starts from published application commit
`085d65ca3298db17989710b3136eaedf9e6e3c26`. It closes five bounded implementation
and local qualification gaps while preserving the Marty/Rifare boundary.

| Area | Delivered change | Remaining qualification |
| --- | --- | --- |
| Machine evidence | Concrete append-only PostgreSQL repository and audited verifier composition; exact bytes/digest/scope retained before proof conversion; migration 0007 links every new full-machine receipt to its retained submitted-proof audit | Provision the restricted audit role and independently qualify/retain evidence at each authoritative source owner |
| Machine credentials | Concrete Core `MartyNestedVc2JwtV1` adapter with real ES256/EdDSA issuer and holder verification, registered credential identity, all required MAP types and current Trust Profile/issuer/key/status binding | Full MachineIdentity/MAP and JWT-VC status owners are explicit source ports; Organization remains SERVICE_ACCOUNT inventory |
| Internal command transport | Dedicated service-hop authentication, exact typed caller metadata, original P03 bytes, bounded authentication propagated through current source reads and COMMIT | Explicit router only; no executable, public Gateway selection or wallet/proof HTTP ingress |
| Concurrent Flow retrieval | Locked comparison of immutable authority with only the existing bounded progress allowance; preserve latest history and monotonic completion/consumption timestamps | Cancellation, changed scope and expiry stay terminal; no automatic retry/re-sign or pending-claim takeover |
| Managed receipt custody | Actual Signing Keys router/kernel exercised with TLS OpenBao Transit and password-protected Redis for Ed25519 and ES256; custom-provider rotation bug fixed | Outer deployed HTTPS adapter, production credential/custody deployment, AWS/IAM and network-timeout profiles remain separate |

The audit writer has SELECT/INSERT on its own table and no use ledger, grant,
Flow, consent or source-owner privileges. The use writer needs audit SELECT only.
The database enforces exact audit hash/reference/document relationships, original
deadlines through deferred COMMIT and receipt binding to tenant, actor, grant
revision, submitted proof, challenge, key and operation. Historical recovery
does not reconstruct authenticated proof. Pre-0007 receipts remain unchanged
and are counted explicitly as legacy history when they have no later audit;
missing post-migration evidence fails validation. No historical evidence is
fabricated.

Independent review found and corrected four concurrency/freshness cases. Source
observations now pass their own maximum-lifetime check before a shorter HTTP
deadline is applied. Original authentication observation and expiry remain both
clock bounds after dispatch. Finalization checks authentication after awaited
proof resolution and preparation before it begins signing. Flow completion uses
the fresh database clock obtained after its row lock, preventing timestamps from
moving behind a concurrent retrieval. Targeted regressions exercise these exact
failure scenarios.

The live provider gate also found a measured custody defect: rotating an
explicitly registered Transit receipt key behind an unchanged DID initially
returned HTTP 200. The corrected receipt-purpose kernel now compares the current
provider public key before remote signing and returns conflict on the stale pin.
The existing standard managed-provider behavior remains intact. Provider audit
counts prove no signing on replay or stale-pin rejection, and exactly one signing
attempt for a real provider permission denial.

### Follow-on verification

These checks use the locked dependency graph offline, real local PostgreSQL and
explicit disposable custody fixtures. Views overlap and must not be summed.

| Check | Result |
| --- | --- |
| Nested JWT-VC credentials and full machine-gate composition | 12 passed using real ephemeral Ed25519/P-256 signatures, including forged issuer under a valid holder and over 100 scoped/status/profile/expiry cases |
| Machine audit PostgreSQL integration | Seven passed: real Core Ed25519 proof, exact retention/recovery, role and guard drift, receipt binding, storage failure and pre-/post-/deferred-COMMIT expiry |
| Internal HTTP boundary | Five passed, including actual loopback HTTP body-read expiry and zero dispatch on malformed/foreign/human metadata |
| Full Delegated Authority library with serialized PostgreSQL fixtures | 210 passed, zero failures or ignores; one unchanged external command-corpus case explicitly filtered |
| Final use/source/clock regression | 29 passed on the final source-validation and original-observation bounds; external command corpus explicitly excluded |
| Read-only upgrade preflight | 131 PostgreSQL tests passed, including historical retention, five new guard bindings, exact critical CHECK constraints, privilege isolation and empty-table constraint drift |
| Concrete Flow transaction and HTTP integration | 17 passed, zero ignored; includes exact immutable-scope comparison, retrieval during signing and row-lock wait, cancellation, signed PERMIT/DENY, historical recovery, source loss and HTTP expiry |
| Final Flow HTTP source/clock regression | Three passed on the final original-observation bound, including fresh finalization, historical recovery, current source denial, overlong source rejection and expiry during signing |
| Live receipt custody | One explicit ignored-by-default gate passed for both Ed25519 and ES256 against actual OpenBao 2.5.5 and Redis 7.4.12; covers real signatures, encrypted credentials, separate roles, default-off, exclusive purpose, replay, provider denial, revocation and rotation |
| Signing Keys library regression | 274 passed; 22 existing independent fixture cases remain ignored in the normal library run |
| Combined all-targets compilation | Passed for Gateway, Flow, Delegated Authority, principal binding, signing grant and Signing Keys |

The broad service and 17-case Flow groups preceded the final original-observation
clock-bound adjustment. The final focused use/HTTP checks cover that adjustment
and both fresh and historical source authorization. The private external command
corpus and unchanged prior UI/Protocol suites are historical evidence above,
not rerun claims in this batch. Synthetic actor, consent, full-machine, issuer
status and policy sources in local tests do not qualify live source ownership.

Only additive Delegated Authority migration 0007 is new. All 15 published Flow,
Organization and Delegated Authority migrations remain byte-identical to the
baseline; Cargo manifest/lock and the Protocol pin are unchanged. The Signing
Keys compatibility file retains CRLF. Scoped formatting, whitespace, local
document links and the OSS commerce boundary pass.

Next deployment work is explicit authoritative workload/MAP and issuer/status
ownership, required attestation/current policy sources, a separately selected
use executable with wallet/proof ingress and reviewed serving roles, production
HTTPS/custody qualification and independent public consumer verification.
Pending-claim reconciliation needs its own reviewed contract. Public support and
discovery remain unchanged until those gates are qualified; Rifare retains its
own execution, budgets, reservations and business idempotency.

The implementation contracts are [internal HTTP](../rust/services/delegated-authority/USE_HTTP.md),
[machine credentials](../rust/services/delegated-authority/MACHINE_CREDENTIALS.md),
[machine audit](../rust/services/delegated-authority/MACHINE_AUTH.md),
[Flow finalization](../rust/services/flow/DELEGATED_USE.md) and
[receipt custody](../rust/services/delegated-authority/RECEIPT_SIGNING.md).


## Concrete source-owner follow-on

The follow-on to `f226585` replaces three missing internal source compositions
with concrete owners. Full MachineIdentity registration is a separate Organization
record with an explicitly assigned deployment MAP. Human administration checks
current tenant membership and exact permissions under locks, preserves original
identity/runtime/source fields and prevents historical key reuse. Selected source
observations retain their exact bytes and immutable revision before return.

The selected credential source reads the actual Trust Profile and Issuance
owners. Its nested JWT-VC authorization metadata is separate from SD-JWT,
selects the original issued artifact by digest and checks tenant, issuer, subject,
key, credential types, current lifecycle and originating transaction. Separate
trust, status and evidence connections are checked again during resolution.

Machine authorization has a dedicated named Organization policy owner and fixed
context-only Cedar schema. Generic policy administration cannot write this type.
The concrete source compiles the current revision through MMF and retains exact
source and evaluation evidence. Delegated Authority migration 0008 requires that
evaluation when a new aggregate machine audit selects machine authorization.
Old evidence remains historical, and no migration creates missing provenance.

These libraries expose no public endpoint and install no serving host. They do
not implement Rifare business permissions, execution, budgets or outcomes.
Required attestation, workload identity, protected proof ingress, current
use/domain authorization and deployed signer/Flow qualification remain the next
serving-path milestones. Public MIP, the Protocol pin and discovery are unchanged.

See [full-machine ownership](../rust/services/organization/MACHINE_REGISTRY.md),
[machine policy ownership](../rust/services/organization/MACHINE_AUTHORIZATION.md),
[policy source and evaluation](../rust/services/delegated-authority/MACHINE_POLICY_SOURCE.md),
and [credential source composition](../rust/crates/machine-credential-source/README.md).

### Source-owner validation

Validation ran locally on Rust 1.95 and PostgreSQL 17.12 against the unchanged
pinned external dependency versions. The complete selected source path uses
actual Organization, Trust Profile, Issuance, MMF and audit owners. Its original
Flow challenge and grant/authority lifecycle are fixture inputs, so this proves
source-to-machine-proof composition without qualifying proof ingress, grant
approval or final business execution.

| Check | Result |
| --- | --- |
| Full delegated-authority library with PostgreSQL gates | 216 passed, none ignored; one separately configured external private-protocol corpus case filtered out |
| Read-only database upgrade preflight | 157 passed, including 26 new source/evaluation, privilege, guard-drift and evidence-preserving upgrade cases |
| Full-machine registry owner/source | 12 passed with real PostgreSQL, current permissions, key rotation/expiry, UTC normalization, exact retention and cancellation during COMMIT |
| Machine-policy owner | 4 passed, including general policy get/list/mutation exclusion, independent permissions and immutable revision history |
| Concrete credential source and composed machine gate | 4 passed with real owners, ES256/EdDSA cryptography, current revocation/status, exact original issuance binding, privilege drift and source/evidence cancellation checks |
| Organization library and permission catalog | 71 library tests and 2 catalog tests passed; new machine administration rights remain limited to the intended role templates |
| Selected nested-profile contract | 1 focused strict grant-namespace test passed |
| Compilation | All targets passed for Organization, Delegated Authority, machine credential source, Trust Profile, Issuance and OID4VP contract |
| Compatibility and hygiene | All 19 previously published Organization/Delegated Authority/Flow/Trust Profile migrations retain exact bytes; existing dependency versions/sources/checksums unchanged; scoped formatting, diff, local documentation links and OSS commerce boundary passed |

The full delegated-authority row includes the five focused machine-policy source
cases. Test views overlap and should not be added as a single independent total.
Final role regressions grant predefined PostgreSQL capabilities and replication
privileges to actual source and evidence logins, then verify rejection and
recovery after revocation. Masking a privileged login with `SET ROLE` also fails
readiness. No privileged server-file or server-program operation is executed.
The new migrations are Organization 0005–0006, Delegated Authority 0008, Trust
Profile 0004 and the new credential-source schema 0001. Existing audit, receipt,
Flow and signing contracts remain intact. The commit uses `[skip ci]`; no hosted
workflow is dispatched, and production/capability qualification is unchanged.

## Current access, delegated policy and authenticated ingress follow-on

The follow-on to `c44579a` implements the remaining internal access, policy and
request/proof boundary owners in parallel. It adds four concrete components:

| Component | Delivered behavior |
| --- | --- |
| Machine-use access owner/source | Human administration of five independent entrypoint rights against the real full-machine registry and immutable deployment assignment; current tenant, identity, key and access checks, attributed history and historical result recovery |
| Delegated-use policy owner/source | Dedicated Organization policy lifecycle with a fixed finite-action EXACT_OPERATION schema, immutable revisions, retained exact observations and real MMF Cedar evaluation |
| Mutual-TLS identity boundary | Mandatory client-certificate listener using the existing remote keyless server identity; exact verified leaf URI and certificate digest mapping to a full machine; request-time certificate bounds and rejection of HTTP identity overrides |
| Protected Flow request/proof ingress | Separate current rights for request retrieval and proof submission, a durable request claim before signing, exact original JWS recovery without another signature, immutable proof retention and original bounds through locks and COMMIT |

The new Organization sources use distinct restricted connections. Neither
machine component access nor transport authentication provides machine-key
proof, grant consent or Rifare domain permission. Completed delegated evaluation
still follows the existing proof, consent, constraint and signed-receipt path.
The concrete delegated-use source deliberately rejects EXTERNAL_PROFILE rather
than inventing consumer domain attributes.

Flow's ordinary request and paired-wallet endpoints now reject delegated
instances, closing an alternate retrieval path around the new ingress boundary.
Original request/response URIs are preserved. This is an internal candidate;
public wallet routing and the complete live serving composition remain separate
work. Unresolved request-signing claims survive failure, cancellation and expiry,
just like unresolved command claims, and cannot trigger automatic signing retry.

Actual role probes also exposed two privilege-check gaps. PostgreSQL 17+
MAINTAIN now fails the selected source/evidence/ingress role checks. The former
`pg_%` LIKE filter treated its underscore as a wildcard and excluded application
schemas such as `pgx_*`; affected checks now exclude only the literal `pg_`
system prefix. Regression tests grant and revoke these privileges and confirm
denial and recovery. The benign security-definer probe is never invoked, and no
privileged server-file, server-program or maintenance operation is executed.

Organization migrations 0007–0008 and Flow migration 0006 are additive. All 24
previously published migrations across Organization, Delegated Authority, Flow,
Trust Profile and the credential-source schema preserve exact bytes. Delegated
Authority remains at migration 0008. The 812 existing dependency package
identities, versions, sources and checksums are unchanged; new Cargo entries
refer only to packages already in the locked graph.

See [machine-use access](../rust/services/organization/MACHINE_USE_ACCESS.md),
[delegated-use policy](../rust/services/delegated-authority/DELEGATION_POLICY_SOURCE.md),
[mutual-TLS transport](../rust/services/delegated-authority/USE_MTLS.md), and
[protected Flow ingress](../rust/services/flow/DELEGATED_USE_INGRESS.md).

The next serving milestone is an explicit default-off executable that composes
these owners, routers and restricted credentials with the existing same-database
Flow finalizer, machine verifier and managed receipt signer. Production CA
issuance/revocation, certificate-pin rotation, required attestation, deployed
request/receipt custody, public wallet contracts and independent consumer
qualification remain open. Public MIP 0.5.0, the Protocol source pin, capability
discovery and Rifare's execution boundary remain unchanged.

### Access, policy and ingress validation

Local validation used Rust 1.95 and disposable PostgreSQL 17.12 with the locked
graph offline. The views below overlap and are not one independent test total.

| Check | Result |
| --- | --- |
| Full Delegated Authority library, including PostgreSQL and real mTLS | 225 passed, none failed or ignored; one unchanged external private-protocol command corpus case explicitly filtered |
| Protected Flow integration | 24 passed, none failed or ignored; includes 17 existing delegated start/use/HTTP cases and all 7 new ingress cases |
| Broader normal Flow library | 93 passed; 26 fixture-gated cases ignored in that normal run; the selected delegated cases were executed separately above |
| Actual machine-use access owner/source | 4 passed with all five rights, immutable history, current permission/identity loss, authorized historical recovery and actual role/schema drift |
| Actual delegated-use policy owner/source | 5 passed with current human permissions, fixed schema, immutable lifecycle/observations, role/schema drift and cancellation during final COMMIT |
| Existing full-machine registry regression | 12 passed, including the new MAINTAIN and custom-schema privilege checks |
| Existing credential-source and composed machine-gate regression | 4 passed, including real signatures and all three restricted-role privilege regressions |
| Organization library and permission catalog | 71 library tests and 2 catalog tests passed; the catalog now has 148 explicit permissions |
| Read-only Delegated Authority upgrade preflight | 157 passed against actual PostgreSQL; these checks retain their documented Delegated Authority schema scope |
| All-targets compilation | Passed for Organization, Delegated Authority, Flow, machine credential source, Trust Profile, Issuance and OID4VP contract |
| Compatibility and hygiene | All 24 historical migrations and all 812 package identities/versions/sources/checksums preserved; scoped formatting of 36 Rust files, diff checks, local documentation links and OSS commerce boundary passed |

The Delegated Authority aggregate includes five new mTLS cases, two real
Organization access-adapter cases and two real policy-source/MMF cases. The Flow
cross-owner case uses the actual Organization registry and access owner/source,
revokes access during request signing, and verifies denied persistence while
earlier evidence stays unchanged. Actual TLS body expiry, signing cancellation,
row-lock expiry and deferred-COMMIT expiry are exercised. Ephemeral test keys and
explicit fixture grant/consent/domain inputs do not qualify production custody
or a complete deployed grant-to-business-operation flow.

Test setup was corrected for a shared advisory-lock identifier during
cross-owner migration, SQL GRANT syntax and PostgreSQL's rewritten CHECK
pretty-printing. The final selected gates passed with the original production
lock and strict schema checks intact. Independent review found no additional
concrete blocker. Public wallet transport, production deployment and capability
promotion remain outside this validation. Publication uses `[skip ci]` and
does not dispatch a hosted workflow.

## Current default-off serving-host follow-on

The follow-on to `1063f32` adds the explicit
[`marty-delegated-use` executable](../rust/services/delegated-use/README.md).
Its selected profile is a managed organization, full-machine identity, KEY
binding and EXACT_OPERATION policy. The executable checks its opt-in before
reading other configuration or credentials, assembles the concrete local owners
and protected remote adapters, completes bounded readiness, and then opens the
mandatory mutual-TLS listener. The original command, request and proof routes
and authenticated status probes share the same certificate identity mapping.

The host joins actual current human authority and retained consent, explicit
machine/MAP registration, use-access rights, Trust Profile and Issuance credential
authority/status, machine and delegated-use Cedar evaluations, append-only audit,
same-database Flow finalization and managed receipt signing. It holds fourteen
distinct restricted database logins. Startup performs no migrations, privilege
provisioning, signing-grant minting, request signing or receipt signing. The
production constructor selects existing protected providers; the separate
`assemble` seam permits explicitly named acceptance fixtures without adding a
production mock mode.

Restricted-role integration required five fixed row-lock helpers under new
Delegated Authority migration 0009 and Flow migration 0007. They preserve exact
source rows while allowing the use writer to lock grants, claims, admissions,
definitions and proofs without UPDATE authority over those records. The claim
guard preserves its original binding checks and takes the stronger grant lock
through the fixed helper. Readiness validates exact bodies, owner, return types,
security mode, search path and PUBLIC execution restrictions.

Independent review additionally closed two privilege gaps. The host applies a
role's table/function allowlist only in its actual selected database; the
application allowlist is empty in other connected databases. Administrative
PostgreSQL parameter ACLs, ALTER SYSTEM and parameter grant options are now
rejected by both the host's role checks and the lifecycle upgrade preflight.
Ordinary USERSET parameters remain available. Tests inspect actual grants and
revocation without disabling a trigger or invoking ALTER SYSTEM.

The actual selected profile also exposed a verifier-identifier mismatch:
Flow emits `decentralized_identifier:did:...`, while the normalized machine
binding parser previously required an RFC URI scheme for authentication
audiences. A dedicated application adapter now qualifies that bounded bare-DID
form in only the record/configuration audience fields. It retains the complete
original client ID and exact allowlist equality; ordinary URI fields retain
their original rules. No pinned Protocol bytes or public schema/version change
is implied.

The combined dependency graph also exposed a strict-JSON decoding difference:
`serde_json` arbitrary precision can deliver fractional/overflow number tokens
through a map visitor. The principal parser now validates original numeric
lexemes before DTO projection, preserving its existing integer-only contract
independently of dependency feature unification. Existing duplicate, nesting,
UTF-8 and schema checks remain in place.

Outbound review corrected the request-signing base to the actual
`/internal/compat` routes. All three selected template/wallet/presentation-policy
gRPC reads now bound the entire unary response, including bodies and trailers.
Definitions selecting optional trust/deployment catalog references are rejected
at readiness because those existing readers require human membership; no human
impersonation or silently omitted reference is introduced. Actual credential
Trust Profile checks and the explicit deployment/MAP source remain selected.

All 27 previously published migrations retain their exact bytes. All 812
existing package identities, versions, sources and checksums are unchanged; the
only additional package is the local `marty-delegated-use` crate. Public MIP
0.5.0, the Protocol source pin, capability discovery and the human Gateway's use
command rejection remain unchanged. Production CA issuance/revocation and pin
rotation, deployed role/network/custody qualification, required attestation,
public wallet contracts and independent receipt consumers remain exit gates.
Rifare still owns domain permission, orchestration, budgets and business commits.

### Serving-host validation

Local validation uses Rust 1.95 and disposable PostgreSQL 17.12. The listed views
overlap and are not an independent combined test total. The new host acceptance
tests explicitly run the normally ignored database cases with actual roles.

| Check | Result |
| --- | --- |
| Complete local host acceptance | 3 passed, none failed or ignored: actual approval-to-receipt/recovery, consent withdrawal after proof, and connected storage/role/helper rejection |
| Host configuration and runtime selection | 12 passed, including default-off behavior, bounded configuration, actual Signing Keys route selection and rejection of human-only catalog references |
| Actual executable smoke tests | 3 passed, including disabled-before-I/O and sanitized invalid startup |
| Principal binding and numeric parser | 29 passed: 27 local conformance cases and 2 parser cases; the independently supplied pinned Protocol corpus remains explicitly ignored in this run |
| Full Delegated Authority library | 225 passed, none failed or ignored, with PostgreSQL and actual mTLS enabled; one independently supplied private Protocol command corpus explicitly filtered |
| Selected PostgreSQL Flow integration | 24 passed, none failed or ignored, including delegated start/finalization and protected request/proof ingress |
| Normal Flow library | 95 passed; 26 fixture-dependent tests ignored in this normal view, with the selected delegated cases executed separately; includes the actual HTTP/2 stalled-body/trailer deadline case |
| Read-only database preflight | 179 passed, including exact new helper checks, evidence-preserving 0008-to-0009 upgrade and six parameter-ACL cases |
| All-targets compilation | Passed for the new host, Delegated Authority, Flow, Organization, machine credential source, Trust Profile, Issuance, OID4VP contract and principal binding |
| Compatibility and hygiene | All 27 historical migrations and all 812 existing package identities/sources/checksums preserved; one additional local crate; scoped formatting of 22 Rust files, local documentation links, diff checks and OSS commerce boundary passed |

The successful host case uses separately credentialed real lifecycle, consent
and authority producers, actual full-machine/MAP and access owners, real Trust
Profile/Issuance authority and status reads, actual nested issuer/holder proof
verification, both Cedar evaluations and linked retained audit. It independently
verifies the request and receipt signatures, recovers the original request and
final result without signing again, and confirms grant/access revocation blocks
the corresponding new use/recovery while preserving original evidence. A
separate withdrawal case preserves submitted proof and produces no receipt or
Flow consumption.

The privilege case exercises independent forbidden UPDATE assertions, wrong
Flow storage, direct and NOINHERIT source authority, administrative parameter
rights, a matching helper signature in a different selected source database and
helper security drift. It first establishes passing baselines and verifies
recovery after revocation. No test executes an administrative parameter change
or disables an integrity trigger to exercise those grants.

Remote presentation/template metadata, ephemeral ES256 request/receipt custody,
bootstrap credential bytes and preauthenticated human/workload transport are
explicit fixtures. All local current owners and cryptographic checks above are
real. The assembled runtime still rejects forwarded service-token authentication
and selects mTLS only; actual mTLS transport is exercised separately by the
Delegated Authority suite. These tests do not qualify a deployed remote CA/KMS,
fresh production credential issuance, public wallets or a Rifare business commit.
Publication uses `[skip ci]` without dispatching a hosted workflow.


## Current receipt recovery, verification and executable qualification follow-on

The follow-on to `3d1f699` closes the missing internal delivery path for signed
receipts and adds an independently usable verifier. It also qualifies a bounded
startup/readiness slice of the actual executable with disposable remote custody.
The three workstreams were implemented in parallel. Receipt recovery and the
consumer are joined in actual local-owner acceptance; the executable has a
separate startup/readiness gate.

### Protected original artifacts

The explicit internal host now mounts
`POST /internal/v1/organizations/{organization}/delegated-use/receipts/recover`.
It accepts the existing strict RECOVER_RESULT intent and uses the existing
current recovery right. The response contains the original FINAL_USE response
with `recovered=true`, exact compact JWS, reference, digest and EVIDENCE_ONLY
semantics. Original command/result DTOs, migrations and permission catalogs are
unchanged.

The service scopes the read by tenant, complete typed actor and original command,
checks the expected command digest and validates the receipt against its retained
result and admission. Bounded read-only repeatable snapshots perform no signing,
evaluation, mutation or pending-claim retry. Current access is checked before
and after the artifact read; the first authentication and access deadlines remain
binding across waits. Expired or revoked grants remain recoverable as history
while current recovery access survives. Revoked access closes the read without
erasing the original evidence.

### Independent consumer evidence

The new [`marty-delegated-receipt-consumer`](../rust/crates/delegated-receipt-consumer/README.md)
crate has no service, database, Core, signing-grant or network dependency. The
caller independently supplies a tenant/typed-issuer/algorithm/key pin, original
request context, an authenticated FINAL_USE reference and original-byte digest,
and an explicit observation time. ES256 and Ed25519 verification authenticate
the exact compact bytes; strict bounded parsing rejects ambiguous JSON, unknown
members, unsafe numbers, unsupported encodings and noncanonical identifiers.

The context includes the grant revision/terms, typed actor/subject, complete
binding and operation, nonce, selected policy, status issuer and original time
window. Generated evidence references and unpinned policy versions remain
signed issuer assertions; optional independent pins can constrain them. The
signature covers the nonce, while the command UUID, Flow challenge UUID and
proof-submission UUID remain external retained-workflow correlations.

Fresh positive evidence and historical evidence are separate sealed types.
Fresh verification rejects signed DENY and applies the caller's bounded lifetime
and evidence-age policy. Its exclusive `fresh_until()` may precede the original
signed expiry. Historical verification preserves original decisions and dates
without converting them into fresh evidence. Neither type conveys business
permission, current revocation status or replay consumption.

A recovered receipt can still satisfy the offline freshness window after its
grant is revoked. That temporal result does not observe the revocation or
restore authority; callers must separately enforce their current authorization
and business rules.

The joined owner test recovers the artifact through the actual current-access
application boundary, then verifies it using independently known bootstrap and
workflow inputs. Database inspection is reserved for separate persistence and
audit-linkage assertions. The test also rejects a different operation, preserves
expired history, recovers after actual grant revocation, and denies recovery
after actual machine-use access revocation.

### Actual executable qualification boundary

The new live target invokes the real binary, configuration and production
`connect()` path. It uses all fourteen restricted PostgreSQL identities, native
TLS OpenBao, password-protected nonpersistent Redis, the real Signing Keys HTTPS
router and managed receipt-key resolution, and actual remote keyless server and
client TLS. It observes provider audit calls to distinguish TLS signatures from
request/receipt signing or signing-grant minting.

Template and presentation-policy metadata are explicitly read-only authenticated
gRPC wire fixtures. Reference origins expose authenticated health fixtures. The
gate verifies mapped-client health/readiness, unlisted/missing certificates,
identity-header spoofing, wrong pins, actual privilege drift, and startup refusal
for invalid remote credentials, workload identity, availability and public-key
selection. It establishes no full request/proof/receipt lifecycle through real
catalog owners and does not qualify a production deployment.

The native wrapper provisions only disposable provider state and scoped keys,
propagates child failures, and removes its providers and temporary credentials.
For this run, OpenBao 2.5.5's archive and checksum-file signatures were verified
against its documented primary fingerprint
`66D15FDD87287219C8E15478D200CD702853E6D0`; the archive SHA-256 is
`2c5577707e97fc95c2086950f39880ead5e45b356c94388e5cb606f5a5c2b697`.
Redis 7.4.12's source matches the separately published official SHA-256
`56588ee1648539556f2b6cf4e873e3734afbbe40fa952fec2fcd6b6d7dae2924` and was
built locally. The [OpenBao verification instructions](https://openbao.org/docs/2.5.x/install/)
and [Redis release checksums](https://github.com/redis/redis-hashes) are the
upstream provenance sources; runtime version checks alone do not authenticate
a release.

### Receipt-consumer and executable validation

Validation completed locally on November 21, 2026, using Rust 1.95 and disposable
PostgreSQL 17.12. The views below overlap; they are not an additive test total.
The actual executable gate also used the independently verified native OpenBao
and Redis builds described above. No hosted workflow was used.

| Check | Result |
| --- | --- |
| Independent consumer | 21 passed in the standalone dependency graph and the same 21 passed under full host/service feature unification; both ES256 and Ed25519, strict JSON/numeric/time handling, exact context/retention, DENY, history and exclusive freshness bounds |
| Full Delegated Authority library | 235 passed, zero failures or ignores, with disposable PostgreSQL and actual mTLS enabled; one independently supplied private Protocol corpus explicitly filtered |
| New recovery cases within the service suite | Five PostgreSQL cases passed: PERMIT/DENY history, tenant/typed-actor/digest/pending/START rejection, blocked-read revocation and original-deadline races, eleven corruption cases including oversized metadata, and bounded cancellation; four HTTP cases and the escaped-header compatibility case also passed |
| Joined local-owner acceptance | 3 passed, zero failures or ignores; includes actual approval-to-proof-to-receipt flow, protected recovery into the independent verifier, grant/access revocation, consent withdrawal and actual restricted-role/storage checks |
| Actual executable over disposable remote custody | 1 passed, zero failures or ignores, in 13.44 seconds; actual production startup/readiness, keyless mTLS, Signing Keys HTTPS key resolution, protected receipt routing and fail-closed dependency/role/pin cases |
| Host unit and executable smoke | 12 unit tests and 3 smoke tests passed |
| Sealed evidence contracts | 4 compile-fail doctests passed: existing authenticated machine proof, recovered receipt, fresh receipt evidence and historical receipt evidence |
| Combined compilation | Library and test targets passed for Delegated Authority, the independent consumer and the delegated-use host, including the actual executable and both acceptance targets |
| Native fixture lifecycle | Successful and failing child exits propagated; provider provisioning and scoped-key denials passed; the live run left zero owned provider processes or temporary credential directories |
| Dependency and migration preservation | All 813 existing package identities/versions/sources/checksums and all 62 repository SQL migrations retain their prior values/bytes; the only added package is the local receipt consumer |
| Consumer dependency boundary | Normal dependency closure contains no Marty service/Core/signing-grant, MMF, database or network-client package |
| Hygiene | Formatting of 22 Rust files, Python syntax, local documentation links, diff checks and OSS commerce boundary passed |

The positive owner lifecycle and the live startup target remain separate
qualification views. Actual template/presentation-policy service owners, managed
fresh credential issuance, complete network request/receipt signing and a
production or public consumer rollout are not established by this batch. Public
MIP 0.5.0, the Protocol pin, capability discovery, the default-off host flag and
Rifare's business-execution boundary remain unchanged. Publication uses
`[skip ci]` and does not dispatch a workflow.

### Remaining next milestones

1. Replace the named metadata wire fixtures in a separate full-lifecycle gate
   with actual template/presentation-policy owners, reviewed workload rights,
   fresh managed credential issuance and managed request/receipt HTTPS signing.
   Exercise protected recovery over that complete network composition.
2. Qualify the public request/response and wallet routing contract, package the
   public transport/client integration, and connect the independent verifier
   without exposing internal storage or private service APIs to Rifare.
3. Qualify production CA issuance/revocation, certificate/key pin rotation,
   separately provisioned roles, custody and outage/restart behavior. Pending
   claim reconciliation still requires a reviewed design; no automatic takeover
   or re-signing is introduced.
4. Add separately selected required-attestation, external-authority/domain and
   represented-subject SESSION profiles. Their data shapes do not establish
   qualified runtime adapters.
5. Promote public support only after the relevant gates pass, then integrate
   Rifare's own domain permission, budget, replay/idempotency and business-commit
   boundary. Marty evidence does not perform or attest a business outcome.


## Current managed network lifecycle follow-on

The follow-on to `0a1ef66` joins the selected operation across the actual
`marty-delegated-use` executable, production template/policy gRPC owners and
managed Signing Keys HTTPS service. The earlier startup gate and local-owner
acceptance remain separate regression views. Three parallel tracks built owner
integration, custody/issuance and network acceptance; coordinated review exposed
and corrected real transport mismatches that synthetic metadata had concealed.

### Actual selected-operation path

1. Provision the disposable organization, machine holder, active catalog records
   and three independently selected signing keys. The template/policy services
   serve their actual repositories and serializers over remotely held TLS keys.
2. Invoke the real Issuance initiation, pre-authorized token exchange, nonce and
   credential applications against PostgreSQL. Native holder-proof verification
   precedes the purpose-bound managed credential signature and atomic issuance
   retention. The helper does not insert a completed credential or sign one with
   a local issuer key. This bootstrap invokes application services in-process;
   it does not exercise Issuance's public HTTP handlers.
3. Independently authorize the selected issuer/key/type in Trust Profile, register
   the full machine/MAP, grant its explicit use rights, and create/approve exact
   operation terms through the actual Organization and Delegated Authority
   owners. Human authentication and privileged setup remain test boundaries.
4. Launch the actual executable with its production configuration, fourteen
   separately restricted PostgreSQL roles, exact caller certificate mapping and
   its own delegated-use outbound workload identity. Complete authenticated
   readiness before accepting commands.
5. Call START_USE, retrieve the protected managed-signed request, independently
   verify its signature and selected DCQL requirement/profile/types, submit the
   machine's real holder proof, and finalize the operation over mTLS HTTP.
6. Recover the original signed receipt through the protected route and verify it
   with the independent consumer. Expected trust, actor, operation, grant, policy,
   nonce and retention binding come from independent provisioning and the
   authenticated workflow. Database reads are only later audit assertions.

The selected credential is one-day `MachineCredential` under the existing
nested VC2 JWT profile. Request, credential and receipt signers use distinct
nonexportable OpenBao Transit keys and separate sign-only credentials. Flow,
Issuance and Delegated Decision have distinct grant-minting roles; Signing Keys
receives verify-only access and uses its existing Redis one-use verifier.
The host's remote TLS key is a different key and carries the exact
`spiffe://marty.internal/service/delegated-use` URI.

Provider audit counters distinguish those artifact-signing and grant-HMAC
invocations from transport signatures. One credential, two separate requests
and one final receipt are expected. Exact command/request/proof retries and receipt recovery
must add no artifact signature or grant. A second submitted proof loses
finalization authority after actual grant revocation; its bytes remain retained
and its challenge remains unconsumed. The first receipt remains recoverable as
history until actual machine-use access is revoked. All protected routes then
refuse even exact duplicate or historical reads without deleting evidence.

The offline consumer rejects a different operation and expired fresh use while
preserving historical evidence and original dates. Its temporal freshness test
does not query current grant revocation or confer Rifare business permission.
The receipt remains `EVIDENCE_ONLY`.

### Integration corrections

- Presentation Policy now permits the exact delegated-use workload to call
  `GetPolicy`, without granting `EvaluatePresentation`. Workload authority comes
  only from the authenticated TLS leaf. Multiple distinct leaf URI SANs fail
  closed; a Flow URI on an issuing CA cannot grant evaluation authority.
- Flow's protobuf template reader canonicalizes the finite recognized public
  format aliases at the boundary. The real owner emits `jwt_vc`, while Flow's
  selected capability is `VC_JWT`. Nested and direct JWT profiles remain
  distinct; unknown capabilities are rejected and list cardinality is preserved.
- Issuance adds explicit native Signing Keys owner constructors. They require an
  unambiguous HTTPS origin and use the actual POST/JSON `/internal/compat`
  resolver and signer routes, with tenant ownership checked in the response and
  organization included in the signing body. Existing gateway constructors keep
  their original GET/query and signing-query behavior. The purpose-bound grant
  still binds the exact owner route, operation, organization, issuer, key,
  algorithm and signing input.
- The selected strict machine credential verifier requires nested `vc.id` to
  equal signed `jti`; the legacy issuer's default omits the nested ID. An explicit
  trusted `with_machine_nested_vc2_jwt_profile()` builder selection uses the
  existing Core preparation/completion APIs to bind both IDs to the reserved
  credential. It is independent of HTTP transport selection and rejects other
  types/formats, direct timing, unsupported algorithms, explicit documents and
  status-bearing inputs before signing. Existing legacy and direct issuance
  defaults, verifier rules and status-source rules remain unchanged.

### Explicit qualification boundary

The selected use path consumes real owner state, cryptographic proof, current
policies, audit and managed signatures. Active catalog records and
organization/trust/registry/grant setup are privileged fixture provisioning.
Human catalog administration and its activation dependencies, including
Compliance evaluation, are not exercised; unused administration and Presentation
Policy evaluation ports deny access.
The fourteen restricted database identities belong to the delegated-use child.
The in-process catalog servers and Issuance bootstrap use the disposable
administrator pool; their separately provisioned serving-role qualification
remains outside this gate.
The no-status issuance lifecycle dependencies are closed bootstrap fixtures
bound to the exact stored template, organization, issuer and subject. This gate
does not qualify revocation publication, broader delivery modes or public
Issuance routing.

Four unselected reference providers share one authenticated readiness-only
fixture origin. Any attempted record read fails, is counted, and must remain
absent. The selected Flow omits the optional human-only catalog references;
actual Trust Profile and
Issuance checks still run through restricted sources. The test also asserts
zero calls to the older ephemeral request/receipt signers.

The caller uses protected internal request/proof routes and does not follow the
unchanged public Flow wallet URIs. No public Gateway contract, capability
promotion, production CA/custody/role qualification or Rifare business operation
is established by this local gate. The executable stays default-off, public MIP
stays 0.5.0, and the Protocol source pin is unchanged.

### Managed lifecycle validation

Local validation on 2026-11-21 completed with the reviewed dependency graph:

| Gate | Result |
| --- | --- |
| Combined delegated-use, Flow and Issuance library/test target build | Passed with `--locked --offline` |
| Actual executable managed network lifecycle | 1 passed, 0 failed, 0 ignored; 11.15 seconds |
| Actual executable startup/readiness regression | 1 passed, 0 failed, 0 ignored; 11.99 seconds |
| Existing actual-owner PostgreSQL acceptance | 3 passed, 0 failed, 0 ignored |
| Delegated-use library and host smoke | 12 + 3 passed, no failures or ignored cases |
| Issuance library | 477 passed, 0 failed, 12 existing fixture-dependent cases ignored |
| Credential signing behavior | 16 passed, 0 failed, 0 ignored |
| Flow library | 97 passed, 0 failed, 26 existing fixture-dependent cases ignored |
| Presentation Policy library | 121 passed, 0 failed, 3 existing fixture-dependent cases ignored |

The explicitly enabled network gate exercised the positive managed lifecycle,
original-byte retries and historical recovery, independent consumer rejection
of a different operation and expired fresh use, wrong recovery digest, unmapped
caller and spoofed identity headers. After grant revocation, new START_USE
returns access denied; a pending FINALIZE_USE returns the existing grant-snapshot
conflict before inserting a finalization claim. Provider invocation counters
remain unchanged, no second receipt is produced, and the pending proof remains
unconsumed. Current access withdrawal then denies all tested protected recovery,
duplicate and read paths while preserving the artifacts.

The Issuance suite includes four native-owner transport/ownership/grant tests
and the new real-signature machine profile regression. The latter preserves the
legacy omitted-ID output, verifies the selected profile with the native
verifier, rejects a modified signature, and prevents signing for seventeen
incompatible selections. Presentation Policy includes four leaf-identity and
method-authorization checks; Flow tests actual protobuf format spellings,
direct/nested distinction and unknown-format rejection.

All 814 dependency identity/version/source/checksum tuples, all 62 SQL
migrations and the reviewed Core/Protocol source pins remain unchanged. The
lockfile adds only the existing local Presentation Policy test dependency edge.
Scoped Rust formatting, both wrapper syntax checks, documentation links, OSS
commerce boundary and source-pin/probe-lock checks passed. Disposable wrapper
failure cleanup also propagated the child exit code, closed the provider ports
and removed its token directory. No production deployment or public support
promotion is included.

### Remaining next milestones

1. Define and qualify the public delegated request/response and wallet routing
   contract. Package the public client and independent receipt verifier without
   exposing internal storage or private service APIs to Rifare.
2. Qualify production CA issuance/revocation, pin/key rotation, separately
   provisioned roles, custody, outage and restart behavior. A pending-claim
   reconciliation contract is still required before any takeover or re-signing;
   this change introduces neither.
3. Implement and qualify separately selected required-attestation,
   external-authority/domain and represented-subject SESSION profiles. Their
   schemas alone do not establish a runtime adapter.
4. Promote public support only for qualified profiles, then integrate Rifare's
   own domain permission, budget, replay/idempotency and business-commit rules.
   Marty evidence does not perform or attest the business outcome.

## Current managed public caller and wallet follow-on

The follow-on to `37b7fdc` completes the recovered unfinished caller slice in
three parallel tracks: guarded wallet routes, an independent Rust client, and
actual-executable acceptance through the advertised request and response URLs.
The existing internal lifecycle remains a separate regression gate. Protocol
PR #38 is the private [ElevenID protocol proposal](https://github.com/ElevenID/marty-protocol/pull/38);
the earlier architecture link to an unrelated public-repository PR is corrected.

### Explicit caller surface and retained authority

`DELEGATED_USE_PUBLIC_CALLER_ENABLED=true` separately mounts the public command,
request, direct-post and original-receipt routes on the existing mandatory
mutual-TLS listener. The default remains false. The host still needs its main
explicit opt-in, fourteen restricted database connections and successful
readiness. Public router construction rejects the internal trusted-forwarder
mode. The selected tenant and complete actor come from trusted composition and
the authenticated leaf mapping; headers and form fields cannot select them.

CHALLENGE responses advertise one exact origin-bound request `Link`, including
original-result recovery. Their retained JSON and command digest are unchanged.
The request contains the signed response URI. Public submission accepts only
the bounded `state` plus DCQL `vp_token` form for the selected nested VC2 JWT
machine profile. Its query ID comes from the frozen request. The emitted request
must already be retained, and the adapter compares its original digest,
configuration, actor, request projection and frozen authority inside the same
locked Flow transaction used by proof retention.

The compact VP is retained without reserialization. Equivalent accepted form
encodings recover the original proof bytes, ID and receive time. Current access
and original authentication bounds continue through the existing source, lock
and COMMIT checks. Terminal exact proof recovery creates no new proof, claim,
signature or consumption. Request retrieval still requires a live original
Flow. Cryptographic proof verification and finalization remain with the existing
delegated-use owner.

### Independent client and verification boundary

The new [`marty-delegated-use-client`](../rust/crates/delegated-use-client/README.md)
workspace crate has no dependency on private Marty Core, owner services or
their storage. It constructs its own TLS verifier from explicit roots and a
client-certificate resolver, permitting remote key custody. It disables
redirects, automatic retries, environment proxies, decompression and idle
connection reuse. Requests and responses have byte and time limits; successful
responses require the selected media type and no-store headers.

Prepared commands retain their caller-selected UUID and locally computed
canonical digest before I/O. The application must persist those original
inputs; the client supplies no durable journal. Results must match that
independent identity, original grant/operation and challenge. Recovery never
copies its expected command digest from a server response. Links and response
destinations must match the configured origin and original challenge exactly.
An uncertain response or absent result cannot authorize a new command identity.

Request artifacts and original receipt bytes remain explicitly unverified.
The caller independently verifies request signing trust, nonce, lifetime,
audience, profile and complete DCQL query before submitting proof. The separate
receipt consumer verifies original signed evidence using independent trust and
context. `PERMIT`, transport success and `EVIDENCE_ONLY` receipts do not supply
Rifare business permission or execute a purchase/refund.

### Actual-owner integration correction

The first public network run found a real adapter/owner mismatch: Flow retains
a MIP PresentationRequest projection, while the new adapter expected the full
JWT payload. The projection has no JWT-only `iss` or `state` fields and records
an unselected presentation definition as null. The adapter consequently refused
valid public input before DCQL association.

The corrected adapter validates the actual MIP message correlation, sender,
nonce and type; payload Flow/policy IDs, client identity, response fields and
frozen query; and the original expected-state context. It accepts only
absent/null presentation definitions and rejects a selected definition. The
fixture now matches the real producer and tests twenty authority mutations.
No expected HTTP status, signed request producer, schema, wire contract,
source pin or authorization check was weakened to obtain a pass.

### Local caller validation

Local validation on 2026-11-21 used Rust 1.95 and locked, offline dependencies.
These are overlapping views and must not be summed as independent tests.

| Gate | Result |
| --- | --- |
| Standalone client build and real mTLS transport suite | 17 passed, 0 failed/ignored |
| Actual internal and public managed network lifecycles | 2 passed, 0 failed/ignored; 31.40 seconds after the projection correction |
| Actual executable remote startup/readiness regression | 1 passed, 0 failed/ignored |
| Existing actual-owner PostgreSQL acceptance | 3 passed, 0 failed/ignored |
| Delegated-use configuration/runtime and executable smoke | 13 + 3 passed, 0 failed/ignored |
| Command and original-receipt HTTP contracts | 8 + 5 passed, 0 failed/ignored |
| Flow library after the projection correction | 103 passed; 26 existing fixture-dependent cases ignored |
| Selected current-access/ingress PostgreSQL regressions | All 7 explicitly executed, 0 failed/ignored |
| New wallet association/transport cases | All 6 passed within the Flow library; includes twenty retained-authority mutations |
| Library and selected executable test-target compilation | Passed with `--locked --offline` |
| Scoped formatting, local documentation links, diff and OSS commerce boundary | Passed |

Both network gates use freshly issued managed MachineCredentials, actual
template/policy owners and purpose-separated OpenBao request/credential/receipt
signing. The public gate follows the returned request link and verified signed
response URI with the independent client. It exercises malformed/duplicate
forms and queries, missing certificates, request-before-submission ownership,
identity-header spoofing, exact retries, terminal proof recovery, original-byte
receipt recovery, grant revocation and current access withdrawal. Rejections
and recovery preserve all artifact-signing and grant-minting counters.

The client suite separately proves one-attempt HTTP/redirect failure and
explicit original-command recovery after a deliberately lost response. Its
synthetic signed-looking bytes are transport fixtures; cryptographic request
and receipt verification is performed in the actual-owner lifecycle.

All 814 previous package identity/version/source/checksum tuples and all 62 SQL
migrations are unchanged. The lock adds one local client package and local
test dependency edges. Reviewed Core/Protocol pins and public MIP 0.5.0 remain
unchanged. The commit uses `[skip ci]`; no workflow dispatch, production
deployment, merge or capability promotion is part of this milestone.

### Next milestones after the caller gate

1. Qualify this selected caller composition with separately provisioned catalog
   and Issuance serving roles, production network/origins and current source
   freshness. The disposable administrator bootstrap and readiness-only
   reference fixtures remain explicit limits of the local gate.
2. Qualify production CA issuance/revocation, caller certificate/pin and signing
   key rotation, remote custody, outage and restart behavior. Define reviewed
   pending-claim reconciliation before any takeover or repeated signing; the
   current client and service never infer permission from an uncertain outcome.
3. Qualify separately selected required-attestation, external-authority/domain
   and represented-subject SESSION adapters when those profiles are requested.
4. Promote support only for the qualified profile, then connect Rifare through
   the public contract with its own durable command intent, domain permission,
   budgets/reservations, provider idempotency and business commit. This batch
   changes no Rifare execution behavior.


## Current next milestone — separated owner deployment qualification

After the managed public-caller gate merged in Marty UI PR #1994, the next milestone is to qualify the selected caller composition against separately provisioned Credential Template, Presentation Policy and Issuance services. The current local lifecycle gate still uses a disposable administrator pool for catalog/policy setup and starts those owner services in-process; Issuance bootstrap is also in-process. These boundaries do not qualify independently restricted owner processes.

The scope, source-backed starting state, work packages OQ-1 through OQ-5, acceptance matrix and execution constraints are tracked in [delegated-use owner deployment qualification](delegated-use-owner-deployment-qualification.md).

The first implementation blocker is privileged startup behavior: Credential Template normal startup currently migrates, reconciles legacy data and seeds the catalog; Presentation Policy normal startup migrates and reconciles built-in policies. These writes must move to explicit operator/bootstrap commands, while normal service startup becomes validation-only and read-only. Issuance already exposes migrate/verify-owned-schema commands and a schema startup mode; its deployed validation-only mode and remaining startup preparation helpers must be audited.

No production credentials, production CA material, paid infrastructure, Actions dispatch, public support promotion or Rifare business execution are included in this milestone. AWS replay is deferred until the source and local acceptance gates pass and the existing Free-plan instance, automatic-stop safeguard and concurrent workload state are reverified.
