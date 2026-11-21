# Agent trust runtime milestone checkpoint

This integration advances the application work after Marty Protocol PR #38.
It reconciles the existing delegated-authority draft in Marty PR #1994 with
main at `f662bb326bd0a83eb8191dc002bc3db57ec08cc3`, including the accepted
Core JWT 11 dependency alignment. It preserves that existing lifecycle service
and Flow admission implementation. The application now includes candidate agent directory administration,
exact-terms organization approval, managed key-control enrollment and an opt-in
human lifecycle command host. Public delegated execution remains gated.

## Implemented in this application slice

| Milestone area | Deliverable | Qualification boundary |
| --- | --- | --- |
| M01 protocol adoption | Independently pinned optional protocol source, manifest and schema checks | Existing public MIP 0.5.0 and support levels remain unchanged |
| M01 runtime reconciliation | Delegation workspace integration and Flow persistence guards alongside current issuance-intent protections | Internal composition; no new public delegated route |
| M01 upgrade operations | Read-only database preflight, role separation checks and evidence-preserving upgrade/rollback procedure | No automatic reconstruction of missing historical evidence |
| M02 principal binding foundation | Strict Rust principal/runtime/key/session consistency checks, typed fingerprints and opaque validated output | Operational proof authentication remains separate; bounded enrollment proof is implemented by the separate purpose-specific adapter below |
| M02 directory and enrollment candidate | Tenant inventory, public-key history, immutable audit, authorized administration, retained signed-challenge enrollment and a local key-custodian signer | Managed entries start PROVISIONED; explicit key-control enrollment permits ACTIVE eligibility, with authority NOT_ASSESSED. Operational MAP, external host trust and suspended-identity resume remain separate |
| M03 approval candidate | Exact immutable terms, explicit human confirmation, durable recovery/withdrawal, independent current Organization authority and an opt-in executable | One configured organization and KEY binding; represented-subject SESSION establishment and broader authority profiles remain separate work |
| P03 application lifecycle commands | Atomic grant/journal/original-result persistence, opt-in human Gateway/host composition, exact producer confirmation and current Organization authorization rechecked after lock waits | Selected human organization/KEY profile only; START_USE and FINALIZE_USE remain unsupported |

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

- Operational machine proof authentication, required machine credentials, Machine
  Authentication Policy/attestation/Cedar evaluation, connection/grant aggregation
  and independent directory qualification. Enrollment key possession is implemented
  but does not satisfy these operational checks.
- Broader approval/authority profiles and qualified represented-subject session
  establishment beyond the implemented human/organization KEY profile.
- Qualified workload/proof authentication adapters and deployment qualification of
  source freshness. Human command authorization/confirmation composition is
  implemented; external and machine callers remain separate work.
- Durable `START_USE` command correlation and retained tenant/verifier nonce
  admission, followed by dedicated `FINALIZE_USE` persistence and managed
  receipt signing. Ordinary Flow finalization remains guarded.
- Public delegated-use hosting, packaged public clients, independent consumer
  verification and explicit capability qualification. Human lifecycle commands,
  directory, enrollment and approval hosting are opt-in candidates.
- Rifare adoption of those public features after the corresponding runtime
  gates pass. This checkpoint changes no Rifare business execution behavior.

See [the optional protocol consumer contract](architecture/agent-trust-protocol-consumer.md),
[principal binding integration](principal-runtime-binding.md),
[the directory and approval candidate](agent-identity-and-approval-candidate.md),
[managed enrollment and human command hosting](managed-agent-enrollment-candidate.md),
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
described below. Operational machine authentication, retained START_USE admission, dedicated FINALIZE_USE
persistence and receipt signing remain required before Rifare uses those paths
for business execution.

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
