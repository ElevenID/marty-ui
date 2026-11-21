# Retained delegated-use runtime candidate

The retained-use baseline at `085d65ca3298db17989710b3136eaedf9e6e3c26`
implemented internal `START_USE`/`FINALIZE_USE`, the concrete Flow transaction
owner, selected full-machine authentication and managed decision-receipt signing.
The current follow-on adds authenticated internal command transport, actual
nested JWT-VC verification, immutable machine-audit storage, safe concurrent
request retrieval and live disposable OpenBao/Redis receipt qualification. It
does not install a delegated-use executable or public route.

The human `marty-delegation-commands` executable and its Gateway surface still
reject use commands. There is no default caller authorizer, machine evidence
source or selected receipt signer. Public MIP remains 0.5.0; support levels and
capability discovery remain unchanged. The Protocol source stays pinned at
`6126da7619e057be2ff58dd38a5d50f49891d1b3`.

## Implemented composition

| Component | Implemented responsibility | Boundary that remains explicit |
| --- | --- | --- |
| `DelegationUseCommandService` | Strict P03 use intent, durable original command claims, current caller authorization, sealed START admission, final PERMIT/DENY evaluation and original-result recovery | Internal KEY-grant API; no automatic host or caller authentication |
| `delegated_use_command_router` | Dedicated service-hop authentication, exact typed forwarding, strict original JSON and observation bounds propagated through current source checks and COMMIT | Explicit assembly only; workload identity source, protected deployment hop and executable remain separate |
| `PgDelegationUseRepository` | Shared lifecycle/use command identity, immutable admission/receipt/result records and deferred deadline checks | Requires separately provisioned privileges and the same PostgreSQL database as its Flow owner |
| `FlowDelegatedUseOwner` | Actual Flow challenge preparation, immutable proof submission, frozen definition/proof checks, retained nonce admission and final consumption on the supplied connection | Proof ingress must authenticate the caller; storing proof bytes does not verify them |
| `MartyMachineOid4vpProofVerifier` | Concrete Core OID4VP verification plus selected full-machine MAP, key/runtime and required evidence checks | Full-machine, credential and attestation providers must be independently qualified |
| `MartyNestedJwtVcMachineCredentialVerifier` | Actual issuer and holder signatures under the selected nested JWT-VC profile; exact registered credential, current Trust Profile/issuer/key/status and all operation scope | Trusted source owner remains explicit; existing SD-JWT owners are not silently broadened |
| `AuditedMachineOid4vpProofVerifier` | Concrete machine verification followed by committed exact audit bytes and a post-COMMIT original-deadline check | Separate restricted audit writer; source evidence records remain owned and retained by their actual producers |
| `MmfMachineAuthorizationVerifier` | Actual MMF Cedar evaluation of the selected `MACHINE_AUTHORIZATION` policy and typed context | Requires a current trusted policy/schema/entity source; delegated/domain authorization still runs separately |
| `HttpManagedDelegatedReceiptSigner` | Pinned managed issuer/key, separate signing-grant origin, remote signing and independent verification of the returned signature | Explicit deployment selection, key provisioning and live provider qualification remain required |

The component contracts are documented in
[retained use commands](../rust/services/delegated-authority/USE_COMMANDS.md),
[internal authenticated transport](../rust/services/delegated-authority/USE_HTTP.md),
[selected machine authentication](../rust/services/delegated-authority/MACHINE_AUTH.md),
[selected credential verification](../rust/services/delegated-authority/MACHINE_CREDENTIALS.md),
[managed receipt signing](../rust/services/delegated-authority/RECEIPT_SIGNING.md)
and the [Flow delegated-use owner](../rust/services/flow/DELEGATED_USE.md).

## Original intent and retained outcomes

The service commits an immutable command claim before preparing a Flow request
or signing a receipt. Its identity includes the organization, complete typed
actor and command UUID; its digest covers the original P03 intent. Lifecycle
and use commands share that namespace, so one command identity cannot be reused
for a different intent or operation kind.

| Retained state | Result of repeating the original command |
| --- | --- |
| No claim or result | Admission may proceed after current authorization |
| Claim without a completed result | `PreparationPending`; external preparation, evaluation and signing are not repeated |
| Completed result with the same intent | Original immutable response with `recovered=true`, after current read authorization |
| Same identity with changed intent | Conflict |

Pending claims survive preparation failures, process exits, ambiguous signing
and final transaction rollback. This candidate has no lease takeover,
automatic retry, claim deletion or reconciliation override. Recovery of an
original result preserves its historical timestamps, decision and evidence; it
does not refresh authority or create another challenge.

### START_USE

The service resolves the exact active grant revision and terms, checks the
requested operation and obtains an opaque `DelegationChallengeAdmission`.
After the command claim is retained, the configured Flow owner prepares its
nonce and wallet request. A command cannot supply the verifier identity,
nonce, private Flow context or a successful verification flag.

The Flow challenge, retained nonce correlation and original `CHALLENGE` result
commit in one local transaction. The concrete Flow owner checks the immutable
storage identity on the supplied `PgConnection`; it cannot report a write from
a different database as part of that transaction. The current Flow definition
is locked and compared with the prepared snapshot. The retained nonce remains
reserved after expiry or consumption, independently of ordinary verification
nonce cleanup.

### Proof submission and FINALIZE_USE

An authenticated future ingress may call `record_proof_submission` to retain
bounded proof bytes against the original tenant, actor and challenge. Repeating
the same bytes returns the retained submission identity. The public projection
contains identifiers, digest and submission time; raw proof bytes stay in the
restricted Flow source table. That storage step establishes no authentication
or authority.

`FINALIZE_USE` names the original challenge and immutable submission ID. The
service reserves one finalization identity per challenge before evaluating or
signing. The configured proof verifier, current grant/consent owner, operation
constraints and active Cedar policy must produce a completed evaluation.

A completed Cedar FORBID or ABSTAIN produces a signed DENY and consumes the
original challenge. A later policy change cannot turn that original finalization
into PERMIT. Invalid proof, unavailable evidence, expiry and signing failure
remain unresolved errors; they do not fabricate a signed decision.

The final transaction locks the retained command, current grant and admission,
then the original Flow instance and immutable proof. It compares the exact
prepared state, rechecks current permission and grant/consent without extending
the earlier deadline, consumes Flow state and persists the exact compact JWS,
receipt digest and original `FINAL_USE` result. Later failures roll those writes
back together; the original command claim remains. Fresh database-clock checks
and deferred guards reject expiry after later lock or commit-time waits.

Request retrieval can update permitted progress metadata while preserving the
original challenge and frozen request. The finalizer compares the complete
immutable authority projection under its lock, allowing only the bounded
progress already admitted by Flow migration 0005. It preserves the latest
history and uses a fresh post-lock database instant for completion and
consumption. Retrieval during signing or the final row-lock wait no longer
causes an unnecessary unresolved command or regressing timestamps. Cancellation,
changed scope, altered cached requests and expiry still fail closed; no signing
retry is introduced.

## Internal HTTP authentication

The explicitly assembled internal router requires a dedicated authenticated
forwarding workload, configured organization and singleton complete typed actor
metadata. It rejects human credentials, foreign organizations, duplicate
metadata, query strings and malformed P03 commands. Original authentication
observation and expiry travel through the application; both remain clock bounds
after body reads, source observations and lock waits.

Current source access is independently validated before its deadline is
shortened to the earlier authentication expiry. A short service-hop lifetime
cannot qualify an overlong source response. Finalization checks the bound again
after proof resolution and Flow preparation, before beginning a new signing
attempt. Expiry during an already-started signer invocation prevents receipt and
Flow persistence while preserving the unresolved original claim. A newly
authenticated retry cannot restart that work. The human command host and public
Gateway do not select this router.

## Selected machine authentication

`MartyMachineOid4vpProofVerifier` implements the existing `DelegateProofVerifier`
port. Its cryptographic step always uses the concrete Core-backed
`MartyOid4vpDelegateProofVerifier`. The existing public-only VP vectors exercise
actual verification; enrollment proofs cannot satisfy this path.

This selection requires a real current `MACHINE_IDENTITY`, a managed runtime,
an assigned deployment, current active registered public key and a MAP selecting
`MACHINE_KEY` with `OID4VP_VERIFIABLE_PRESENTATION`. The authentication audience
is the Flow verifier client ID; the relying operation audience remains a
separately bound value.

The current Organization inventory remains `SERVICE_ACCOUNT`. Its ACTIVE and
`KEY_CONTROL_VERIFIED` enrollment state does not manufacture a full
MachineIdentity. No automatic conversion or fallback directory source is
provided. A deployment must independently source the full machine record,
current key/runtime state and actual MAP assignment.

Every selected credential type must be authenticated under the configured Trust
Profile and associated with a currently registered machine credential. Required
attestation must bind the selected format, verifier Trust Profile, machine key,
runtime and challenge. A selected machine authorization policy must produce an
error-free permit under its exact current policy identity, revision and digest.
Missing or unqualified providers fail closed. Positive results are trusted
in-process evidence records; HTTP callers cannot supply success booleans.

All provider results bind the entire derived machine, key, runtime, MAP, grant,
challenge and operation scope. Source observations are bounded to 30 seconds,
the full read-only gate has a five-second timeout, and later observations cannot
extend the original deadline. The trusted clock is reread after awaited work.
These are bounded observations across owners, not a distributed atomic
revocation transaction.

The selected `MartyNestedVc2JwtV1` credential adapter verifies actual issuer and
holder signatures for one registered credential covering every required MAP
type. Current authority binds all machine-operation scope, the original compact
credential digest, Trust Profile and issuer key; unknown/revoked/suspended status
fails closed. Its source port requires independently retained authority/status
evidence. No full-machine registry or JWT-VC status owner is inferred from the
existing Organization or managed SD-JWT contracts.

The concrete audited composition retains the canonical machine audit bytes,
document, digest, original times and complete scope in PostgreSQL before
returning a generic proof. Storage failure, deferred COMMIT expiry and expiry
after COMMIT fail closed. Exact duplicate retention is idempotent; expired
historical recovery cannot reconstruct authenticated proof or refresh its time.

Migration 0007 additionally requires every new `MACHINE_IDENTITY` receipt to
reference matching stored audit evidence, including the exact submitted Core
proof digest, actor, tenant, grant revision, key, challenge, operation and
deadline. It rejects machine-audit references on other actor types. Selecting a
plain Core verifier cannot bypass this durable full-machine boundary. Previously
retained receipts remain unchanged and are reported as legacy history when they
lack this later audit; no synthetic backfill is created.

## Managed receipt custody

The managed signer uses a configured HTTPS Signing Keys origin and an exact
tenant, typed issuer, verification method, provider key reference, algorithm and
public-key pin. It resolves the current profile again after receipt preparation
and verifies returned ES256 or Ed25519 signatures over the exact signing input.
The production constructor holds no local private key.

The dedicated `DelegatedDecision` signing-grant origin binds the receipt ID,
tenant, route, issuer, key, purpose, algorithm and exact input digest. Existing
gateway, issuance and Flow origins cannot sign for that purpose. Signing Keys
consumes the one-use grant before its provider call. Receipt-purpose profiles
and key bindings require explicit configuration and cannot reuse another
registered purpose. The default origin set and public purpose catalog do not
acquire receipt authority.

`MARTY_DELEGATED_RECEIPT_SIGNING_ENABLED` only selects the new verifier origin;
it does not create a receipt key, provider policy, use host or capability.
The adapter has separate read and signing credentials, but the read credential
is the existing broader internal Signing Keys credential. A narrower resolver
role, where needed, remains deployment work.

The explicit disposable gate now exercises the actual Signing Keys router/kernel
with OpenBao Transit over local TLS and password-protected Redis, for both
Ed25519 and ES256. It verifies actual signatures, encrypted registry credentials,
distinct mint/verify and resolver/issuer roles, one-use replay, real provider
permission denial, revocation, default-off selection and receipt-only key purpose.
The gate found and fixed stale custom-provider key rotation: receipt signing now
compares the current provider public key before remote signing, as it already
did for the standard managed provider. Provider audit counts verify no signing
call on replay or stale-key rejection and one call for provider permission denial.

This qualifies the actual router/kernel and disposable OpenBao/Redis composition.
It does not qualify the outer HTTP adapter against deployed HTTPS, AWS/IAM,
network timeouts or production credentials. The standalone adapter's real-crypto
HTTP fixture remains separate evidence.

## Persistence and operator boundaries

Delegated Authority migration 0006 adds the shared command identity and retained
use ledger. Flow migration 0005 adds its storage identity, immutable challenge
and proof records, consumption evidence and guards. Additive Delegated Authority
migration 0007 adds exact machine audit retention and receipt linkage. Earlier
migration bytes are preserved. Follow the
[read-only upgrade and rollback procedure](delegated-authority-upgrade.md);
readiness never repairs missing historical evidence.

Existing lifecycle writers additionally require the narrowly scoped shared
command-identity access. They do not receive the use ledger, proof, receipt,
consent or authority producer's privileges. A use writer needs its own reviewed
role composition across the relevant local schemas. Preserving separate
producers and source readers remains necessary even when Flow and the ledger
participate in the same database transaction.

The machine audit writer needs only schema usage, migration metadata SELECT and
SELECT/INSERT on its own audit table. It has no grant, command, Flow, consent or
source-owner access. A future use writer receives audit SELECT only. Readiness
and preflight validate the actual role boundary, guard/index shape, critical
hash/reference/byte-document CHECK constraints and retained-data consistency.

Disabling a future host stops new admissions while preserving original claims,
nonce reservations, proofs, decisions and receipts. Rollback does not erase an
ambiguous command or free its identity for reuse.

## Evidence meaning and Rifare

The result and Flow completion carry `semantics: EVIDENCE_ONLY`. They record the
Marty identity and authority decision for one exact request. A valid receipt
does not assert that a merchant accepted an order, a payment occurred, a budget
was reserved or a provider completed work.

Rifare continues to own logical agents, models and prompts, orchestration,
domain/resource permissions, budgets, business idempotency, reservations,
provider execution and business outcomes. It must consume qualified public
Gateway contracts; this candidate does not permit importing private Marty Core
code or reading Marty storage. A local atomic receipt/nonce commit does not
make an external business side effect atomic.

## Retained-use baseline validation

The following are separate verification views and overlap; do not add them into
one aggregate. Rust checks use the locked dependency graph offline. Hosted
Actions and production deployment are outside this evidence. This table records
the prior `085d65c` baseline; the current follow-on checks are recorded in the
[milestone checkpoint](agent-trust-runtime-milestones.md#machine-evidence-and-authenticated-transport-follow-on).

| Check | Result |
| --- | --- |
| Principal binding, enrollment and pinned Protocol corpus | 56 passed, zero ignored; includes 10 new MAP tests and four compile-fail contracts |
| Selected machine gate and real MMF Cedar | 13 passed, zero ignored; actual Core VP crypto, full evidence scope, requirements, clocks, timeout and aggregate audit provenance |
| Opaque machine-proof contract | One service compile-fail doctest passed |
| Retained use command ledger | 15 focused tests passed, including all 14 explicit PostgreSQL cases |
| OID4VP verifier-ID compatibility and retained ledger | 24 focused tests passed after preserving opaque verifier client IDs; includes the 15 ledger tests |
| Read-only upgrade preflight | 101 live PostgreSQL tests passed |
| Receipt signing adapter | Six tests passed with actual ES256/Ed25519 signatures and negative returned-key/origin/response cases |
| Signing-grant library | 32 passed; three existing live provider fixtures remain ignored |
| Signing Keys library | 274 passed; 22 existing live/external fixtures remain ignored |
| Signing Keys executable | Targeted binary compilation passed |
| Full delegated-authority regression | 184 passed, zero failures or ignores, with all PostgreSQL cases enabled and serialized; one separately configured external command-corpus case was explicitly filtered |
| External command corpus | The filtered case separately passed against the clean pinned Protocol checkout |
| Concrete Flow transaction/proof integration | 10 passed, zero ignored; includes six new explicit PostgreSQL cases with actual Core/ES256 proof, signed PERMIT/DENY, post-sign rollback, source isolation, retrieval progress and deferred expiry |
| Broader Flow library | 92 passed; 13 fixture cases ignored in the normal run, including the six delegated-use cases and public-retention case executed explicitly |
| Existing Flow PostgreSQL regressions | Five passed across retained-data handling, physical-start/finalization/callback atomicity, issuance-prerequisite freshness and public HTTP retry/quota/cancel races; one separate fenced-role case remains ignored |
| Combined six-package all-targets compilation | Passed for Gateway, Flow, Delegated Authority, principal binding, signing grant and Signing Keys |
| Formatting and whitespace | Scoped Rust formatting and CRLF-aware diff checks passed |

The full service aggregate preceded the final verifier-client-ID correction;
the subsequent 24-test run covers that correction and the ledger/OID4VP paths.
The external command corpus was then run separately with its explicit source
configuration instead of being counted as an unexecuted aggregate case.
The focused Flow group overlaps the normal library suite in four tests. Its six
delegated-use cases and the separately selected public-retention case cover
seven of the normal run's thirteen fixture-gated ignores. External TLS/OpenBao
and separately provisioned fenced-role qualification remain outside these runs.

The public VP fixtures contain no private keys. Signature adapter tests generate
ephemeral keys in memory. Credential and attestation test providers exercise
the gate's contract; they do not qualify external issuers or attesters. The
receipt HTTP fixture models Signing Keys responses and replay denial; it does
not replace live custody qualification. The current follow-on separately
executes the disposable OpenBao/Redis receipt gate described above; AWS/IAM and
external HTTPS deployment remain open.

## Remaining runtime milestones

1. Qualify the independently authenticated full-machine/MAP source, credential
   issuer/status sources, required attestation and active machine/domain policy
   sources. Connection/grant aggregation and broader authority/session profiles
   retain their separate contracts.
2. Compose the implemented internal router into an explicit executable after
   authoritative workload sources are qualified. Separately authenticate wallet
   request retrieval and immutable proof submission; provision reviewed use,
   Flow, audit and source credentials. The human administration host must
   continue rejecting use commands.
3. Qualify deployed HTTPS and production custody/credentials beyond the passing
   disposable OpenBao/Redis gate, including the outer receipt adapter and any
   selected AWS/IAM or network-timeout profile.
4. Qualify retained recovery, source freshness and the selected public
   request/response and independent consumer verification contracts across the
   deployed services. Pending command reconciliation needs its own reviewed
   design before any automatic retry or takeover is introduced.
5. Promote public support/discovery only after those gates pass, then integrate
   Rifare through those public features with its own operation commit and
   idempotency rules. This checkpoint changes no Rifare execution behavior.
