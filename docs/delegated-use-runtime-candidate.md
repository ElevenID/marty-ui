# Retained delegated-use runtime candidate

The retained-use candidate combines internal `START_USE`/`FINALIZE_USE`, the
concrete Flow transaction owner, full-machine authentication, actual credential
and policy sources, immutable machine audit and managed decision-receipt signing.
The current follow-on adds explicit machine-use access rights, a concrete current
delegated-use Cedar policy owner, certificate-authenticated internal transport,
and protected request retrieval/proof submission with retained original results.
The explicit `marty-delegated-use` executable now assembles these owners behind
mandatory mutual TLS. It stays disabled unless explicitly configured and does
not install a public Gateway route.

Original signed receipts now have a protected recovery route using current
`RECOVER_RESULT` access. A separate offline consumer verifies their signatures,
exact original request context and retained byte digest, returning distinct
fresh and historical evidence types. The actual executable also has a disposable
remote-custody startup/readiness gate; its metadata wire fixtures are explicitly
separate from qualification of full deployed owner services.

A separate managed lifecycle gate now uses actual template/policy gRPC owners,
fresh managed machine issuance and the real Signing Keys HTTPS service for
request, credential and receipt signatures. The actual host serves the full
internal use/recovery sequence and the independent consumer verifies the
returned receipt. Privileged catalog/trust/identity setup, in-process Issuance
bootstrap and readiness-only reference fixtures are documented in the
[host qualification runbook](../rust/services/delegated-use/README.md#actual-executable-and-managed-lifecycle-qualification).
The separately selected managed caller surface now serves the advertised
request and signed response URIs through the same mTLS and current-access
owners. Its independent Rust client retains original commands, requires
configured TLS trust, and performs no automatic redirect or retry. The public
machine lifecycle is qualified separately from the internal lifecycle;
production deployment and general wallet interoperability remain separate.

The human `marty-delegation-commands` executable and its Gateway surface still
reject use commands. Each current source, transport, database role and receipt
signer still requires explicit composition. Public MIP remains 0.5.0; support levels and
capability discovery remain unchanged. The Protocol source stays pinned at
`6126da7619e057be2ff58dd38a5d50f49891d1b3`.

## Implemented composition

| Component | Implemented responsibility | Boundary that remains explicit |
| --- | --- | --- |
| `marty-delegated-use` | Default-off serving executable, strict bounded configuration, fourteen restricted database connections, concrete source/provider assembly and readiness before mandatory mTLS listen; separate opt-in managed caller routes | Deployed CA/custody/role qualification and general wallet interoperability remain separate |
| `DelegationUseCommandService` | Strict P03 use intent, durable original command claims, current caller authorization, sealed START admission, final PERMIT/DENY evaluation and original-result recovery | Internal KEY-grant API; requires explicit authenticated host composition |
| `OrganizationDelegationUseCommandAuthorizer` | Current active tenant/full-machine/deployment and five explicitly assigned entrypoint rights, including historical result recovery | Does not authenticate the transport or grant consumer business rights |
| `delegated_use_command_router` | Explicit mutual-TLS or trusted-forwarder authentication, strict original JSON and observation bounds propagated through current source checks and COMMIT | The new executable selects mTLS only; no public Gateway installation |
| `BoundDelegatedUseMtlsServer` | Mandatory client certificate verification, exact leaf URI/digest-to-machine mapping and original certificate validity bounds; remote keyless server identity | CA issuance, revocation, pin rotation and deployed custody remain operator qualification |
| `PgDelegationUseRepository` | Shared lifecycle/use command identity, immutable admission/receipt/result records and deferred deadline checks | Requires separately provisioned privileges and the same PostgreSQL database as its Flow owner |
| `FlowDelegatedUseOwner` | Actual Flow challenge preparation, immutable proof submission, frozen definition/proof checks, retained nonce admission and final consumption on the supplied connection | Storing proof bytes does not verify them |
| `FlowDelegatedUseIngress` | Authenticated current-authorized request retrieval and proof submission; exact retained request JWS; durable preparation claim before signing; deadline checks through COMMIT | The selected public wallet adapter associates frozen DCQL direct_post input; general wallet interoperability remains separate |
| `MartyMachineOid4vpProofVerifier` | Concrete Core OID4VP verification plus selected full-machine MAP, key/runtime and required evidence checks | Full-machine, credential and attestation providers must be independently qualified |
| `MartyNestedJwtVcMachineCredentialVerifier` | Actual issuer and holder signatures under the selected nested JWT-VC profile; exact registered credential, current Trust Profile/issuer/key/status and all operation scope | Trusted source owner remains explicit; existing SD-JWT owners are not silently broadened |
| `AuditedMachineOid4vpProofVerifier` | Concrete machine verification followed by committed exact audit bytes and a post-COMMIT original-deadline check | Separate restricted audit writer; source evidence records remain owned and retained by their actual producers |
| `AuditedMmfMachineAuthorizationVerifier` | Actual MMF evaluation against the concrete current Organization machine policy and retained source/evaluation evidence | Machine authentication eligibility remains distinct from delegated-use policy |
| `OrganizationDelegationCedarPolicySource` | Concrete current Organization policy, immutable attributed revisions and exact retained source scope; real MMF compilation under a fixed context schema | Selected EXACT_OPERATION only; external-domain attributes and permissions remain separate consumer adapters |
| `HttpManagedDelegatedReceiptSigner` | Pinned managed issuer/key, separate signing-grant origin, remote signing and independent verification of the returned signature | Explicit deployment selection, key provisioning and live provider qualification remain required |
| `delegated_use_receipt_router` | Bounded current-authorized recovery of the exact FINAL_USE compact receipt, original result and digest, with original times preserved | Existing RECOVER_RESULT access; internal host only; no reevaluation or new signature |
| `marty-delegated-receipt-consumer` | Independent ES256/EdDSA verification, caller-pinned trust/context/retention, strict wire checks and separate fresh/history output types | Offline evidence only; no service/storage dependency, current revocation lookup or business-execution permission |
| `marty-delegated-use-client` | Independent mTLS transport, retained command IDs/digests, exact same-origin advertised URLs, bounded strict responses and original result/receipt recovery | Caller supplies verified request fields and separate receipt trust; no private service/storage dependency or automatic retry |

The component contracts are documented in the
[serving-host runbook](../rust/services/delegated-use/README.md),
[retained use commands](../rust/services/delegated-authority/USE_COMMANDS.md),
[internal authenticated transport](../rust/services/delegated-authority/USE_HTTP.md),
[certificate-authenticated transport](../rust/services/delegated-authority/USE_MTLS.md),
[explicit machine use access](../rust/services/organization/MACHINE_USE_ACCESS.md),
[current delegated-use policy](../rust/services/delegated-authority/DELEGATION_POLICY_SOURCE.md),
[selected machine authentication](../rust/services/delegated-authority/MACHINE_AUTH.md),
[selected credential verification](../rust/services/delegated-authority/MACHINE_CREDENTIALS.md),
[managed receipt signing](../rust/services/delegated-authority/RECEIPT_SIGNING.md),
the [independent receipt consumer](../rust/crates/delegated-receipt-consumer/README.md),
the [Flow delegated-use owner](../rust/services/flow/DELEGATED_USE.md), and
[protected request/proof ingress](../rust/services/flow/DELEGATED_USE_INGRESS.md).

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

### Recovering the exact signed artifact

`POST /internal/v1/organizations/{organization}/delegated-use/receipts/recover`
accepts only the existing `RECOVER_RESULT` wire. It binds the original command
and digest to the exact tenant and typed actor, checks current recovery access,
reads the matching FINAL_USE artifact in a bounded read-only snapshot, and
rechecks access after awaited reads. The result adds the original compact JWS
beside the unchanged original response, receipt reference/digest and
`EVIDENCE_ONLY` marker. A START_USE result or pending claim cannot supply bytes.

The read can recover historical evidence after grant revocation or expiry while
the caller still has current recovery access. It does not sign, mutate the
ledger, reevaluate the decision, refresh timestamps or renew the first access
deadline. The independent consumer authenticates those exact original bytes
using a separately trusted public key and context; it never derives an expected
actor, operation, nonce or policy from an unverified receipt. Current transport
authorization and the original command/challenge/proof correlation remain
responsibilities of the caller's authenticated workflow.

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

The explicit `FlowDelegatedUseIngress` authenticates and authorizes retrieval
and proof submission against the original tenant, actor and challenge. Its
request preparation claim precedes external signing. A completed retrieval
returns the exact original signed request; an unresolved claim never signs
again automatically. Generic and paired-wallet request handlers reject delegated
instances, preserving this boundary. See [protected Flow ingress](../rust/services/flow/DELEGATED_USE_INGRESS.md).

The internal `record_proof_submission` owner retains bounded proof bytes. Repeating
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

The explicitly assembled internal router selects either verified mutual TLS
with an exact leaf certificate/URI-to-machine mapping or the earlier separately
trusted forwarding workload. The mutual-TLS path derives its typed actor from
deployment configuration and rejects HTTP identity overrides. The forwarding
path requires its dedicated service credential and singleton complete typed
actor metadata. Both preserve the configured tenant, strict P03 input and
original authentication observation/expiry through body reads, source
observations and lock waits.

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

The Organization SERVICE_ACCOUNT inventory remains separate. Its ACTIVE and
`KEY_CONTROL_VERIFIED` enrollment state does not manufacture a full
MachineIdentity. The concrete full-machine registry explicitly owns a separate
machine record, current key/runtime state and deployment MAP assignment, with
retained source observations. No automatic inventory conversion or fallback
directory source is provided.

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
evidence. The concrete source composes the actual Trust Profile and Issuance
owners for this explicit nested JWT-VC selection. Existing managed SD-JWT
contracts are not broadened.

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
migration 0007 adds exact machine audit retention and receipt linkage. Migration
0008 binds selected machine authorization to retained source and MMF evaluation
records. Organization migrations 0007–0008 add dedicated machine-use access and
delegated-use policy ownership. Flow migration 0006 adds immutable request
preparation claims, exact request results and proof-ingress authorization.
Delegated Authority migration 0009 and Flow migration 0007 add five fixed
migration-owned row-lock helpers. Serving credentials can take the required
locks without UPDATE authority on grants, definitions or immutable evidence.
The original claim trigger delegates only its grant lock to the new helper;
all original claim checks remain. Readiness checks exact helper bodies, owners,
return types and search paths, and rejects PUBLIC execution.
Earlier migration bytes are preserved. Follow the
[read-only upgrade and rollback procedure](delegated-authority-upgrade.md);
readiness never repairs missing historical evidence.

The signed migrations image includes the explicit operator entry point
`/usr/local/bin/marty-delegated-use-migrate`. Run it once with
`delegated-authority` and once with `machine-credential-source`, using a
separate one-shot container for each schema on the selected application
database. Mount only that schema's owner URL and the PostgreSQL server CA as
read-only files. Set `DELEGATED_USE_MIGRATION_DATABASE_URL_FILE` and
`DELEGATED_USE_MIGRATION_DATABASE_CA_FILE` to their container paths. The
command uses one connection with certificate and hostname verification, and
reuses the native migration ledger for safe retries. Run the existing
application migrations before these optional owner migrations, then apply the
reviewed serving grants and validate the restricted runtime roles. Remove the
owner mounts when each container exits. The default migrations entry point and
the delegated-use server do not invoke this command.

Existing lifecycle writers additionally require the narrowly scoped shared
command-identity access. They do not receive the use ledger, proof, receipt,
consent or authority producer's privileges. A use writer needs its own reviewed
role composition across the relevant local schemas. Preserving separate
producers and source readers remains necessary even when Flow and the ledger
participate in the same database transaction.

The machine audit writer needs schema usage, migration metadata SELECT,
SELECT on retained machine-authorization evidence, and SELECT/INSERT on its own
audit table. It has no grant, command, Flow, consent or
source-owner access. The explicit use writer receives audit SELECT only. Readiness
and preflight validate the actual role boundary, guard/index shape, critical
hash/reference/byte-document CHECK constraints and retained-data consistency.

Disabling the host stops new admissions while preserving original claims,
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
[milestone checkpoint](agent-trust-runtime-milestones.md#current-managed-network-lifecycle-follow-on).

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

1. Qualify the concrete full-machine/MAP, credential, machine-policy, use-access
   and delegated-use policy sources in a deployed composition. Implement and
   qualify required attestation when selected. External domain policy,
   connection/grant aggregation and broader authority/session profiles retain
   their separate contracts.
2. Qualify deployment of the implemented default-off executable, including its
   mandatory mutual TLS, exact certificate bindings and separately provisioned
   use, Flow, audit and source credentials. Qualify CA issuance/revocation and
   pin rotation. The human administration host continues rejecting use commands.
3. Qualify production custody/credentials beyond the disposable complete host
   lifecycle, including production HTTPS origins, restart/outage behavior and
   any selected AWS/IAM or network-timeout profile. The local lifecycle already
   exercises the outer request/credential/receipt HTTPS adapters with separate
   managed keys; it does not select production credentials.
4. Qualify the implemented protected receipt recovery and independent verifier
   across deployed services, together with source freshness, public clients and
   the selected public request/response contract. Pending command reconciliation needs its own reviewed
   design before any automatic retry or takeover is introduced.
5. Promote public support/discovery only after those gates pass, then integrate
   Rifare through those public features with its own operation commit and
   idempotency rules. This checkpoint changes no Rifare execution behavior.
