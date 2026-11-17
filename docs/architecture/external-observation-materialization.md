# Explicit unsigned observation materialization

The public Common Gateway is the only connector-to-Marty interface. A producer
submits an unsigned observation with its organization API key. Admission writes
an immutable receipt, not a verified evidence fact or an issuance authorization.

Core can explicitly attach that receipt to its application evidence journal:

* `POST /v1/organizations/{organization_id}/external-observation-receipts/{observation_id}/materialize`
  accepts only `source_id` and `expected_application_revision`.
* `POST /v1/organizations/{organization_id}/external-observation-receipts/{observation_id}/materialization`
  accepts only `source_id` and returns a snapshot of the original attachment.

Both require an authenticated administrator session, allowed Origin, matching
active session tenant, and current canonical `external-observation:manage`.
Producer API keys cannot invoke either action. The Gateway forwards bounded
original JSON with trusted service and user context; Core reauthorizes the actor.
The body limit is 4096 bytes. Responses are `no-store`.

On first attachment Core locks the current binding and application, requires the
latest receipt head, exact current binding revision and definition, matching
application subject, pending/under-review lifecycle, unexpired application, and
the expected application revision reported by binding inspection. Every evidence
identity, scope, timestamp, claim and producer reference comes from the admitted
receipt and Core binding. Persisted envelopes pass the strict wire decoder again;
admission audit and receipt metadata must agree. Private key material is rejected
using the same shared policy as other canonical evidence writers.

The fact always has `verification.status = UNVERIFIED` and
`verification.method = UNSIGNED_PRODUCER_ATTESTATION`, with no requirement ID.
The action does not call a verifier, approval evaluator, transaction preparer,
signer, or issuer. Claims cannot override verification. Separate Core verification
and policy remain necessary for issuance. Revoking a producer does not erase its
admitted history: a currently authorized administrator may attach an already
admitted receipt while the binding and application remain eligible. Receipt age
does not turn an unsigned fact into a current verified assertion.

Fact insertion, current-head replacement, application revision advancement and
actor event commit atomically in a SERIALIZABLE transaction. Final checks recheck
authority, application expiry, the binding, admission receipt/audit/head and the
exact inserted fact/head/event after writes. The action changes no application
status, claims, submitted evidence, approval, or issuance transaction. Advancing
`updated_at` invalidates stale application approval snapshots. A new fact can
supersede only an older unsigned attachment for this same producer/binding; an
existing verified or unrelated head is protected.

Fact and event IDs are domain-separated deterministic UUIDs derived from tenant
and immutable receipt ID. The logical key is a SHA-256 digest of the versioned
unsigned-mapping namespace, tenant, producer and binding. Payload hashing uses the
normalized receipt content. The original intent revision, actor, receipt/key/
binding/observation references and resulting application revision are retained.
Matching retries require the original expected application revision and return
the original result, including its original actor; they never move an old head,
advance the application again, or reapply after application closure. A different
expected revision conflicts. Current administrator authorization remains required
for every retry and inspection.

A failed COMMIT is `admin_reconciliation_required`, not proof of rollback. Inspect
the same source and observation ID. Found returns the original historical result,
not current application eligibility. Absence is a snapshot and cannot prove an
in-flight transaction will not commit. No automatic write retry or replacement ID
is permitted; reconcile the original intent manually. This API supplies durable
reconciliation, not provider/process recovery automation.

Only the canonical Core application-writer pool mounts these two actions. The
separate observation role remains unable to insert/update/delete canonical facts,
fact heads, events or issuance transactions, or mutate application authority.
Startup checks both roles' privileges without creating roles, grants or tables.
No new schema migration, connector database access, private connector-to-service
call, or shared credential custody is introduced. The feature remains under the
existing disabled-by-default observation setting; existing Kubernetes/Compose
profiles do not activate it or forward its isolated database credentials.

Qualification requires the focused real-PostgreSQL tests, the actual pinned Core
policy regression in issuance library tests, full Gateway/production crate CI,
and independent security review of the exact candidate. These checks do not
replace the outstanding deployed end-to-end connector/Gateway/wallet and network
isolation qualification.
