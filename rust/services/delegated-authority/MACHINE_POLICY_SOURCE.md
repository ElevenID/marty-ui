# Current machine policy source and durable MMF decision

`machine_policy_source` supplies a concrete current source and audited evaluator
for the MAP's optional `MACHINE_AUTHORIZATION` requirement. It composes with the
existing full-machine gate. It adds no public route, service host, discovery
capability, domain execution or alternate proof wire.

## Concrete composition

The configured host constructs these components:

1. Organization's `PgMachineAuthorizationPolicySource`, using a dedicated
   read-only credential for the actual Organization policy owner.
2. `PgMachineAuthorizationEvidenceRepository`, using a separate append-only
   delegated-authority credential.
3. `OrganizationMachineCedarPolicySource`, pinned to one organization and
   deployment. It reads only the exact policy UUID selected by the qualified MAP.
4. `AuditedMmfMachineAuthorizationVerifier`, which accepts that concrete source,
   evaluates through the actual MMF Cedar engine and retains the exact result.

The host passes the audited evaluator as the machine gate's authorization
provider. An arbitrary `MachineCedarPolicySource`, caller policy text or
successful decision flag cannot replace either the owner source or engine in
this concrete wrapper.

The Organization owner supplies only the explicit named machine policy type,
its immutable revision and the fixed `MartyMachine/1.0` schema. Generic `CUSTOM`
policies do not qualify. Source inspection verifies active organization and
policy state, exact history bytes, schema and text. The policy digest binds both
the actual enabled statements and schema. See the
[owner lifecycle](../organization/MACHINE_AUTHORIZATION.md).

## Scope and source evidence

The source binds the complete already qualified machine scope: tenant, machine
UUID, deployment, complete typed principal, runtime, current key, MAP and digest,
grant and revision, challenge and nonce digest, verified proof reference, action,
audience, resource, operation profile and digest. Tenant or deployment mismatch,
unsupported principal, unknown policy, inactive state and invalid fields fail
before evaluation.

Its two Cedar entities contain only the exact principal and machine UUID. They
have no attributes or hierarchy. This bounded schema supports context-based
machine authentication rules without fabricating roles, status or business
permissions. The authoritative full-machine source still owns the underlying
machine, deployment, key, assignment and status. The policy source does not
reclassify a service-account directory record.

Before returning a policy result, the source retains an exact record containing
the complete scope, owner policy snapshot and history reference, policy text,
schema, entities, digest and original observation/deadline. The reference is
`urn:marty:machine-policy-source:sha256:<digest>`. The actual record exists before
its reference leaves the adapter.

## Evaluation evidence and database enforcement

The audited evaluator performs actual MMF Cedar evaluation. Only an error-free
permit can produce an accepted result. Forbid, abstain, invalid entities/schema,
source failure and expired evidence fail closed. The separate delegated/domain
Cedar evaluation remains required downstream.

For a permit, the wrapper retains the exact scope and constructed context,
source reference, selected policy UUID/revision/digest, observation, evaluation
time, deadline and decision under
`urn:marty:machine-authorization:sha256:<digest>`. It returns the existing typed
provider result only after durable retention and a fresh deadline check.

Migration `0008_machine_authorization_evidence.sql` adds the append-only
`machine_authorization_evidence` table. Byte/document/digest/reference CHECKs
bind the exact retained record. Source and evaluation guards require all scope,
policy and time bindings to match; an evaluation cannot refer to a missing or
different source. Deferred guards check the original deadline during transaction
completion; the post-COMMIT runtime check covers later database or network delay.
Exact duplicate retention preserves original bytes and retention time.
Updates, deletion and truncation fail even through ordinary owner SQL.

An additive guard on new aggregate `machine_authentication_evidence` requires
every selected machine authorization result to match a retained permit with
the same complete scope, policy revision/digest and time bounds. Therefore a
hash-only result from the earlier unaudited MMF composition cannot reach a new
durable machine receipt. Earlier aggregate history remains unchanged; no audit
backfill or renewed authority is invented.

The new evidence writer has only SELECT/INSERT on its own table and SELECT on
the migration ledger. It receives no policy, machine registry, lifecycle, grant,
Flow, receipt or aggregate-audit write privilege. The aggregate machine audit
writer additionally needs SELECT on this table for the binding guard, never
INSERT. Readiness checks actual role capabilities, exact trigger shapes,
byte/digest/reference CHECK expressions and primary-key shape. Grant options,
reachable administrative or predefined `pg_` roles, replication capability and
cross-owner capabilities are rejected.

## Deadlines, cancellation and history

Every source uses the original observation's at-most-30-second bound. Database
time and the trusted runtime clock are checked across reads, evaluation,
retention and COMMIT. Later reads never renew the original deadline. Original
RFC 3339 timestamps remain in exact evidence bytes; PostgreSQL converts those
same timestamp strings for its comparison columns, avoiding disagreement from
separate nanosecond-to-microsecond serialization paths.

The enclosing provider timeout still bounds unavailable sources. Only the final
immutable evidence COMMIT is shielded in a narrowly spawned completion task.
If a caller is cancelled or times out at that point, COMMIT may finish as
history; the caller receives no positive proof and no automatic retry occurs.
The normal successful path awaits completion and rechecks the original clock
bounds. There is no business action or grant mutation in this task.

`recover` returns opaque historical evidence scoped by tenant and exact
reference. It verifies bytes and digest and performs no source read or policy
evaluation. It has no conversion into current machine authorization. A host must
separately authorize historical inspection; there is no public audit route.

## Verification and remaining deployment work

`machine_policy_source_tests.rs` exercises actual local PostgreSQL, real
Organization policy administration and the MMF engine. It covers exact retained
source/evaluation records, current policy archival, complete scope retention,
foreign tenant/deployment rejection, actual forbid behavior, duplicate history,
writer isolation, missing source, immutable records and expiry after successful
source/evaluation COMMIT. Its upstream machine and cryptographic proof inputs
are explicitly synthetic fixtures; it does not claim live workload or
attestation qualification.

The sources now have a concrete selected owner and durable evidence path.
Production source deployment, authenticated workload/actor use permissions,
required attestation formats, separate domain policy sourcing, protected use-hop
transport, authenticated Flow request retrieval/proof ingress, custody and
end-to-end host qualification remain independent gates.
