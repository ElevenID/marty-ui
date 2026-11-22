# Full machine registry and selected deployment source

The optional `machine_registry` module owns a distinct full `MACHINE_IDENTITY`
registration, managed runtime binding and deployment Machine Authentication
Policy (MAP) selection. It supplies the live state required by the existing
Core-backed machine proof gate. Organization's agent directory remains
`SERVICE_ACCOUNT` inventory; enrollment never creates a registry entry.

No executable, public route or capability announcement enables this module.
The current internal application API and concrete PostgreSQL source are ready
for an explicitly configured host to compose and qualify.

## Accountable administration

`MachineRegistryService` uses the existing Organization database and real
human membership/RBAC model. `register` and `replace` require both the matching
`machine-identity:create` or `machine-identity:update` permission and
`machine-authentication-policy:assign`. `inspect` requires
`machine-identity:view`; the lifecycle methods require the corresponding
`machine-identity:suspend`, `machine-identity:revoke` or
`machine-identity:retire` permission. Forwarded API keys cannot use these APIs.

The owning host must authenticate the forwarded human identity before calling
the application, as with the existing Organization administration services.
The service independently loads and locks current active organization,
membership, role and permission rows. It reloads authorization after lock waits
and before commit. Caller-created permission lists and ownership claims are
not accepted. The immutable revision history, current projection and ordinary
Organization audit event commit together; an incomplete revision cannot commit.

Publication accepts the four existing pinned documents:

- A principal/runtime binding record.
- Its independently selected deployment configuration.
- A complete full MachineIdentity snapshot and registered credential IDs.
- The exact active selected MAP document, including every credential,
  attestation and machine authorization requirement.

The bounded strict parsers and `qualify_machine_binding` validate all four.
The selected principal is `MACHINE_IDENTITY`, runtime is `MANAGED`, and both
authentication issuer and subject equal the machine principal. A session
binding is unsupported. The active public JWK and typed fingerprint must agree,
the key must be current, and no conflicting machine lifecycle marker is allowed.
Credential IDs are registration facts; this service never claims those
credentials have been verified or issued.

The MAP is selected in the administrator-published deployment registration.
An operational use request supplies no MAP or replacement configuration.
Assignments are versioned per registered machine: replacing one registration
does not silently mutate the selections of another machine. A host that wants
a coordinated policy rollout must explicitly update each affected registration.
The source does not infer current policy from another registry or from a
shared policy ID alone.

`replace` requires the expected revision and is available only while the
registration is active. It preserves organization, full machine ID, typed
principal/source identity, runtime instance, deployment, creation provenance
and the machine's original creation timestamp. It explicitly replaces selected
key, credentials, policy or other permitted document metadata. A key identifier
cannot be rebound to different material, and a replaced historical key or
fingerprint cannot be reactivated. Existing grants are never retargeted.

Suspension, revocation and retirement disable current lookup. These transitions
preserve the last published protocol documents as history and increment the
administrative revision. This candidate has no resume operation. Retirement is
terminal; revocation can only be followed by retirement. An expired key does
not prevent inspection or terminal administration of its historical entry.

An active registration establishes the owner's current facts and selection.
It does not establish workload key possession, host isolation, credential issuer
trust, attestation, machine authorization, delegated authority or a business
permission. Those are still verified independently by the machine and delegated
use gates.

## Concrete current source

`PgMachineRegistrySource` takes a `MachineRegistrySelection` containing the
trusted configured tenant and deployment. `observe` takes the complete typed
machine principal/key plus immutable grant/revision, challenge and requested
operation identity. The delegated-authority
`OrganizationMachineAuthenticationStateSource` adapter validates the grant and
request relationship, constructs that scope, and implements the existing
`MachineAuthenticationStateSource` trait.

The source uses one repeatable-read PostgreSQL snapshot for active organization,
current registration and its exact immutable revision. It chooses by configured
tenant/deployment and requested typed machine identity. It revalidates
all documents and key validity at observation time; a missing, inactive, foreign,
expired or inconsistent source fails. A wrong grant key cannot select a newer
key by matching only the principal.

The exact source revision, all four documents, administrator provenance,
original request scope, database observation and original deadline are retained
in `machine_registry_observations`. The evidence reference hashes the exact
stored bytes and has the form `urn:marty:machine-registry:sha256:<digest>`.
A successful result is returned only after an exact stored-byte reread, the
evidence commit and another
trusted clock check. The corresponding source record therefore exists before
the aggregate machine audit refers to it.

The deadline is the earliest of the incoming operation start plus 30 seconds
and the registered key expiry. Waiting for the database or retention lock cannot
renew it. A deferred database guard checks the original deadline at commit;
the process also checks after commit. Only the final COMMIT runs in its own
task, so cancellation by the bounded machine gate detaches that decision and
allows it to finish. It yields no positive observation or automatic retry.
An uncertain or expired result grants no
positive source assertion, even if durable history later proves that it committed.

This is a bounded cross-owner observation. Administrative revocation after its
database snapshot does not retroactively rewrite it or make the entire machine
gate a distributed serializable transaction. The machine gate preserves its
original deadline, and the final-use owner still checks current grant authority,
challenge admission and atomic replay protection.

`recover` returns `HistoricalMachineRegistryObservation` scoped to the configured
tenant/deployment and exact reference. It validates original bytes, digest and
timestamps. It has no conversion to a current observation or proof and never
renews a deadline. A host must separately authorize history inspection; no
public history route is installed.

## Storage and privilege boundary

Migration `0005_machine_registry.sql` is additive. It creates
`machine_registry_entries`, `machine_registry_history` and
`machine_registry_observations`, plus eight guards. Historical Organization
migrations and existing rows are unchanged. Current identity and one-way lifecycle
rules, complete administrator/audit provenance, historical key non-reuse,
append-only evidence and exact byte/digest/reference binding are enforced in
PostgreSQL. Readiness checks trigger timing/shape and the exact reviewed function
bodies; matching names alone are insufficient.

The source uses a dedicated nonowner connection identity. It needs schema USAGE,
SELECT on `rust_schema_versions`, `organizations`, `machine_registry_entries`,
`machine_registry_history` and `machine_registry_observations`, and INSERT only
on `machine_registry_observations`. It has no current registry or history writes,
grant/use/Flow access, unrelated table access, destructive privileges, schema
creation, executable security-definer escape or reachable administrative role.
Predefined PostgreSQL roles and replication privilege are also rejected; this
source needs no server-file, server-program or other predefined-role capability.
PostgreSQL 17 `MAINTAIN` is rejected. The catalog scan excludes only the literal
`pg_` schema prefix; application schemas such as `pgx_*` remain fully inspected.
These checks run for each observation, including roles reachable with SET ROLE.
The source reads through MVCC and does not receive UPDATE merely to take row
locks. The administration connection remains distinct from this source identity.

## Local qualification

`tests/machine_registry_postgres.rs` exercises actual PostgreSQL with a restricted
source connection and real Organization owner/member/role records. The cases
cover attributable publication and retention, absence of inventory promotion,
separate MAP assignment permission, membership removal during a row wait,
explicit policy replacement and immutable older evidence, revision conflicts,
revocation, disallowed source writes, excessive privileges, foreign deployment
and scope, stale/future starts, retention lock expiry, historical mutation guards,
SERVICE_ACCOUNT rejection, missing credentials, malformed MAPs and immutable
runtime identity. They also check key expiry with preserved history and terminal
administration, key rotation without historical key reuse, privilege grant
options and named constraint replacement, complete provenance at deferred
commit, and caller cancellation while the actual evidence COMMIT is in progress.

These tests use locally authored machine registrations and public fixture keys.
They qualify this source's storage and authorization behavior. Deployment source
provenance, real credential issuer/status ownership, attestation providers,
authenticated workload transport and production host qualification remain
separate requirements.
