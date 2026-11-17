# External connector boundary

Provider integrations run in independently owned repositories and deployments.
The public Common Gateway is the single platform integration point. Platform UI
and services own generic capabilities; provider protocols and administration
belong to the connector. The extracted [Canvas connector](https://github.com/ElevenID/canvas-integration)
is one implementation of this boundary.

## Ownership and authority

| Owner | Responsibilities |
| --- | --- |
| Connector | Provider protocol callbacks, provider credentials, administration UI, mappings, cursors, jobs and connector-owned storage |
| Common Gateway | Public request schemas, API-key authentication, organization binding, permissions, bounds and forwarding to canonical owners |
| Core | Canonical identity, learner ownership, evidence admission, policy, approval, application lifecycle, issuer keys, signing, status and audit |

An external observation is not identity proof, learner ownership, approval or
signing authority. Email, provider subject IDs and course membership do not
establish canonical learner association. Authorization derives from the
platform principal and canonical resource ownership, not caller-supplied tenant
or identity fields.

A server-side connector client uses a fixed public Gateway HTTPS origin and an
organization-scoped `X-API-Key`. It verifies TLS, refuses redirects, and bounds
requests and responses. Provider tokens and Gateway keys stay out of browser
bundles, URLs and logs. Read permissions never authorize writes.

Connectors cannot import private platform application modules, call private Core
or service endpoints, access platform databases or Redis, use shared internal
queues, or receive service keys, signing grants or issuer private material.
Provider tool signing remains connector-owned; canonical credential signing
remains Core-owned. Connector callbacks validate their own protocol proofs and
do not create platform authentication exceptions.

## Public contracts and disabled gaps

Each enabled operation needs a published generic Gateway contract: method/path,
request/response DTOs, minimum permission, tenant and ownership rules, audit and
retry/idempotency semantics. An unknown write outcome requires reconciliation
before retry. The connector cannot bypass a missing public capability through
private endpoints or direct persistence.

Unsupported workflows stay disabled with owned TODOs. The connector owner owns
missing adapters and provider administration; the Gateway/Core owner owns any
missing public capability and its authorization contract. Production adapters,
cloud end-to-end qualification and cutover are separate work, not prerequisites
for retiring provider implementation from this repository.

The [historical administration inventory](https://github.com/ElevenID/marty-ui/blob/71c30b443278bea2aa3a0b7b3da3d32b87c4ed70/docs/architecture/canvas-administration-api-migration.md)
records the removed provider API. It is not a supported route list or permission
to restore a compatibility adapter. Historical audit records, frozen observations
and old demonstration manifests retain provenance; they do not enable current
platform features.

## Current platform contracts

- [External learner association](external-learner-association.md): own-session proof and canonical learner binding.
- [Observation admission](external-observation-admission.md) and [authority](external-observation-authority.md): organization, schema and policy boundaries.
- [Observation wire contract](external-observation-wire.md), [journal](external-observation-journal.md) and [materialization](external-observation-materialization.md): generic processing owners.
- [Issuance schema boundary](issuance-schema-boundary.md): baseline v2, old-ledger rejection and the separate legacy-upgrade TODO.

Source retirement does not authorize a running deployment change or a data
migration. Existing data must not be dropped, rewritten or relabeled implicitly.
Static dependency/network checks complement deployment isolation; they do not
prove it. Retain API-key, tenant, ownership, permission, signing and audit tests.
Local checks drive development, with required protected checks, reviews and
merge queues retained for integration.


## Demo catalog ownership

The current platform portfolio and next unbound draft contain generic Gateway
journeys. Provider-specific demos belong to the independent connector. Archived
public manifests and assets remain unchanged, and the August edition is checked
against its hash-pinned original portfolio. The UI validates those archives before
projecting platform-owned scenarios; retired provider routes are unavailable in
both fetched and prerendered pages. A next-edition draft does not update VERSION,
the public release index, qualification evidence or publication state. The draft
generator refuses to overwrite a different existing edition.

## Local maintenance boundaries

Source-pinned maintenance helpers accept closed platform cohorts: twenty base
roles, or twenty-one for the current cohort with event-stream. Provider roles
cannot appear in an observed cohort or hide as extra Compose services. Old
twenty-two-role receipts cannot authorize a current operation. Existing cache
volume names are retained allocation identities, not connector integration.

TODO (platform maintenance owner): prepare fresh, complete runtime observations
and orphan-workload absence evidence before a separately qualified rollout.
Local source tests and previews do not authorize stopping, starting or migrating
a running deployment. This operational qualification remains outside the split.


The two frozen full-service build profiles are retired, along with their
executable recipe. Their original manifests are hash-pinned read-only evidence
in `contracts/scoped-full-build-legacy-reference.json`. The current source
preparer, launcher and shared builder reject those IDs before export, journal
construction or compiler dispatch. Recover existing historical jobs through
their preserved source-bound operator; this change neither stops them nor
deletes their receipts, refs, source exports or caches.

TODO (platform build owner): provide a fresh current-source all-service profile
if one is needed. The current provider-neutral CI image recipe remains the
active image build path. A replacement historical build is not a split gate.


Kubernetes credential reload and adoption use the shared inventory of fifteen
retained platform consumers. They do not restart the retired connector worker.
Historical native inspection still binds its original signed credential inventory;
that evidence is not a current workload roster. New reload completion receipts
use platform status and the exact retained count; old sixteen-workload receipts
cannot authorize a current completion. Full-environment health remains separate.


The platform delivery catalog seeds only its two generic wallet destinations.
Provider account setup, provider OAuth and publication belong to the independent
connector; the platform does not advertise a provider mirror capability or accept
provider-specific destination types. Custom external destinations retain generic
tenant and organization-administrator validation. Connector interaction still
uses only the public Common Gateway; it gains no issuance or signing authority.

TODO (platform data owner): review historical provider destination records and
references before any separately authorized data migration. Source retirement
neither deletes tenant records nor rewrites them as generic destinations. No
provider publication workflow is enabled by this split.


Provider-scoped maintenance is retired. The Northstar exception that admitted a
paused stock-provider stack is unavailable; current callers inherit the shared
strict registration-ID checks. Old scoped receipts fail admission rather than
falling back to a weaker census. Existing jobs and their source-bound recovery
operators remain historical; this source change does not operate on them.
Metadata derivation and retained-role checks reject retired connector roles,
and retained running services require healthy observations without exceptions.

The external-transit CLI's old recorder transport is removed. Execution now
refuses before authority input reads or output creation; source-only checks remain.
TODO (platform maintenance owner): qualify a provider-neutral native verifier
before reenabling this entrypoint or migrating old maintenance profiles. This
replacement and production rollout are outside the Canvas split. Preserve old
receipts and use their original source-bound recovery owner for existing jobs.

Older metadata/Northstar helpers retain their source-bound 22-role evidence shape;
they do not admit the current 21-role profile or authorize a migration. Their
retired provider role names are rejected before runtime inspection. A fresh
maintenance generation remains a separate TODO, outside the split.

The [pre-retirement source](https://github.com/ElevenID/marty-ui/tree/32c30274abdebf657378653aa71821cf023113df/scripts)
preserves the old scoped operators for their original source-bound jobs. This
reference is historical evidence and does not authorize a new operation.


The JavaScript current D12/D05 observer admits the same exact 21-role set as
its Python execution owner. Old, unknown, missing and duplicate roles fail
before Docker reads. Created-container IDs, start acknowledgments, process
lineage, selected mounts, UID and healthy-state constraints remain mandatory.
Provider issuer and bootstrap-fence overlays are retired from shared runtime
selection and exports; generic service and issuance policies keep their checks.
Existing source/hash-bound callers require fresh approval for changed observers.
Local observer tests do not qualify or dispatch a rollout.

Retired selector fields are rejected before shared profile dispatch and at each
predecessor layer, including mixed and falsy declarations. Read-only authority
consumers cannot use a retired wrapper to reach a generic admission path.
