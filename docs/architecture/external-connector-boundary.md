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
