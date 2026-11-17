# Canonical application ownership

This candidate adds a Core-owned relationship between an issuance application
and an authenticated Marty user. It does not derive ownership from provider
claims, email, `applicant_identifier` equality or an applicant-service record ID.

## Implemented storage and adapter

Migration0016 adds one current relationship per organization/application and an
immutable original-operation journal. A proposal captures the subject from the
locked canonical application and starts at `proposed`. The intended user must
confirm before the relationship becomes `confirmed`. Revocation and a new
proposal advance the revision and remove prior confirmation. A proposal for a
different user requires fresh confirmation.

Proposal and revocation require current canonical `application:manage-ownership`
permission. Existing external-observation administration permission does not
grant ownership authority. The migration does not assign permissions to roles.
The schema owner must explicitly install grants when the composed feature is
qualified. Runtime SQL is trusted application code, not a tenant SQL sandbox.

Core checks the expected relationship and application revisions, canonical
subject, active organization, application lifecycle and expiry. Updates and
their actor receipts commit together. Original-operation replay checks the
original actor and intent and returns the original receipt. Conflicting UUID
reuse fails; matching historical replay cannot restore revoked ownership.
Postimage and final authority checks reject trigger rewrites and late expiry.
Revocation remains available for closed or changed applications.

The Rust adapter accepts bounded typed commands, rejects duplicate/unknown JSON
fields and performs one database statement. Its trusted mutation context cannot
be deserialized from a browser body. Transport failures and malformed returned
receipts are uncertain outcomes: reconcile the original operation without an
automatic write retry. Receipts expose no canonical subject or provider data.

## Activation and public interface

Migration0016 is registered with the protected schema-owner command and checked
against a separate exact metadata catalog. Runtime performs no DDL or grants.
Startup rejects schema drift, missing ledger registration, ownership of protected
objects, dangerous reachable roles and forbidden history/identity writes,
including role memberships declared `INHERIT FALSE`.

`MARTY_APPLICATION_OWNERSHIP_ENABLED=true` explicitly enables the Core router;
the default is false. The Gateway service credential and qualified database
capabilities are required. The organization permission catalog includes
`application:manage-ownership` for normal owner/admin seeding; reviewer, operator,
viewer, applicant and other role templates do not receive it.

The public session-only paths are
`POST /v1/organizations/{organization_id}/application-ownerships/{application_id}/{action}`.
Actions are `propose`, `confirm`, `revoke`, `inspect` and `receipt`. Mutations carry
`operation_id`, `expected_revision` and `expected_application_revision`; proposal
also carries the intended `user_id`. Initial proposal uses revision0; subsequent
mutations use the last relationship revision. The actor and canonical subject
are never body fields. Inspect accepts `{}`. Receipt lookup accepts only the
original `operation_id` and is scoped to its original actor. Its `kind:receipt`
result is distinct from the `kind:current` inspect result; historical confirmation
does not restore current authorization after revocation or application drift.

Gateway route construction, original-byte guarding, no-retry routing and OpenAPI
declarations are implemented. Full native-service and Gateway runtime qualification,
existing-AWS deployment and browser consent remain required before merging or
claiming a working provider-association replacement.

The Gateway must reject producer API keys for every ownership operation, use
current authenticated session identity for confirmation, enforce an allowed
Origin and strict bounded original-byte framing, strip caller identity headers
and forward only its trusted identity context. A request body must never select
its actor or canonical subject. The Core handler must authenticate the Gateway
service transport independently and perform no automatic mutation retry.

Ownership alone grants no producer scope, evidence verification, approval,
signing, issuance or account creation. A separate approved-source provider-proof
and one-use learner association contract is still required. Its challenges must
fence current ownership, application, binding, source and browser revisions; a
historical ownership receipt is not current authorization.

## Local evidence

`scripts/test_application_ownership.py` runs the exact migration against pinned
disposable PostgreSQL16. It checks restricted runtime privileges, eight-way
original-operation concurrency, intended-user confirmation, wrong actor/tenant,
revision/subject/expiry changes, exact permission, revocation, immutable history
and postimage rollback. Its small synthetic canonical-table fixture is not a
qualification of the full owner command, actual session authentication or a
deployed role.

`scripts/run_application_ownership_contract.py` compiles the exact production
Rust modules with registry packages already in the production lock. It runs the
Gateway guard, Core Axum handler and actual restricted PostgreSQL composition,
including lost-reply receipt reconciliation without duplicate writes and fresh
revocation status. The fixture supplies a synthetic already-authenticated
identity; it does not qualify the real identity provider, network TLS, full
Gateway runtime or protected owner command. Clippy runs with warnings denied.
No deployed identity or end-to-end provider replacement is claimed.
