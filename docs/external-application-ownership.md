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

## Unfinished integration

This feature is not available through HTTP yet. Migration0016 is not yet
registered with the protected schema-owner command. Startup catalog/role
qualification, canonical permission provisioning, public Gateway routing,
session-only actor/tenant authentication, current-state/receipt reads and browser
consent remain to be implemented and qualified together before merging.

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

`scripts/run_application_ownership_contract.py` compiles the unchanged production
Rust module using registry packages already in the production lock. It covers
strict input decoding and mutation-context validation. It does not yet exercise
the Rust adapter through an actual Gateway/PostgreSQL composition. No deployed
identity or end-to-end provider replacement is claimed by either command.
