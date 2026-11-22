# Delegated-use owner deployment qualification — next milestone

Status: **planned / not yet qualified**. This is the next milestone after the merged managed public-caller gate. It does not authorize production deployment or public capability promotion.

## Objective

Replace the remaining privileged test/bootstrap boundaries with separately provisioned owner services and restricted runtime identities, then qualify the selected managed MachineCredential / full-machine / KEY / EXACT_OPERATION caller against those services over the configured HTTPS/mTLS origins.

The acceptance target is not another in-process composition. The actual Credential Template, Presentation Policy and Issuance executables must run as independent processes, each connected with its own runtime database role. The delegated-use host must consume their public service contracts and must not receive their migration or administrator credentials.

## Verified starting point

The merged main source currently has these explicit boundaries:

- marty-delegated-use uses fourteen independently checked PostgreSQL connections and mandatory mTLS. Its public caller is separately default-off.
- rust/services/delegated-use/tests/support/lifecycle_owners.rs creates Credential Template and Presentation Policy schemas and records through one disposable administrator PgPool, then starts their actual application/gRPC services in the test process. The read calls use actual TLS and service-token authentication, but this does not qualify separately provisioned database roles or independent processes.
- The actual selected lifecycle's Issuance bootstrap is in-process. The host's reference/status reader uses configured HTTPS origins and the Issuance API key, but the live lifecycle does not yet prove the independently deployed Issuance service and its restricted database role.
- rust/services/credential-template/src/main.rs has migrate and verify-owned-schema commands, but normal startup also migrates, reconciles legacy data and seeds the system catalog.
- rust/services/presentation-policy/src/main.rs migrates its schema and reconciles built-in policies during normal startup; the executable currently has no equivalent explicit operator-only migration/bootstrap command.
- rust/services/issuance/src/main.rs has migrate and verify-owned-schema commands and a schema startup mode. The deployed acceptance configuration must select validation-only startup. The application-ownership and external-association startup helpers are explicitly read-only schema/role preflights; they do not perform DDL or seed writes. Their independent database identity and privilege boundaries still require qualification.
- The AWS replay qualified the selected composition in an isolated container on the existing development host. It did not qualify a bare-host deployment, the installed stack, or the external catalog/Issuance serving roles.

These are source-backed limitations, not inferred deployment failures.

## Work packages

### OQ-1 — Remove privileged startup behavior

1. Credential Template: make normal service startup schema-validation-only and read-only with respect to migrations, legacy-data reconciliation and system-catalog seeding. Keep those writes in explicit operator/bootstrap commands that require the migration/owner credential. Preserve existing migration bytes.
2. Presentation Policy: add explicit migration, schema verification and built-in-policy bootstrap commands. Make normal service startup validate-only and remove policy reconciliation writes from the runtime path.
3. Issuance: configure the deployed service to use MARTY_SCHEMA_STARTUP_MODE=validate; audit its remaining startup preparation helpers and separate any DDL/seed operation into explicit owner commands.
4. Add executable tests proving a runtime-role database can start and serve its read contract while lacking CREATE/ALTER, migration-ledger writes and unrelated owner writes. Prove each operator command fails under the runtime role and succeeds only under its dedicated owner role.
5. Ensure readiness validates schema/migration identity without repairing it. No startup auto-migration, automatic grant provisioning or historical reconstruction.

### OQ-2 — Separate database roles and owner processes

Provision separate, least-privilege roles for:
- Credential Template serving;
- Presentation Policy serving;
- Issuance serving and the narrowly scoped status/API path;
- each service's migration/bootstrap operator;
- the existing fourteen delegated-use host connections.

Use the checked-in role contracts and migration owners as the source of truth. Do not copy the delegated-use host's rights to an owner service. Runtime identities must not be superusers, owners, schema creators, migration owners, role/database administrators, RLS bypass identities or members of a role that supplies those powers. Check effective privileges and reachable memberships, not just direct grants.

The qualification harness must record SESSION_USER and CURRENT_USER for each process and prove denied DDL and denied cross-owner reads/writes. It must also prove the delegated-use host cannot connect using an owner or migration identity.

### OQ-3 — Independent HTTPS/mTLS service composition

Run the actual Credential Template gRPC service, Presentation Policy gRPC service and Issuance native HTTP service as separate processes with independent configuration, health/readiness and shutdown.

- Use exact HTTPS origins, explicit trust roots and workload client certificates. Do not accept plaintext fallback in the deployed profile.
- Bind server certificates to the expected service identity; verify SAN/URI mapping and reject wrong CA, wrong identity, expired certificates and unpinned replacement certificates.
- Preserve service-token/API-key separation. No inbound header may select tenant, actor, credential, issuer, policy or source snapshot.
- Verify redirect refusal, response-size bounds, per-call deadlines, body/trailer timeout handling and no credential forwarding to a different origin.
- Do not expose PostgreSQL, OpenBao or Redis ports publicly. The first replay remains isolated on the existing AWS development host.

### OQ-4 — Current source and credential freshness

Exercise the full chain using records created by the real owner services:
1. provision a machine credential template and active presentation policy through their operator path;
2. issue the managed MachineCredential through the independently running Issuance service;
3. resolve issuer/key authority and current credential status through the configured source origins;
4. execute the public request-link / direct_post / finalization / original-receipt flow;
5. change or revoke the source credential/policy/key and prove subsequent operations fail closed within the documented source-observation and authentication deadlines;
6. interrupt each owner independently and prove timeout/outage fails closed without renewing authority, retaining a false permit, duplicating signing, or consuming a new operation;
7. restore the owner and prove only fresh current observations permit a new operation. Historical receipt recovery must preserve original bytes and dates and still require current recovery access.

Do not treat a successful health/readiness response as proof of current credential authority. Preserve the five-second aggregate source-read budget, per-source bounds and the original deadline through locks and commit. No stale cache may extend an observation beyond its configured validity.

### OQ-5 — Repeat complete selected-caller lifecycle

Run both internal and public lifecycle regression gates plus the independent client and receipt consumer against the separate owner processes. Include:
- returned request URL and signed response URI are followed exactly;
- real holder proof, issuer and holder signature verification;
- original receipt verification with independently supplied trust/context;
- exact retry, lost response and post-restart original-result recovery;
- grant revocation, credential suspension/revocation, policy revision change and current machine-access withdrawal;
- unknown source, stale observation, invalid service identity, missing certificate, wrong token, redirect, timeout and owner outage;
- unchanged claim, nonce, signature, grant and consumption counters on denial/recovery;
- preserved original issue/expiry times and no automatic pending-claim takeover or re-signing.

## Acceptance gates

| Gate | Required result |
| --- | --- |
| Startup privilege separation | All three runtime executables start using only their own restricted runtime identities; no migration/bootstrap writes during startup |
| Owner database boundaries | Runtime roles cannot migrate, create objects, grant privileges or write outside their documented owner contract |
| Independent service identity | Each HTTPS/gRPC/HTTP peer is authenticated against its exact configured trust and identity; wrong identity fails closed |
| Actual Issuance | Credential is issued by the running Issuance service; no pre-completed credential insertion or in-process Issuance shortcut |
| Source freshness | Credential, issuer/key, Trust Profile, MAP and policy changes are observed within their declared bounds; unknown/stale/outage denies |
| Full caller lifecycle | Internal and public lifecycles pass with the normal serving executable and independent client/receipt consumer |
| Recovery and replay | Restart recovers only committed original results; no new signing, grant or consumption; uncertain pending claims remain unresolved |
| Cleanup | All owned databases, processes, certificates and containers are removed; existing workloads and the six-hour auto-stop safeguard are preserved |

All test selections must produce positive nonzero test summaries. Capture Cargo artifacts before building the normal serving binary last, record the exact source/tree and binary hashes, and invoke the captured harnesses directly. Keep original failure logs. Do not claim a test passed from a zero exit alone.

## Execution constraints

- Reconcile the branch with current main before implementation and preserve all accepted changes.
- Prefer local/offline tests first. Do not dispatch GitHub Actions or change CI policy as part of the development loop.
- For AWS, use only the existing elevenid-marty-disposable Free-plan development instance in us-east-2. Verify account/plan/credits, instance identity, automatic-stop time, current workloads and other active workers before starting it. Do not create/resize infrastructure, add swap, change IAM/network rules, install host packages, or stop another worker's services.
- Use a new checkout, evidence directory and owned rootless test container. Keep the network disconnected for locked builds and test execution; publish no ports. Preserve existing volumes, OpenBao mounts, credentials and diagnostics.
- Stop the instance after the replay and verify the stopped state. AWS qualification remains a development-host composition result, not a production rollout or bare-host claim.
- Do not use production credentials or production CA material. Do not promote public MIP support/discovery or enable the default-off host/caller.

## Explicitly deferred

Production CA issuance/revocation, automated certificate/pin and signing-key rotation, AWS KMS/IAM custody, provider-outage reconciliation beyond the selected disposable tests, pending-claim takeover/re-signing, required attestation, external-authority/domain profiles, represented-subject SESSION grants and Rifare business execution are later milestones. This milestone must not blur the Marty/Rifare boundary: Marty supplies identity, current authority and evidence; Rifare owns domain permission, durable business intent, budgets/reservations, provider idempotency, business commits and outcomes.
