# Codex Handoff — Marty OQ-1 Owner Startup Qualification

Prepared: 2026-11-22  
Repository: ElevenID/marty-ui  
Branch: qualify/delegated-use-owner-roles  
PR: https://github.com/ElevenID/marty-ui/pull/2038  
Latest observed head: 1684acc47e6f94894bdee88d8b2d57a7d76eddfc  
PR state at last inspection: open, draft, mergeable. Do not merge yet.

This is the authoritative pickup brief for Codex. Continue the existing branch and PR; do not recreate the work. Re-fetch the branch, PR diff, reviews/comments, main and check runs before editing because this state can advance.

## 1. Immediate Codex instructions

1. Fetch the current remote branch and verify its head. It may have advanced beyond the SHA above.
2. Inspect the full PR diff and current main. Preserve accepted upstream work and any other worker's changes.
3. Reproduce the latest failures locally before changing source.
4. Keep PR #2038 draft. Do not merge or enable auto-merge.
5. Do not dispatch or manually rerun GitHub Actions. The user prefers local validation and requires zero-dollar Actions spending. Normal pushes may trigger repository CI automatically; avoid unnecessary commits.
6. Do not start AWS qualification until local and hosted gates are green and the exact candidate source is stable.
7. Do not touch Rifare. Another worker is progressing there; preserve the Marty/Rifare integration boundary.

First task: fix the exact current CI failures in section 8, beginning with Rust formatting, Organization test compilation, and the self-host Compose model diff.

## 2. Product purpose and responsibility boundary

Rifare is a consumer of the ElevenID/Marty identity and authorization stack. Marty provides delegated identity, machine authentication, organizational authority, current credential/policy evidence, proof verification, operation finalization, receipt evidence and recovery. Rifare remains the external Agent Commerce Gateway. Merchant systems remain authoritative for their own commerce records.

Responsibilities:
- Marty / ElevenID: agent identity, managed MachineCredentials, organizational authority, Presentation Policy/Cedar, credential/key/status observations, authenticated delegation, proof verification, finalization and receipt evidence/recovery.
- Rifare: merchant/domain permissions, orchestration, user intent, budgets, reservations, durable business intent, provider idempotency, payment/order execution, business commits and business outcomes.
- Merchant/provider: authoritative inventory, payment, order and fulfillment state.

Do not move business authorization, budgets, reservations, provider idempotency or commerce execution into Marty. Do not create a competing authorization engine. Keep existing Presentation Policy/Cedar, Signing Keys, Issuance/grant and Gateway owners.

Selected caller profile:
- managed MachineCredential;
- full-machine credential;
- KEY grant;
- EXACT_OPERATION;
- guarded public caller path;
- signed proof submission and original receipt recovery.

Host/caller feature flags remain default-off. Receipts remain EVIDENCE_ONLY. Public MIP remains 0.5.0. Do not promote support/discovery or enable this feature by default.

## 3. Completed predecessor milestones — do not redo

### Marty delegated authority/public caller

Marty UI PR #1994 merged through the mandatory merge queue:
- Merge commit: https://github.com/ElevenID/marty-ui/commit/58acfb97f8df8578f0d72e19e0c385a9cd44696c
- PR: https://github.com/ElevenID/marty-ui/pull/1994

Protocol PR #38 merged:
- https://github.com/ElevenID/marty-protocol/commit/1952c56e11d2ad1346b139da8c0a5e98cd7a2f73

The selected managed caller path had been qualified on AWS at source checkpoint 3c8a9386. That replay ran 210 selected Rust tests across 14 gates; 41 driver commands passed; 30 normal-host executable hash comparisons matched. This evidence is tied to that earlier source checkpoint, not to later OQ-1 source changes.

Prior behavior already implemented and tested:
- guarded caller and wallet routes;
- reusable Rust client transport;
- caller follows advertised request URL and signed submission URL;
- command identity/digest correlation;
- explicit mutual TLS trust;
- redirects and automatic retries disabled;
- proof, finalization, original receipt recovery and independent receipt verification;
- current-access checks on recovery;
- receipt recovery preserves original bytes and timestamps;
- no additional signing, grants or consumption on denial/recovery.

AWS predecessor evidence:
- docs/agent-trust-aws-qualification-2026-11-22.json
- Prior AWS replay was an isolated development-host composition, not a bare-host qualification or production rollout.
- Existing Free-plan instance was stopped after that replay; stopped state verified.
- Do not repeat predecessor work unless a later change invalidates a specific gate.

Earlier delegated-agent identity work also established:
- managed agent directory entries are provisioned; key registration is not authentication;
- approvals require exact-term confirmation plus independent current organizational authority;
- API keys and impersonation are not substitutes for authenticated machine identity;
- tenant/organization selection must not be caller-controlled;
- grant lifecycle and authority checks stay with their existing owners.

Accepted service placement:
- Presentation Policy/Cedar: rust/services/presentation-policy/
- managed signing: rust/services/signing-keys/
- grant lifecycle/persistence: rust/services/issuance/
- gateway/discovery: rust/services/gateway/

## 4. OQ milestone scope

OQ means Separated Owner Deployment Qualification. It follows PR #1994.

The target is not another in-process test composition. Actual Credential Template, Presentation Policy and Issuance executables must run as independent services with their own restricted runtime database roles. Organization must also have operator-only bootstrap behavior. Marty delegated-use must consume public service contracts and must not receive owner migration/admin credentials.

Full plan and acceptance matrix:
- docs/delegated-use-owner-deployment-qualification.md
- docs/agent-trust-runtime-milestones.md

Work packages:
- OQ-1 — Startup privilege separation: explicit operator migration/bootstrap commands; normal service startup validates schemas only and does not migrate, reconcile legacy data, seed catalogs or repair records.
- OQ-2 — Separate DB roles/processes: distinct runtime and migration identities for Organization, Credential Template, Presentation Policy and Issuance; prove effective privilege boundaries and no inherited escalation.
- OQ-3 — Independent HTTPS/mTLS composition: actual separate processes, exact service identities, trust roots, workload certificates, deadlines, redirect refusal, response bounds and shutdown.
- OQ-4 — Current source/credential freshness: current credential, issuer/key, Trust Profile, MAP and policy state; unknown/stale/outage fails closed within existing observation deadlines.
- OQ-5 — Complete caller lifecycle: internal and public lifecycles, actual issuance, proof, finalization, receipt verification, retry, revocation and restart recovery against independent owners.

This PR is currently OQ-1. OQ-2 follows only after OQ-1 is correct and qualified.

## 5. Current branch and implementation

Latest observed branch head: 1684acc47e6f94894bdee88d8b2d57a7d76eddfc  
Latest commit message: test: require Flow runtime validation mode  
PR #2038: open, draft, mergeable at last inspection. Re-check current status.

### Organization

Files:
- rust/services/organization/src/main.rs
- rust/services/organization/src/application.rs
- rust/services/organization/tests/http_core_behavior.rs
- rust/services/organization/tests/support/membership_approval.rs

Changes:
- explicit migrate, verify-owned-schema and bootstrap commands;
- bootstrap provisions organization records and bootstrap memberships via reconcile_organization_startup;
- normal startup no longer reconciles organization/membership data;
- OrganizationApplication::initialize validates the existing organization schema and no longer migrates schema or outbox;
- outbox migration/health checks moved to operator command path;
- PostgreSQL tests now explicitly migrate organization schema and PostgresOutboxStore in fixture setup.

Review:
- ensure CLI migrate/verify covers both organization schema and durable outbox;
- ensure normal readiness checks outbox without migration;
- ensure bootstrap is idempotent and does not require runtime TLS serving certificates;
- inspect two compiler errors in http_core_behavior; do not put migration back into runtime initialization to make fixtures pass.

### Credential Template

Files:
- rust/services/credential-template/src/main.rs
- rust/services/credential-template/src/runtime.rs

Changes:
- explicit bootstrap command performs migration, schema validation, legacy-data reconciliation and system-catalog seeding;
- bootstrap reads DB URL and catalog/issuer settings without requiring runtime workload TLS certificates or serving credentials;
- normal runtime startup validates schema only;
- runtime readiness no longer requires system-catalog seeding.

Review:
- verify PUBLIC_API_URL, hostname, scheme, issuer DID and migration profile validation;
- compare bootstrap semantics with configured_authority, canonical_slug and configured_did_web;
- ensure every supported deployment/migration entrypoint uses bootstrap;
- do not change historical migration bytes.

### Presentation Policy

File:
- rust/services/presentation-policy/src/main.rs

Changes:
- explicit migrate, verify-owned-schema and bootstrap-builtins commands;
- normal runtime validates schema and no longer migrates or reconciles built-in policies.

Review:
- ensure production/beta organization ID is explicit; fallback only for disposable/dev contexts;
- ensure pool/store handles are dropped before pool close;
- TLS crypto provider initialization occurs exactly once;
- run rustfmt and Clippy.

### Deployment orchestration

The branch adds an owner-migrations one-shot job to base and self-host Compose. It provisions Organization, Credential Template and Presentation Policy before their runtime services start. The current implementation uses the application DB secret. This is OQ-1 separation only, **not yet the OQ-2 final least-privilege role design**.

Intended operator command order:
1. marty-organization migrate
2. marty-organization bootstrap
3. marty-credential-template bootstrap
4. marty-presentation-policy migrate
5. marty-presentation-policy bootstrap-builtins

Runtime Organization, Credential Template and Presentation Policy services depend on successful owner-migrations completion. Issuance migrations/runtime must be ordered after the catalog/policy prerequisites they consume.

Propagation touched:
- docker-compose.base.yml
- docker-compose.beta.yml
- docker-compose.profile.conformance.yml
- docker-compose.profile.ghcr.yml
- docker-compose.selfhost.prod.yml
- docker-compose.selfhost-migrations-disposable.yml
- docker-compose.selfhost-migrations-scoped-disposable.yml
- docker-compose.selfhost.bundle.override.yml
- deploy/helm/marty/templates/migrations.yaml
- Kubernetes activation workflow
- self-host migration probes and image lock
- conformance one-shot tracking
- passkey application lab
- beta/PowerShell deployment qualification.

Audit every entrypoint with repository-wide searches for old migrate commands and new bootstrap commands. Do not assume propagation is complete.

### Issuance and Flow

Issuance already has migrate and verify-owned-schema commands and a schema startup mode. Deployed runtime must explicitly select validation-only mode. Audit application-ownership and external-association startup helpers; earlier source inspection found read-only schema/role preflights, not DDL/seed writes.

Flow should also run validation-only where schema startup applies. A regression assertion at current head requires MARTY_SCHEMA_STARTUP_MODE: validate in the Flow Compose service. Verify exact env var and behavior from source; extend coverage to all relevant runtime executables.

## 6. Security/correctness invariants

1. Normal runtime startup must not migrate, execute DDL, reconcile legacy records, seed catalogs, reconcile built-in policies, provision grants or write administrator records.
2. Operator/bootstrap commands must be explicit, auditable, idempotent and separately invokable.
3. Runtime role must not be superuser, schema owner, migration owner, schema creator, role/database administrator, RLS bypass role or member of any role granting those powers.
4. Check effective privileges and transitive role membership, not only direct grants.
5. Owner runtime and migration identities must be separate. OQ-2 creates separate identities for Organization, Credential Template, Presentation Policy and Issuance. Do not reuse the delegated-use host's fourteen DB identities.
6. Delegated-use host must not possess owner/migration credentials.
7. No production credentials or production CA material in tests or AWS.
8. Do not alter historical migration SQL bytes.
9. Preserve mandatory mutual TLS, exact service identity, explicit trust roots, service-token/API-key separation, redirect refusal, response bounds, per-call deadlines and fail-closed behavior.
10. Preserve current-source freshness: aggregate source-read budget remains five seconds with per-source bounds; original deadline continues through locks and commit; no stale cache may extend authority.
11. Receipt recovery preserves original bytes/timestamps and requires current recovery access. It must not renew authority or create signatures/grants/consumption.
12. Uncertain pending claims remain unresolved; no automatic takeover or re-signing.
13. Marty does not own Rifare business budgets, domain permissions, provider idempotency or commerce commits.

## 7. Latest CI status and evidence

Latest observed CI run on head 1684acc47e6f94894bdee88d8b2d57a7d76eddfc:
- https://github.com/ElevenID/marty-ui/actions/runs/45075682026
- CI Gate failed.
- CodeQL check was neutral; Rust Supply Chain and Security Scanning passed.
- UI shards, Website Surface, Rust selfhost tests, Rust Feature Regression Probe, Public Protocol Contract, MIP 0.5 browser gate, Native KMS amd64/arm64, Python lint, Windows custody and several service lanes passed.
- Four main CI lanes failed: Rust Lint and Packaging, Rust Service Tests (contracts), Rust Service Images, Release Contract Tests. Rust Service Tests (flow) also failed. See exact jobs below.
- Installer trial image was an expected skip.
- These green jobs do not offset the failures.

### Formatting failure

Job:
https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396046

cargo fmt --all -- --check failed in rust/services/organization/src/application.rs around line 358. rustfmt expects the PostgresOutboxStore::new call formatted over multiple lines (pool clone, source, partition count, closing ?). Run cargo fmt --all, inspect diff, then cargo fmt --all -- --check.

### Organization test compile failure

Job:
https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396134

marty-organization test target http_core_behavior failed to compile due to two previous errors. The hosted log excerpt only exposed the final “could not compile” line, not both compiler diagnostics. Recent edits are in:
- rust/services/organization/tests/http_core_behavior.rs
- rust/services/organization/tests/support/membership_approval.rs

Reproduce the exact target locally and inspect full compiler diagnostics. Likely areas to inspect: import visibility, helper/constructor signatures, async setup ordering. Ensure organization schema and PostgresOutboxStore are explicitly migrated in fixture setup before application initialization. Do not reintroduce runtime migration.

### Rust Service Images / self-host model failure

Job:
https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396083

scripts/test_selfhost_native_owner_compose.py fails in assert_models; traceback reaches line 613 where it asserts a provider is not already in a consumer's dependencies. The owner-migrations service and dependency graph are not fully admitted by the strict self-host model.

This is a closed-model guard. Do not delete it or broadly relax it. Inspect assert_models expected vs actual Compose model and unified diff. Admit only exact reviewed owner-migrations service, bounded environment/secrets/volumes and intended owner dependencies. Preserve unrelated dependency constraints. Confirm no unexpected dependency edge was accidentally introduced. Extend negative mutation tests so unexpected dependency, secret, mount, port, command, env key or restart policy still fails.

tests/test_build_selfhost_image_lock.py must include owner-migrations in the actual base and override fixture strings, not only in expected output. A prior edit updated expected values but missed fixture inputs; this was partially corrected. Re-verify.

### Release Contract Tests / frozen model failures

Job:
https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396059

Observed result: 191 failed, 12,990 passed, 1,043 skipped, 107 errors, 798 subtests passed.

Many failures came from scripts/test_selfhost_native_owner_compose.py, covering customer-name parity, Redis policy, applicant template auth, Compose field closure, passport credential consumers, migration/KMS identity closure, signing-key token boundaries, connector retirement, web selection, and provider dependency checks.

This indicates a broad actual Compose model divergence from the frozen reviewed model. Do not patch 191 assertions one by one or accept the entire model wholesale. Start with first traceback and unified model diff from assert_models. Identify exact unexpected services/fields/dependencies. Update only the intended owner-migrations delta and preserve all unrelated invariants. If unrelated Compose fields changed, fix Compose source rather than expanding the allowlist.

Check base, self-host, beta, conformance, GHCR, bundle override and generated Compose model.

### Flow isolated database contract failure

Job:
https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396062

Step “Run isolated database contract suites concurrently” failed. The visible hosted excerpt did not include a useful test summary/diagnostic. Re-run the exact isolated DB contract command locally with pinned PostgreSQL/Redis fixture images and concurrency. Preserve full stdout/stderr, positive nonzero test counts and cleanup evidence. Inspect shared schema/bootstrap ordering and Flow validation-only setting, but establish cause before changing code.

## 8. Local validation sequence

Use a clean local checkout/worktree of the exact current remote branch head. No concurrent uncommitted work from another worker.

1. git status --short --branch; git rev-parse HEAD; git fetch origin; verify current branch ancestry and PR head.
2. Inspect full diff against origin/main, PR comments/reviews and current CI logs.
3. cargo fmt --all -- --check; fix known formatting first.
4. Run Organization library and http_core_behavior target; get both compiler diagnostics.
5. Run python3 scripts/test_selfhost_native_owner_compose.py and corresponding pytest tests; capture first model diff.
6. Run the release-contract tests that invoke the strict self-host model. Capture all relevant diffs.
7. Run scripts/check_selfhost_installed_runtime_plan.py and its pytest tests.
8. Run scripts/qualify_selfhost_migrations.py and tests/test_qualify_selfhost_migrations.py.
9. Run scripts/test_build_selfhost_image_lock.py and its pytest tests.
10. Run Flow isolated DB contracts with pinned fixtures.
11. Run affected Organization, Credential Template and Presentation Policy Rust suites; then workspace Clippy/package checks.
12. Run full local repository check where practical.
13. Capture test artifacts before building normal serving executables last. Record source/tree and binary hashes if running integration qualification.
14. Only then publish fix commits. No manual Actions dispatch.

CI uses Rust 1.95 in relevant lint lane. Preserve lockfile unless a specific dependency change is required and independently reviewed.

## 9. OQ-1 acceptance criteria

OQ-1 is not complete merely because source calls were moved.

Runtime startup:
- Organization validates organization schema and durable outbox; no migration or organization/membership reconciliation.
- Credential Template validates schema; no migration, legacy repair/reconciliation or catalog seed.
- Presentation Policy validates schema; no migration or built-in policy reconciliation.
- Issuance deployed runtime explicitly uses validation-only schema mode; inspect startup helpers.
- Flow runtime explicitly uses validation-only schema mode where applicable.
- Readiness is validation-only; it never repairs/provisions.

Operator commands:
- Each owner has explicit migrate, verify-owned-schema and bootstrap/seed commands as appropriate.
- Commands are repeatable/idempotent and fail under runtime credentials.
- Bootstrap does not require runtime serving certificates when not needed.
- Operator order is explicit in every supported deployment.
- OQ-2 later moves to dedicated owner/migration credentials; current shared app DB secret is not the final design.

Deployment entrypoints:
- base, beta, self-host production;
- disposable/scoped migration compose;
- Helm migration Job and readiness;
- Kubernetes activation/renewal;
- self-host bundle image override/lock;
- conformance one-shot tracking;
- passkey application lab;
- PowerShell beta deployment;
- installer, migration rehearsals, scripts and CI references.

Executable tests:
- Runtime role starts and reads but cannot CREATE/ALTER, update migration ledger, seed catalog, reconcile memberships/policies or write outside contract.
- Operator commands succeed only under intended operator role and fail under runtime role.
- Effective role membership checked transitively.
- Tests prove no startup write side effects, not only source text absence.
- Actual independent processes are OQ-3, not satisfied by current in-process test helpers.

## 10. OQ-2 and later work

After OQ-1 is green and merged, implement OQ-2:
- separate runtime and migration/bootstrap roles for Organization, Credential Template, Presentation Policy and Issuance;
- derive exact grants from migration ownership and SQL access patterns;
- no superuser/owner/role admin/schema create/migration ledger write/RLS bypass/inherited privileged membership for runtime roles;
- record SESSION_USER and CURRENT_USER from each actual process;
- prove denied DDL and cross-owner reads/writes;
- prove delegated-use host cannot connect with owner/migration identities;
- keep fourteen delegated-use host DB connections and role contracts separate;
- use disposable PostgreSQL only.

Then OQ-3 independent HTTPS/mTLS owner processes, OQ-4 freshness/outage/recovery, OQ-5 full caller lifecycle against those processes.

## 11. AWS and cost constraints

Previous AWS qualification used the existing elevenid-marty-disposable Free-plan EC2 instance in us-east-2. It was stopped after that run and stopped state verified.

Before any future start:
- verify account/plan/credits, exact instance identity, state, six-hour auto-stop, workloads and other active workers/sessions;
- use only this existing instance;
- do not create/resize infrastructure, add swap, change IAM/network rules, install host packages or stop another worker's services;
- use a separate checkout/evidence directory and owned rootless test container;
- publish no ports; do not expose PostgreSQL/OpenBao/Redis;
- keep locked build/test network disconnected after dependencies are prepared;
- preserve volumes, OpenBao mounts, credentials, diagnostics and unrelated containers;
- stop instance after replay and verify stopped state;
- no production credentials, production CA material, signing keys or production data.

No AWS replay until local source/tests and hosted CI are green.

GitHub Actions:
- user requires zero-dollar Actions spending and prefers local testing;
- do not manually dispatch or rerun workflows;
- do not change CI budget/policy;
- normal PR pushes may automatically trigger CI, so avoid unnecessary commits.

## 12. PR and collaboration rules

- Continue on qualify/delegated-use-owner-roles / PR #2038 unless main materially advanced and branch reconciliation is required.
- No force-push, history rewrite or overwriting another worker's changes.
- Fetch current file versions before edits and use current SHAs.
- Preserve accepted main changes.
- Keep PR draft until all required checks pass and source review is complete.
- Do not merge or enable auto-merge.
- Do not dismiss/suppress CodeQL alerts.
- Keep qualification claims tied to exact tested source commits. AWS evidence belongs to 3c8a9386, not this OQ-1 branch.
- Do not modify Rifare; another worker owns current Rifare development.

## 13. Useful links

- PR #2038: https://github.com/ElevenID/marty-ui/pull/2038
- Branch: https://github.com/ElevenID/marty-ui/tree/qualify/delegated-use-owner-roles
- Latest known CI run: https://github.com/ElevenID/marty-ui/actions/runs/45075682026
- Rust lint: https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396046
- Organization compile: https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396134
- Self-host image model: https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396083
- Release contracts: https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396059
- Flow DB contracts: https://github.com/ElevenID/marty-ui/actions/runs/45075682026/job/137372396062
- Merged predecessor PR #1994: https://github.com/ElevenID/marty-ui/pull/1994
- Merged Protocol PR #38: https://github.com/ElevenID/marty-protocol/pull/38
- OQ plan: docs/delegated-use-owner-deployment-qualification.md
- Milestone record: docs/agent-trust-runtime-milestones.md
- Previous AWS evidence: docs/agent-trust-aws-qualification-2026-11-22.json

## Final direction

Do not expand scope into new protocols, agent UI, Rifare business behavior, production deployment or AWS. Finish operator/runtime separation cleanly, restore strict deployment contracts, prove executable tests, then proceed to least-privilege owner database identities.

First: reproduce current PR #2038 failures on the exact latest head, fix rustfmt and Organization compile errors, then use the self-host Compose model diff to narrowly correct the owner-migrations contract while preserving every unrelated security/deployment invariant.
