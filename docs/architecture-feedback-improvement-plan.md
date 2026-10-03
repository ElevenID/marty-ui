# Architecture and development-feedback improvement tracker

Created: 2026-10-02 (America/Denver; baseline CI completed 2026-10-03 UTC).
Status: A0 inventory and first A1 acceptance-package extraction in progress.

## Objective and scope

Reduce the amount of unrelated code and infrastructure needed to validate a change. Establish independently testable Rust boundaries, select checks from their actual dependencies, and report failures earlier while preserving behavior, features, security guarantees, and release qualification.

The user authorized implementation of the investigated improvements, requires self-review and regression prevention, and prefers reuse of Rust code following DRY. All repositories are eligible for a justified change; the evidence currently prioritizes `marty-ui`, with a smaller selector/preflight follow-up in `marty-core`. Repository creation, service deployment splits, and broad framework replacements are not prerequisites.

This document coordinates the new architecture work. [The original build audit](rust-build-audit.md) and [its evidence](rust-build-audit-evidence.md) remain historical records of earlier optimizations. Those completed changes must not be reimplemented.

## Evidence baseline

The investigation inspected UI main `8ad6c73f2b44d1a23feecc7754f1284d64655e66`, Core main `73f6d5898b2147d0ab4f7cca318c76006a2fa3d6`, and MMF main `c55d323e6aa64cad4f49308792f1d21eaab0ebc8`. Refresh these revisions before implementing each PR; the original audit worktree is not an implementation base. The first implementation worktree is `marty-ui/worktrees/architecture-acceptance`, based on UI `92e16b2f15045e91a92a737b0a42b431895a8b66`.

| Observation | Evidence and consequence |
| --- | --- |
| Canvas acceptance took 61m40s; other Rust contracts took 12m29s | [Protected UI run 37077519687](https://github.com/ElevenID/marty-ui/actions/runs/37077519687). Passport image: 9m59s; release contracts: 8m06s; Rust lint/packaging: 7m26s. These parallel jobs must not be added together. |
| The Canvas lane combines multiple sequential responsibilities | Compilation 6m25s; Bookworm compilation 9m43s; public image 12m06s; preflights 8m09s; main database-backed group 23m20s. Separating test execution alone does not eliminate its build prerequisites. |
| A nominal Canvas executable also owns system acceptance | [`canvas_published_schema_contract.rs`](https://github.com/ElevenID/marty-ui/blob/8ad6c73/rust/services/issuance/tests/canvas_published_schema_contract.rs) includes self-host, Kubernetes, Envoy, DIDComm, renewal, and Flow composition. |
| Issuance is a broad compilation boundary | Approximately 124,000 lines under `rust/services/issuance/src`, including embedded tests; approximately 55,000 in Canvas-prefixed modules and 12,500 in passport-prefixed modules. Its manifest has 60 normal and 20 development dependencies. Size is supporting evidence, not a timing measurement. |
| Tests couple neighboring service implementations | Gateway and issuance have mutual development dependencies; issuance tests also depend on Flow, signing keys, and packaging crates. These are test edges, not proof of a production dependency cycle. |
| UI selection is coarse | [`ci.yml`](https://github.com/ElevenID/marty-ui/blob/8ad6c73/.github/workflows/ci.yml) enables both Rust lanes for all Rust/proto/contract changes and sets `all=true` for merge groups. Both lanes compile the workspace. |
| Declared Cargo dependencies permit narrower candidates | Local manifest analysis found notification's reverse dependency closure contains only notification, out of 23 packages. Runtime/API/deployment consumers must also be mapped before omitting acceptance checks. |
| Core's selector is not sufficient as a sole gate | [`ci_affected_packages.py`](https://github.com/ElevenID/marty-core/blob/73f6d58/scripts/ci_affected_packages.py) follows package dependencies, but a local fixture-path probe selected nothing for JSON changes; its Git diff excludes deletions. Full gates still provide broader coverage. |
| Historical and native verification are distinct | Timeout tests separately reproduce frozen Python observations and run native worker scenarios against the recorded corpus. Their input closures differ and should be tracked independently. |
| Other repositories are not established priorities for restructuring | Latest sampled successful MMF CI was about five minutes and integration-repository hermetic CI about 90 seconds. Core PR CI was about 17.5 minutes, including a 14m23s preflight. These are different runs/workloads, not comparative benchmarks. |

No speedup is promised from crate size or static graph inspection. Preserve before/after evidence from normal validation; use a small local experiment when it resolves a specific design uncertainty.

## Implementation queue

Statuses: `planned`, `investigating`, `implementing`, `review`, `CI`, `merged`, `deferred`. A deferred item needs an evidence-backed reason, a retained safety guarantee, and an explicit disposition; it must not silently disappear from the goal.

| ID | Work and intended result | Dependencies | Status | Owner / PR / evidence |
| --- | --- | --- | --- | --- |
| A0 | Inventory test obligations and their inputs; identify effective execution, owning package, runtime dependencies, and current gate | None | investigating | Primary agent; [initial inventory](architecture-test-obligations.md) |
| A1 | Move cross-service/system tests into a dedicated workspace acceptance package; separate deployment/packaging, DIDComm/renewal, and Canvas groups | A0 | implementing | Primary agent; `codex/architecture-acceptance` |
| A2 | Extract one small domain/compatibility boundary from issuance, preserving public behavior and reusing existing Rust implementations | A0; coordinate moves with A1 | planned | Unassigned |
| A3 | Harden Core selection and implement conservative UI affected-check planning in shadow mode | A0; map A1/A2 changes | planned | Unassigned |
| A4 | Assign overlapping case matrices to the lowest adequate test level, retaining real adapter and process guarantees | A0; use A2 where appropriate | planned | Unassigned |
| A5 | Separate historical oracle qualification from native regression testing; define complete reference inputs and evidence validity | A0, A1 | planned | Unassigned |
| A6 | Enable proven selective validation and earlier failure reporting; validate the assembled result on protected main/release paths | A1-A5 review and evidence | planned | Unassigned |
| A7 | Evaluate and, where justified, separate Core's cheap preflight feedback from extensive feature/security validation | A3; independent scoped follow-up | planned | Unassigned |

Begin with A0 and a small A1 PR. Avoid a single PR that simultaneously moves tests, changes their assertions, and reduces their triggers.

### A0: obligation and dependency inventory

Record each test group, its behavior/security obligations, owner, fixtures, environment switches, executable/image inputs, and required gate. Account for helper/child tests, ignored tests explicitly invoked elsewhere, and tests that return early without configured services. A matching test count alone does not prove matching execution.

Capture dependencies not represented in Cargo: HTTP/gRPC consumers, protobuf generation, embedded JSON/Markdown, schemas/migrations, scripts, compiler features, Dockerfiles, Compose/Kubernetes configuration, and pinned cross-repository artifacts. Prefer one machine-readable group/input manifest reused by planning, execution, and coverage checks over duplicated lists.

### A1: acceptance ownership

Keep service behavior and adapter tests with their service. Move tests that compose several implementations into an acceptance package that depends on them. Remove service-to-service development edges only when their consumers have moved and standalone package validation confirms the boundary.

Share exact-owned fixture and process-management Rust helpers. Preserve resource isolation, bounded cleanup, child-process protocols, provenance checks, and preflight coverage accounting. Investigate `CARGO_BIN_EXE_*`, `CARGO_MANIFEST_DIR`, relative fixtures, and artifact-discovery assumptions before moving tests: an acceptance package does not automatically receive dependency binary paths.

Completion evidence: before/after obligation mapping, focused package checks, relocated scenario execution, packaging/Bookworm acceptance at a meaningful milestone, and no lost mandatory checks. Test moves must initially retain current triggers and assertions.

### A2: one narrow Rust extraction

Choose the smallest coherent candidate after dependency inspection: response text/JSON compatibility or a Canvas domain/projection group. Reuse the existing code and corpus. Keep HTTP, SQLx, runtime composition, and passport cryptography out of the new package when they are not intrinsic to its responsibility.

For later worker-domain extraction, separate lease identity from PostgreSQL operations without weakening transaction fencing or the database-clock check after acquiring a lock. Do not move database guarantees into an unverified mock.

Completion evidence: the new package builds/tests independently, consumers retain behavior, its dependency graph excludes unnecessary runtime implementations, and measured feedback supports or limits further extraction. Temporary re-exports may preserve callers; duplicate implementations may not become permanent.

### A3: affected-check planning

Reuse useful existing selection logic after correcting its gaps. Handle additions, modifications, deletions, renames, fixtures, build inputs, dependency consumers, and merge-group base/head semantics. Include dev/build dependencies and relevant feature configurations. Missing history, unknown paths, incomplete mappings, or invalid evidence must broaden selection.

Run the planner in shadow mode while current full gates remain authoritative. Log why each group was selected. Exercise representative changes and compare the planned obligations with full results. Use small deliberate fault probes where necessary to show a relevant failure would be selected; ordinary green runs alone are insufficient.

Completion evidence: selector regression tests, representative dependency cases, shadow results, and reviewer agreement on every newly omitted group. No GitHub gate may treat an unexpectedly missing required group as success.

### A4: lower-level behavioral coverage

Use table-driven tests and shared Rust scenario data for pure decoding, projections, validation, and scheduling decisions. Reuse existing repository/provider ports; share contract tests between test doubles and real adapters where practical. Tests should assert externally meaningful outcomes, not mirror implementation steps.

Retain real PostgreSQL coverage for atomicity, locking, tenant isolation, recovery, and expiry after lock waits. Retain real TLS, signals, shutdown, and packaged-runtime coverage where those are the obligation. Controlled Tokio time applies to isolated Tokio scheduling, not database clocks or separate processes.

Replace an expensive assertion only after documenting its lower-level equivalent and the remaining integration proof. Preserve all unique cases and negative/security expectations. Keep independent expected observations independent: DRY must not make a test calculate its expected answer with the production implementation under test.

### A5: historical reference qualification

Identify the complete reference closure: historical image digest, capture code and helpers, scenarios, schema/migrations, expected corpus, and relevant execution environment. Native comparisons remain responsive to native changes.

Separate reference qualification first without skipping it. Reduce its frequency only after evidence is bound to the complete closure and stale/missing evidence forces verification. Reference input changes trigger requalification; preserve periodic full comparison to detect environment drift. A version label alone is not evidence validity.

### A6-A7: rollout and fast feedback

During rollout, keep broad merge validation while proving selection. The intended steady state is affected package tests and contracts during development, broad checks for shared/unknown inputs, and qualification of actual release artifacts. Periodic exhaustive compatibility runs supplement required change-specific checks. Full validation must not wait for a major version increment.

Ensure cheap failures can be reported promptly. Additional lanes must justify their compilation/setup cost and retain every required obligation. For Core, examine the 14m23s preflight before separating work; preserve its feature/security matrix and avoid merely duplicating builds.

## Review, validation, and coordination

1. Start each implementation PR from current upstream main in an isolated worktree. Claim its tracker row and list affected paths; avoid overlapping ownership of manifests, fixture helpers, and workflow selectors.
2. Write the behavioral and coverage invariants before editing. Identify shared Rust code to reuse and any temporary compatibility layer to remove later.
3. Run package-scoped checks, targeted tests, and relevant workflow/packaging validation. Reserve expensive full runs for meaningful milestones and existing protected CI; do not rerun them after every small edit without a reason.
4. Self-review the complete diff and dependency/test-selection changes. Have a reviewer worker examine implementation PRs for regressions, missed inputs, boundary leaks, and coverage loss, following the user's established review loop.
5. Resolve findings and review again. Record validation against the reviewed commit; invalidate affected evidence after subsequent changes. Do not merge with unresolved correctness, security, or coverage findings or failed required checks.
6. Merge ready maintenance PRs through the existing protected process. Preserve tests, features, environment approvals, and the open-source/free-tier constraint. Record PR, merge SHA, checks, reviewer disposition, and any justified deviations here.
7. Verify normal post-merge behavior at milestones and compare equivalent job/step timings. Distinguish execution time, compilation, setup, queue/approval delay, and runner work; report warm/cold conditions and uncertainty.

Self-review specifically checks error paths, tenant/security boundaries, feature combinations, ownership/cleanup, public interfaces, dependency changes, and whether a test really executed its intended scenario. For selection changes, it also checks negative cases and conservative fallback behavior.

## Progress and decisions

| Date | Item | Decision / result | Evidence |
| --- | --- | --- | --- |
| 2026-10-02 | Plan | User requested a coordination document and active implementation goal, with self-review, regression prevention, and Rust reuse/DRY | Conversation authorization |
| 2026-10-02 | Baseline | Architecture investigation complete; implementation and speed estimates remain unverified | Baseline above |

For each subsequent PR append: item ID, owner, PR link, reviewed SHA, findings/fixes, targeted checks, full-CI evidence when applicable, changed obligation mapping, merge SHA, observed timing, and next dependency unblocked.

## Goal completion criteria

- Accepted changes are reviewed, validated, and merged; each queue item has a documented final disposition.
- Tests have explicit owners and inputs; cross-service acceptance no longer requires unjustified service development dependencies for the moved scenarios.
- At least one justified narrow Rust boundary is independently testable, with shared implementations and no untracked duplicate logic.
- Selective validation is supported by dependency and regression evidence; unproven exclusions remain broad.
- No unique behavioral/security obligation, feature, test case, or protected release requirement is lost.
- Historical reference and native validation responsibilities are explicit, with any evidence reuse checked for validity.
- Normal GitHub runs demonstrate the resulting feedback behavior. Record actual savings or absence of savings without extrapolating from code size.

## Design references

- [Cargo workspaces and package selection](https://doc.rust-lang.org/cargo/reference/workspaces.html): use package boundaries within the current workspace for independent validation.
- [The practical test pyramid](https://martinfowler.com/articles/practical-test-pyramid.html): place detailed behavior at fast levels while retaining focused integration proof.
- [Contract versus functional tests](https://docs.pact.io/consumer/contract_tests_not_functional_tests): message compatibility does not establish durable side effects.
- [Tokio testing](https://tokio.rs/tokio/topics/testing): controlled time and I/O doubles for appropriate isolated tests.
- [Semantic Versioning](https://semver.org/): version numbers express intended compatibility, not the impact of implementation changes.
