# Architecture and development-feedback improvement tracker

Status: active requirements and queue, 2026-10-16.

## Current delivery priority

Enable outside testers to anonymously download and install a self-host bundle.
The `v1.1.247-selfhost-preview.2` archive is an unsupported experimental preview,
not a qualified standalone verifier or supported deployment. Preparation,
archive/Compose/image-pull checks and exploratory lower-memory runs are not
installation acceptance. Before a supported handoff, require disposable tester
installation evidence, documented hardware limits and the 16 GiB envelope,
a clean Linux installed journey, KMS custody proof, signed qualified assets,
and independent anonymous download/install replay. Defer unrelated A0-A7
optimization behind this handoff.

## Objective and scope

Reduce the amount of unrelated code and infrastructure needed to validate a change. Establish independently testable Rust boundaries, select checks from their actual dependencies, and report failures earlier while preserving behavior, features, security guarantees, and release qualification.

The user authorized implementation of the investigated improvements, requires self-review and regression prevention, and prefers reuse of Rust code following DRY. All repositories are eligible for a justified change; the evidence currently prioritizes `marty-ui`, with a smaller selector/preflight follow-up in `marty-core`. Repository creation, service deployment splits, and broad framework replacements are not prerequisites.

The October 7 product-packaging and integration plan is now part of this active
work, not a competing CI plan. Its product-level work IDs remain the source of
truth for distribution, integration, consumer, and commercial acceptance; this
tracker coordinates their implementation with A0-A8. The consumer audit was
made against release v1.1.230 and source revisions older than current main, so
each defect and dependency must be rechecked against the implementation base.
Private business sources and unapproved pricing/marketing claims are not
copied into this repository or turned into engineering decisions.

This document coordinates the new architecture work. [The original build audit](rust-build-audit.md) and [its evidence](rust-build-audit-evidence.md) remain historical records of earlier optimizations. Those completed changes must not be reimplemented.

## Implementation queue

| ID | Work | Dependencies | Status | Remaining boundary |
| --- | --- | --- | --- | --- |
| A0 | Inventory test obligations and their inputs; identify effective execution, owning package, runtime dependencies, and current gate | None | investigating | Effective execution, runtime inputs and complete dependency/obligation inventory remain incomplete; source-name or positive-summary sentinels are not a complete graph. |
| A1 | Move cross-service/system tests into a dedicated workspace acceptance package; separate deployment/packaging, DIDComm/renewal, and Canvas groups | A0 | implementing | Dedicated acceptance owners and the zero service-to-service dev-edge guard have landed. Preserve all moved obligations; installed system acceptance remains distinct from component tests. |
| A2 | Extract one small domain/compatibility boundary from issuance, preserving public behavior and reusing existing Rust implementations | A0; coordinate moves with A1 | merged | The narrow shared Rust extraction is landed. Keep one implementation and public/error/resource-limit compatibility across consumers. |
| A3 | Harden Core selection and implement conservative UI affected-check planning in shadow mode | A0; map A1/A2 changes | implementing | UI planning remains shadow-only until the complete non-Cargo graph and conservative fallback are qualified; preserve Core feature/security owners. |
| A4 | Assign overlapping case matrices to the lowest adequate test level, retaining real adapter and process guarantees | A0; use A2 where appropriate | implementing | Retain old/new case-ID, fixture, assertion and required-lane parity; keep real database, adapter, process and cancellation obligations at their actual boundary. |
| A5 | Separate historical oracle qualification from native regression testing; define complete reference inputs and evidence validity | A0, A1 | implementing | Historical reference closure remains incomplete. No additional qualification skips or weakened current-input/source/producer checks are authorized. |
| A6 | Enable proven selective validation and earlier failure reporting; validate the assembled result on protected main/release paths | A1-A5 review and evidence | implementing | Unknown and mixed inputs remain broad. Preserve fail-closed planned-skip policy, required protected-main/full release gates and same-run evidence validity. |
| A7 | Evaluate and, where justified, separate Core's cheap preflight feedback from extensive feature/security validation | A3; independent scoped follow-up | merged | Cheap Core preflight separation is landed. Preserve the complete KMS, lint, compatibility, feature and security checks; do not extrapolate timings. |
| A8 | Split release E2E by verified release tier: nightly prerelease happy paths on one Linux target; stable official releases keep complete happy/error evidence; YouTube recording/publication only for official releases | A0, A4, A5 | implementing | Nightly qualification remains open: one Linux happy-path tier with no YouTube activity. Official releases retain complete happy/error E2E and official-only YouTube. Unknown tier or missing evidence fails closed. |

## Product packaging and integration gates

The coordinating workspace product plan
`artifacts/consumer-audit-2026-10-07/marty-product-packaging-and-integration-plan.md`
retains the detailed PKG01-09, INT01-06, TST01-05, CICD01-04, BUS01-02,
MKT01-02 and QA01-02 criteria. Preserve these identifiers when reconciling work.

- TST/CICD: map old/new case IDs, fixtures, assertions and required lanes;
  establish run-bound parity and conservative selection. Nightly discovery
  cannot replace required merge or release checks.
- INT01/PKG01-02: use anonymously accessible, digest-bound artifacts and fresh
  installation evidence. Default Canvas worker behavior remains unchanged;
  no-Canvas is opt-in. Any default switch requires pre-upgrade detection,
  existing-customer rehearsal and rollback. Do not narrow Canvas CI without
  dependency closure and affected-case parity.
- PKG03-07/INT02-04: prove independent verification/issuance artifact and adapter
  closures, tenant/security/transaction boundaries, migrations and ownership.
  A smaller image alone does not establish an independent verifier.
- INT05-06/PKG08-09: qualify installed capability authorization, supported
  existing-customer migration/recovery, public SDK/install paths, exact-artifact
  journeys and digest-preserving promotion. Keep official-release E2E and
  critical negative/security coverage.
- BUS/MKT/QA: retain license, source/notices and demonstrable public artifact
  facts. Commercial/legal owners decide pricing, license routes, hosted
  availability and public claims. Engineering does not invent those claims.

## Coverage and evidence safeguards

[The obligation inventory](architecture-test-obligations.md) retains assertion,
input and execution owners. An assertion move is not a new independent oracle.
Keep tests and source/dependency ownership aligned; an ignored, conditional,
undiscovered or empty test does not satisfy a gate. Reuse evidence only when
its source, inputs, producer, environment and scope remain valid. Require full
qualification on the exact protected-main source before stable preparation;
a changed source requires a new applicable qualification run.

Batch related changes by owner and validation path. Moving tests, changing
assertions and reducing triggers together requires independent coverage proof.
Report measured setup, compilation, execution, queue and approval times
separately, with comparable warm/cold conditions; file size is not a speedup.

## Review, validation, and coordination

1. Start each implementation PR from current upstream main in an isolated worktree. Claim its tracker row and list affected paths; avoid overlapping ownership of manifests, fixture helpers, and workflow selectors.
2. Write the behavioral and coverage invariants before editing. Identify shared Rust code to reuse and any temporary compatibility layer to remove later.
3. Run package-scoped checks, targeted tests, and relevant workflow/packaging validation. Reserve expensive full runs for meaningful milestones and existing protected CI; do not rerun them after every small edit without a reason.
4. Self-review the complete diff and dependency/test-selection changes. Have a reviewer worker examine implementation PRs for regressions, missed inputs, boundary leaks, and coverage loss, following the user's established review loop.
5. Resolve findings and review again. Record validation against the reviewed commit; invalidate affected evidence after subsequent changes. Do not merge with unresolved correctness, security, or coverage findings or failed required checks.
6. Merge ready maintenance PRs through the existing protected process. Preserve tests, features, environment approvals, and the open-source/free-tier constraint. Record PR, merge SHA, checks, reviewer disposition, and any justified deviations here.
7. Verify normal post-merge behavior at milestones and compare equivalent job/step timings. Distinguish execution time, compilation, setup, queue/approval delay, and runner work; report warm/cold conditions and uncertainty.

Self-review specifically checks error paths, tenant/security boundaries, feature combinations, ownership/cleanup, public interfaces, dependency changes, and whether a test really executed its intended scenario. For selection changes, it also checks negative cases and conservative fallback behavior.

## Goal completion criteria

- Accepted changes are reviewed, validated, and merged; each queue item has a documented final disposition.
- Tests have explicit owners and inputs; cross-service acceptance no longer requires unjustified service development dependencies for the moved scenarios.
- At least one justified narrow Rust boundary is independently testable, with shared implementations and no untracked duplicate logic.
- Selective validation is supported by dependency and regression evidence; unproven exclusions remain broad.
- No unique behavioral/security obligation, feature, test case, or protected release requirement is lost.
- Historical reference and native validation responsibilities are explicit, with any evidence reuse checked for validity.
- Normal GitHub runs demonstrate the resulting feedback behavior. Record actual savings or absence of savings without extrapolating from code size.
- Release-tier tests prove nightly single-Linux happy-path qualification and no YouTube activity, while official production releases run the complete happy/error E2E inventory with release-bound evidence and official-only YouTube publication; unknown tier and missing evidence fail closed.
- The test inventory demonstrates a genuine pyramid across unit, integration/contract, and E2E layers, with explicit tier/trigger ownership and no lost unique assertion; nightly executes only its declared happy-path cases at each layer, major-version qualification executes the complete mapped matrices, and every official stable release retains complete E2E qualification.

## Historical checkpoints

Chronological implementation, PR, run and timing snapshots are recoverable at
Git commit `c86b2f8c6b34ba7ec1bac5461ded03b28adb7745`. They were removed from this active queue.
Keep current requirements and unresolved acceptance here; store per-run output
in CI artifacts or ignored local directories. Historical branch/recorder reports
do not authorize removal of local unmerged work or imply current workspace state.
