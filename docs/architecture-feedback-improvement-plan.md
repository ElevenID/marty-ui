# Architecture and development-feedback improvement tracker

Status: active requirements and queue, 2026-10-17.

## Current delivery priority

Current handoff checkpoint (2026-10-17): the published v1.1.250 preview below
predates known fresh-install repairs and should not be the next tester handoff.
Stack v1.1.254 published its standard signed assets and an unqualified prepared
bundle in [run #39068340445](https://github.com/ElevenID/marty-ui/actions/runs/39068340445).
Its fresh installed journey completed the public issue/present/verify/revoke
flow and live OpenBao custody verification, but failed when diagnostics rejected
later custody phase names. Reviewed [PR #1388](https://github.com/ElevenID/marty-ui/pull/1388)
repairs that reporting contract on protected main
`76a7fb4ef6e2ad594dc431da511686a1664979ab` and selects v1.1.255.
A fresh local rehearsal with the candidate diagnostics module passed the public
journey, Keycloak refresh, both database custody checks and owned teardown;
that overlay run does not qualify an immutable release.
Its redacted local diagnostic report recorded 173.885 seconds overall:
113.953 seconds startup, 1.986 seconds public journey and 33.516 seconds cleanup.
The Linux-visible VM had 16,265,674,752 bytes RAM; sampled host used memory
reached 7,913,373,696 bytes and swap use reached 2,653,372,416 bytes. These are
shared-host observations, not stack-specific requirements. Container peak
memory and OOM evidence were not collected, so this run cannot establish a
supported memory minimum. Reports remain local at
`/home/canvasrunner/kms-qualification/v1.1.254/private/install-39068340445-b/installed-diagnostic.json`
and the sibling `installed-journey.json`.
The subsequent cleanup audit found nine older disposable OpenBao services still
running. Each was matched to its stage marker, exact Compose path and owned state
mount before being stopped; containers, state and reports were retained. The
existing stack was left running. Future evidence must include separate OpenBao
cleanup as well as the main runner's teardown, and distinguish remaining shared
host workloads from the new installation's own container measurements.

Current-main CI evidence: the completed contracts lane of full qualification
[run #39074993676](https://github.com/ElevenID/marty-ui/actions/runs/39074993676)
recorded a 113.029-second ordinary DB group, including 98.520 seconds in
`canvas_sync_worker_postgres_contract`. Its nested phase timings included
50.947 seconds renewal job outcomes, 30.301 seconds renewal write failures and
10.085 seconds renewal generation; these overlap the parent timing and must
not be added to it. The separately running Canvas acceptance lane was still
pending when this evidence was collected. The host compile cache report showed
645 Rust hits and four Rust misses, with four cache-write errors. These are
single-run observations, not before/after speedup measurements; preserve real
renewal semantics and investigate the write errors before drawing conclusions
about cache capacity or changing cache configuration.

Next handoff work, in order:

1. Produce the signed v1.1.255 Stack release and its exact prepared bundle.
2. Replay a fresh installation from those unchanged artifacts, retaining the
   original qualified preparation transaction and source/run/digest binding.
   Record the complete journey, custody checks, cleanup and hardware measurements.
3. Publish a separate explicitly unsupported experimental preview with the ZIP,
   image lock, receipt, descriptor, original preparation transaction, tester
   guide and checksums. Verify anonymous downloads independently and hand that
   version to outside testers. Existing approval permits this experimental
   distribution before supported qualification; retain accurate limitations.
4. Finish independent installed replay and review the measured hardware envelope
   before publishing qualified self-host assets or making support claims.

Enable outside testers to anonymously download and try a disposable self-host
bundle. The [v1.1.250 experimental preview](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.250-selfhost-preview.1)
is published from protected-main source
`5a89b3915f19e35c3f77bf9f278c212663e1150f`, with seven anonymously
downloadable assets. An independent anonymous download passed checksum,
archive, receipt, descriptor, source and run-lineage checks. Local Docker/Compose
preflight passed all 31 locked services and confirmed that two project names
produce separate default networks and Redis socket volumes. The
[Stack release run](https://github.com/ElevenID/marty-ui/actions/runs/39007886412)
passed image, security, integration, anonymous-pull and prepared-consumer gates.
These are preparation checks, **not** installed acceptance; the preview remains
unsupported and unqualified.

The preview release notes now clarify the external tester's public seven-asset
path: it supersedes the immutable v1.1.250 source-tag runbook's older Actions
artifact acquisition step. Staging must not be repeated against the same
private root. Main-line bundle/runbook guidance points to the current preview;
neither clarification changes preview assets or installation qualification.

The disposable staging, isolated locked-image OpenBao startup, Keycloak inputs,
workload TLS and custody helpers are on protected main after reviewed
[PR #1375](https://github.com/ElevenID/marty-ui/pull/1375) and its prerequisites.
The fresh-install KMS/startup repair from reviewed
[PR #1379](https://github.com/ElevenID/marty-ui/pull/1379) is also on protected
main. The published preview predates that repair; a new exact-source
experimental candidate is needed before installed replay. Neither merge
constitutes installed acceptance.
The preview guide uses the original preparation transaction and a clean exact
source checkout; it requires a non-root Linux operator and disposable private
state. [Issue #1350](https://github.com/ElevenID/marty-ui/issues/1350)
tracks the next evidence: an external tester's fresh installed journey with
KMS custody, measured RAM/CPU/disk/swap/OOM and owned cleanup. Before a
**supported** handoff, also establish a reviewed 16 GiB operating envelope or
document the actual minimum, complete Linux qualification on suitable hardware,
signed qualified self-host assets and independent anonymous install replay.
The 15.1 GiB local Docker VM has completed a candidate-overlay rehearsal;
fresh immutable-release acceptance and a reviewed measured hardware envelope
remain pending. Defer unrelated A0-A7 optimization behind this handoff.

The [v1.1.248 Stack release](https://github.com/ElevenID/marty-ui/releases/tag/v1.1.248)
published signed standard assets, but its [self-host preparation
job](https://github.com/ElevenID/marty-ui/actions/runs/38959969195) failed before
producing a customer ZIP. The receipt verifier expected two OpenBao services
after the packager added `openbao-tls-init`. PR #1370 repaired the exact
three-service image check on main. `v1.1.249` published signed assets and a
prepared ZIP, but its rendered Compose pinned the production default network,
so the fresh isolated installation was unqualified.
[PR #1377](https://github.com/ElevenID/marty-ui/pull/1377) fixed project
network/Redis isolation. `v1.1.250` published the signed standard Stack assets,
but that qualification does **not** qualify its separate self-host preview or
either earlier bundle.

## Installed setup requirements

The workload TLS and Keycloak disposable provisioners are now on protected
main. Preserve their remote-only contract: workload private keys stay in Transit,
public certificates bind to the selected remote keys, and per-key/realm/purpose
policies reject foreign-key and cross-realm use. Provisioning and TLS-oracle
success do not establish installed Compose or supported release acceptance.

- The exact v1.1.250 DIDComm-plugin image passed its release image gate for the
  Keycloak JWE path; the older cached published image did not support it.
  Current disposable JWE policies cover the initial key version only and
  require scoped-token reprovisioning after rotation. Installed rotation
  readiness remains unqualified.
- The complete local journey inventory closes all 76 secret names:
  17 scalar credentials,
  31 workload TLS files, seven Keycloak files, 15 OpenBao outputs and six
  disabled-optional placeholders. A staged persistent root and fresh installed
  acceptance still require evidence. The HAIP token retains its narrow KMS policy.
- For generated text credentials, preserve the private POSIX directory (`0700`)
  and container-readable final files (`0444`), with initial `0600` creation and
  rollback on a failed mode transition. Six optional integration files may be empty only when those
  integrations are disabled. The local journey does not use a Cloudflare token.
- Installed hooks require loopback HTTPS OpenBao at the selected signing-keys
  port and must verify the staged public CA. Wrong-host and foreign-CA
  rejection remain required.

Disposable setup helpers enforce the POSIX private-root/mode contract and reject
non-POSIX hosts. The seven Keycloak remote-key inputs share that private root,
use container-readable final modes and must not overwrite existing files. The
extracted bundle includes the small shared HTTPS OpenBao client and provisioner;
focused Linux/Windows tests are not installed-journey acceptance.

The exact services digest pinned by preview .2 lacks
`/usr/local/bin/marty-passport-tls-bootstrap`; newer source does not repair
that immutable older image. The v1.1.250 release gate passed the executable
check on its exact services digest after native-schema qualification. This does
not prove extracted-image startup or installed acceptance. A healthy
source-built stack with existing state on a 15.1 GiB VM is not a fresh install
or measured 16 GiB customer envelope.

The Linux-only disposable TLS helper verifies the extracted image lock and the
running OpenBao Compose owner, image and state mount. It stages only the 31
verified self-host public certificates/scoped tokens into the existing private
root, including the Verification client and exact Rust/catalog filenames; it
stages neither a root token nor a private workload key. Preserve shared binding
validation and chmod/chown/Docker-timeout cleanup failure handling. Fresh signed
image installation and preview qualification remain open.

Release-operator Cargo checks on both Linux architectures must report positive
executed test counts before building/validating binaries. Preserve the unfiltered
package, target builds, attestations and protected release gates; current-head
hosted validation remains required.

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
| A0 | Inventory test obligations and their inputs; identify effective execution, owning package, runtime dependencies, and current gate | None | investigating | DB-contract executables now resolve by package, test target and unique path from this run's Cargo compiler artifacts in CI; effective execution, runtime inputs and complete dependency/obligation inventory remain incomplete. Source-name or positive-summary sentinels are not a complete graph. |
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

Additional October 16 setup checkpoint history is recoverable from protected
main commit `4f2b6d83922f0c8e5d6b26dddd903ef928566c59`; its active constraints are retained above.

The installed-setup requirements also incorporate protected-main checkpoint
`dd0d8d17a556696d6d287b785f40c3fc61f72b66`; source/package checks do not qualify the preview.
