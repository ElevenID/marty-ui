# Repository restructuring foundation

Status: standalone website publication and signed cross-owner composition are
qualified. Application source, test, asset and dependency separation is in progress. Production
cutover remains a separate gate.

## Current development priorities

The November 20 regression audit changes the next implementation order. The
accepted historical runs below remain evidence for their original source; they
do not qualify the current repair branch.

1. **Repair behavior and restore the established toolchain.** Complete the
   Bun 1.4.4 frozen-install path in the standalone website and portable
   application, including actual dependency identities, lifecycle patches,
   SDK/WASM, deterministic package restoration and explicit release metadata.
   Preserve validation of original npm evidence. Include the audited login,
   invitation navigation, apply-return destination, loading-style and website
   development-resource fixes in the same regression milestone. Validate
   locally before requesting hosted checks; do not start chargeable CI work.
2. **Remove the owned marketing source.** Resolve the old combined/default
   build entries, website Docker/CI targets and release consumers. The private
   commerce publisher still builds a selected historical `marty-ui` source:
   migrate that path or explicitly constrain legacy modes to a supported
   historical source before deleting their current-source inputs. Convert
   migration checks that require old files into checks against reintroduction,
   then delete the owned modules, assets and obsolete tests. Recheck application
   and customer builds. The 34-module ownership roster is the starting point;
   the portable package's complete omission list is not a deletion manifest.
3. **Adopt the independently published application.** Carry the selected Bun
   identity through publication, intake and backend qualification. Reconcile
   the pending intake/backend-preparation work with the new evidence schemas.
   Authenticate the actual first publication and select a backend supporting
   the application's current endpoints before composition adoption.
4. **Complete runtime adoption and ownership closure.** Exercise the real
   authentication/OIDC journey and isolated-host promotion, rollback and
   recovery before live adoption. Complete the remaining source/release
   ownership work before repository renaming. Production activation retains
   its separate acceptance decision.

Steps 2 and 3 have different gates. Fresh installation and standalone
application/container evidence already justify beginning bounded source
cleanup. OIDC, host deployment and production activation are not blanket
prerequisites for removing unused marketing files. A source-removal change
must still preserve or deliberately retire every remaining supported consumer.

## Current continuation checkpoint

Latest recorded evidence, November 20, 2026 (America/Denver):

| Workstream | Completed evidence | Next gate |
| --- | --- | --- |
| Standalone website producer | Successful signed `ElevenID/website` run [`44449706828`, attempt 2](https://github.com/ElevenID/website/actions/runs/44449706828/attempts/2), source `7ec0707aa348939a0e48e6a26b24fb1af8671b9b` | Preserve this exact original release selection for composition; newer source requires a newly qualified release |
| Cross-owner composition | [PR #1999](https://github.com/ElevenID/marty-ui/pull/1999) merged as `6daf2a21`; protected-main [run `44594894023`, attempt 1](https://github.com/ElevenID/marty-ui/actions/runs/44594894023/attempts/1) signed and verified the composition; its six-file artifact and original evidence bytes were independently inspected | Qualify the actual application/OIDC flow and isolated-host promotion, rollback and recovery with this exact composition |
| Application source preparation | [PR #2001](https://github.com/ElevenID/marty-ui/pull/2001) merged as `cf333d61e4cc406d0fdaa870829396291d887ea7`; clean local and hosted builds passed with 37 audited inputs absent, and [normal queue CI](https://github.com/ElevenID/marty-ui/actions/runs/44635771801) completed with 27 successful jobs and one intended skip | Preserve the accepted source boundary while expanding application test, asset and dependency qualification |
| Application source, tests and assets | [PR #2002](https://github.com/ElevenID/marty-ui/pull/2002) merged normally as `780b531a22a89ed75442e71ed51ce4cb727c08ec`. Clean local and hosted v3 rehearsals passed with 71 inputs absent, 284 tests across 23 selected files, 54 preserved public resources and 73 checked HTTP responses. Both [PR CI](https://github.com/ElevenID/marty-ui/actions/runs/44641102200) and [merge-queue CI](https://github.com/ElevenID/marty-ui/actions/runs/44647472085) completed with 27 successful jobs and one intended skip; all queue output bytes match the accepted PR rehearsal | Preserve the merged boundary and its exact diagnostic evidence while extending independent application qualification |
| Independent application packages and browser startup | [PR #2004](https://github.com/ElevenID/marty-ui/pull/2004) merged normally as `d1cf7bf93460344eaf78bbf5496eb949835138f6`. Its accepted source `83a59f65902a6691f46d2051773313f7e2b5ff3b` passed [CI `44657507012/1`](https://github.com/ElevenID/marty-ui/actions/runs/44657507012): 27 successful jobs and one intended skip. Both fresh profiles passed 296 tests across 24 files and emitted identical 88-file output. Hosted nginx/browser execution observed the SDK WASM, public/console rendering, unavailable-session Retry and aborted-WASM recovery; owned cleanup passed | Preserve the accepted package/runtime boundary while qualifying independent publication; actual authentication/OIDC and host acceptance remain separate |
| Portable application source package | [PR #2007](https://github.com/ElevenID/marty-ui/pull/2007) merged normally as `6fd59c730a28e413cec3855037ad600f8e2dabf3`. Its source `316afe12b21ee8ece006406ab510917f2c470574` passed [CI `44677296614/1`](https://github.com/ElevenID/marty-ui/actions/runs/44677296614); all six original artifacts were independently verified against the exact integration tree `18f67468ade76f527136fcc906a7d8c2af4deeb3`. The 575-file source package plus manifest restores outside Git; all three installations pass 296 tests and produce identical 88-file output and a normalized 92-file runtime payload. Real restored-package container/browser gates and cleanup passed | Preserve the merged source boundary, archive and original hosted evidence while qualifying independent application publication |
| Package-built application image | [PR #2010](https://github.com/ElevenID/marty-ui/pull/2010), source `56276dadd401e86cc505eab2d334b903dbce68db`, passed [CI `44689242895/1`](https://github.com/ElevenID/marty-ui/actions/runs/44689242895). Its actual integration source `3b291bf41e90aca2d4950d80f8f345f0a5ecb4f8` built the separate production recipe from the verified consumer context. All seven original artifacts were independently inspected, including real sandboxed browser, Retry, WASM-failure recovery and owned cleanup evidence | PR #2010 merged as `f81bf70f867569db97f73b06dbaef7813e89118b`. Inspect the first actual protected-main publication after the current toolchain repair is qualified. The accepted composition remains unchanged; CI records a local release-image build and does not establish registry publication or host/OIDC readiness |

Continue from the [standalone website composition checkpoint](website-composition-checkpoint.md)
and the exact run/artifact records in those PRs. The application source/test
rehearsal separately classifies combined adapters, demo projections and test
setup as application omissions. Shared application inputs, assets and
dependencies remain retained in the baseline. The accepted source/asset rehearsals
reused installed dependencies; PR #2004 separately establishes fresh locked
installation. These earlier qualifications do not establish source deletion, signed application
publication or an actual host/OIDC journey. The separate application-image
producer records its own evidence before publication can be accepted.

The [public asset audit](application-assets-audit.md) records the 26 additional
application omissions and the retained locale/runtime resources. The completed
71-input rehearsal binds 54 retained public resources to their original bytes,
with actual local HTTP and translation-fallback checks. Its exact committed
source and independently verified hosted artifact are recorded in PR #2002. A local
resource probe cannot replace production server, browser startup or actual
host/OIDC qualification.

The [dependency and runtime boundary](application-dependency-boundary.md) retains
the current full-lock baseline and immutable release selections. The explicit
application profile is a separate selection; the root manifest, both root locks
and default website/combined build behavior remain the baseline. Both fresh
installations run before CI bootstrap changes the root package manifest, and both
container checks exercise the unchanged production nginx/startup files. Removing
the four audited roots is a bounded dependency reduction. The [portable source-package milestone](application-source-package.md) carries this
accepted profile into an independently restored source tree. The
[application image producer](application-image-release.md) builds from that
consumer context and retains independent publication evidence. Complete package
graph minimization, final source extraction and isolated-host/OIDC qualification
remain subsequent gates.

The browser increment replays the immutable application-profile context after the
existing UI bootstrap makes diagnostic browser tooling available. It keeps all
five fresh-install, audit and container gates before bootstrap. The browser probe
must observe actual application rendering and the exact SDK WASM response under
production nginx/CSP, then independently fail startup when that WASM is blocked.
No identity provider or deployment account is needed for this bounded startup
check. Successful authentication and the actual host/OIDC journey remain separate.
The console entrypoint also carries the existing startup recovery shell, so a
module failure can offer the same reload action as the public entrypoint. Both
documents use the unchanged startup script, and their recovery regression cases
are included in the selected application test suite.

The bootstrap status and initial sequence below preserve the November 15
foundation. Use the checkpoint above for the current execution stage. Actual
host promotion, rollback/recovery and OIDC qualification remain distinct from
publication and packaging; production changes and repository renaming require
their later acceptance gates.

## Adopted repository names

The ElevenID GitHub organization provides the namespace. Repository names are functional and do not repeat the organization or product name.

| Target repository | Responsibility |
| --- | --- |
| `platform` | Canonical product entry point: installer, deployment, release selection/composition, upgrades, diagnostics and recovery |
| `website` | Public marketing website, SEO, product information and public demos |
| `application` | Authenticated user application, organization and applicant experiences, credential workflows |
| `protocol` | Marty protocol specifications |
| `core` | Core Marty protocol implementation |
| `docs` | Technical and developer documentation |
| `blog` | Publishing and content package |
| `cli` | Developer/operator command-line tooling |
| `recorder` | Demo recording and evidence tooling |
| `subscriptions` | Private billing and commerce |

Existing independently maintained backend services remain independently owned. Do not create a catch-all `services` repository merely to normalize names. Existing package/crate names and external repository identities are not automatically renamed.

## Target architecture

- `platform` consumes published, immutable artifacts and signed release manifests. It must not need the application source checkout to install a release.
- `website` and `application` build and release independently.
- `protocol` and backend/service repositories own their implementation source.
- Private subscription/commerce code remains in `subscriptions`.
- The Canvas source split is merged into the existing [`canvas-integration`](https://github.com/ElevenID/canvas-integration) repository. Provider protocols, credentials, administration, workers and storage remain connector-owned; the public Common Gateway is its sole platform interface. Core retains canonical identity, ownership, evidence, approval, signing and audit. Existing licenses/provenance remain with their owners; production adapters and deployment/cutover qualification are separate owned TODOs, with unsupported flows disabled.

## Bootstrap execution status (November 15, 2026)

| Workstream | Status | Next gate |
| --- | --- | --- |
| Naming and ownership standard | Adopted in planning | Apply consistently to new repositories |
| Website extraction audit | Static import audit inspected 79 files at `df6ec6c4bfee803d89c54e9333297f29f378cee3`; extraction closure remains open | Resolve assets, tests, build inputs and workflow dependencies |
| Platform extraction audit | In progress | Classify installer vs product runtime/service assets |
| Canvas source extraction | Merged into `ElevenID/canvas-integration` | Preserve Gateway-only authority and source/license provenance; qualify disabled connector capabilities separately before activation |
| New repository creation | Public `platform` and `website` exist with `main` as default; `application` is not created | Keep `marty-ui` as migration source until extraction qualification |
| Destination branch and Actions policies | Active default-branch rulesets and restricted Actions settings verified; website requires its passing contract check | Establish platform CI before adding its required status checks |
| Website contract bootstrap | [PR #1](https://github.com/ElevenID/website/pull/1) merged through the protected merge path; six hosted tests passed | Continue website dependency closure and independent build qualification |
| Source migration | Application and installer source extraction not started | Complete audits and qualify each independently reviewable extraction batch |
| Release/provenance migration | Not started | Agree on cross-repository producer trust and manifest contract |
| Production cutover | Not authorized | Separate live qualification and rollback approval |

## Destination repository checkpoint

Verified on November 15, 2026 (America/Denver):

| Repository | Repository ID | Default branch | Active ruleset | Required status check |
| --- | --- | --- | --- | --- |
| [`ElevenID/platform`](https://github.com/ElevenID/platform) | `1459541945` | `main` | [`27350361`](https://github.com/ElevenID/platform/rules/27350361) | None yet |
| [`ElevenID/website`](https://github.com/ElevenID/website) | `1459542519` | `main` | [`27350292`](https://github.com/ElevenID/website/rules/27350292) | `Website contracts` |

Both destinations are public. Website `main` now contains the route-contract and validation foundation; platform `main` remains README-only. Each active ruleset targets the default branch, requires a pull request and resolved review threads, has no bypass actors, and blocks branch deletion and force pushes. Required approval count is zero. Website's required check is bound to GitHub Actions integration `15368`, requires the branch to be up to date, and is enforced on branch creation (`do_not_enforce_on_create: false`). Platform has no required status check yet. The website foundation's source and hosted validation evidence are recorded in the [website audit checkpoint](website-extraction-audit.md#execution-checkpoint); build and release qualification remain open.

Actions require full-length action commit SHAs, require approval for external contributors, use a read-only default workflow token, and do not allow Actions to create or approve pull requests. Add further required status checks only after their destination workflows have run successfully and their check names are verified. Preserve these policies while expanding CI.

`ElevenID/application` has not been created. Do not rename or delete `marty-ui` before website extraction and the independent application qualification gates pass.

## Guardrails

1. Preserve current production workloads, data, deployment state and hostnames.
2. Do not cut over production as part of repository extraction.
3. Preserve OpenBao, rootless Docker, TLS, secret boundaries and existing automatic-stop safeguards.
4. Do not move private commerce source or secrets into public repositories.
5. Preserve Git history where practical.
6. Do not change crate/npm package names, image names, signing identities or release URLs as incidental cleanup.
7. Keep immutable image digests and original provenance evidence.
8. Do not blindly move every file matching an installer-related name. Ownership is based on responsibility and dependency closure.
9. Keep website, application, Canvas and installer PRs separate where practical; coordinate shared CI and release-file edits.
10. Treat current inventories as candidate ownership maps, not authorization to delete source from `marty-ui`.

## Release contract direction

Introduce a signed product release manifest consumed by `platform`. It must identify each component's repository, immutable image/package digest, version, platform, source commit, original producer workflow/run/attempt, provenance/signature references, compatibility constraints and minimum platform version. A schema sketch is not a release authorization.

Website and application producers should publish independently. Product composition selects already-published compatible artifacts and preserves original producer evidence. The installer verifies the complete release before deployment.

## Original execution sequence

1. Continue from the merged website route-contract foundation and its enforced `Website contracts` check. Refresh the destination branch before starting each subsequent batch.
2. Finish website import, asset, route, build and workflow closure audit. The 79-file static observation is not a qualified export manifest.
3. Resolve shared assets and contracts that must remain with application/backend or become versioned contracts; complete destination security policy, licensing and build documentation.
4. Migrate website source with history where practical in small batches, each with its applicable tests and independent build qualification.
5. Finish platform source, workflow, bundle and test ownership classification, then bootstrap its CI and required status gates in a separate PR.
6. Migrate installer/platform in separate history-preserving batches without introducing application source dependencies.
7. Convert `marty-ui` into `application` only after website source and release ownership have moved and the remaining application build has been proven self-contained.
8. Preserve the completed Canvas source boundary and coordinate any future generic Gateway contract or shared workflow changes with their owners; do not move provider code back into application or platform.
9. Introduce signed cross-repository product manifest and qualify fresh install, upgrade, rollback and recovery before production cutover.

## Checkpoint discipline

Keep each batch independently reviewable. Commit and push each coherent, validated change before beginning another substantial batch. Record the repository, branch, source commit, remote commit/PR, validation performed and remaining gate in the batch's PR or checkpoint documentation. Distinguish local completion, pushed source, passing CI, merge completion and deployment. Continue PR #1969 for this migration plan; do not duplicate it or its branch.

The earlier repository-creation and settings capability blocker is resolved by the verified destination checkpoint above. Repository availability does not close the source, build, provenance or deployment qualification gates.
