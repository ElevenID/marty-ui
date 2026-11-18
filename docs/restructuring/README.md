# Repository restructuring foundation

Status: destination repository bootstrap and extraction preparation; no production cutover authorized.

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

## Execution status

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

## Next execution sequence

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
