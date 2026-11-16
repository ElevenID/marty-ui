# Repository restructuring foundation

Status: migration preparation; no production cutover authorized.

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
- Canvas extraction remains a parallel workstream. Its source, license and release boundary must be determined by the existing Canvas migration rather than assumed to belong to `application`.

## Execution status

| Workstream | Status | Next gate |
| --- | --- | --- |
| Naming and ownership standard | Adopted in planning | Apply consistently to new repositories |
| Website extraction audit | In progress | Resolve complete import/dependency closure |
| Platform extraction audit | In progress | Classify installer vs product runtime/service assets |
| Canvas extraction | Parallel existing work | Preserve current handoff and release boundaries |
| New repository creation | Blocked by GitHub capability | Create `platform` and `website` in ElevenID organization |
| Source migration | Not started | Complete audits and create destination repositories |
| Release/provenance migration | Not started | Agree on cross-repository producer trust and manifest contract |
| Production cutover | Not authorized | Separate live qualification and rollback approval |

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

1. Finish website import, asset, route, build and workflow closure audit.
2. Finish platform source, workflow, bundle and test ownership classification.
3. Resolve shared assets and contracts that must remain with application/backend or become versioned contracts.
4. Create destination repositories `website` and `platform`.
5. Bootstrap destination CI, security policy, license, README and branch protections.
6. Migrate website with history and independent build qualification.
7. Migrate installer/platform in a separate history-preserving change.
8. Convert `marty-ui` into `application` only after website source and release ownership have moved and the remaining application build has been proven self-contained.
9. Reconcile Canvas extraction independently.
10. Introduce signed cross-repository product manifest and qualify fresh install, upgrade, rollback and recovery before production cutover.

## Known tooling constraint

The connected GitHub capability available for this work can inspect repositories, create branches/files and pull requests, but does not expose organization repository creation or branch-protection administration. Destination repository creation and protection must be completed by an organization administrator. No destination repository or production change is claimed until GitHub confirms it.
