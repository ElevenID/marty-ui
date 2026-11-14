# Repository layout conventions

The root is the entry point for readers and tools, not the default destination for new working notes. Prefer existing folders and keep filenames stable when a directory move is sufficient.

## Documentation placement

| Folder | Content |
| --- | --- |
| `docs/architecture/` | Architecture explanations and design boundaries |
| `docs/development/` | Contributor workflows, setup details, localization, and repository conventions |
| `docs/reference/` | Component and implementation reference material |
| `docs/operations/` | Operational procedures and manual checklists |
| `docs/testing/` | Test guides and interoperability procedures |
| `docs/project/` | Implementation summaries, planning, and historical status notes |

Add a link in the [documentation index](../README.md) for each important guide. Keep `README.md`, license files, contributor entry points, tool-discovered configuration, package manifests, and lockfiles in their supported locations. Do not move Rust workspace members or Flutter platform directories merely for visual consistency.

## First-pass document moves

| Previous root file | Current location |
| --- | --- |
| `COMPONENT_QUICK_REFERENCE.md` | [Reference](../reference/COMPONENT_QUICK_REFERENCE.md) |
| `DASHBOARD_IMPROVEMENTS.md` | [Project notes](../project/DASHBOARD_IMPROVEMENTS.md) |
| `DEVOPS.md` | [Operations](../operations/DEVOPS.md) |
| `I18N_STATUS.md` | [Development](I18N_STATUS.md) |
| `LOCALIZATION.md` | [Development](LOCALIZATION.md) |
| `MANUAL_READINESS_TASKS.md` | [Operations](../operations/MANUAL_READINESS_TASKS.md) |
| `MICROSERVICES.md` | [Architecture](../architecture/MICROSERVICES.md) |
| `OID4VCI_TESTING_GUIDE.md` | [Testing](../testing/OID4VCI_TESTING_GUIDE.md) |
| `OPEN_SOURCE_READINESS.md` | [Project notes](../project/OPEN_SOURCE_READINESS.md) |

The content remains versioned; moving a progress report does not revalidate its status claims. Commands and plain source paths in these guides remain relative to the repository root unless a guide explicitly changes the working directory. Markdown links are relative to the document that contains them.

## Files deliberately unchanged in this pass

Compose files, environment templates, `install.sh`, `Makefile`, `deploy/`, `deploy-config/`, `docker/`, `k8s/`, application source, and release artifact contracts retain their paths. Remaining root-level setup, security, and self-host guides need a separate caller and packaging audit before relocation. No production qualification or release admission changes are implied.

## Deployment cleanup follow-up

The proposed destination for Compose definitions is `deploy/compose/`, grouped only where useful into profiles, self-host, service overlays, and acceptance scenarios. This is a plan, not an implemented directory layout.

Before moving deployment files:

1. Inventory references in Make targets, shell/PowerShell/Python scripts, workflow path filters, Docker build contexts, bundle builders, manifests, and other ElevenID repositories.
2. Compare rendered Compose configurations before and after each supported combination, with explicit project directory and environment-file handling. Check build contexts, bind mounts, includes, `extends`, secrets/config files, and relative paths from callers outside the repository root.
3. Preserve the published installer and release-bundle layout unless a separately reviewed compatibility change is intended. Do not create root-level copies or symlink aliases that would recreate the clutter or behave differently on Windows.
4. Run installer/package contract tests and disposable deployment smoke checks before merge. Prefer the existing local/AWS validation workflow; no new release pipeline is required merely for moving files.

Use separate reviewable changes for documentation, deployment layout, and Rust workspace structure. Do not reorganize upstream fork source layouts without accounting for future upstream synchronization.
