# Application build boundary rehearsal

This batch prepares the application side of the website split. It provides a
repeatable build with an audited subset of website inputs absent from a
temporary source export. The existing checkout remains intact. This is a
source and build check; the combined application release remains the selected
compatibility producer during standalone website composition.

## Application configuration

The application surface now resolves `publicConfig.application.js`. It preserves
the public application capabilities and website handoff links while requesting
only the translation namespaces retained in application output. In particular,
the application no longer requests `marketing.json`, which its existing output
pruner removes.

Application builds also skip the website demo generator. The website and
combined build paths retain their generation behavior. The application module
guard reads and validates the ownership roster without requiring the forbidden
website source files to exist. Website, combined and customer build guards
continue checking that all roster entries exist as regular files.

## Audited temporary export

`ui/scripts/application-source-closure.mjs` inventories the UI source and the
two existing ownership/routing contracts, then creates a fresh directory outside
the checkout. Its export omits:

- The 34 modules in `contracts/website-source-ownership.json`.
- The three raw demo catalog inputs `ui/public/demos/manifests/index.json`,
  `2026.07.0.json` and `2026.08.0.json`.

The export retains the dependency manifests and lockfile, shared application
authentication and routing, navigation, assets, generated demo projections and
their reader. The generated projections remain intentionally conservative
retained inputs. The 37 omissions do not constitute a complete website source,
asset, package or workflow extraction manifest.

The harness runs the existing `build-web-surface.mjs application` entrypoint.
It checks the emitted application/source/route marker, the main and console
entrypoints, all seven English fallback translation namespaces, and absence of
the marketing output paths and locales already excluded by the application
build. The existing emitted-module guard still rejects website-owned modules.
It also verifies that the original source inventory, byte hashes, file modes
and Git status are unchanged. The temporary export is removed after success or
failure unless it was explicitly requested for inspection.

Source and output inventories are written into the JSON report. A dirty source
checkout is explicitly recorded with its own input hashes; its build is not
evidence for the unmodified commit named by `HEAD`. Such output uses the
`development` source marker. Only a clean checkout uses its exact commit in the
output marker.

## Running the check

Use the repository's normal UI dependency installation and postinstall patches.
From `ui/`:

```sh
npm run test:application
npm run check:application-source-closure -- --report /tmp/application-source-closure.json
```

The report must be a new file outside the source checkout. Omit `--report` to
write JSON to standard output; build logs go to standard error. Optional
`--dependencies /absolute/path/to/node_modules` selects an existing dependency
installation, and `--keep-export` retains the generated source and build for
inspection. The report identifies the export location. A failed build, output
check or source-preservation check exits nonzero.

This rehearsal reuses installed dependencies. Its report records the dependency
directory and source lockfile hash, and explicitly sets
`independent_dependency_installation` to `false`. A successful rehearsal does
not qualify a separate package installation or claim that its dependencies were
installed from that lockfile. In CI, the existing verified release-package
bootstrap may edit the working package manifest; the report records that dirty
state rather than presenting it as a clean committed-source release.

The required `Website Surface` lane runs the focused application tests and the
real temporary-export build in addition to its existing website, application
and customer builds. It retains the JSON report as
`application-source-closure-RUN-ATTEMPT` for 14 days when a report is available.
This diagnostic artifact has no release authority.

## Acceptance and next gates

A completed checkpoint records the exact candidate commit, whether the source
checkout was clean, omitted/retained path inventories, the report's input and
output hashes, local validation and the exact hosted CI result. Run the final
candidate rehearsal after committing the reviewed changes so that its source
identity can be reproduced. Record the resulting evidence in the candidate PR.

The report keeps source extraction, independent dependency installation, signed
publication, host deployment and OIDC qualification explicitly incomplete.
Finish the signed standalone website composition milestone before queueing this
follow-up. Then classify the remaining source/assets and qualify an independent
application producer, compatibility intake and actual application/OIDC behavior
before removing source, selecting a slim application image or renaming the
repository.
