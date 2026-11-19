# Application build boundary rehearsal

This batch prepares the application side of the website split. It provides a
repeatable build and application test profile with audited inputs absent from a
temporary source export. The existing checkout remains intact. This is a
source, build and component-test check; the combined application release remains the selected
compatibility producer during standalone website composition.

## Application configuration

The application surface now resolves `publicConfig.application.js`. It preserves
the public application capabilities and website handoff links while requesting
only the translation namespaces retained in application output. In particular,
the application no longer requests `marketing.json`, which its existing output
pruner removes.

Application builds also skip the website demo generator. The website and
combined build paths retain their generation behavior. Vite loads the demo
scenario helper through a fixed file URL only within their catalog branch, so
loading the application configuration does not require that helper. The application module
guard reads and validates the ownership roster without requiring the forbidden
website source files to exist. Website, combined and customer build guards
continue checking that all roster entries exist as regular files.

## Application test profile

`ui/vitest.application.config.ts` shares the existing plugins, test environment,
common setup and coverage settings. It explicitly replaces the profile's setup,
test-file and inline-dependency arrays and selects `publicConfig.application.js`
and `publicSite.application.jsx`. The existing combined configuration and its
website tests keep their original aliases and discovery. The commerce alias
continues to use the public stub.

The application setup imports the seven English application namespaces without
loading marketing translations. `ui/scripts/application-test-profile.mjs` names
23 exact test files covering route handoff, login and callback decisions,
session selection, auth availability, public/console route tables and navigation.
The profile regression lives outside the combined configuration's `src` test
discovery and exercises the actual application alias and root-to-login handoff.
The shared `contracts/organization-domain-behavior.json` input is retained for
the session tests.

The existing `tsc -p tsconfig.build.json` build gate is unchanged. Its JavaScript
source scan and excluded test fixtures remain as before; this batch does not
claim a separate or complete application compiler project. The Vitest profile
exercises jsdom components and mocked API behavior. Actual OIDC qualification
remains a later gate.

## Audited temporary export

`ui/scripts/application-source-closure.mjs` inventories the UI source and the
two existing ownership/routing contracts plus the exact session-test contract,
then creates a fresh directory outside the checkout. Its export omits 45 inputs:

- The 34 modules in `contracts/website-source-ownership.json`.
- The three raw demo catalog inputs `ui/public/demos/manifests/index.json`,
  `2026.07.0.json` and `2026.08.0.json`.
- The combined entry adapters `ui/src/components/LandingPage.jsx` and
  `ui/src/variants/publicSite.public.jsx`.
- `ui/src/services/demoManifestService.js`, `ui/src/services/platformDemoScenarios.js`,
  `ui/src/generated/demoManifests.generated.js` and
  `ui/src/generated/demoWalletSchema.generated.json`.
- The combined test setup `ui/src/test/i18nTestSetup.js` and its English
  `ui/public/locales/en/marketing.json` input.

The export retains the dependency manifests and lockfile, shared application
authentication and routing, navigation, the public application configuration,
other assets and the selected tests. The extra omissions have explicit
application-only classifications; the exclusive-website ownership roster stays
at 34 modules. In particular, the combined adapters retain their original
combined behavior in the checkout. The 45 omissions do not constitute a complete
website source, asset, package or workflow extraction manifest.

The harness runs the existing `build-web-surface.mjs application` entrypoint and
then runs the application Vitest profile within the same omitted-input export.
It requires every selected test source to exist before export. A successful
Vitest exit must also provide a JSON report naming exactly the selected files,
with passing assertions and no skipped or pending tests. Build and test
completion are recorded separately in the version 2 diagnostic report.

It checks the emitted application/source/route marker, the main and console
entrypoints, all seven English fallback translation namespaces, and absence of
the marketing output paths and locales already excluded by the application
build. The existing emitted-module guard still rejects website-owned modules.
Every omitted input must stay absent after both the build and test processes.
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
write JSON to standard output; build and test logs go to standard error. Optional
`--dependencies /absolute/path/to/node_modules` selects an existing dependency
installation, and `--keep-export` retains the generated source and build for
inspection. The report identifies the export location. A failed build, test,
test-report validation, output check or source-preservation check exits nonzero.

This rehearsal reuses installed dependencies. Its report records the dependency
directory and source lockfile hash, and explicitly sets
`independent_dependency_installation` to `false`. A successful rehearsal does
not qualify a separate package installation or claim that its dependencies were
installed from that lockfile. In CI, the existing verified release-package
bootstrap may edit the working package manifest; the report records that dirty
state rather than presenting it as a clean committed-source release.

The required `Website Surface` lane runs the focused application tests and the
real temporary-export build/test rehearsal in addition to its existing website, application
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
The separate website composition checkpoint records the signed producer evidence;
this application rehearsal does not replace its combined application image.
Next classify the remaining source/assets and qualify an independent
application producer, compatibility intake and actual application/OIDC behavior
before removing source, selecting a slim application image or renaming the
repository.
