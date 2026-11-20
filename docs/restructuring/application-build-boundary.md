# Application build boundary rehearsal

This batch prepares the application side of the website split. It provides a
repeatable build, application test profile and local resource probe with audited inputs absent from a
temporary source export. The existing checkout remains intact. This is a
source, build, component-test and resource check; the combined application release remains the selected
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
then creates a fresh directory outside the checkout. Its export omits 71 inputs:

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
- The 26 additional public asset paths listed in
  [the application public asset audit](application-assets-audit.md): website RSS,
  author/demo/social images, `llms.txt` and the five remaining marketing locales.

The export retains the dependency manifests and lockfile, shared application
authentication and routing, navigation, the public application configuration,
other assets and the selected tests. The extra omissions have explicit
application-only classifications; the exclusive-website ownership roster stays
at 34 modules. In particular, the combined adapters retain their original
combined behavior in the checkout. All 42 application locale files and 12 shared
public resources are required and must retain their exact original source bytes.
The 71 omissions do not constitute a complete
website source, asset, package or workflow extraction manifest.

The harness runs the existing `build-web-surface.mjs application` entrypoint and
then runs the application Vitest profile within the same omitted-input export.
It requires every selected test source to exist before export. A successful
Vitest exit must also provide a JSON report naming exactly the selected files,
with passing assertions and no skipped or pending tests. Build and test
completion are recorded separately in the version 4 diagnostic report.

It checks the emitted application/source/route marker, the main and console
entrypoints, all seven English fallback translation namespaces, and absence of
the marketing output paths and locales already excluded by the application
build. The existing emitted-module guard still rejects website-owned modules.
Every omitted input must stay absent after the build, test and resource processes.
It also verifies that the original source inventory, byte hashes, file modes
and Git status are unchanged. The temporary export is removed after success or
failure unless it was explicitly requested for inspection.

Source and output inventories are written into the JSON report. A dirty source
checkout is explicitly recorded with its own input hashes; its build is not
evidence for the unmodified commit named by `HEAD`. Such output uses the
`development` source marker. Only a clean checkout uses its exact commit in the
output marker.

## Local resource and fallback probe

The harness starts `ui/scripts/application-resource-smoke.mjs` as a separate
asynchronous child after the build and selected tests. The child uses the
installed Vite preview implementation with `configFile: false`, the exported
output directory and an ephemeral `127.0.0.1` port. It does not load the combined
Vite configuration, start a browser, access an external host or contact an
application backend.

Both HTML entrypoints and the manifest are parsed without script execution.
Local resource targets must resolve to regular output files. The probe fetches
the 54 preserved public resources, both entrypoints and emitted JavaScript,
CSS and WASM. Every required response must have the expected bytes and content
type. A redirect, missing file or HTML SPA fallback cannot satisfy an asset
check. External font URLs are recorded outside this local qualification and
are not fetched.

The installed i18next HTTP backend then requests all seven German and English
namespaces from that server. The actual German dictionary must contain
`actions.cancel` and omit `common.login`; the actual English dictionary must
contain `common.login`. The probe checks the translated German value and the
English fallback value and language returned by i18next. Its report records
the 14 backend request paths. It uses the real dictionaries without rewriting
them or supplying an inline translation default.

The server must close before the child reports success. The parent binds served
hashes to the complete output inventory and requires that inventory's paths,
bytes, hashes and modes to remain unchanged during the probe. A child cannot
fetch valid output and then replace it before final qualification.

This observes resource delivery and library fallback behavior. The default
branding configuration and mobile icon are served as preserved files; browser
rendering, application startup, injected production runtime configuration,
host deployment and OIDC behavior remain unobserved. Existing Puppeteer
application QA remains available for those separate browser checks.

## Running the check

Use the repository's normal UI dependency installation and postinstall patches.
From `ui/`:

```sh
npm run test:application
npm run check:application-source-closure -- --report /tmp/application-source-closure.json

# Install the unchanged full npm lock into a fresh export, then prepare a
# separate static context for the nonpublishing container check.
npm run check:application-source-closure -- --fresh-install \
  --runtime-context /tmp/application-runtime-context \
  --report /tmp/application-source-closure-fresh.json
```

The report must be a new file outside the source checkout. Omit `--report` to
write JSON to standard output; build, test and resource logs go to standard error. Optional
`--dependencies /absolute/path/to/node_modules` selects an existing dependency
installation, and `--keep-export` retains the generated source and build for
inspection. The report identifies the export location. A failed build, test,
resource probe, report validation, output check or source-preservation check exits nonzero.

The default rehearsal reuses installed dependencies and keeps
`independent_dependency_installation` false. `--fresh-install` instead runs a
strict npm clean installation from the unchanged source lock, verifies both
postinstall patches and the actual SDK WASM, and binds that binary to emitted
output. It cannot be combined with `--dependencies` and has no fallback to a
borrowed installation. The new mode qualifies installation of the existing full
graph; it does not claim that the application's dependency graph is minimized.
See [the dependency and runtime boundary](application-dependency-boundary.md)
for installation isolation, packaging rules and failure handling.

The existing verified release-package bootstrap may edit the working package
manifest and Bun lock. The required CI lane therefore executes the fresh gate
before that bootstrap. Other callers that use dirty sources still receive the
`development` marker and recorded source hashes.

The required `Website Surface` lane runs the focused application tests and the
fresh temporary-export build/test/resource rehearsal and a nonpublishing
application container check before its existing website, application and
customer builds. It retains the JSON report as
`application-source-closure-RUN-ATTEMPT` for 14 days when a report is available.
The container result is retained separately as `application-runtime-RUN-ATTEMPT`.
These diagnostic artifacts have no release authority.

## Acceptance and next gates

A completed checkpoint records the exact candidate commit, whether the source
checkout was clean, omitted/retained path inventories, the report's input and
output hashes, local validation and the exact hosted CI result. Run the final
candidate rehearsal after committing the reviewed changes so that its source
identity can be reproduced. Record the resulting evidence in the candidate PR.

Reused-dependency reports keep independent installation incomplete. Fresh mode
can qualify that one operation after it actually succeeds. Both modes keep
dependency minimization, complete source extraction, signed publication, host
deployment and OIDC qualification explicitly incomplete. Preparing a runtime
context does not claim that Docker ran; the separate hosted checker must observe
the actual image build and resource checks.
The separate website composition checkpoint records the signed producer evidence;
this application rehearsal does not replace its combined application image.
Next classify the remaining source/assets and qualify an independent
application producer, compatibility intake and actual application/OIDC behavior
before removing source, selecting a slim application image or renaming the
repository.
