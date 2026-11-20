# Application dependency and runtime boundary

This increment extends the 71-input application rehearsal with a fresh locked
dependency installation and a closed static runtime context. It preserves the
existing package graph, source layout, combined/website/customer build paths and
release producers. It creates no repository, publishes no image and selects no
new production image.

## Source checkpoints

The original application preparation in PR #2001 landed through the protected
merge queue at `cf333d61e4cc406d0fdaa870829396291d887ea7`. Its required CI completed
with 27 successful jobs and one intended skip.

PR #2002 combines the application test and public asset increments as separate
commits. Its M21 source is `dc2372c0a3ecde82faaff6e3f00055ce86c3cb49`. The clean
local 71-input proof and its hosted version 3 Website Surface artifact
`14586277717` were verified; that candidate's Website Surface and Security gates
passed. At the start of this increment, full CI and normal queue admission for
PR #2002 remained pending. Evidence from earlier runs with reused dependencies
does not qualify a fresh installation or container.

## Fresh installation contract

`ui/scripts/application-source-closure.mjs --fresh-install` exports the existing
71-input omission boundary without a `node_modules` directory or prebuilt
output. `ui/scripts/application-dependency-install.mjs` installs the unchanged
`package.json` and npm version 3 lock into that export with `npm ci`. npm's
[clean-install contract](https://docs.npmjs.com/cli/commands/npm-ci/) refuses a
manifest/lock mismatch and does not update either file.

The installer uses a new temporary npm cache, explicit empty user/global npm
configuration, the public registry and explicit development-dependency and
lifecycle-script settings. It excludes inherited npm configuration, `NODE_ENV`,
`NODE_OPTIONS`, `NODE_PATH` and application runtime settings. Project npm
configuration, npm extension hooks and a shrinkwrap file require separate review
and currently refuse this gate. Required proxy/CA transport settings may pass
through without being written into the diagnostic report. `HOME` is unchanged.

`PUPPETEER_SKIP_DOWNLOAD=true` skips browser acquisition because this gate does
not launch a browser. Puppeteer remains installed: the application-owned
`ui/scripts/public-verification-browser.mjs` uses it for separate browser QA.
The installer has no alternate install command, lock rewrite or borrowed
dependency fallback.

The report records exact Node/npm versions, install arguments, source input
hashes and installed package identity. Installed npm records must match the
committed lock's version, resolved location and integrity at the corresponding
package paths; every declared direct dependency must be present. Platform-specific
optional packages can remain absent on platforms where npm does not install
them. This is a Linux execution gate, not cross-platform qualification.

Both existing postinstall patches must run. The gate verifies the prerender
`ts-deepmerge` call replacements and the exact reviewed checker patch hashes plus
its cleanup helper. It rechecks the package manifest, both locks and all three
patch source files after installation. npm and SDK processes have bounded deadlines and own
their process groups; their descendants are terminated on completion or failure.
Captured output uses owned files so a descendant cannot keep a pipe open past
the parent's deadline.

## SDK and WASM

`ui/src/services/api.jsx` and `ui/src/services/publicVerificationApi.js` require
the released `@elevenid/marty-api-core` package. The current lock pins version
`0.3.6` and its original HTTPS tarball with SHA-512 integrity. Importing its
`src/index.js` initializes `src/wasm/marty_api_client_bg.wasm` through top-level
await. The new check resolves that entry from the fresh installation, validates
the WASM, imports the actual package and constructs a client without making a
request. The emitted application WASM must match the installed binary's bytes
and hash, and the existing resource probe must serve it with the expected type.

The optional `ui/src/wasm/biometricsWasm.js` bridge is separate. This increment
does not require its ignored generated package, a sibling SDK checkout, a Rust
toolchain or `wasm-pack`. Node SDK initialization is recorded separately from
browser execution, which remains unobserved.

## Closed static runtime context

`--runtime-context /absolute/new/directory` prepares a context only after the
build, selected tests, resource probe and original-source preservation succeed.
The context carries all verified output files and these fixed source inputs:

| Source | Context role |
| --- | --- |
| `ui/scripts/application-runtime.Dockerfile` | Fixed static runtime recipe with the existing digest-pinned nginx base |
| `ui/nginx.prod.conf` | Unchanged production nginx routing and headers |
| `scripts/ui-production-start.sh` | Unchanged production startup hook |
| `scripts/load-secrets-env.sh` | Unchanged startup dependency |

The two root startup scripts enter the source inventory only for context mode.
Their original bytes and the nginx/recipe bytes are rechecked before copying;
source and output preservation are checked again after preparation, including
failure paths. A failed final check or export cleanup cannot retain a qualified
context. Existing destination paths are never replaced.

The context contains no source checkout, dependency installation, cache, Git
metadata, private commerce source or unrelated root contracts. Output bytes
remain identical while packaging modes are explicit: regular assets are `0644`,
directories `0755`, and executable hooks `0755`. This is necessary because the
disposable source export intentionally uses `0600` and Vite preserves that mode
for copied public files. Source/output mode checks remain unchanged; the context
records each packaging transformation separately.

The prepared-context manifest records the base commit and the route marker's
effective source identity. A dirty build retains `development` and cannot claim
exact committed-source qualification. Preparing the context keeps Docker,
browser, production host and OIDC execution flags false.

## Hosted runtime qualification

The required Website Surface lane runs fresh installation and context creation
before its existing release-package bootstrap. It then invokes:

```sh
node ui/scripts/application-runtime-context.mjs --check-container \
  --context /absolute/application-runtime-context \
  --report /absolute/application-runtime.json
```

The checker builds and starts an owned diagnostic container without publishing
it. It checks nginx configuration, the route marker, every output file's
readability and all 54 retained public resources, then fetches the resources
through an ephemeral loopback endpoint. It verifies bytes and content types,
including the actual SDK WASM, and exercises missing-resource controls.

The real startup hook deliberately rewrites `runtime-config.js` and HTML
verification metadata. Those expected default transformations are checked
explicitly; other asset bytes must remain unchanged. The context uses the actual
reviewed hook and nginx configuration. It does not contact an API, production
host or AWS origin.

The report is successful only after actual build/runtime checks and owned
container/image cleanup. Unit fixtures exercise the Docker protocol and failure
paths but are labeled `fixture-passed` with container qualification false. This
workspace has no Docker/Podman/BuildKit executable on `PATH`; local fixture
success cannot substitute for the hosted container result. Exact candidate
execution and hosted evidence belong in the candidate PR.

## Remaining dependency work

The current full lock is intentionally retained. Four narrowly identified
application-profile removal candidates are `@elevenid/marty-blog`,
`@prerenderer/rollup-plugin`, `@prerenderer/renderer-puppeteer` and
`vite-plugin-sitemap`. The shared Vite configuration still resolves their build
imports, including the literal dynamic blog import, and the shared postinstall
requires the prerender directory. A later removal must move those imports behind
their owning surface, choose the application postinstall explicitly, generate
reviewable locks and repeat fresh-install/build/test/security qualification.

Puppeteer, the API SDK, the checker patch, bundle analysis and other application
development/test dependencies remain retained. This increment adds no advisory
acceptance and does not relax either existing audit scope. Independent locked
installation is distinct from a minimized graph, complete source extraction,
signed application publication, deployment or OIDC qualification.
