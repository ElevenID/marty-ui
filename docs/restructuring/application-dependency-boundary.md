# Application dependency and runtime boundary

This batch qualifies the application through fresh locked dependency
installation and a closed static runtime context. Its full-profile baseline
preserves the existing package graph. An explicit application package profile
removes four reviewed website dependencies and must produce identical application
output. The shared dependency declarations, root lockfiles, source layout,
combined/website/customer build paths and release producers remain unchanged. It creates no repository, publishes no image and selects no
new production image.

## Source checkpoints

The original application preparation in PR #2001 landed through the protected
merge queue at `cf333d61e4cc406d0fdaa870829396291d887ea7`. Its required CI completed
with 27 successful jobs and one intended skip.

PR #2002 combines the application test and public asset increments as separate
commits. Its M21 source is `dc2372c0a3ecde82faaff6e3f00055ce86c3cb49`. The clean
local 71-input proof and its hosted version 3 Website Surface artifact
`14586277717` were verified. Full PR CI completed with 27 successful jobs and one intended
skip. Normal queue run `44647472085` has also passed its Website Surface
rehearsal; its recorded output inventory matches the accepted PR proof. The
remaining aggregate queue checks are still required.

PR #2004's first checkpoint, `7929095c071cfc9a427dc28b46643dbdadde2011`,
separately passed a clean local full-profile fresh install and actual hosted
fresh-install and nginx-container checks in run `44645683982`. Both reports
were independently inspected, including original source hashes, SDK/WASM
binding, all 88 output files, HTTP resource checks and successful container/image
cleanup. The application profile below is the next candidate in that same PR;
it requires its own same-source baseline comparison and actual runtime evidence.

## Fresh installation contract

`ui/scripts/application-source-closure.mjs --fresh-install` exports the existing
72-input omission boundary without a `node_modules` directory or prebuilt
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

In the full-profile baseline, both existing postinstall patches must run. The gate verifies the prerender
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

## Explicit application package profile

`ui/profiles/application/package.json` and `package-lock.json` are the reviewed
application-specific inputs. The root package manifest and both root locks remain
the normal shared defaults. The profile is materialized only into the disposable
UI export; running `npm ci` directly from the profile directory is not its build
entrypoint because its scripts belong at the exported UI root.

The application manifest removes exactly these four roots:

| Removed root | Owning website behavior |
| --- | --- |
| `@elevenid/marty-blog` | Released website blog data |
| `@prerenderer/rollup-plugin` | Website prerender plugin |
| `@prerenderer/renderer-puppeteer` | Website prerender renderer |
| `vite-plugin-sitemap` | Website sitemap generation |

`ui/scripts/website-build-tools.mjs` owns those dependency imports and loads
through a fixed file URL only for the website/combined catalog branch. The
application export omits this helper as its 72nd omitted input. The exclusive
website ownership roster remains 34 modules. Website/combined prerender guards,
sitemap behavior and customer-build behavior are preserved.

The committed profile lock has 618 total records versus the original 742: 124
records are removed, no records are added, and every retained package record
matches the original. These counts include the root record. The validator binds
the profile to the current root manifest/lock, checks dependency closure, rejects
removed identities in paths and aliases, and refuses any retained identity or
metadata drift. Root maintenance scripts may change independently; the profile
has an exact five-script map:

| Profile scripts | Selected command |
| --- | --- |
| `build`, `build:application` | `node scripts/build-web-surface.mjs application` |
| `test`, `test:application` | `vitest run --config vitest.application.config.ts` |
| `postinstall` | `node scripts/patch-checker-worker-cleanup.mjs` |

From `ui/`, `node scripts/application-dependency-profile.mjs --check` validates
the committed selection without installing or modifying anything. The fresh
harness performs the same check before any export. It then replaces only the
exported `package.json` and `package-lock.json` with the exact selected bytes,
recording original, selected and materialized hashes. The original Bun lock is
inventoried and preserved as an unselected baseline input; this profile has no
new Bun lock. The full-profile mode remains the default.

The selected-profile installer uses the same isolated `npm ci` contract as the
full baseline and verifies the checker patch and actual SDK/WASM. It explicitly
does not select the prerender patch. It checks all four removed roots against
the selected manifest, lock, npm installed graph and actual package directories,
including nested paths and package-name aliases. Selected input preservation is
checked after installation and after build/resource/runtime-context preparation.

## Comparison and security gates

Application selection requires `--fresh-install`, `--dependency-profile application`
and an absolute `--baseline-report` naming the passed full-profile fresh report
from the same source. It cannot borrow dependencies or use a profile report as
its own baseline. Version 5 records both substitutions and the baseline report's
byte count and SHA-256. The baseline must bind the same commit, dirty state,
source inventory, omitted/retained boundary, route and selected-test contracts;
its inventory digests must be internally valid. Every output path, byte count,
hash and mode, and every preserved public resource must match exactly. A changed
or incomplete baseline fails the gate.

The required CI lane retains the full fresh-install and container checks. It
then runs `scripts/ci/audit-application-dependencies.py` against the fixed profile
directory, using the existing npm audit scope:
`npm audit --json --omit=optional --package-lock-only --audit-level=low`.
The scanner uses clean npm configuration and a temporary cache and must preserve
both selected inputs. It reuses the existing duplicate-free JSON, npm finding
and status validators. All findings, malformed documents and scanner errors fail;
no advisory acceptance is added. Existing full npm/Bun Security Scanning is
unchanged. The application-profile fresh build/test/resource comparison and its
own actual nonpublishing container check follow before the existing release
bootstrap. Both profile reports are archived separately from the baseline.

Puppeteer, the API SDK, Storybook, the checker patch, bundle analysis and other
application development/test dependencies remain retained. The four-root
reduction is an explicit, bounded change; `package_graph_minimized` and complete
source extraction remain false. Fresh installation, output equality and static
container checks do not qualify browser startup, signed application publication,
host deployment or an OIDC journey. Those remain subsequent development gates.
