# Portable application source package

This milestone packages the accepted application build and selected test
boundary into an archive that can be restored and used outside the original
Git checkout. It preserves the existing application profile, source bytes,
shared contracts, runtime hooks and licensing.

The package is a source-distribution boundary. It does not complete the wider
source-ownership audit or create a new release producer identity.

## Source selection

The explicit export contract maps reviewed original paths to package paths.
It retains every accepted non-test application/shared source file, including
development support outside the current entrypoint graph. It includes the
25-file application test roster and its six support files, all 54 accepted
public resources, the three shared contracts, nginx configuration, two shared
runtime hooks and the original `LICENSE`.

The three profile files are materialized at `ui/package.json`,
`ui/package-lock.json` and `ui/bun.lock`. Bun 1.4.4 and the frozen Bun lock
are the selected installation contract; the npm lock remains a reference and
audit input. Unmodified copies also remain under
`ui/profiles/application/` for the existing installed-dependency inspector.
The committed [package README](application-package-README.md) is copied to the
package root. Package names, SDK coordinates and dependency selections remain
the existing profile's values.

The original npm v1 payload had 575 source files. The archive adds its
`application-source-origin.json` manifest as one explicit self-excluded entry,
for 576 members in v1. The Bun v2 package adds the selected Bun inputs and
expanded regression coverage; its manifest is authoritative for the current
member inventory. The reviewed v2 payload has 578 files and 579 archive
members including the manifest. The manifest records all payload paths, source mappings, byte
counts, hashes, Git identities and modes. An independently supplied manifest
must have exactly the same bytes as the archive's copy.

The package omits the existing 72 application exclusions, unselected tests and
unused test support, unselected package configuration, migration diagnostics,
Git metadata, installed dependencies and build state.
These are package selections, not source deletions or additions to the
exclusive website ownership roster.

### Retained inactive source

Three existing boundaries remain explicit:

- `ui/src/components/pages/index.js` retains twelve re-exports of already
  omitted website modules. The selected application and test graphs do not
  import this legacy barrel.
- `ui/src/utils/analytics.example.js` retains its pre-existing unresolved
  example import. It is outside the selected application, build and test graphs.
- `ui/src/wasm/biometricsWasm.js` retains its inactive optional bridge. That
  optional feature is not qualified by this source package.

The package preserves these source bytes and records their limited scope.
The supported application entries and selected test/build graphs have no
unresolved local static import edge in the reviewed inventory.

## Deterministic source and separate evidence

Bun v2 source, producer and consumer schemas explicitly bind the selected
manager and Bun lock. The full/profile source rehearsals use v6/v7. Original
npm v1 package evidence and v4/v5 rehearsals retain separate validation; they
are not relabeled as Bun evidence. Node.js 24 and Vitest remain the runtime and
test runner used by the package scripts.

The archive and its canonical source manifest depend on the clean source
commit/tree, reviewed export contract, source bytes and Git-derived modes.
Their content excludes ephemeral paths, resource-probe ports, timestamps and
raw test-report digests.

A separate producer receipt binds the source archive and manifest digests to
the actual same-source application-profile rehearsal. That receipt carries the
volatile diagnostic report identity. This keeps a source artifact stable while
preserving the exact evidence used to qualify its production.

Production requires a clean, exact checkout. Every copied file must agree with
its Git object and working bytes/mode; source drift and changed profile inputs
fail the operation. The output archive, external manifest and receipt are new
paths outside the checkout.

Restore verifies externally supplied archive and manifest pins, closed member
membership, safe relative paths, regular-file types and declared modes before
creating a fresh destination. Duplicate paths, links, special files, unexpected
members and destination reuse fail. The source manifest excludes only its own
self-referential record; the external digests bind its actual bytes.

## Ordinary consumer and verified qualification

The supported package commands remain:

```sh
cd ui
bun install --frozen-lockfile
bun run build
bun run test
```

Ordinary builds retain the existing `development` marker. The application does
not acquire an exact-commit claim by reading its own source manifest. Only the
external qualifier supplies the existing `MARTY_UI_SHA` value after archive,
manifest, producer receipt and same-source baseline verification.

The qualifier restores into an owned ordinary directory outside Git, with no
borrowed dependency directory. It runs the pinned Bun package scripts with the
reviewed clean environment, fresh cache, isolated package-manager configuration and
`PUPPETEER_SKIP_DOWNLOAD=true`. The actual lifecycle patch, installed locked
identities, removed website dependencies and SDK/WASM initialization are checked
through the existing dependency inspector.

The restored source inventory is checked before and after installation, build,
tests, resource probing and runtime preparation, including failure paths.
Only `ui/node_modules/` and `ui/dist-application/` are permitted generated trees;
their contents are validated separately. Reports and other temporary state stay
outside the restored source.

The selected tests must complete all 25 files and their declared assertions.
The output must match the same-source profile baseline in every path, byte
count and hash. Source/package scripts and locks remain unchanged throughout.

## Explicit mode transformations

The accepted private rehearsal writes source files at `0600`. Its 54 copied
public outputs retain that mode, while the other 34 outputs use `0644`.
The source archive preserves the reviewed Git modes, so those same 54 public
outputs become `0644` in the ordinary package build.

The consumer records each of those 54 specific transformations. Every other
mode difference fails; the existing full/profile equality check is unchanged.
The allowed set is exactly `APPLICATION_RETAINED_PUBLIC_FILES`, including all
42 retained locale files and the twelve fixed public resources.

All four runtime inputs have Git mode `100644`. The source archive carries the
nginx configuration and two hooks at `0644`. The diagnostic runtime recipe is
provided separately from the reviewed tooling. Runtime preparation preserves
the existing normalization: Dockerfile/nginx at `0644`, hooks at `0755`, and all
88 application outputs at `0644`.

Both prepared contexts must therefore have identical complete 92-file payload
inventories. Their whole manifest hashes are distinct because source-mode
records and resource-probe observations differ. Each manifest is independently
validated and kept under its own hash.

## Diagnostic ownership and CI

Archive production, verification, the consumer driver and runtime/browser
qualification remain external migration tooling. The package excludes the
browser worker, Python bridge and platform process guardian. Ordinary package
builds use only its retained source and freshly installed profile dependencies.

The resource probe explicitly resolves diagnostic package dependencies from the
restored UI when requested; its existing default behavior is preserved. A
small owned staging directory combines the exact shipped nginx/hooks with the
separately identified diagnostic Dockerfile for runtime preparation.

CI preserves the five existing pre-bootstrap full/profile install, audit and
container gates. Source production, fresh consumer qualification and its
static-container check also run before the shared checkout bootstrap. The
existing profile browser gate and an explicit consumer-context browser gate
then run with the normal diagnostic browser tooling. Existing website,
application and customer checks remain required.

Source package, manifest, producer and consumer reports, static-runtime evidence
and browser/runtime reports are retained as actual CI artifacts. Fixtures stay
nonqualifying. Success requires source preservation and completed owned cleanup;
failures retain their actual phase and cleanup status.

The source-package evidence remains separate from complete dependency graph
minimization, an independently signed application image, authentication/OIDC,
host promotion and production activation.
