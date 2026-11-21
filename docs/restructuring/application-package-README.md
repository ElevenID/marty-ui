# ElevenID application source

This package contains the ElevenID public application and console entrypoints,
their shared client code, the selected application tests, and the build inputs
needed to use them outside the original repository checkout.

## Install, build and test

Use Node.js 24 and Bun 1.4.4. From the extracted package directory:

```sh
cd ui
bun install --frozen-lockfile
bun run build
bun run test
```

The frozen Bun install uses the included application `bun.lock` and runs the
existing checker-worker patch. The application build writes
`ui/dist-application/`. `bun run test` invokes the existing Vitest suite in
`scripts/application-test-profile.mjs`, including authentication redirects,
invitation navigation, organization-domain behavior and startup recovery.
The Node-based build and test runtime remains Node.js 24.

Puppeteer remains in the selected dependency profile. For build and test work
that does not need a downloaded browser, set `PUPPETEER_SKIP_DOWNLOAD=true`
before `bun install --frozen-lockfile`. The package qualification uses that
setting with a fresh cache and isolated package-manager configuration. Its
evidence records the exact Node/Bun versions, authoritative Bun lock and
installed-package identities. Dependency lifecycle permissions are explicit
in the selected manifest; the existing project postinstall patch is verified.

The package keeps the existing `marty-ui` npm name, SDK coordinates and selected
dependency versions. `ui/profiles/application/` retains the original selected
manifest, Bun lock and npm reference lock; their bytes match the three
materialized files at `ui/`. `package-lock.json` remains a reviewed dependency
reference and audit input. The v2 package selects Bun for installation. The
consumer selects the exact reviewed source map by its contract digest; original
npm v1 and earlier Bun v2 packages retain their original maps and test policies.

## Layout and supported scope

| Path | Purpose |
| --- | --- |
| `ui/` | Application source, public resources, selected tests and build configuration |
| `contracts/` | The three shared contracts used by the selected build and test boundary |
| `scripts/` | The two shared production runtime hooks |
| `application-source-origin.json` | Exact source, destination, hash, mode and origin records for this package |
| `LICENSE` | Original repository license |

The output is the existing static application surface. Authentication and
application requests use the configured platform gateway. Platform release
selection and deployment supply that runtime integration.

Shared development source is retained byte for byte from this source revision.
The pages barrel has no retired marketing re-exports. The analytics example
remains outside the configured application and selected test graphs. The
optional biometrics bridge is also outside this qualification.
The source manifest records these retained boundaries. The selected tests are
the supported package suite; the original repository retains the broader test
and migration tooling.

## Source identity and verification

An ordinary build uses the existing `development` source marker. The external
package qualifier verifies the archive, manifest, source inventory and matching
producer evidence before supplying an exact commit through the existing
`MARTY_UI_SHA` build setting. A source marker by itself is not verification.

The source manifest is included inside the archive and supplied separately with
identical bytes. It records the original commit and tree, source paths and Git
modes, the selected contracts and test roster, and the three package-profile
materializations. The separate producer receipt binds the archive and manifest
digests to its validation evidence. Check those digests against the producer
record when consuming a package.

The original 72 retired marketing and combined-surface paths must be absent
from the current source checkout and every application export. They remain a
fixed forbidden roster after physical removal. Present but unselected source
files have separate omission records; removed files are no longer represented
as present source inputs. Historical package manifests keep their original
omission records and are validated against their frozen approved contracts.

Source files use their reviewed Git modes. The external consumer qualification
accounts explicitly for the public files whose private rehearsal mode was
`0600` and whose packaged source mode is `0644`; every output path, byte count
and hash must still match the same-source application baseline.

## Licensing and release status

The original `LICENSE` and source notices remain with their files. Installed
dependencies retain their own package metadata and notices.

This is a source package with recorded build and test evidence. Signed image
publication, platform compatibility selection and production activation use
their existing release contracts.
