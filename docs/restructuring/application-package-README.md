# ElevenID application source

This package contains the ElevenID public application and console entrypoints,
their shared client code, the selected application tests, and the build inputs
needed to use them outside the original repository checkout.

## Install, build and test

Use Node.js 24 and npm. From the extracted package directory:

```sh
cd ui
npm ci
npm run build
npm test
```

`npm ci` uses the included application lock and runs the existing checker-worker
patch. The application build writes `ui/dist-application/`. `npm test` runs the
selected suite in `scripts/application-test-profile.mjs`, currently 24 test
files covering routing, authentication states, organization-domain behavior and
startup recovery.

Puppeteer remains in the selected dependency profile. For build and test work
that does not need a downloaded browser, set `PUPPETEER_SKIP_DOWNLOAD=true`
before `npm ci`. The package qualification uses that setting with a fresh npm
cache and explicit empty user/global npm configuration. Its evidence records
the exact Node, npm and installed-package identities.

The package keeps the existing `marty-ui` npm name, SDK coordinates and selected
dependency versions. `ui/profiles/application/` retains the original selected
manifest and lock; their bytes match the two materialized files at `ui/`.

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

Shared development source is retained byte for byte. The legacy pages barrel
and analytics example remain outside the configured application and selected
test graphs. The optional biometrics bridge is also outside this qualification.
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
modes, the selected contracts and test roster, and the two package-profile
materializations. The separate producer receipt binds the archive and manifest
digests to its validation evidence. Check those digests against the producer
record when consuming a package.

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
