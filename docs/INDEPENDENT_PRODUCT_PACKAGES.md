# Independent server and console packages

The server and console have separate package identities and version sources:

| Product | Version source | Release tag namespace | Owned images |
| --- | --- | --- | --- |
| `marty-server` | `release/server-version.txt` | `server-vMAJOR.MINOR.PATCH` | services, migrations, OpenBao DIDComm plugin, Keycloak |
| `marty-console` | `release/console-version.txt` | `console-vMAJOR.MINOR.PATCH` | UI |

Both new channels start at `0.1.0`. These are source package versions, not
published or supported releases. They are independent of the existing combined
stack version, the private frontend npm version, client SDK semver and MIP.
The legacy calendar `VERSION` file and combined release transaction remain
unchanged for existing consumers and the separately owned installer work.

`release/product-packages.json` declares the producer boundary. The server plan
requires no frontend source, frontend version, npm package lock or UI image.
The console plan uses only its frontend Docker build and its pinned SDK/blog
dependencies; it does not build Rust server binaries. Each product uses its own
registry namespace under `ghcr.io/elevenid/`.

Generate source-bound plans without an installer or registry access:

```sh
python scripts/product_package_plan.py --product marty-server \
  --source-sha <exact-source-commit> --output server-build-plan.json
python scripts/product_package_plan.py --product marty-console \
  --source-sha <exact-source-commit> --output console-build-plan.json
```

Plans bind the selected version file and Dockerfiles by digest and record the
exact source revision. Console plans also bind their dependency lock and supply
the existing self-host Docker target with its required variant, Nginx and pinned
dependency build arguments. They reject role mixing, cross-product tag/image
namespaces, escaping source paths, invalid versions and unbound dependencies.
They always report `qualification: unqualified`.

The declared shared interface is public HTTP `v1` and MIP `0.5.0`. Matching those
labels is necessary metadata, not proof that arbitrary server/console versions
interoperate. A promoted combination needs an exact compatibility result from
the release qualification owner. Server startup and API readiness must not
depend on a console; console absence must preserve backend routing and failure
propagation. The existing API-only composition and edge tests are the source
foundation for that runtime boundary.

The remaining packaging implementation is to wire these independent plans into
the producer workflow and digest-bound package manifests, expose independently
versioned deployment composition, and retain compatibility with the combined
release path. Source and local development tests belong to this work. Installer
implementation and independent release-artifact verification belong to the
other assigned workers. Build plans alone do not complete this packaging work
or establish a new supported distribution.
