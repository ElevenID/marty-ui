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
dependencies; it does not build Rust server binaries. Its explicit `console`
Docker target adds the public-server proxy to the existing static UI. The
legacy public and self-host image targets keep their existing behavior.
Each product uses its own
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

The `Independent product packages` workflow consumes the selected plan on exact
protected-main source. Selecting the server builds its four backend roles;
selecting the console builds only its UI role. The workflow pushes images by
digest, requests BuildKit SBOM/provenance and emits GitHub build attestations.
It does not write a stable version tag or create a supported release.

Each image receipt binds its product, version, source, role, image URI, workflow
run and attempt. Package assembly requires every expected role from the same
attempt and rejects missing, extra or mismatched receipts. It rechecks the
frozen plan against the source inputs before emitting `product-package.json`,
the build plan and checksum inventory as an attested workflow artifact.
`deploy-config/schemas/product-package.schema.json` defines this versioned
consumer interface. Its state remains experimental/unqualified; a producer
receipt is not independent verification of an image or compatibility result.

## Canonical candidate archive

The workflow artifact contains `product-package.tar.gz` and its adjacent
`.sha256` checksum. Extract that tarball into a new directory before using its
runtime files. The surrounding workflow artifact ZIP is only transport: raw
artifact files do not preserve Unix execution modes.

The tar payload records directories and shell entrypoints as `0755`, other
files as `0644`, with fixed timestamps and owner metadata. Linux runtime shell
files use LF line endings; their original and emitted hashes remain in the
frozen build plan. `SHA256SUMS` inside covers the emitted files, while the outer
checksum covers the tarball. Both archive and checksum are attested/uploaded
with the candidate. These producer checks do not replace independent release
verification.

```sh
mkdir extracted-product
# Use the verified candidate tarball supplied by the release verification owner.
tar -xzf product-package.tar.gz -C extracted-product
cd extracted-product
```

## Runtime composition

`scripts/compose_product_packages.py` renders Compose JSON from the selected
product package. It binds OCI digests and product metadata; it does not install
software, generate secrets, start containers or verify release signatures.
The release verification owner supplies the verified package inputs. The
installer owner supplies the resolved server runtime layout and prerequisites.

```sh
python scripts/compose_product_packages.py --package server-package.json \
  --base resolved-server-base.json --runtime-dir runtime --output server.compose.json
python scripts/compose_product_packages.py --package console-package.json \
  --server-origin https://api.example.com --output console.compose.json
```

The server renderer preserves backend health checks, mounts, commands, secrets
and dependency conditions while binding the server image roles and release
version. It removes the UI dependency and UI-only secrets, selects the existing
console-free edge behavior, and omits the legacy vendor tunnel services for
direct API ingress. The existing Canvas backend worker remains; this is not a
minimal or no-Canvas distribution. External runtime images in the supplied base
must already be digest-pinned. Unresolved includes/extensions, unbound source
builds and hidden frontend dependencies fail instead of becoming runtime inputs.
Existing combined deployment defaults and installer scripts are unchanged.
The base is an existing fully resolved runtime layout, not an installer recipe.
With all current profiles selected, the source model changes from 32 services
to 28 by excluding the UI and three tunnel services. Bootstrap profile selection,
backend mounts, commands and health/dependency conditions stay with that layout.
The installer owner's legacy full-stack DAG validator therefore needs an
explicit independent-product mode when consuming this output; its current
combined-product contract is preserved here.

The server bundle includes an explicit allowlist of 27 existing container runtime
files under `runtime/`: edge configuration, database initialization, container
entrypoints and Keycloak realm/theme assets. The packaged realm omits all seeded
development users and literal client secrets; the deployment owner provisions
real identities and credentials. The shared source realm remains unchanged.
Both input and emitted file hashes are bound into the frozen build plan; emitted
bytes also appear in the bundle checksum inventory. No secrets, state,
installer scripts or UI application source are copied. The console bundle does
not include those server files.

Run the example from the extracted bundle. `--runtime-dir runtime` explicitly
selects its static assets and replaces only the known service/mount-target pairs;
all state mounts, secret references, health checks and other runtime settings
remain supplied by the normalized deployment layout. Missing required assets
fail before a composition is written. Omit that option to retain an existing
custom layout's asset paths. The renderer does not modify the supplied assets,
prepare state or secrets, run Keycloak setup, or start any services. The existing
container commands consume those files when the deployment owner starts them.

The console renderer produces one UI service with no backend images, secret
mounts or startup dependencies. `MARTY_SERVER_ORIGIN` is a reachable public
HTTP(S) origin, with no credentials, path, query or fragment. The console serves
its assets independently and proxies API, identity and metadata namespaces to
that server. API failures stay failures. HTTPS verifies both certificate trust
and hostname against `/etc/ssl/cert.pem`; a private-CA deployment provides its
approved public CA bundle through its container trust configuration. Server
callback/allowed-origin configuration must include the console's public origin.
The source template `docker-compose.console.yml` exposes the same interface.

The required public-protocol CI lane exercises the real console Nginx renderer
with HTTP/TLS fixtures, including missing server, denied API responses, invalid
origins, untrusted certificates and wrong hostnames. These are source routing
tests, not a complete login/business journey or release qualification.
Locally, the same routing probe can use a compiled self-host frontend through
`--assets-dir <dist-selfhost>`; it compares the served console entry bytes and
retains the same API, failure and TLS assertions. The probe owns and removes
only its labelled fixture containers/network and records its cleanup result.

The remaining packaging implementation is qualified publication/promotion that
consumes the verification owner's exact candidate evidence and the applicable
runtime/compatibility results. Existing combined releases retain their current
transaction and qualification gates. Source and local development tests belong
to this work. Installer implementation and independent release-artifact
verification belong to the other assigned workers. Candidate production and
composition rendering alone do not establish a supported distribution.

## Qualification intake boundary

Promotion must accept the verification owner's report as an explicit workflow
run/artifact input; its filename and producing workflow are not yet fixed. The
report must bind the exact candidate archive checksum, package manifest,
producer run and attempt, source commit, product/version, and every image role
and digest. The promotion workflow must authenticate the producing repository,
workflow identity, successful run, artifact provenance and report checksum
before it trusts any verdict. A local JSON file or a caller-supplied `passed`
flag alone is insufficient.

The verifier owns payload, image provenance, SBOM and cross-host checks. The
promotion owner consumes those verdicts without repeating their checks, and
separately requires exact server-without-console runtime results and, for a
console combination, a result for the selected server and console digests.
Missing, stale, failed, mismatched or unauthenticated evidence blocks promotion.
The candidate manifest stays immutable and unqualified; any later qualification
record must be a separate, digest-bound object. Support windows and supported
profile claims need the relevant product decision and qualifying runtime and
upgrade/recovery evidence before publication. No new version tag or supported
release is created by the candidate producer.
