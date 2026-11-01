# Customer UI and production website releases

The customer application and the ElevenID production website use the same UI
source tree, with separate build targets and signed image identities.

| Release | Docker target | UI variant | Image | Included web content |
| --- | --- | --- | --- | --- |
| Stable customer stack | `selfhost` | `selfhost` | `ghcr.io/elevenid/marty-ui-oss/ui` | Customer application and console |
| Customer installer | `selfhost` | `selfhost` | `ghcr.io/elevenid/marty-ui-oss/ui-selfhost` | Customer application and console |
| Independent console | `console` | `selfhost` | `ghcr.io/elevenid/marty-console/ui` | Customer application and console, with its configured API origin |
| Production website | `public` | `public` | `ghcr.io/elevenid/marty-ui-oss/ui-public` | Production homepage, marketing pages, public resources and crawler artifacts |

Customer builds exclude production marketing routes and assets at build time.
The retained `full` and `tester` profile names are compatible customer settings;
neither includes the production marketing website. Runtime settings can narrow
the customer application further, but cannot add pages omitted from its image.

## Customer releases

Both `ui` and `ui_selfhost` in the nightly build plan explicitly select the
`selfhost` target and variant. Stable `Stack release` also builds its `ui` role
with that target. The existing closed image-role contracts and customer release
coordinates remain intact, including the installer image lock.

Each image includes an `io.elevenid.ui.audience` OCI label and
`marty-ui-release.json` with the audience, variant, release version, and full
source SHA. These values are derived from the Docker variant. Customer producers
check `audience=customer`, `ui_variant=selfhost`, the exact version, and the exact
source before signing or qualifying the image. A legacy production image cannot
be resumed through this check as a new customer image.

`scripts/ui_release.py check-image` implements the same check for nightly,
stable, and independent-console producers. Customer UI build scripts also check
that forbidden marketing modules and copied assets are absent from their output.

## Startup selection

For the signed installer, put `web.enabled_sections` in the hosting JSON before
installation; see [hosting configuration](installer-hosting.md#select-customer-webpages-at-startup).
The installer records this selection and emits the corresponding environment
value. For an independent Compose deployment, set `UI_ENABLED_SECTIONS` in the
deployment environment before starting the UI. The accepted values are:

| Value | Application pages | `/console/**` |
| --- | --- | --- |
| `public,console` (default) | Enabled | Enabled |
| `public` | Enabled | Excluded |
| `console` | Excluded | Enabled |
| `none` | Excluded | Excluded |

Here `public` means the customer application's public entry points, such as
login, organization, invitation, and wallet pages. Application flows that hand
off to the console require both sections. It does not enable the production marketing website.
The startup hook renders the setting into `web.enabled_sections` in runtime
configuration and into the server route policy. Excluded routes return 404.
Invalid settings fail startup. `/healthz` remains available when all web sections
are excluded, so UI availability is independent of the container health check.
Shared authentication callbacks and assets remain available when either section
is enabled. Application flows under `/apply` require both sections. Console
aliases redirect only when the console is enabled; the independent console's
API proxy remains available even when both web sections are excluded.

The required CI command `python3 ui/scripts/test_nginx_crawler_routes.py` executes
the actual startup hooks against the pinned Nginx Docker image and checks all
four modes for both server configurations over HTTP. Developers without Docker
can run the same section assertions with an explicit local Nginx executable:

```sh
python3 ui/scripts/test_nginx_crawler_routes.py --local-nginx /absolute/path/to/nginx
```

That optional adapter changes only fixture paths, listener ports, and the test
API origin. It is refused in CI; the default test always requires Docker.

## Production website pipeline

Run **Production website release** (`production-web-release.yml`) on `main`:

```sh
gh workflow run production-web-release.yml --repo ElevenID/marty-ui --ref main
```

The workflow checks out the exact dispatch SHA, verifies its protected-main
lineage, and records a deterministic build plan. It reuses the console's locked
npm dependency validation for API core and blog packages, including their exact
repository, version, download URI, and SHA-256 digest. The plan records the source
SHA, Dockerfile digest, and dependency-lock digest.

The workflow explicitly builds the `public` target with `UI_VARIANT=public` and
`NGINX_CONFIG=nginx.prod.conf`. It publishes only to the dedicated `ui-public`
coordinate by digest, checks the real prerendered homepage and production image
metadata, emits image SBOM and provenance, and signs the image with Cosign.

Its downloadable artifact is named
`production-web-<version>-<run-id>-<run-attempt>` and contains:

- `build-plan.json`: the exact public build recipe and locked source inputs.
- `image-metadata.json`: the metadata read back from the running image.
- `production-web-release.json`: the public image digest, source SHA, plan digest,
  dependency-lock digest, and exact producing workflow run and attempt.
- `production-web-release.json.sigstore.json`: the manifest's keyless signature.

The manifest also has GitHub build provenance. It uses its own
`marty.production-web-release/v1` schema, separate from the customer stack and
installer manifests. The pipeline prepares signed production website artifacts;
it does not deploy them or promote customer release tags.

After downloading the artifact from the exact successful run, verify its
manifest and image provenance against the recorded source SHA and this workflow
before deploying the digest. For example:

```sh
source_sha="$(jq -r .source_sha production-web-release.json)"
image="$(jq -r '.image.uri + "@" + .image.digest' production-web-release.json)"
gh attestation verify production-web-release.json --repo ElevenID/marty-ui \
  --signer-workflow ElevenID/marty-ui/.github/workflows/production-web-release.yml \
  --source-digest "$source_sha" --source-ref refs/heads/main --deny-self-hosted-runners
gh attestation verify "oci://$image" --repo ElevenID/marty-ui \
  --signer-workflow ElevenID/marty-ui/.github/workflows/production-web-release.yml \
  --source-digest "$source_sha" --source-ref refs/heads/main --deny-self-hosted-runners
```

Existing production website deployments that previously selected the stable
customer `ui` role must select the independently verified `ui-public` artifact
when they next update. Historical released image digests remain immutable.
