# Customer UI and production website releases

The customer application and the ElevenID production website use the same UI
source tree, with separate build targets and signed image identities.

| Release | Docker target | UI variant | Image | Included web content |
| --- | --- | --- | --- | --- |
| Stable customer stack | `selfhost` | `selfhost` | `ghcr.io/elevenid/marty-ui-oss/ui` | Customer application and console |
| Customer installer | `selfhost` | `selfhost` | `ghcr.io/elevenid/marty-ui-oss/ui-selfhost` | Customer application and console |
| Independent console | `console` | `selfhost` | `ghcr.io/elevenid/marty-console/ui` | Customer application and console, with its configured API origin |
| Public website without private commerce | `public` | `public` | `ghcr.io/elevenid/marty-ui-oss/ui-public` | Production homepage, marketing pages, public resources and crawler artifacts |
| Full production website | `public` with the authenticated commerce context | `public` | `ghcr.io/elevenid/marty-subscriptions/ui-production` | All public pages, pricing, subscription checkout and billing console UI |

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

### Organization creation and public telemetry

`ORGANIZATION_CREATION_ENABLED` controls both the backend policy and the UI's
organization creation/setup controls. The deployment default is `false`; select
`true` explicitly in the installer's application settings or the independent
Compose environment when onboarding is intended. Both audience startup hooks
accept only `true` or `false`. The image audience still determines which pages
exist, and Keycloak's user-registration setting is a separate policy.

Both audience hooks load the existing `GOOGLE_ANALYTICS_MEASUREMENT_ID_FILE` and
`GOOGLE_SITE_VERIFICATION_FILE` inputs. A nonempty analytics ID must use the GA4
`G-` plus uppercase letters/digits format; an empty value disables analytics.
The public production hook refreshes verification metadata in every prerendered
HTML page, including pricing. `runtime-config.js` is served with `no-store`, so
updated deployment settings are not retained as a year-long immutable asset.
The production CSP permits the exact basic GA4 script and collection origins.
It does not enable Google Ads or tag-preview domains. Existing analytics behavior
is unchanged: configuring an ID enables analytics on normal origins; this change
does not add a consent-management system. The consent-gated demo player remains
independent.

## Public-only production pipeline

Run **Production website release** (`production-web-release.yml`) on `main`:

```sh
gh workflow run production-web-release.yml --repo ElevenID/marty-ui --ref main \
  -f stack_release_tag="$stack_tag"
```

Set `stack_tag` to an already published stable `vMAJOR.MINOR.PATCH` release whose
verified installer inventory has the same source SHA and version as the dispatch.
This workflow produces the public-only image. It does not satisfy a request for
all production pages; use the private producer below for that release.

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
- `deployment/production-deployment.json` and `deployment/production-openbao.zip`,
  each with a Sigstore bundle: the production UI bound to the verified stable
  OpenBao backend described below.

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

## Full production pipeline and private source boundary

Run **Full production UI release** in `ElevenID/marty-subscriptions` after the
matching stable backend is published. `ui_source_sha` must be the exact public
source of that verified stable release:

```sh
gh workflow run production-ui-release.yml --repo ElevenID/marty-subscriptions \
  --ref main -f ui_source_sha="$ui_source_sha" -f stack_release_tag="$stack_tag"
```

The producer uses its exact private `main` commit and its own repository access.
It fetches the public source anonymously and stages only committed frontend blobs
under `extension/src/`, plus `extension/commerce-source.json`. No private source
is copied into this public repository or delivered in a source archive. Its
named BuildKit context is `commerce_extension`; the public Dockerfile consumes
`/extension` from that context.

The public build contract requires `MARTY_PRODUCTION_PAGES=full`, the exact
`MARTY_COMMERCE_SOURCE_SHA`, and the fixed extension entrypoint. It verifies the
marker repository/source pair and requires that entrypoint in the emitted bundle.
A missing extension, mismatched source, or customer-audience full request fails.
The default public-only build continues using the OSS stub. Full builds disable
source maps; only compiled static output enters the final image.

The full manifest uses `marty.production-web-release/v2`. Its top-level
`repository` and `source_sha` identify the public UI/backend source. Its
`commerce_extension` and `producer` identify the private repository and exact
private commit. The image and release provenance are signed by
`ElevenID/marty-subscriptions/.github/workflows/production-ui-release.yml` at
`refs/heads/main`; verify them against the private producer SHA, while separately
requiring the manifest's public SHA to equal the stable backend source. Do not
compare the private attestation source directly to the public UI SHA.

The `production-full-<version>-<run-id>-<run-attempt>` artifact retains the build
plan, image metadata and provenance, UI release manifest, deployment manifest,
archive, and the corresponding signature/provenance files. Select the exact
successful run and independently record its public and private source SHAs before
verification. With those expected values and the artifact downloaded:

```sh
jq -e --arg public "$ui_source_sha" --arg private "$commerce_source_sha" '
  .schema == "marty.production-web-release/v2" and
  .source_sha == $public and .production_pages == "full" and
  .commerce_extension == {repository: "ElevenID/marty-subscriptions", source_sha: $private} and
  .producer.source_sha == $private
' production-web-release.json
for subject in production-web-release.json production-deployment.json production-openbao.zip; do
  gh attestation verify "$subject" --bundle "$subject.provenance.jsonl" \
    --repo ElevenID/marty-subscriptions \
    --signer-workflow ElevenID/marty-subscriptions/.github/workflows/production-ui-release.yml \
    --source-digest "$commerce_source_sha" --source-ref refs/heads/main --deny-self-hosted-runners
done
image="$(jq -r '.image.uri + "@" + .image.digest' production-web-release.json)"
gh attestation verify "oci://$image" --bundle image.provenance.jsonl \
  --repo ElevenID/marty-subscriptions \
  --signer-workflow ElevenID/marty-subscriptions/.github/workflows/production-ui-release.yml \
  --source-digest "$commerce_source_sha" --source-ref refs/heads/main --deny-self-hosted-runners
```

Pricing is explicitly prerendered in full mode. The producing workflow requires
its real `<h1>`, canonical `/pricing` URL, and prerender status marker. Checkout
uses `/pricing/checkout`, organization setup `/console/org/setup`, and the billing
console `/console/org/billing`. A successful HTTP fallback for an application
route establishes only that its shell is served; it does not prove authentication,
organization creation, a provider call, or a payment.

## Production OpenBao deployment package

Both producers first authenticate the original stable installer subjects with
the installer-pinned GitHub verifier. `scripts/package_production_deployment.py`
then checks their exact inventory, hashes, image closure and bundle ownership.
It refuses a version/source mismatch. The resulting `production-openbao.zip`
contains the original five stable subjects and their provenance bytes unchanged,
the selected production UI manifest, and `compose.production-ui.yml`. Only the
UI image, customer UI bind mounts, and root HTTP healthcheck are adjusted.
Backend images, provider configuration, OpenBao plugin and secret owners remain
those of the verified stable release.

This is a separate ordinary Compose deployment. Extract the nested backend
bundle and follow its `SELFHOST_BUNDLE.md` and `SELFHOST_OPENBAO.md` instructions
for secrets, key provisioning, migrations and one-time OpenBao initialization;
the package README gives the exact layer order. Application AWS KMS and a
Cloudflare connector are not required. Do not apply the production overlay to
an existing installation whose journal and lifecycle are owned by the native
installer. Nightly and stable customer installers retain their customer image
and managed OpenBao option.

The deployment record deliberately retains `qualification.runtime_tested=false`
and `qualification.billing_journey_tested=false`. Image build and static HTTP
checks cannot establish those qualifications. The private extension calls
`/v1/billing/*`, `/v1/usage*`, and payment APIs, but this package does not supply a
deployable private billing backend, its schema lifecycle or configured payment
provider. Those remain a concrete qualification blocker for a working checkout.
Full-page production packaging must not be presented as a tested billing release.
