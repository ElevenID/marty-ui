# Website and application delivery

The default public build remains the combined website and application. Two
additional build surfaces allow marketing delivery to advance independently:

| Command | Output | Contents |
| --- | --- | --- |
| `bun run build` | `dist` | Existing combined public, login, checkout, and consoles |
| `bun run build:website` | `dist-website` | Marketing, blog, demos, static support catalog, optional private pricing |
| `bun run build:application` | `dist-application` | Login, callbacks, documentation, checkout, and consoles |
| `bun run build:selfhost` | `dist-selfhost` | Existing customer full/tester profiles |

The application-only output is available for a separately qualified migration.
Creating the website image does not activate a new edge or replace the running
combined application. The release/composition helpers must qualify that change.

## Ownership and compatibility

`contracts/web-surface-routes.json` is the route authority shared by browser
handoffs, website Nginx, and edge composition. Unknown routes stay with the
application. `/resources` is a marketing page; `/resources/` and its descendants
remain application/protocol routes. Marketing page trailing-slash aliases are
explicit. Login, `/login/error`, callbacks, documentation, and checkout remain
application-owned even though they are reachable before authentication.

`contracts/website-source-ownership.json` lists exact marketing-owned source
modules. CI uses this roster for website change selection, and both application
and customer guards reject every roster member from emitted chunks. Shared
providers, navigation, assets, authentication wrappers, build policy, and unknown
paths retain broader validation. Changes to the roster itself require broader CI.

The website guard inspects emitted module identities and rejects authentication,
console, API-client, payment provider, and private checkout modules. These checks
run during the actual build, after bundling and tree shaking. A static protocol
support snapshot comes from `contracts/protocol-support-catalog.json`; the UI
identifies it as a product snapshot. Deployment-specific support status remains
available through the live application catalog.

Combined and application builds emit `/marty-web-routes.json` with their surface,
source SHA, and route contract digest. This is additive to the existing stack
release identity. The website emits `/marty-website-release.json` with its exact
public/private source inputs and route digest. It does not claim a stack release.
The digest uses recursively sorted compact UTF-8 JSON without a trailing newline.

## Resources and navigation

Website resources live at `/_website/<revision>/`. The revision is the full public
commit SHA for public pages or `<public-sha>-<private-sha>` for full pages. This
keeps application assets and website assets separate. Runtime settings load from
`/_website/runtime-config.js` with `Cache-Control: no-store`; immutable versioned
resources use a one-year cache lifetime. Crawler files and the release metadata
remain stable file-only endpoints. Missing resources return 404 rather than HTML.

Links and imperative navigation crossing website/application ownership load the
receiving document. Console and public application entry points also use a full
document handoff in both directions. Query strings and fragments are preserved.
Login `next` values accept this origin or the explicitly configured canonical
entry origin; unsafe schemes, external origins, credentials in URLs, backslashes,
and control characters are rejected. Canonical-entry navigation loads the
canonical document, including transitions within one surface.

The website does not initialize authentication. Its login and free-signup buttons
hand off to the application's login route. Full pricing retains the existing
`DISABLE_PUBLIC_GET_STARTED_BUTTONS` flag as `disableSandboxSignup` and sends paid
plan selection to `/pricing/checkout?plan=...`. Entitlement and organization
creation policy continue to be enforced by the application and backend.

## Private commerce source

Full production builds require these existing source inputs:

```sh
MARTY_PRODUCTION_PAGES=full
MARTY_COMMERCE_SOURCE_SHA=<exact-private-commit>
MARTY_COMMERCE_EXTENSION_PATH=/workspace/commerce-extension/src/extension.jsx
```

The staged source root must contain `commerce-source.json` binding repository
`ElevenID/marty-subscriptions` to the same SHA. The builder authenticates that
binding and selects adjacent `website.jsx` or `application.jsx` for the requested
surface. `extension.jsx` remains the combined adapter. Missing adapters, missing
identity, mismatched SHAs, private inputs in public mode, or commerce in customer
builds fail the build. The private library also checks each emitted adapter's
transitive chunk graph.

## Docker targets

`docker/ui.Dockerfile` keeps `public` as its default final target. Existing
`selfhost` and `console` targets retain their profiles. New production targets are:

| Target | Required arguments |
| --- | --- |
| `website` | `UI_VARIANT=public`, `UI_SURFACE=website`, `NGINX_CONFIG=nginx.website.conf`, exact `MARTY_UI_SHA`, matching `MARTY_WEBSITE_REVISION` |
| `application` | `UI_VARIANT=public`, `UI_SURFACE=application`, application Nginx configuration |

Use the release helpers to supply verified API/blog packages and the exact source
inputs. The website serves `/healthz` and includes `X-Marty-Website-Revision` on
responses. Its Nginx configuration has no backend upstream. The existing startup
hook writes its public runtime settings to the website-specific config path.

## Local qualification

Install dependencies from the committed lockfile. A compatible Chromium is
required for prerendering; use `PUPPETEER_EXECUTABLE_PATH` when it is not installed
in Puppeteer's default location.

```sh
cd ui
bun run test:website
bun run build:website
node scripts/assert-website-dist.mjs dist-website
bun run build:application
bun run build:selfhost
```

`DISABLE_PRERENDER=1` is useful for a quick graph-only build, but does not satisfy
the website artifact qualification. The artifact check expects prerendered pages,
correct resource namespaces, provenance, crawler files, and unique sitemap URLs.

With a local Nginx binary, run the real configuration and browser smoke:

```sh
NGINX_BIN=/path/to/nginx node scripts/smoke-website.mjs dist-website
```

The smoke exercises slash routing, the protocol boundary, missing-resource
responses, revision/cache headers, the proof lab, static catalog, demos, docs and
login handoffs. For both page sets, it checks that pricing URLs return 404 and
pricing/upgrade actions are absent, while retaining docs and login handoffs. A local application sentinel proves that the browser
loads a receiving document. It does not simulate authentication, authorization,
payment, or a live deployment; those remain separate integration qualifications.


## Private pricing boundary

Public pricing navigation and CTAs are disabled; pricing is omitted from crawler
and prerender discovery. Detailed commercial pricing/claim modules are refused
from combined, website and application output, including shared/lazy chunks from
the private adapter. Existing route ownership still reserves `/pricing` to the
website and `/pricing/checkout` to the application; it does not promise that
those pages are available. The paired private adapter withholds both routes and
plan checkout while retaining detailed source privately. Hiding a link or adding
a client-side auth guard is insufficient to protect downloadable static data.
Do not ship the private library directory or source maps as public assets.
