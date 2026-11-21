# Application and website delivery

`marty-ui` builds the application and customer UI. Marketing pages, the blog,
public demos, crawler files and website publication belong to
[ElevenID/website](https://github.com/ElevenID/website).

Run these commands from `marty-ui/ui`:

| Command | Output | Contents |
| --- | --- | --- |
| `bun run build` | `dist` | Default public application, login, callbacks, documentation and consoles |
| `bun run build:application` | `dist-application` | The same application surface with an explicit output directory |
| `bun run build:selfhost` | `dist-selfhost` | Customer application with the existing `full` or `tester` profile |

The website and combined build modes are retired in this checkout. Current
application and customer builds require the audited marketing source paths to
remain absent. Historical release validators and approved source-package
contracts retain their original evidence; they do not re-enable those modes.
See the [source-removal checkpoint](../docs/restructuring/website-source-removal.md)
for the retained source and release boundaries.

## Ownership and navigation

`contracts/web-surface-routes.json` is the route authority shared with the
standalone website and edge composition. Unknown routes stay with the
application. `/resources` is a marketing page; `/resources/` and its descendants
remain application/protocol routes. Login, `/login/error`, callbacks,
documentation, verification and consoles remain application-owned.

`contracts/website-source-ownership.json` retains the exact retired marketing
module roster. The current source and emitted-module guards reject those files
from application and customer builds. Shared providers, navigation,
authentication, the 54 retained public resources and application translations
remain in this repository.

Application output emits `/marty-web-routes.json` with its application surface,
source SHA and route-contract digest. This is additional to the existing stack
release identity. The digest uses recursively sorted compact UTF-8 JSON without
a trailing newline. The standalone website owns its website release marker,
versioned resource namespaces, prerendering and crawler qualification.

Navigation across website/application ownership loads the receiving document.
Console and public application entry points also use document handoffs. Query
strings and fragments are preserved. Login `next` values accept this origin or
the configured canonical entry origin; unsafe schemes, external origins,
credentials in URLs, backslashes and control characters are rejected.
Canonical-entry navigation loads the canonical document, including transitions
within one surface.

The website hands sign-in to the application's login route. The application
continues to enforce authentication, entitlements and organization policy with
its backend. Route ownership does not imply that a withheld commercial route
is available.

## Private application source

Private production application builds retain the reviewed commerce source
binding:

```sh
MARTY_PRODUCTION_PAGES=full
MARTY_COMMERCE_SOURCE_SHA=<exact-private-commit>
MARTY_COMMERCE_EXTENSION_PATH=/workspace/commerce-extension/src/extension.jsx
```

The staged source root must contain `commerce-source.json` binding
`ElevenID/marty-subscriptions` to the same SHA. The application builder selects
the adjacent `application.jsx` adapter. The `extension.jsx` input identifies the
existing staged source layout; it does not select a combined build. Missing
adapters, identity mismatches, private inputs in public mode and commerce in
customer builds fail validation.

Public pricing navigation and CTAs remain disabled. Detailed commercial pricing
and claim modules are rejected from application output, including shared or lazy
chunks of the private adapter. The shared route contract still reserves
`/pricing` to the website and `/pricing/checkout` to the application; the paired
private adapter withholds those routes. Private library directories and source
maps must not become public assets.

## Docker targets

The repository-source recipe, `docker/ui.Dockerfile`, has these current targets:

| Target | Required surface and profile arguments |
| --- | --- |
| `application` (default final target) | `UI_VARIANT=public`, `UI_SURFACE=application` |
| `selfhost` | `UI_VARIANT=selfhost`, `UI_SURFACE=application`, `NGINX_CONFIG=nginx.spa.conf`; `SELFHOST_PUBLIC_PROFILE=full` or `tester` |
| `console` | The selfhost arguments, plus the console's existing runtime API-origin configuration |

The old `public` and `website` targets are absent. Standalone website images use
the website repository's Docker recipe. The independent application publisher
uses `docker/application.Dockerfile` with the verified restored application
package context. Follow [application image publication](../docs/restructuring/application-image-release.md)
and [release audiences](../docs/ui-release-audiences.md) for the exact source,
package, image and producer evidence requirements.

## Local qualification

Use Node.js 24 and the pinned Bun 1.4.4 toolchain. From the repository root:

```sh
cd ui
bun install --frozen-lockfile --linker=hoisted
bun run test:application
bun run build
bun run build:application
bun run build:selfhost
```

`bun.lock` is the current install lock. `package-lock.json` remains a reviewed
compatibility/reference input for dependency and historical-evidence checks.
The frozen install must not change either lock.

The CI application/customer lane also runs the shared route/build contract tests
and the real Nginx route matrix. With Docker available, from `ui`:

```sh
node --test scripts/web-surface-contract.test.mjs scripts/web-surface-build-contract.test.mjs scripts/production-build-contract.test.mjs
python3 scripts/test_nginx_application_routes.py
```

For website development, tests, prerendering and image qualification, use the
[website repository's instructions](https://github.com/ElevenID/website/blob/main/README.md)
from that checkout. `test:website` and `build:website` are not Marty package
commands. Source/build qualification does not activate an edge, publish a
release or establish live OIDC and deployment readiness.
