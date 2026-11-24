# Static console and Auth origins

A static application needs a console origin and an API origin. The website and
authorization UI are separate surfaces. `VITE_API_URL` selects the API for
browser Auth fetches, provider details, learner-consent requests,
login/registration navigation and logout POST. Empty keeps
relative self-hosted requests. An explicit value must be an HTTPS origin, with
HTTP allowed only on loopback; paths, queries, fragments and credentials fail.

For example, this Auth runtime profile separates the provider callback from the
browser return. These are illustrative domains, not deployed URLs:

```dotenv
UI_BASE_URL=https://console.elevenid.example
PUBLIC_API_URL=https://api.elevenid.example
AUTH_PUBLIC_API_ORIGIN=https://api.elevenid.example
OIDC_REDIRECT_URI=https://api.elevenid.example/v1/auth/callback
OIDC_POST_LOGOUT_REDIRECT_URI=https://console.elevenid.example/
CORS_ORIGINS=https://console.elevenid.example
COOKIE_SECURE=true
COOKIE_SAMESITE=lax
```

The static application build uses `VITE_API_URL=https://api.elevenid.example`.
Register the exact API callback with the provider. When
`AUTH_PUBLIC_API_ORIGIN` is set, an explicit `OIDC_REDIRECT_URI` must match it;
otherwise Auth derives that same callback. Host/forwarded headers cannot move
the callback. Empty leaves the existing selected-UI callback behavior intact.

The browser supplies its absolute console return URL. Auth accepts only
configured UI origins and binds the validated destination into the existing
one-time PKCE state; the callback revalidates that destination. Unknown origins
cannot become browser return hosts. Additional UI origins must be explicit in
`UI_ALLOWED_ORIGINS` (or `UI_ADDITIONAL_BASE_URLS`). Account PATCH, enrollment and
logout require exactly one allowed browser Origin in this mode. Provider-local
logout clears the API session cookie and returns to the canonical console.

Use same-site HTTPS custom domains for the console and API with SameSite=Lax.
A `pages.dev` preview and an unrelated API domain do not establish that cookie
journey. The gateway must allow the exact console origins with credentials;
Pages headers must permit the intended API connection and logout form target.
Browser credentials stay in host-only HttpOnly cookies at the API, not in the
static build or browser storage.

Keycloak email enrollment for credential-only sessions retains its existing
same-origin email-return restriction. A split-origin console does not authorize
additional provider email destinations. Qualify those client allowlists and the
native account-enrollment path separately; a router-port fixture is not proof
of provider enrollment or email delivery.

For OIDC-based managed Keycloak passkey enrollment, the static build permits
only the API origin by default. If Keycloak uses a separate host, explicitly
set the public `VITE_AUTH_PROVIDER_ORIGIN` to that HTTPS origin. The dedicated
enrollment handoff requires the passwordless-enrollment action and exact API
callback in the provider URL. It grants no authority to general application
links. Unconfigured provider hosts are refused visibly. External-provider
capabilities and native email enrollment retain their separate contracts.

## Installer selection

For a fresh signed installation, extend the existing hosting input with these
fields. This is a fragment of `elevenid.installation-hosting/v1`, not a complete
hosting configuration; retain the selected listener, keyless TLS and connector
configuration from [the Cloudflare hosting guide](hosting-cloudflare-addon.md).

```json
{
  "mode": "external-proxy",
  "public_origin": "https://api.elevenid.example",
  "web": {
    "enabled_sections": [],
    "external_application_origin": "https://console.elevenid.example"
  }
}
```

The application origin must be a distinct canonical HTTPS DNS origin. Local
hosting, a public-entry IP alias and locally enabled web sections cannot be
combined with this selection. The journal binds the selection before application
rendering. The installer adds its authenticated external-application Compose
layer, removes the local `ui` service and `UI_UPSTREAM`, and derives the UI, CORS,
callback and post-logout settings shown above. Additional UI origins are refused
for this installer profile. Maintenance uses the same bound layer.

When login is also external, the installer selects the combined application/OIDC
upstream-reset layer before the external-provider layer. This preserves both
removals with Compose 5.6.1; separate later environment resets leave the UI
upstream behind. Managed Keycloak uses the separate application-only variant,
which retains its provider route. Do not interchange or reorder these assets.

The API ingress keeps API, health, callback and issuer routes. GET/HEAD requests
for UI paths receive a permanent redirect to the selected application origin,
preserving their path and query. Other methods at those UI locations are
refused. An ingress redirect check establishes only that handoff; it does not
verify Pages assets or an authenticated browser journey.

Gateway preflight for this Auth/learner transport admits only the declared
Auth endpoint/method pairs and canonical learner-association POST paths, one
configured Origin and JSON Content-Type. It returns explicit credentialed CORS
headers without contacting an upstream. Actual operations still require their
existing session, own-session, tenant, Origin and body checks. Provider and
administrator association endpoints do not gain browser preflight admission.
This is not a blanket CORS grant for every console SDK operation.

## Deployment acceptance

### Prepare the static Pages directory

Build the application with `MARTY_UI_SHA` set to the exact reviewed source commit
and `VITE_API_URL` set to the selected HTTPS API origin. Run the normal application
build and resource checks first. From the repository root, package that output:

```sh
python tools/cloudflare/prepare_console_pages.py \
  --source ui/dist-application --output /private/qualification/console-pages-candidate \
  --source-revision FULL_REVIEWED_COMMIT_SHA \
  --console-origin https://console.elevenid.example \
  --api-origin https://api.elevenid.example
```

Replace the illustrative domains and commit with the actual deployment inputs;
the destination must be new and outside the build directory.
Source and destination paths, including their supplied ancestors, must not use
symlinks or Windows junctions; select their ordinary filesystem locations.
The helper copies the build without changing it, checks its source marker and both HTML entries,
and creates static Pages rules. Console deep links use `console/index.html`;
declared public browser routes use `index.html`. A custom `404.html` disables
the implicit global SPA fallback, so API, missing asset and locale paths are not
rewritten into the application shell. Keep the explicit route list aligned with
the application routers; its test checks the current absolute route declarations.

The generated CSP preserves the production script/WASM, font, analytics and
frame sources and adds the exact API connection and logout-form origin. Static
responses use no-store headers while this deployment is being qualified. No
Worker, Pages Function, API proxy or credential is added. Upload the complete
prepared directory through the selected free Pages deployment path.

When logout redirects to a separately hosted identity provider, also pass
`--auth-provider-origin https://login.elevenid.example` with that exact configured
provider logout origin. Align it with the selected provider and the build's
`VITE_AUTH_PROVIDER_ORIGIN` when applicable. This adds only the provider's exact
origin to `form-action`, because browsers can enforce that policy across the
logout POST's redirect chain. It does not add general provider connection or
navigation permission. The chosen provider origin is recorded in the report.

The generated `pages-deployment.json` records selected origins and file hashes.
Matching a build's source marker does not prove source custody or the API origin
compiled into JavaScript. The report explicitly leaves compiled-origin,
publication and provider-journey acceptance false. Validate those against the
actual deployed browser and Gateway before acceptance. A synthetic preparation
test is not evidence of a live Pages deployment.

Cloudflare documents the static [`_headers` format](https://developers.cloudflare.com/pages/configuration/headers/)
and [`_redirects` proxy rules](https://developers.cloudflare.com/pages/configuration/redirects/).
These rules apply to static assets; Functions require their own response handling.

This source profile does not qualify a deployment. Complete native installer
and target Compose-version qualification, Pages build/routes/CSP/custom-domain
checks, actual Gateway/browser preflight and operation checks, native
authentication review, the signed installed login/profile/consent/logout
journey, restart/recovery checks and rollback before switching traffic. Keep
the current production routes until those checks pass. A `pages.dev` response,
synthetic router port or rendered Nginx syntax check does not establish the
same-site installed cookie journey.
