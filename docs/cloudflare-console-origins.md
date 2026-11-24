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

This source profile does not qualify a deployment. Complete native installer
and target Compose-version qualification, Pages build/routes/CSP/custom-domain
checks, actual Gateway/browser preflight and operation checks, native
authentication review, the signed installed login/profile/consent/logout
journey, restart/recovery checks and rollback before switching traffic. Keep
the current production routes until those checks pass. A `pages.dev` response,
synthetic router port or rendered Nginx syntax check does not establish the
same-site installed cookie journey.
