# Static console and Auth origins

A static application needs a console origin and an API origin. The website and
authorization UI are separate surfaces. `VITE_API_URL` selects the API for
browser Auth fetches, login/registration navigation and logout POST. Empty keeps
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

This origin contract alone does not qualify a deployment. The installer still
needs its explicit external-console hosting model and omission of the local UI
container. Complete the Pages build/routes/CSP/custom-domain and gateway CORS
checks, native authentication review, actual signed installed login/profile/
logout journey, restart/recovery checks and rollback before switching traffic.
