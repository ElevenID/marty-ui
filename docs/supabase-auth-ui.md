# Static Supabase sign-in and consent companion

The companion in [`integrations/supabase-auth-ui`](../integrations/supabase-auth-ui/)
provides the authorization UI required by Supabase's OAuth server. It supports
an existing verified account signing in with email/password, an enrolled TOTP
challenge when the account requires additional verification, and an explicit
allow/deny decision for a configured OAuth application. It is a static site;
it adds no application server, worker, database or Pages Functions.

This is a local implementation with synthetic tests and a static build, not a
record of a deployed or qualified Supabase project. Complete the existing
[external-provider qualification](oidc-provider-qualification.md) before using
it with an installation. The application still owns its authorization-code
exchange, PKCE, state/nonce validation, signed identity verification, membership
and application session.

## Responsibilities and supported flow

| Component | Responsibility |
| --- | --- |
| Supabase Auth / OAuth server | Account credentials, factors, authorization records, consent grants, code issuance and token issuance. |
| This static companion | Fresh page-local sign-in, verified-account and enrolled-TOTP checks on this UI path, trusted request display, explicit decisions and safe return navigation. |
| ElevenID OAuth client | Existing Auth service, its exact callback, validated identity, organization membership and ElevenID session. |
| Rifare OAuth client | Its separately registered Medusa customer-auth provider, exact callback, customer identity binding and Rifare session. |

One Supabase project may serve both applications, but **ElevenID and Rifare must
have different OAuth client IDs and callback registrations**. Shared provider
identity does not confer ElevenID membership, merchant authority, or a Rifare
customer binding. This companion does not perform identity mapping.

The page accepts only `authorization_id` in its query string. It rejects
missing, duplicate, unknown, malformed or oversized input and any fragment.
It does not accept a return URL, a client ID, a token or a requested scope from
the incoming URL. The authorization ID is an opaque 16–128-character ASCII
identifier using letters, digits, `_` and `-`.

After validating the request, the page immediately removes its query string
from browser history and retains the authorization ID only in memory. Reloading
or restoring the page therefore requires a new sign-in started by the
application; it cannot offer another account a request the provider may already
have bound or consumed.

After password sign-in, the companion calls the SDK's server-backed `getUser()`
and requires a real `email_confirmed_at` value on that user. It does not use a
password-response user object as its verification result and does not invent
an `email_verified` claim. The signed identity received by ElevenID or Rifare
must independently satisfy that application's verification rules.

The page checks session assurance and fetches the enrolled factor list. An
unmet AAL2 requirement with a verified TOTP factor leads to a six-digit
authenticator challenge. Multiple enrolled TOTP factors can be selected. A
successful challenge must actually result in AAL2 before authorization details
are retrieved. An unmet requirement for only phone, WebAuthn, recovery codes or
an unknown factor type is blocked; it never falls back to password-only
consent. Registration, email confirmation, password recovery, factor enrollment,
recovery codes, social login, SSO and CAPTCHA are not implemented here. Accounts
or project policies that require those flows need further product work.

Authorization details come from the provider SDK. The request ID, user ID,
email, client ID and registered callback must match the current verified
account and local allowlist. The UI displays the configured application label,
the provider's registered name when different, every requested scope, and the
return origin. Provider names and scopes are rendered as text. Provider images
and links are not loaded. No render, password submission, MFA completion or
account switch implicitly calls the approval endpoint.

### Existing consent and account switching

Supabase's details endpoint can return only `redirect_url` when existing
consent permits immediate provider approval. That response contains no fresh
scope list or client ID. The companion identifies the application from its
unique configured callback, validates the code-bearing URL, and displays an
explicit **Continue** action. It does not navigate automatically and does not
call approval again. Cancelling this page clears its local session and stops
navigation; it does not revoke the provider's previous consent or an already
issued code.

The provider also binds an authorization record to the user when details are
first retrieved. Once that request has started, the same authorization ID
cannot be safely reused for another account, even if the HTTP request is later
aborted. **Use another account** therefore clears this page and instructs the
user to return to the originating application and start a new sign-in. It does
not fabricate an authorization-start URL. Before details retrieval starts
(for example, on the password or TOTP screen), switching can start a fresh
page-local session using the still-unbound authorization request.

These behaviors follow the pinned SDK's
[`OAuthAuthorizationDetails` / `OAuthRedirect` union](https://github.com/supabase/supabase-js/tree/master/packages/core/auth-js)
and the reviewed provider
[authorization handler](https://github.com/supabase/auth/blob/10ef10789d1ee4fb422b448047e67e3e264c0482/internal/api/oauthserver/authorize.go).
Recheck them when upgrading the provider or SDK.

## Public configuration

`public/config.example.json` is deliberately synthetic. Its domains end in
`.invalid`, its key is not usable, and its client IDs are placeholders. Neither
the build nor tests contact a Supabase project.

Copy it to ignored `config.local.json` and replace every illustrative value
when preparing a real build. That file's contents are published as
`dist/config.json`; **all configuration is public**.

```json
{
  "schema": "elevenid.supabase-auth-ui/v1",
  "supabaseUrl": "https://PROJECT_REF.supabase.co",
  "publishableKey": "sb_publishable_REPLACE_WITH_THE_PUBLIC_PROJECT_KEY",
  "brand": "ElevenID",
  "clients": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "label": "ElevenID",
      "redirectUris": ["https://elevenid.example.com/v1/auth/callback"]
    },
    {
      "id": "22222222-2222-4222-8222-222222222222",
      "label": "Rifare",
      "redirectUris": ["https://rifare.example.com/auth/customer/oidc/callback"]
    }
  ]
}
```

The callback paths above illustrate configuration shape. Obtain Rifare's
actual callback from its selected Medusa provider implementation and ElevenID's
callback from its canonical installation. Do not register an example path
unless it is the real application's callback.

| Field | Accepted value |
| --- | --- |
| `schema` | Exactly `elevenid.supabase-auth-ui/v1`. |
| `supabaseUrl` | One exact canonical HTTPS project origin, without a path, trailing slash, credentials, custom port, query or fragment. A custom Auth domain may be used if it is the actual selected project origin. |
| `publishableKey` | Only a modern `sb_publishable_` key. Secret keys, service-role keys, legacy JWT keys and management credentials are rejected. |
| `brand` | A bounded plain-text site label. |
| `clients` | 1–16 explicitly registered clients, each with a unique opaque ID, a plain-text label and 1–8 exact HTTPS callback URLs. |

Each object has a closed set of fields. Callback URLs have ordinary exact paths
and no query, fragment, wildcard, credentials, custom port or percent-encoded
path. A callback cannot belong to two clients because an already-consented
response may identify the client only by that callback. Use separate
configuration and registrations for beta and production.

The publishable key is intentionally available to every browser. Supabase
database permissions and RLS remain a separate operator responsibility. OAuth
client secrets stay in their respective server-side applications; this page
must never receive them.

## Local verification and static build

Run from the companion directory with Bun. The checked-in lock pins
`@supabase/supabase-js` and its Auth package to **2.119.2**. Local verification
used Bun **1.4.4**. Installation hooks are disabled.

```sh
cd integrations/supabase-auth-ui
bun install --frozen-lockfile --ignore-scripts
bun test
bun build.mjs --config public/config.example.json
```

For a reviewed real public configuration:

```sh
bun build.mjs --config config.local.json
```

The build validates configuration before writing output. It bundles the SDK
and application JavaScript locally, includes no source maps, and creates:

| File | Purpose |
| --- | --- |
| `index.html` | Accessible sign-in, TOTP and consent shell. |
| `app.js`, `app.css` | Local application bundle and styles; no external scripts or fonts. |
| `config.json` | The validated public configuration for this build. |
| `_headers` | Cloudflare Pages security and cache policy derived from that exact project origin. |
| `_redirects` | Exact `/oauth/consent` and `/oauth/consent/` rewrites to the static page. |

The output directory contains no Functions. `node_modules/`, `dist/` and
`config.local.json` are ignored inside this companion, and it has its own Bun
lock; the application's root frontend dependencies are unaffected.

Tests exercise pure protocol and controller behavior, including malformed
queries, callback confusion, denial, unknown clients, unverified email,
unsupported or incomplete MFA, stale account/decision results, error redaction,
provider-bound authorization reuse, and explicit action requirements. Separate
tests run the installed SDK through an in-process fake HTTP transport and
check real password/user/consent request shapes, TOTP session upgrade, and
actual memory-session cleanup. No test sends email or uses a live account.
These tests do not establish browser appearance, deployed header behavior or
hosted provider interoperability.

## Cloudflare Pages and provider wiring

Prepare a Pages static deployment containing the complete `dist/` output.
Deployment, custom-domain setup and changes to Supabase are separate operator
actions; none are performed by this build. Use the normal reviewed deployment
process for the chosen account. Do not add Pages Functions or place secrets in
Pages variables for this companion.

For a page served at `https://identity.example.com`, configure the Supabase
OAuth server's Site URL as that origin and its Authorization Path as
`/oauth/consent`. Supabase then routes an authorization request to the page with
its `authorization_id`. Enable the OAuth server and register both applications
with their exact callbacks. Keep each confidential client's credential in
that application. Apply the selected signing algorithm, PKCE, scopes and
identity checks required by each application's provider profile. See the
official [OAuth server setup](https://supabase.com/docs/guides/auth/oauth-server/getting-started)
and [OAuth flow documentation](https://supabase.com/docs/guides/auth/oauth-server/oauth-flows).

The generated Pages `_headers` policy applies to every asset, including the
auth HTML and public config. It sets `Cache-Control: no-store`, a Cloudflare
CDN no-store policy, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff` and a restrictive permissions policy. CSP
allows only local scripts/styles, the same origin for config, and the exact
configured Supabase origin for API connections. It forbids framing, forms
navigating elsewhere, images, external fonts, object content and base-URL
overrides. See Cloudflare's
[static Pages headers documentation](https://developers.cloudflare.com/pages/configuration/headers/).

Rebuild `_headers` and `config.json` together when changing project origin.
Editing only the public config would leave the API blocked by the previous
CSP. Do not add analytics, external script loaders, provider logos or a service
worker to this sign-in page without revisiting its credential-handling and
cache boundaries. After deployment, inspect the actual response headers on
the consent URL and config; a local static-file preview does not apply
Cloudflare `_headers` automatically.

## Session, callback and trust boundaries

Every attempt creates a separate SDK client with `persistSession: false`,
`autoRefreshToken: false` and `detectSessionInUrl: false`. Passwords, codes and
tokens are not written to browser storage, public render state, logs or
telemetry by this companion. Account switching, cancellation, page exit and
navigation discard the attempt, abort its requests and clear its SDK memory
session using `signOut({ scope: 'local' })`.

The pinned SDK removes the local session before trying the logout HTTP call.
The companion's already-aborted transport prevents that call from reaching the
provider. This deliberately avoids revoking the parent provider session while
the application exchanges its OAuth code. It is **local cleanup**, not
provider-wide logout, token revocation or consent revocation. Real-SDK tests
verify the local session is absent and no logout HTTP request is sent. Browser
reload has no retained authorization ID and requires a new application-initiated
flow; a back/forward-cache restore reloads instead of reviving a consent screen.

Every asynchronous result is checked against the current attempt. An old
password, TOTP, details or consent response cannot render a new account or
redirect after the user switches or cancels. Cancelling a request does not
undo an approval the provider may already have processed; no such guarantee
is made.

For approve and deny, the SDK is called with `skipBrowserRedirect: true`.
Before any navigation, the page requires an exact configured HTTPS callback
scheme/host/path. Approval allows only `code`, optional `state`, and optional
`iss`; denial allows only `error=access_denied`, optional `error_description`,
`state` and `iss`. Duplicate keys, fragments, extra parameters, normalized path
tricks and mismatched callbacks are rejected. If `iss` is present, it must be
the exact configured `${supabaseUrl}/auth/v1` issuer. Query values are bounded.
The final callback is kept out of render state, and navigation replaces the
current history entry.

The companion cannot compare callback state to the original application's
state because it receives only the authorization ID. The application must
still require and validate its own state, nonce, PKCE verifier, issuer,
audience and code exchange. Redirect validation here does not replace those
checks. SDK/network errors are mapped to fixed messages rather than displaying
provider bodies, token-bearing URLs or credentials.

## Provider qualification still required

Fresh password entry and an enrolled TOTP challenge on this page do **not**
prove Supabase honors OAuth `prompt`, `max_age`, or emits a usable `auth_time`,
`amr` or `acr` for ElevenID. They also do not establish provider-wide MFA
enforcement: a UI check cannot by itself prevent a different client from
calling provider endpoints. See Supabase's
[MFA guidance](https://supabase.com/docs/guides/auth/auth-mfa).

ElevenID's existing `prompt=consent login` and `max_age=0` defaults remain
unchanged, and all existing client validation remains in place. **Even a passing
ElevenID callback is not proof of interactive freshness.** The reviewed provider
source may stamp `auth_time` during code exchange, so a sufficiently recent
timestamp does not necessarily establish when the person last authenticated.
See the [Supabase freshness and MFA source review](oidc-provider-qualification.md#supabase-freshness-and-mfa-source-review).
Hosted freshness remains unqualified. Any explicitly selected policy adjustment
must be qualified and recorded by the operator as described in the provider
runbook; the UI is not a reason to silently relax authentication policy.

Before treating the stack as usable, qualify a real project and separately
registered ElevenID and Rifare clients: first-time consent, prior consent,
denial, wrong or unverified accounts, required TOTP, unsupported MFA, expired
requests, account switching through a new application authorization, actual
signed claims, application membership/customer binding, local logout and
restart behavior. Registration, recovery, enrollment, account management and
provider-wide assurance remain explicit further work. No hosted qualification
is claimed by the synthetic test suite or static build.
