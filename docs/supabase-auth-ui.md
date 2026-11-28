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
consent. Recovery codes, social login, SSO and CAPTCHA are not implemented here.
Registration, email confirmation, initial TOTP enrollment and password recovery
are available only with the explicit v3 configuration below.

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
  "brand": "ElevenID LLC",
  "clients": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "label": "ElevenID",
      "redirectUris": ["https://elevenid.example.com/v1/auth/callback"]
    },
    {
      "id": "22222222-2222-4222-8222-222222222222",
      "label": "Rifare",
      "redirectUris": ["https://rifare.example.com/auth/customer/external-oidc/callback"]
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
| `schema` | `elevenid.supabase-auth-ui/v1`, explicit native-proof transport `elevenid.supabase-auth-ui/v2`, or opt-in account lifecycle `elevenid.supabase-auth-ui/v3` described below. |
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

### Native MFA proof transport (release qualification pending)

The optional `elevenid.supabase-auth-ui/v2` schema requires a `callbackMode`
on **every** client: either `redirect` or `native_mfa_post`. Version 1 rejects
this field and retains its existing redirect-only behavior. Enable the POST
mode only for a first-party application whose deployed Auth callback supports
the protocol. The Auth source implements this POST protocol behind the explicit
runtime selection below; its generic GET callback cannot supply native proof.
Signed installer selection and installed end-to-end qualification must also be
complete before deploying a configuration that enables this browser mode.

For `native_mfa_post`, an explicit approval or Continue action requires a TOTP
challenge completed in this page's current attempt. Password-only accounts are
blocked before approval. After checking the current session and account again,
the page submits a top-level, URL-encoded POST to the exact configured callback
without a query string. Its three fields are `code`, `state`, and
`native_access_token`. The token is read from the memory-only SDK session; it
does not enter the URL, public controller state, local storage or error text.
A transient hidden form carries the body and is removed after submission.
Denial uses the existing error redirect and never reads or sends the token.
Account switching or disposal during asynchronous session retrieval prevents
submission. The generated CSP permits forms only to the origins of clients
explicitly configured for POST; redirect-only builds retain `form-action 'none'`.
POST builds use `strict-origin` in both the HTTP referrer policy and HTML meta
tag. This sends the public login-page origin, with no path or query, and
preserves a verifiable `Origin` on the cross-origin form submission. The
receiver must require that exact configured origin and reject `null`, absent
or unexpected origins. Redirect-only builds retain `no-referrer`.

The browser checks transport shape, not cryptographic assurance. The receiving
Auth service must independently verify the native token's signature, fixed
issuer/audience, subject, expiry, AAL2, signed password and TOTP event times,
and freshness against its one-time login state. It must also perform the
normal OAuth code exchange and verify client binding, PKCE, nonce and signed
verified identity, requiring both identities to match before provisioning or
creating an application session. Native assurance must be retained as separate
typed evidence rather than inserted into the provider's ID-token claims.
Provider-session revocation and application logout need their own qualified
implementation. Configuring this browser mode alone satisfies none of those
server requirements.

The Auth runtime selection consists of `OIDC_NATIVE_PROOF_MODE=supabase_totp`,
`SUPABASE_AUTH_UI_ORIGIN` (one exact HTTPS origin, without a trailing slash), and
`SUPABASE_PUBLISHABLE_KEY` (the same public project key used by the companion).
It requires external OIDC mode, the exact project `/auth/v1` issuer, a UUID
client ID, only ES256 signatures, and `OIDC_MAX_AGE_SECONDS=0`. The application
cookie must use Lax or secure None SameSite policy for the cross-origin POST
and its subsequent redirect. The signed installer's fresh provider-selection
input exposes these through its explicit
[`native_supabase_totp` block](installer-external-oidc.md#supabase-native-password-and-totp-proof).
Do not bypass authenticated configuration ownership by editing a retained
installation. Source support does not establish that an installed release has
qualified this protocol.

Auth snapshots the native-proof origin in one-time PKCE state. A GET callback,
changed provider policy or mismatched POST origin fails before code exchange.
The POST body is limited to 24 KiB, has exactly the three named fields and has
no query string. Normal OAuth signature, audience, client, nonce, verified
email and request-freshness checks remain in place. Native proof uses the same
trusted JWKS, an exact `authenticated` audience, AAL2, matching subject/email,
and actual signed password/TOTP events no earlier than the request start
(with five seconds of clock tolerance). Refresh issuance cannot make old
authentication events fresh. A shared atomic cache marker reserves each native
provider session for one use, including concurrent callbacks and other states.

After both proofs validate, Auth revokes this user's OAuth grant for its own
configured client, then attempts local native-session logout. Both must succeed
before provisioning or saving an application session. Grant revocation covers
all provider sessions for that user/client and requires consent again on a
later login; it does not delete other ElevenID application sessions. Bootstrap
bearer and refresh tokens are not stored in the application session. Provider
JWTs remain cryptographically valid until expiration, as with ordinary Supabase
logout. The application session retains separate typed authentication-event
evidence and the unchanged signed ID claims. Internal step-up checks use the
actual earlier authentication event, never the OAuth exchange timestamp.

### Account lifecycle (v3, delivery qualification pending)

`public/config.lifecycle.example.json` shows the closed v3 schema. It retains
v2 per-client callback modes and requires `accountLifecycle` with a `clientId`
and `signInUri`. The selected client must use native MFA POST, and the sign-in
URI must be exactly `/v1/auth/login` on the same origin as that client's
registered `/v1/auth/callback`. Query strings, fragments and arbitrary return
destinations are rejected. This starts a new application login after recovery;
it cannot reuse an old OAuth state or turn an email token into an application
session.

The static build adds `/account/register`, `/account/confirm`, `/account/security`,
`/account/recover` and `/account/verify` rewrites only when v3 is selected. The
sign-in screen then offers account creation, authenticator setup and password recovery.
Recovery requests use the provider's normal email API with a fixed verification
page callback and a non-enumerating success message. A recovery request does
not create an account or sign the browser into an application.

Configure the Supabase recovery email template from `email/recovery.html`.
Set its Site URL to the exact authorization-site HTTPS **origin**, without a
trailing slash, and allow the exact `/account/verify` redirect there. The email
template puts only `token_hash` and `type=recovery` in the URL fragment. The
page removes both query and fragment from browser history before loading its
configuration or contacting the provider; hashes never enter HTTP URLs,
rendered controller state, local storage or error messages. Malformed,
duplicate, wrong-purpose or redirect-bearing links fail closed.

An explicit confirmation button consumes the one-time email credential only
after the user acts. This follows Supabase's
[email-prefetching guidance](https://supabase.com/docs/guides/auth/auth-email-templates#email-prefetching)
so loading a link preview does not itself verify the credential. A server-backed
account check then preserves required MFA. Enrolled TOTP must complete and
actually reach AAL2 before a password update; unsupported required factors are
blocked. The page checks account and verified-factor identity again before
writing, requires matching passwords of 12–1024 characters, and leaves stricter
provider password policy authoritative. Passwords and codes are cleared from
inputs on submit and never enter public controller state.

After a successful password change, another account/factor check and local
provider logout precede the automatic return to the fixed application sign-in
entry. There is no extra Return button on that successful path. If cleanup
fails after the write, the page clearly says the password was saved and offers
a manual fresh sign-in; it does not falsely report an unchanged password.
Disposal stops stale work from rendering or redirecting and clears the local
memory session. It cannot undo a request the provider already committed.

This source has synthetic pinned-SDK and Chrome checks, not live email-delivery
or real password-reset acceptance. Verify the custom SMTP sender, Free-plan
limits, exact site/redirect configuration, email template and actual delivered
link before enabling v3 on the deployed site. No provider settings or human
accounts are changed by a build. Recovery for a lost authenticator still requires
additional product work.

#### Signup, email confirmation and first authenticator

The signup form sends email/password directly through the pinned SDK with a
fixed `/account/confirm` destination. Matching passwords must contain 12-1024
characters; stricter provider rules remain authoritative. A successful request
shows a generic email notice and never grants organization or merchant access.
Email confirmation must be enabled: an unexpected signup session is logged out
and blocked instead of accepted as verified signup.

Configure Supabase's confirmation template from
`integrations/supabase-auth-ui/email/confirmation.html` and allow the exact
`/account/confirm` redirect on the same Site URL origin. Its link carries only
`token_hash` and `type=email` in the fragment. The page scrubs the URL before
configuration/provider requests, and an explicit confirmation action protects
the one-time credential against email prefetching. After server-backed verified
account validation, local provider logout precedes automatic navigation to
`/account/security`. An email link never grants an application session or
silently enrolls an authenticator.

Setup requires a fresh password sign-in and another server-backed account/factor
check. An existing verified TOTP factor is preserved and the browser returns to
the fixed application sign-in entry without enrolling or replacing anything.
Unsupported required factors block setup. For accounts without verified factors,
the user explicitly chooses enrollment; duplicate clicks cannot create multiple
factors in that page attempt. The provider-generated QR uses a passive SVG data
image, never SVG markup inserted into the document. Only v3 permits `data:` in
the CSP image directive. The manual setup key is hidden until requested, and
both key and QR remain outside public controller state and persistent storage.

Verification targets only the factor created by that setup attempt. Account
identity and its pending factor are checked before verification; actual AAL2
and the same verified factor are required afterward. Success clears the setup
material, logs out the provider session locally and automatically opens a fresh
application sign-in. Explicit rejected OTP responses permit another code;
uncertain network or account/factor changes clear setup material and block the
attempt. Cleanup failure reports the completed change with a manual sign-in
fallback. No setup path removes a factor. Cancelling or closing the page can
therefore leave an unverified factor at the provider; repeated abandoned
attempts can reach provider limits and require operator inspection. These pages
do not provide factor replacement or lost-authenticator recovery.

Automated Chrome checks at 390px and 1280px exercise the built site with the
real pinned SDK and entirely synthetic HTTP responses, including signup,
explicit email confirmation, fresh password setup, passive QR loading, manual
key visibility, factor verification, local logout and automatic return. This
does not prove real mail delivery, a scannable provider QR, actual enrollment,
or acceptance by the installed ElevenID application.

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

### Separate API and console origins

When the native callback accepts the POST at one origin and issues a redirect
to a different console origin, use `elevenid.supabase-auth-ui/v4`. It retains
the v3 account lifecycle fields and requires `postRedirectOrigins`, a bounded
list of unique exact HTTPS origins, for example:

```json
"postRedirectOrigins": ["https://console.example.invalid"]
```

The build adds those origins to `form-action` alongside the registered native
callback origins. This allows the browser's subsequent redirect navigation;
the callback helper still sends code, state and native MFA proof only to the
exact registered callback URI. Callback validation, provider verification,
Origin validation and MFA requirements are unchanged. Wildcards, schemes,
paths, query strings, credentials, nondefault ports and duplicate origins are
rejected. v1–v3 configuration behavior remains unchanged.

Without the final origin, a browser can accept the callback POST and its
session cookie, then block the console redirect and leave the auth page at
“Returning”. `tests/test_native_auth_callback.py` exercises that three-origin
case with the actual production form helper and generated policies, including
the blocked v3 control, permitted v4 console and an unlisted origin that stays
blocked. It uses synthetic data and intercepted requests, not a live provider.

For an actual deployment, retain the reviewed callback/provider/client values,
set the schema to v4, set `brand` to `ElevenID LLC`, and supply only the intended
console origin in `postRedirectOrigins` before rebuilding. The synthetic full
example is `public/config.split-origin.example.json`.

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
restart behavior. Real registration, recovery and enrollment journeys, account
management and provider-wide assurance remain explicit qualification work. No hosted qualification
is claimed by the synthetic test suite or static build.
