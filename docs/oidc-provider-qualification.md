# External OIDC provider qualification

Use this runbook with [the native external-OIDC installer](installer-external-oidc.md)
or [the Helm chart](../deploy/helm/marty/README.md#external-oidc). One installation
has one retained issuer/client selection. Keep beta and production in separate
provider applications and installations, with separate client credentials,
callback registrations, operator accounts and acceptance evidence.

## Qualification levels

Treat each result as a separate gate:

| Gate | What it establishes | What it does not establish |
| --- | --- | --- |
| Configuration validation | The selected fields are supported and the retained inputs are consistent. | Network reachability or provider behavior. |
| Auth metadata preflight | Exact issuer, trusted HTTPS endpoints, selected client authentication, and a usable configured signing algorithm/key. | Client-secret validity, callback registration, returned identity claims, or a successful login. |
| Browser login | The actual authorization-code/S256 PKCE exchange, signed identity validation, verified email, application membership and session creation. | Application issuance/persistence after restart. |
| Application acceptance | An authenticated operator can perform the existing issuance and persistence contract. | A stored-session import alone does not prove the upstream login journey. |
| Restart and rotation | The installation retains its selected provider and activates the next credential generation through the normal transaction. | An operator-created remote provider secret has been revoked at the provider. |

A metadata-only receipt intentionally does not mark the installation ready or
the browser login qualified.

## Cloudflare Access candidate

Cloudflare documents its **SaaS application → OpenID Connect** integration as
an OIDC provider for an application. This is the relevant configuration; putting
a self-hosted Access policy in front of Marty does not itself select an OIDC
issuer in Marty. See the official
[generic OIDC application guide](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/saas-apps/generic-oidc-saas/).

Create one dedicated SaaS OIDC application for beta and another for production.
For each application:

1. Register exactly the environment's canonical HTTPS callback,
   `https://beta.example.com/v1/auth/callback` or
   `https://app.example.com/v1/auth/callback`. Do not use a wildcard callback.
2. Enable authorization-code flow with S256 PKCE. Keep the client confidential
   for the recipe below; retain its secret in the private installer input file.
3. Select `openid`, `email` and `profile`. Request groups only if an application
   feature needs them; group membership is not a replacement for Marty's
   application membership.
4. Scope the Access allow policy to the intended operator/test population and
   select the intended upstream identity provider. Qualification must not
   change unrelated applications or account-wide authentication policies.
5. Copy the exact **Issuer** and **Client ID** displayed for this application.
   Cloudflare's issuer includes the SaaS client identifier; the team hostname
   alone is not the issuer.
6. Retain separate beta/production secrets and operator records. Use the
   provider's existing presentation initially. `provider_name` labels Marty's
   account screen; it does not customize a provider-hosted login page.

Example private installer input (replace every illustrative value):

```json
{
  "schema": "elevenid.installer-external-oidc/v1",
  "external_oidc": {
    "issuer_url": "https://TEAM.cloudflareaccess.com/cdn-cgi/access/sso/oidc/CLIENT_ID",
    "client_id": "CLIENT_ID",
    "client_secret_file": "/home/operator/marty-input/beta/oidc-client-secret",
    "admin_email": "operator@example.com",
    "allowed_algorithms": ["RS256"],
    "client_auth_method": "client_secret_basic",
    "scopes": ["openid", "email", "profile"],
    "userinfo_mode": "disabled",
    "provider_name": "Cloudflare Access"
  }
}
```

Use the exact signing algorithm observed at the selected issuer. This example
retains Marty's default `prompt=consent login` and `max_age=0`. When a max age is
requested, the callback requires a signed, sufficiently recent `auth_time`.
If a provider cannot honor those parameters, an operator can explicitly select
`"prompt": []` and/or `"max_age": "omit"`; qualify the resulting session behavior
and document that it no longer requests a fresh upstream authentication. Do
not change the common defaults to accommodate one provider.

If required identity fields are missing from the signed ID token, test the
opt-in `userinfo_mode: "fallback"`. The UserInfo subject must equal the signed
ID-token subject, and email must be present and verified. UserInfo cannot
supply organization membership, roles, authentication freshness or arbitrary
authorization claims. Never invent `email_verified: true` as a constant to
make a provider pass.

### Observed Cloudflare metadata

On 2026-11-14, the new Auth executable successfully completed its metadata-only
preflight against a Cloudflare Access SaaS issuer. The observed discovery
document advertised `RS256` and a UserInfo endpoint. It omitted the standard
`token_endpoint_auth_methods_supported` field but included a vendor field
named `token_endpoint_auth_methods`. The standard missing-field default,
`client_secret_basic`, therefore matched the chosen confidential client.

That discovery response did not advertise an end-session endpoint or the
registration `create` prompt. The public capabilities correctly reported
local logout only and no in-app registration or native Keycloak passkey
enrollment. The preflight did not use a client secret. The candidate application
was not saved; its generated issuer supported discovery/public-key inspection,
but client registration was not established.

This observation is **not a completed Cloudflare login qualification**. At the
time of this record, no real ID token/UserInfo claims, provider login callback,
Marty membership/session, logout or restart journey had been qualified.
Record a new browser qualification result before recommending the issuer for
production. Do not place real client credentials, browser exports or raw
tokens in this repository.

## Browser qualification checklist

Run this against a fresh external-OIDC installation and its selected release,
not by switching the issuer on an existing Keycloak installation.

1. Run `marty-deploy external-oidc preflight` using the selected installation.
   Retain the private result and release/image identity.
2. Visit the canonical application origin and start ordinary login. Inspect
   the provider-visible application name, redirect destination and requested
   scopes. Complete the provider's login/MFA/consent journey.
3. Verify callback success through the actual Auth service and confirm
   `/v1/auth/me` identifies the expected email, stable Marty user ID and
   application organization. The token validator must accept the actual
   signature, issuer, audience, nonce and optional access-token hash.
4. Inspect identity claims only in private operator tooling. Record a sanitized
   summary: signing algorithm; whether verified email came from the signed ID
   token or subject-matched UserInfo; presence/type of `auth_time`, `amr` and
   `acr`; and the effective prompt/max-age policy. Do not publish claim values,
   tokens, secrets, authorization codes or session cookies.
5. Confirm an unauthorized account cannot gain application membership. Confirm
   cancellation or a rejected callback does not leave an authenticated Marty
   session. Existing tests cover mismatched subject/nonce/state and malicious
   endpoint responses; retain the real provider's refusal behavior as well.
6. Check the account screen's provider label, configured account/recovery links,
   registration capability and logout explanation.
7. Log out and verify the local session is gone. If discovery has no
   `end_session_endpoint`, explicitly observe that the provider's browser
   session can remain active. A subsequent login may reuse it when the selected
   prompt/max-age policy permits that.
8. Run issuance/persistence acceptance, restart through the normal installer
   operation and run acceptance resume for the same operator.
9. For a confidential client, exercise secret rotation using an overlap window
   if the provider supports it. Retain the normal generation/readiness receipt,
   test a new login, then revoke the old remote secret through the provider.
   The local command does not create or revoke remote secrets.

Record the tested source/release identity, environment, issuer, selected auth
method, signing algorithm, scopes, policy, capability results and pass/fail
outcomes. Keep only sanitized findings in source-controlled documentation.

## Provider-neutral application acceptance

After an operator completes real provider login and MFA, export that browser
context using Playwright:

```js
await context.storageState({ path: '/absolute/private/operator-state.json' });
```

Protect that file with mode `0600`. Treat it as a live session credential,
keep it outside the checkout, and delete it when qualification is complete.
Use the exported session instead of `--password-file`:

```bash
node tests/scripts/run-kubernetes-acceptance.cjs \
  --origin https://beta.example.com \
  --issuer-did did:web:beta.example.com:orgs:ORG \
  --storage-state-file /absolute/private/operator-state.json \
  --email operator@example.com \
  --user-id EXPECTED_MARTY_USER_ID \
  --state-dir /absolute/private/acceptance-state
```

Supply the existing organization/template options when the deployment differs
from the runner's fixture defaults. The initial stored-session acceptance
requires `--user-id`; obtain it from the actual authenticated Marty account,
not an upstream provider subject.

The runner accepts only a bounded private regular file, refuses symlinks and
hard links, and imports eligible secure, unexpired cookies for the exact
canonical host and shared API scope. It discards localStorage, provider/domain-
wide cookies and unsuitable cookie paths. Duplicate eligible cookie names are
refused. It validates the exact expected email and user ID through
`/v1/auth/me` before issuance.

Use `--phase resume` after restart. A new receipt binds resume to the retained
operator; a fresh private export may be supplied for that same operator.
Legacy receipts without an operator binding require an explicit `--user-id`.
The stored-session result reports `sessionVerified: true` and
`loginVerified: false`: it proves authenticated acceptance and persistence,
not the upstream login journey.

## Supabase alternative

Supabase's OAuth server can be the OIDC issuer, but that integration also needs
an operator-owned sign-in and authorization/consent UI. The provider routes
authorization requests to the configured UI, which retrieves the authorization
details and approves or denies the request. See Supabase's
[OAuth server overview](https://supabase.com/docs/guides/auth/oauth-server)
and [authorization UI guide](https://supabase.com/docs/guides/auth/oauth-server/getting-started).

That UI can use the project's custom design and brand. It is separate from
Marty's provider label and from a Keycloak theme. Do not point Marty at a
Supabase project merely because it supports social login; enable/configure its
OAuth server, register the client, implement the consent journey, and apply
the same metadata/browser/acceptance gates above. The repository includes a
[static Supabase sign-in/consent companion](supabase-auth-ui.md) for existing
verified accounts, with separate registered ElevenID and Rifare clients. It can
be built independently for static hosting; it does not provision a project,
register clients or qualify a hosted provider.

### Supabase freshness and MFA source review

On 2026-11-21, a review of upstream `supabase/auth` commit
`10ef10789d1ee4fb422b448047e67e3e264c0482` found a material distinction between
ordinary account authentication and the guarantees requested by Marty's default
`prompt=consent login` and `max_age=0` policy:

- The [authorization handler](https://github.com/supabase/auth/blob/10ef10789d1ee4fb422b448047e67e3e264c0482/internal/api/oauthserver/authorize.go)
  does not parse or retain `prompt` or `max_age`. Its authorization-details GET
  can approve an existing consent immediately, returning a callback instead of
  new consent details.
- The [code exchange](https://github.com/supabase/auth/blob/10ef10789d1ee4fb422b448047e67e3e264c0482/internal/api/oauthserver/handlers.go)
  calls `IssueRefreshToken` before generating the ID token. The
  [token service](https://github.com/supabase/auth/blob/10ef10789d1ee4fb422b448047e67e3e264c0482/internal/tokens/service.go)
  sets `user.LastSignInAt` to the current time in that call, then signs it as
  `auth_time`. From this source order, a numerically recent signed `auth_time`
  can describe code exchange rather than the user's last interactive sign-in.
- The OAuth routes use ordinary authenticated-session middleware, without an
  AAL2 requirement. The reviewed ID-token claims have no `aal`, `acr` or `amr`.
  A TOTP check performed by the companion is a requirement of that UI path;
  it is not provider-wide enforcement or signed MFA evidence for Marty.

This is a source-level observation, not a measurement of the selected hosted
project or its deployed version. [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
defines `max_age` using the user's last active authentication. A normal successful
login and a recently signed token therefore cannot establish this guarantee.

The companion requires a new password sign-in and any required enrolled TOTP
before calling the authorization-details endpoint. It uses an isolated
memory-only SDK session, presents new consent explicitly, and labels a reused
consent response separately. These controls improve that browser path; other
callers of the provider API are outside its enforcement boundary. Keep Marty's
default policy and signed-claim validation unchanged.

Hosted qualification must include an older-session negative case: request
`prompt=consent login&max_age=0` using a previously authenticated provider session
and verify that a usable result cannot be obtained without new interaction.
Inspect whether `auth_time` refers to that interaction, and separately verify
whether MFA can be required beyond the companion. Until those behaviors are
established, do not qualify Supabase for provider-enforced fresh authentication
or MFA step-up. Ordinary OIDC identity validation and the PostgreSQL integration
are separate questions.

## Deliberate boundaries

These changes support one selected issuer per installation. They do not
migrate existing Keycloak identities, route one installation among multiple
issuers, synchronize users through SCIM, turn UserInfo into a role mapper,
or add a generic provider-management API. Existing OpenBao/KMS custody,
release admission and normal generation activation remain authoritative.
