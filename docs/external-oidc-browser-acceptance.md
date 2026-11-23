# Real external-OIDC browser acceptance

This operator-assisted companion to [provider qualification](oidc-provider-qualification.md)
exercises a **new login**, rather than importing an existing session. Use a fresh
external-OIDC beta installation and the previously configured provider client.
It does not provision Cloudflare/Supabase, change an installation's issuer, migrate
users, deploy a release, or change organization policy.

## Prerequisites

Run the existing `marty-deploy external-oidc preflight` first. Obtain the exact
authorization endpoint and client ID from that selected provider's configuration.
Keep beta and production clients, callbacks, accounts and evidence separate.

Use a Linux/macOS desktop with Node 24 and the repository's existing
`tests/@playwright/test` dependency and Chromium installation. The desktop browser
connects to the existing development server; no additional cloud infrastructure
or local identity server is required. A headless AWS shell alone cannot display
the manual sign-in window. This runner never attaches to a personal browser or
imports its cookies. Complete passwords, MFA and consent directly in the isolated
test browser; do not put them in CLI arguments, scripts or chat.

The expected Marty user ID and organization ID must already be known from the
selected test account. The runner deliberately refuses to learn an unknown
operator's identity and then treat it as the expected identity. Use the prior
manual qualification procedure for initial administrator bootstrap.

Create an owned private parent directory outside the checkout. The run directory
must not exist. All sample domains and IDs below are illustrative.

```sh
mkdir -m 700 "$HOME/marty-oidc-evidence"
node tests/scripts/run-external-oidc-login.cjs \
  --origin https://beta.example.com \
  --authorization-endpoint https://identity.example.com/authorize \
  --client-id BETA_CLIENT_ID \
  --email operator@example.com \
  --user-id EXPECTED_MARTY_USER_ID \
  --organization-id EXPECTED_ORGANIZATION_ID \
  --source-sha EXACT_40_CHARACTER_LOWERCASE_COMMIT_SHA \
  --output-dir "$HOME/marty-oidc-evidence/beta-login-01"
```

Use Cloudflare's exact SaaS OIDC authorization endpoint for a Cloudflare test,
not a generic self-hosted Access login URL. Do not change shared CRM policies.
`--required-role EXACT_ROLE` optionally asserts an application role from
`/v1/auth/me`; there is no provider-specific role-name assumption.
`--timeout-seconds` defaults to 300 and accepts 30 through 900.

## What a pass means

The runner establishes an explicit anonymous baseline, requires an external
provider, observes Marty's authorization redirect and the actual main-frame
navigation to the configured endpoint, checks the client/callback, code flow,
S256 PKCE, state and nonce, and observes the correlated callback response. It then
requires the exact operator email/user ID and the expected organization in
`/v1/organizations/mine`.

Organization inventory and an optional role assertion do not replace the existing
issuance/authorization acceptance. Token signature, issuer, audience, verified
email and `auth_time` checks remain the deployed Auth service's responsibility.
The browser runner does not inspect raw ID tokens or independently certify those
checks, and it does not claim that observed manual interaction proves MFA.

The runner copies only eligible application cookies into a second isolated
context and verifies that they really authenticate as the same operator. It then
calls **local Marty logout**, checks anonymous status in the original context,
and retries the old cookie in the second context. A pass requires explicit
unauthenticated results in both. A redirect, unavailable API, or invalid JSON is
not treated as successful logout. It does not follow the provider logout URL or
claim that the upstream IdP session was revoked.

A private `receipt.json` records separate gate results. Its configuration digest
binds the origin, endpoint, client, expected email/user/organization, optional role
and declared source SHA. It contains no email, raw tokens, authorization codes,
nonce, state, cookie values, screenshots or page bodies. The source SHA is an
**operator declaration**, not an independently measured deployment identity;
`sourceDeploymentVerified` remains false. Keep release admission evidence alongside
it. MFA, provider logout, issuance, restart and secret rotation remain false until
separately qualified; do not reinterpret this receipt as those checks passing.

Exit status is zero only when the implemented gates pass. Failures emit fixed
stage/error codes, not remote error text. Browser resources close on success and
failure. A failed or completed run is never overwritten.

## Hand off to issuance acceptance

To export an application session for the existing acceptance runner, add:

```sh
--export-session true
```

This first completes the logout/revocation test above, then requires a **second
real login in another empty context** for the same expected operator and
organization. Only that new session is written to `session-export.json`, with mode
0600 under the mode-0700 run directory. Provider cookies, domain-wide cookies,
partitioned cookies and all local storage are excluded. The export is a **live
credential**, not a report: keep it outside Git, do not attach it to a PR, and
remove it after testing. Closing Chromium does not revoke this exported session.

Use it without changing the existing issuance contract:

```sh
node tests/scripts/run-kubernetes-acceptance.cjs \
  --origin https://beta.example.com \
  --issuer-did did:web:beta.example.com:orgs:EXPECTED_ORGANIZATION_ID \
  --storage-state-file "$HOME/marty-oidc-evidence/beta-login-01/session-export.json" \
  --email operator@example.com \
  --user-id EXPECTED_MARTY_USER_ID \
  --organization-id EXPECTED_ORGANIZATION_ID \
  --state-dir "$HOME/marty-oidc-evidence/beta-issuance-01"
```

Supply the deployment's credential-template and scenario arguments as described
in the existing runbook. That command issues synthetic data; the login runner
itself does not issue credentials. After a normal restart, use the existing
`--phase resume`. After client-secret rotation, run a **new** browser qualification
with the same identity configuration before revoking the old remote secret. A
post-rotation login alone does not prove the old secret has been revoked remotely.

## Regression tests and evidence boundaries

```sh
node --test tests/scripts/run-external-oidc-login.test.cjs
```

These deterministic tests require no browser, provider account or credentials.
They cover the actual runner functions using a simulated browser and API, including
failure and cleanup paths. Passing them is **not** live Cloudflare/Supabase
qualification. The existing Kubernetes acceptance CI job runs them alongside the
existing acceptance contracts, without a new workflow or paid infrastructure.


## Separate identity and application origins

Start normal sign-in from the ElevenID application. Its Auth callback creates
an application session and returns the user to the console. The identity
provider's account console manages sign-in methods and provider identity fields;
it is not the application console or the owner of organization membership and
business profile data. Selecting Supabase PostgreSQL does not change those
application responsibilities or select an unqualified OAuth provider.

For the packaged ElevenID Keycloak theme, set public navigation on the Keycloak
container when it has a different origin from the website and API:

| Environment setting | Purpose |
| --- | --- |
| `ELEVENID_AUTH_HOME_URL` | Absolute website destination for Home. An empty value retains the registered client base URL, then the existing `/` fallback. |
| `ELEVENID_CREDENTIAL_LOGIN_URL` | Absolute application credential-login endpoint. The same-origin default remains `/v1/auth/credential-login`. |
| `ELEVENID_CREDENTIAL_LOGIN_ENABLED` | Set `false` while that endpoint is unavailable or not qualified. Hiding it preserves configured social providers and removes an otherwise empty alternative-sign-in section. |

These settings supply navigation only. They do not change registered callbacks,
consent, required MFA, state/nonce/PKCE validation, or the application's session
and authorization checks. Keep the credential option hidden until its actual
application endpoint passes the selected profile's qualification. A custom login
screen must not invent MFA assurance that the selected provider's signed tokens
do not establish.

Verify the rendered Home and credential links from the real public identity
origin. A root-relative link on a separate login host reaches that host; a valid
application path at another origin does not make that link usable. After an
asset update, verify the delivered CSS bytes and cache behavior as well as the
HTML. The provider account console is a diagnostic/security-settings destination,
not a substitute for the installed application callback journey.


The Keycloak adapter gives inherited OTP, information and required-action pages
the same heading/card treatment as the custom forms. For a successful native
information page with an explicit server-provided return URI, it returns to the
matching existing link automatically. This is limited to HTTPS and loopback
HTTP development destinations. An action URI, pending required actions, errors,
`skipLink`, a missing destination or a native/nonsecure remote scheme retains
explicit navigation. The existing return link remains usable without JavaScript.
No return destination is taken from an incoming query parameter, and neither a
first consent decision nor a required-action confirmation is approved implicitly.
