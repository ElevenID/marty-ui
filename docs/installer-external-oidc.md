# External OIDC with managed OpenBao

For a fresh installation, `--external-oidc-file ABSOLUTE_PATH` selects an existing
external OpenID Connect provider for Marty login while retaining managed
OpenBao for application signing, workload TLS and key custody. The installer
omits the Keycloak server and configurator, reducing the services that the
installation host must run. Managed Keycloak remains the default when this
option is absent.

Login, key custody and public hosting have separate inputs:

| Selection | Input |
| --- | --- |
| Managed Keycloak and managed OpenBao | Default; omit both provider-selection files. |
| External OIDC and managed OpenBao | `--external-oidc-file` with the configuration below. |
| External OIDC and preprovisioned AWS KMS | Existing `--foundation-file`; see [AWS foundation](compose-installer.md#preprovisioned-aws-foundation). |
| Canonical public URL, listener, certificates and optional Cloudflare Tunnel | Existing `--hosting-file`; see [Cloudflare hosting](hosting-cloudflare-addon.md). |
| Supported application policy | Existing `--settings-file`; see [application settings](installer-application-settings.md). |
| External PostgreSQL with external OIDC and managed OpenBao | Optional `--external-postgres-file`; see [external PostgreSQL](installer-external-postgres.md). |

`--external-oidc-file` and `--foundation-file` are mutually exclusive: the AWS
foundation already owns its external OIDC selection. The independent option
requires no AWS resources or cloud KMS account. It uses the provider and client
that the operator has already configured; provider account creation, service
plans and DNS configuration remain separately operated.

## Provider prerequisites

Configure the external provider before installation:

1. Register an authorization-code client that supports S256 PKCE. Its redirect
   URI must be the canonical hosting origin followed by `/v1/auth/callback`, for
   example `https://beta.example.com/v1/auth/callback`.
2. Select a public client (`client_auth_method: "none"`) or a confidential client
   (`"client_secret_post"` or `"client_secret_basic"`). Discovery must support the
   selected method. When the standard `token_endpoint_auth_methods_supported`
   field is absent, the OIDC default is `client_secret_basic`; a public or POST
   client therefore requires an explicit matching advertisement. Omitting the
   installer option retains the existing choice: `none` without a client-secret
   file, and `client_secret_post` with one.
3. Supply the provider's exact HTTPS issuer and an explicit allowlist of ID-token
   signing algorithms matching its keys. Marty reads
   `ISSUER/.well-known/openid-configuration`, checks the returned issuer, and
   requires HTTPS discovery endpoints. Endpoints on another origin require an
   explicit `trusted_endpoint_origins` entry.
4. Create the initial operator account at the provider. Its email must match
   `admin_email`, and the provider must issue a nonempty subject and email with
   `email_verified: true`. By default these claims must be in the signed ID
   token. The optional UserInfo fallback described below can supply missing
   identity fields after token validation and an exact subject match. The installer seeds the application administrator
   membership using that email. It does not create the remote account or issue
   a local operator password for this selection.

The existing Auth runtime owns discovery, JWKS, token and login validation. A
valid installer input alone does not prove the provider supports the complete
browser journey. Test login and logout against the selected issuer and client
before relying on a deployment.

### Discovery compatibility and account lifecycle

If discovery includes `id_token_signing_alg_values_supported`, Auth requires a
well-formed list with at least one signed algorithm from the configured
`allowed_algorithms`. An empty list or a list with no overlap fails provider
readiness before a code or client secret is sent to the token endpoint.
Discovery does not add algorithms to the configured token policy. The adapter
preserves its existing behavior when this metadata field is absent; token
signature, issuer, audience and nonce validation still apply.

The pinned token validator supports `RS256`, `RS384`, `RS512`, `ES256`, `ES384`,
`PS256`, `PS384`, `PS512` and `EdDSA` signatures. `ES512` is not supported. Its
access-token hash (`at_hash`) verification covers these same algorithms,
including SHA-384 for `RS384`/`PS384` and SHA-512 for `RS512`/`PS512`. A supplied
hash must match the returned access token. Select and test the actual algorithm
and claims issued by the provider; this support does not qualify a provider's
complete browser flow.

Auth defaults to the `openid profile email` scopes. A provider may omit supported
scopes from `scopes_supported`, as described in
[OpenID Connect Discovery section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
The adapter therefore does not infer that a requested scope is unsupported just
because it is absent from that list. The selected provider must include a
nonempty `sub` and `email`, with `email_verified: true`, in the signed ID token
under the default `userinfo_mode: "disabled"`. Set `userinfo_mode: "fallback"`
only when the provider supplies required email/profile claims through UserInfo.
Auth first validates the signed ID token, then uses the returned access token at
the trusted discovered UserInfo endpoint when identity fields are missing. The
UserInfo `sub` must match the ID-token subject exactly; contradictory or
unverified identity claims still fail. UserInfo cannot replace token signature,
issuer, audience, nonce or access-token-hash validation.

The external provider owns registration, recovery, MFA and account presentation:

- Marty's `/v1/auth/register` flow requires discovery to advertise `create` in
  `prompt_values_supported`. Without that capability, create accounts through
  the provider and use normal login. A discovery `registration_endpoint` is for
  registering OAuth clients, not for registering people.
- The Keycloak account console and native Keycloak passkey-enrollment actions
  are unavailable with external OIDC. Use the provider's account-management
  features for those operations.
- Logout ends the local Marty session. When discovery supplies an
  `end_session_endpoint`, Marty also redirects the browser there. Without that
  endpoint, the provider's browser session can remain active. Normal login
  defaults to `prompt=consent login` and `max_age=0`; the typed options below can
  narrow or omit these parameters. Qualify the provider's actual
  browser behavior rather than treating those parameters as proof of a new
  authentication event.

## Private configuration

Store the JSON and any referenced client-secret file outside the source checkout,
using absolute paths. Files must be owned regular files with mode `0600`, with
one link and no symlinks, under owned private directories with mode `0700`.
Duplicate and unknown JSON fields are rejected. Supply real provider values in
place of the illustrative identifiers below.

### Public client

For a provider client configured with token-endpoint authentication method
`none`, omit `client_secret_file`:

```json
{
  "schema": "elevenid.installer-external-oidc/v1",
  "external_oidc": {
    "issuer_url": "https://identity.example.invalid/auth/v1",
    "client_id": "marty-beta",
    "admin_email": "operator@example.com",
    "allowed_algorithms": ["ES256"]
  }
}
```

Choose the algorithm actually used by the provider; `ES256` is an example.
The installer retains an empty private secret placeholder for this public-client
selection and leaves the Auth secret-file setting empty. S256 PKCE still applies.

### Confidential client

For token-endpoint authentication method `client_secret_post`, reference the
private file containing the provider-issued client secret:

```json
{
  "schema": "elevenid.installer-external-oidc/v1",
  "external_oidc": {
    "issuer_url": "https://identity.example.invalid/tenant",
    "client_id": "marty-production",
    "admin_email": "operator@example.com",
    "client_secret_file": "/home/tester/marty-input/production/oidc-client-secret",
    "allowed_algorithms": ["RS256"],
    "trusted_endpoint_origins": ["https://login.example.invalid"]
  }
}
```

Put the secret bytes only in the referenced file. The JSON contains its path;
command-line arguments, application settings and public environment values must
not contain the secret. The installer imports the file into its private
installation and verifies its retained content during later operations.

`trusted_endpoint_origins` is optional and defaults to an empty list. Include an
entry only when discovery uses an endpoint on that separate origin. Each entry
must be an exact HTTPS origin without a path, query, fragment or trailing slash;
at most eight distinct origins are accepted. This list authorizes discovery
endpoint locations, not additional application callback URLs.

### Optional scopes

`external_oidc.scopes` optionally selects the scopes requested at authorization,
for example `["openid", "email"]` when the provider supplies the required claims
with that narrower set. Omit it to retain `openid`, `profile` and `email`. The
same optional field is supported within the existing AWS foundation's
`external_oidc` object.

An explicit list must include `openid` and contain at most 32 distinct,
case-sensitive scope tokens. Each token must be 1–128 printable ASCII characters
with no whitespace, double quotes, backslashes, commas or apostrophes; the
comma-joined list is limited to 2,048 bytes. Provider-specific tokens such as
`urn:example:groups` are allowed when configured at that provider. The character
restrictions preserve the existing environment-file transport. The provider
must still issue the verified email and subject needed for membership, even
when the chosen scope list differs from the default.

The selected list is retained with the installation and checked against the
resolved Auth configuration. Existing selections that omit this field keep
their original default behavior. Supply scopes through this input file rather
than editing generated environments or retained selection records.

### Optional provider compatibility and account links

These fields belong inside `external_oidc` in either the independent OIDC file
or the existing AWS foundation file. They are optional; omitting them preserves
old serialized selections and runtime defaults.

| Native field | Allowed value and default |
| --- | --- |
| `client_auth_method` | `none`, `client_secret_post`, or `client_secret_basic`. Default derives from absence/presence of `client_secret_file`. `none` refuses a secret file; both confidential methods require one. |
| `userinfo_mode` | `disabled` (default) or `fallback`. Fallback requires a trusted discovered UserInfo endpoint and matching `sub`. |
| `prompt` | A distinct list drawn from `login`, `consent`, `select_account`, `none`. Omitted defaults to `["consent", "login"]`; `[]` omits the parameter. `none` must be the only item. Registration uses its own discovered `create` capability. |
| `max_age` | An integer from `0` through `86400`, or the string `"omit"`. Omitted retains `0`. |
| `provider_name` | Optional display name, trimmed and at most 80 UTF-8 bytes, without controls. It changes the provider label, not the hosted login page's theme. |
| `account_url`, `recovery_url` | Optional fixed HTTPS links on the issuer origin or an explicit `trusted_endpoint_origins` origin. Queries/fragments are allowed; credentials and wildcard hosts are refused. These links do not implement account recovery or account-management APIs. |

The native environment-file transport also excludes apostrophes and backslashes
from display names and links. URL-encode those characters in links. These input
choices are retained with the provider selection and are not a configuration
migration mechanism for an existing installation.

For example, a confidential provider that requires HTTP Basic authentication,
returns email through UserInfo, and does not accept forced consent can use:

```json
{
  "schema": "elevenid.installer-external-oidc/v1",
  "external_oidc": {
    "issuer_url": "https://identity.example.test/tenant",
    "client_id": "marty-beta",
    "admin_email": "operator@example.test",
    "client_secret_file": "/home/tester/marty-input/beta/oidc-client-secret",
    "allowed_algorithms": ["RS256"],
    "client_auth_method": "client_secret_basic",
    "userinfo_mode": "fallback",
    "scopes": ["openid", "email", "profile"],
    "prompt": [],
    "max_age": "omit",
    "provider_name": "Example Identity",
    "account_url": "https://identity.example.test/account",
    "recovery_url": "https://identity.example.test/recover"
  }
}
```

Select these options from the provider's actual requirements. Do not enable
UserInfo or change authentication prompts merely because another provider uses
them. Custom themes remain configured in the identity provider's login UI.

## Read-only provider compatibility check

Fresh native installations run Auth's discovery and public-key preflight after
release/image admission and before local credential generation or OpenBao and
application startup. The installer uses the selected, pinned services image in
an isolated read-only container, bypasses the normal service entrypoint, and
passes only OIDC configuration. It neither mounts nor sends customer secrets,
starts a database, creates provider accounts, nor exchanges an authorization
code. The probe can populate the local image cache and writes private probe
evidence; its completed container is removed.

For an installed stack, use the retained operator and selected Auth image:

```bash
"$INSTALL_DIR/marty-deploy" external-oidc preflight \
  --install-dir "$INSTALL_DIR" \
  --docker-bin /usr/bin/docker
```

To check a provider before creating an installation directory, use the services
image from an independently verified release inventory. This standalone command
does not verify an arbitrary image's signature for you. Create a private env file
containing provider settings only; an actual client secret is unnecessary:

```dotenv
OIDC_PROVIDER_MODE=external
OIDC_ISSUER_URL=https://identity.example.test/tenant
OIDC_CLIENT_ID=marty-beta
OIDC_ALLOWED_ALGORITHMS=RS256
OIDC_TOKEN_ENDPOINT_AUTH_METHOD=client_secret_basic
OIDC_USERINFO_MODE=fallback
OIDC_PROMPT=
OIDC_MAX_AGE_SECONDS=omit
OIDC_SCOPES=openid,email,profile
```

```bash
chmod 600 /home/tester/marty-input/beta/oidc-preflight.env
# SERVICES_IMAGE is the verified ghcr.io/elevenid/marty-ui-oss/services@sha256:... reference.
docker --host "unix:///run/user/$(id -u)/docker.sock" run --rm \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=32 --memory=128m --cpus=0.5 --user=65532:65532 \
  --network=bridge --log-driver=none \
  --entrypoint=/usr/local/bin/marty-auth \
  --env-file /home/tester/marty-input/beta/oidc-preflight.env \
  "$SERVICES_IMAGE" oidc-preflight
```

The Auth report uses `elevenid.oidc-provider-preflight/v1` and reports
`metadata_compatible` only after trusted discovery, the selected client method,
well-formed discovery metadata, and compatible public signing keys pass. It also
reports discovered registration/logout capabilities. This is a metadata check:
it does not test the real client secret, callback registration, browser cookies,
the provider's prompt/session behavior, returned user claims, administrator
membership, or a complete login/logout.
Qualify those with the actual beta deployment before production.
See [provider recipes and qualification status](oidc-provider-qualification.md)
for the Cloudflare metadata check, current live-test limits, and the separate
beta/production rollout checklist.

## Install with the existing hosting selection

Use the signed installer and the normal admitted release selector:

```sh
/usr/bin/setpriv --no-new-privs -- sh /absolute/install.sh \
  --version EXACT_ADMITTED_RELEASE_TAG \
  --install-dir /home/tester/marty-installations/beta \
  --hosting-file /home/tester/marty-input/beta/hosting.json \
  --external-oidc-file /home/tester/marty-input/beta/oidc.json \
  --settings-file /home/tester/marty-input/beta/application.json
```

Omit `--settings-file` when no application-policy override is needed. The existing
`--channel nightly|stable` or signed `--candidate-test EXACT_SIGNED_NIGHTLY_TAG`
selection can replace `--version`; the selected release's admission rules still
apply. The release must contain this option and its authenticated Compose layer.

For Cloudflare Tunnel, use the existing `external-proxy` hosting configuration
and optional signed connector described in [Cloudflare hosting](hosting-cloudflare-addon.md).
That hosting file determines Marty's canonical browser URL and callback identity.
The OIDC file independently identifies the login provider. Cloudflare routing
does not change the provider's issuer or provision its OAuth client.

Managed `KEYCLOAK_*` settings, Google login credentials, Keycloak SMTP credentials,
and enabled Keycloak-admin-dependent credential-login policies are rejected with
external OIDC. Configure the external provider's registration, email, social
login and account presentation through that provider. Application policies such
as organization creation retain their existing typed settings interface.

## Separate beta and production

Use separate installations, provider projects or tenants, client registrations
and private inputs. Each installation has its own retained selection and Compose
project. A shared frontend can use the same application design while its
deployment selects the appropriate provider and callback.

| Input | Beta example | Production example |
| --- | --- | --- |
| Canonical hosting origin | `https://beta.example.com` | `https://app.example.com` |
| Registered callback | `https://beta.example.com/v1/auth/callback` | `https://app.example.com/v1/auth/callback` |
| Provider project or tenant | Dedicated beta project | Dedicated production project |
| Client registration | `marty-beta` | `marty-production` |
| Private input directory | `/home/tester/marty-input/beta` | `/home/tester/marty-input/production` |
| Installation directory | `/home/tester/marty-installations/beta` | `/home/tester/marty-installations/production` |

Provide each project's actual issuer in its OIDC file and register only that
installation's approved callback URLs. When both installations share a host,
their hosting files must use distinct local listener ports. Keep provider
secrets and any Cloudflare connector tokens separate.

## Retained lifecycle and qualification limits

The selection is bound to the fresh installation's journal, private evidence and
derived Compose sessions. A changed or missing retained selection or an
unrecorded secret replacement fails validation. Ordinary `start` uses the selected external provider
and continues to require healthy managed OpenBao; it does not recreate Keycloak.
Do not edit retained records, generated environment files or secret generations
to change the issuer, client or provider. Existing installed provider selections
and user identities require a separately designed migration.

### Replace a confidential client secret

An existing independent external-OIDC installation with managed OpenBao can
replace a confidential client secret while keeping the same issuer, client,
administrator and provider options. Public clients and imported AWS foundations
do not use this native operation. The installed lifecycle must be running; an
unrelated pending credential generation, operator upgrade or root-retirement
operation must finish first.

1. Create the replacement for the **same registered client** at the provider.
   Where the provider supports overlapping secrets, retain the old secret until
   the new deployment passes a real login. Store the replacement in an owned
   absolute regular file, mode `0600`, under a private `0700` directory. The
   existing immutable credential transport accepts nonempty ASCII text up to
   65,536 bytes, without NUL bytes or private-key material.
2. Run the retained operator:

   ```bash
   "$INSTALL_DIR/marty-deploy" external-oidc rotate-secret \
     --install-dir "$INSTALL_DIR" \
     --client-secret-file /home/tester/marty-input/beta/oidc-client-secret-next \
     --docker-bin /usr/bin/docker
   ```

3. Complete a real login and verify the expected operator account before
   revoking the provider's old secret. Metadata preflight and service readiness
   cannot prove that the provider accepts a new credential.

The command retains a private immutable replacement request bound to the
original provider-selection digest, the previous generation, and the new secret
fingerprint. It runs the existing full OpenBao credential renewal and native
generation activation, including normal workload replacement and readiness
validation. This can restart affected application services; it is not an
in-place file edit. Original provider records, prior secrets, custody receipts
and generation evidence remain intact. The result reports activation and the
readiness observation separately from browser-login qualification.

If interrupted, rerun the same command with the same replacement file. The
retained generation engine reconciles the same request and any interrupted
producer/activation; it never overwrites an immutable request with different
secret bytes. Preserve evidence on failure. Editing `secrets/`, an existing
`application-generation` directory, or the original provider-selection JSON is
unsupported. To return to a provider credential that remains valid, complete
the current operation and submit that credential as a subsequent replacement.

The current managed generation and renewal contracts retain the existing
one-shot OpenBao custody helper named `installer-keycloak`, its honest setup
receipt, and currently unused renewable custody data. This helper uses the
OpenBao setup path. The Keycloak server and configurator are absent from the
selected application model. Workload TLS, credential signing and renewal keep
their existing OpenBao owners and validation boundaries.

Source tests cover selection validation, private input retention and native
Compose composition. They do not establish a live Supabase or Cloudflare OIDC
integration, a completed browser login, or production capacity. Complete the
selected provider's login, logout, operator membership and applicable
registration/recovery checks, together with the installation's existing
issue/present/verify/revoke and restart acceptance, before claiming that
deployment is qualified.
