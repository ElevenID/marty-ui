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
2. Select either a public client or a confidential client. Discovery must
   explicitly advertise `none` for a public client, or `client_secret_post` for
   a confidential client. A provider advertising only `client_secret_basic`
   cannot use this adapter.
3. Supply the provider's exact HTTPS issuer and an explicit allowlist of ID-token
   signing algorithms matching its keys. Marty reads
   `ISSUER/.well-known/openid-configuration`, checks the returned issuer, and
   requires HTTPS discovery endpoints. Endpoints on another origin require an
   explicit `trusted_endpoint_origins` entry.
4. Create the initial operator account at the provider. Its email must match
   `admin_email`, and the provider must issue a nonempty subject and email with
   `email_verified: true`. The installer seeds the application administrator
   membership using that email. It does not create the remote account or issue
   a local operator password for this selection.

The existing Auth runtime owns discovery, JWKS, token and login validation. A
valid installer input alone does not prove the provider supports the complete
browser journey. Test login and logout against the selected issuer and client
before relying on a deployment.

Registration and account recovery belong to the external provider. Marty's
external registration entry point requires discovery to advertise `prompt=create`;
otherwise use the provider's own registration flow. Provider-wide logout is
available only when discovery supplies a supported `end_session_endpoint`.
Marty's local session logout remains separate. Managed Keycloak account and
passkey-enrollment actions are unavailable for external OIDC.

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
derived Compose sessions. A changed or missing retained selection or imported
secret fails validation. Ordinary `start` uses the selected external provider
and continues to require healthy managed OpenBao; it does not recreate Keycloak.
Do not edit retained records, generated environment files or secret generations
to change the issuer, client or provider. Existing installed provider selections
and user identities require a separately designed migration.

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
