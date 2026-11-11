# Native installer application settings

The signed Linux installer accepts an optional `--settings-file ABSOLUTE_PATH`
for a **fresh installation**. The same input works with signed nightly candidate
testing and admitted nightly/stable installation. Managed OpenBao remains the
default foundation. The selected release's admission and qualification rules
still apply; accepting a settings file does not grant production readiness.

The installer retains a closed, typed application policy before provisioning.
It does not import an arbitrary environment file. The canonical origin, generated
identities, runtime paths, image digests, private ports and key custody remain
with their existing installer owners.

## Registration and email defaults

Managed Keycloak self-registration defaults to **enabled**, matching the bundled
realm and production example. The previous native renderer forced it off; that
override hid the register link even though the login theme contained it.
Explicit `KEYCLOAK_USER_REGISTRATION_ENABLED: false` remains supported.

Email verification and password reset default to disabled until an operator
supplies real Keycloak SMTP configuration and explicitly enables the desired
features. Google login and external integrations remain opt-in. Organization
creation defaults to `false`, matching `.env.selfhost.production.example`;
`ORGANIZATION_CREATION_ENABLED: true` enables the supported backend policy and
its UI runtime flag together.

Keycloak SMTP supplies **Keycloak registration-verification and password-reset
email**. It does not enable application notification email. The native
notification worker currently returns `EMAIL_ADAPTER_UNAVAILABLE` for email
delivery; its legacy `SMTP_*` environment fields are not a functioning adapter.
The settings input therefore rejects `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`
and raw SMTP passwords as application settings. Webhook notification delivery
has a separate existing implementation.

## Input format

Place the settings JSON and each referenced credential in a directory owned by
the installing user with mode `0700`. Each file must be an ordinary, singly
linked file with mode `0600`; symlinks, unsafe paths and oversized files are
refused. Paths must be absolute. JSON is bounded to 65,536 bytes and rejects
duplicate or unknown fields. Values use JSON booleans, integers, strings, arrays
or the specifically documented public JSON objects. Boolean strings such as
`"true"` are refused. Public string values use bounded ASCII without control
characters, single quotes or backslashes.

For example, a policy that permits organization creation and configures
authenticated Keycloak email has this shape:

```json
{
  "schema": "elevenid.installer-application-settings/v1",
  "values": {
    "ORGANIZATION_CREATION_ENABLED": true,
    "KEYCLOAK_USER_REGISTRATION_ENABLED": true,
    "KEYCLOAK_VERIFY_EMAIL": true,
    "KEYCLOAK_RESET_PASSWORD_ENABLED": true,
    "KEYCLOAK_SMTP_HOST": "smtp.mail.example.net",
    "KEYCLOAK_SMTP_PORT": 587,
    "KEYCLOAK_SMTP_FROM": "noreply@example.net",
    "KEYCLOAK_SMTP_FROM_DISPLAY_NAME": "Example Identity",
    "KEYCLOAK_SMTP_USERNAME": "identity-mailer",
    "KEYCLOAK_SMTP_SSL": false,
    "KEYCLOAK_SMTP_STARTTLS": true
  },
  "secret_files": {
    "smtp_password": "/home/tester/marty-input/smtp-password"
  }
}
```

Supply the actual provider settings and credential file before using that
example. For a registration-only installation, omit the file or use the same
schema with empty `values` and `secret_files` objects. The installer does not
invent an email service or provider credential.

Add the selection to the usual reviewed command:

```sh
/usr/bin/setpriv --no-new-privs -- sh /absolute/install.sh \
  --candidate-test EXACT_SIGNED_NIGHTLY_TAG \
  --hosting-file /home/tester/marty-input/hosting.json \
  --settings-file /home/tester/marty-input/application.json
```

For admitted installation, the existing `--channel` or `--version` selector
replaces `--candidate-test`. Do not edit a retained installation's environment,
settings records or secret files to change policy. This input is not an in-place
configuration migration or credential-rotation command.

## What was suppressed, and who owns it now

The former renderer forced the following fifteen values to `false` and fifteen
to an empty string. Their treatment is now explicit rather than accidental.

| Former forced value | Current ownership and behavior |
| --- | --- |
| `KEYCLOAK_USER_REGISTRATION_ENABLED=false` | Typed boolean, default `true`; controls managed realm registration. |
| `KEYCLOAK_VERIFY_EMAIL=false`, `KEYCLOAK_RESET_PASSWORD_ENABLED=false` | Typed booleans, default `false`; enabling either requires complete Keycloak SMTP. |
| `KEYCLOAK_SOCIAL_LOGIN_ENABLED=false` | Typed boolean, default `false`; enabling requires both Google credential files. |
| `KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED=false` | Typed boolean, default `false`; requested enablement configures the Keycloak organization realm feature and browser-flow execution. This is separate from ElevenID organization creation. |
| `KEYCLOAK_PASSKEYS_ENABLED`, `KEYCLOAK_PASSKEY_RP_ID` | Optional boolean and lowercase RP hostname. Omission preserves policy; enabling requires the explicit RP ID and qualified Keycloak 26.8.x. Password, Google and Open Badge remain available. See [passkey setup](keycloak-passkeys.md). |
| `KEYCLOAK_SMTP_SSL=false`, `KEYCLOAK_SMTP_STARTTLS=false` | Explicit SMTP transport booleans; defaults are SSL `false`, STARTTLS `true`. Configured mail requires exactly one secure transport. |
| `ORGANIZATION_CREATION_ENABLED=false` | Typed boolean, default `false`, shared by backend and UI. |
| `CANVAS_PORTABLE_INTEGRATION_ENABLED=false` | Opt-in with explicit pilot organizations, tool-signing identity, public RS256 JWKS, credential issuer-profile inventory, real API provider and reviewed worker timeout. |
| `CANVAS_MIRROR_WORKER_ENABLED=false` | Opt-in with organization, API token, real provider, API URL and issuer/badge identity. |
| `CANVAS_ALLOW_PRIVATE_BASE_URLS=false` | Opt-in only with an explicit exact HTTPS origin allowlist. |
| `CANVAS_LEGACY_EVENT_INGEST_ENABLED=false` | Remains false: the portable production path forbids legacy event ingestion. |
| `CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS=false` | Remains false: HTTP localhost providers are a development exception. |
| `DID_PUBLIC_FALLBACK_ENABLED=false` | Opt-in with an explicit `DID_WEB_ALLOWED_HOSTS` array. |
| `DIDCOMM_ALLOW_PRIVATE_ENDPOINTS=false` | Historical unused name; accepted only as `false`. Actual `DIDCOMM_ALLOW_PRIVATE_IPS` remains a fixed false production policy. |
| `UI_ADDITIONAL_BASE_URLS=` | Typed exact HTTPS-origin array. Extends browser origin policy without changing the canonical issuer identity. The operator must separately own DNS, routing and certificates for additional frontends. |
| `KEYCLOAK_SMTP_HOST=`, `KEYCLOAK_SMTP_USERNAME=` | Typed mail configuration; host, sender, secure transport and matching authentication inputs are validated together. |
| `SMTP_HOST=`, `SMTP_USERNAME=` | Unimplemented application-email transport; not offered as a working capability. |
| `CANVAS_CREDENTIALS_API_BASE_URL=` | Typed HTTPS URL. Its effective existing default is `https://api.badgr.io`; the previous empty value was also replaced by Compose's `:-` default. |
| `CANVAS_CREDENTIALS_PUBLISH_URL=`, `CANVAS_CREDENTIALS_STATUS_SYNC_URL=` | Optional explicit HTTPS provider endpoints. |
| `CANVAS_CREDENTIALS_ISSUER_ID=`, `CANVAS_CREDENTIALS_BADGECLASS_ID=` | Typed provider identifiers. |
| `CANVAS_PILOT_ORGANIZATION_IDS=` | Typed unique identifier array; required for the portable integration. |
| `CANVAS_PRIVATE_ORIGIN_ALLOWLIST=`, `CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST=` | Typed unique exact HTTPS-origin arrays. |
| `UNIVERSAL_RESOLVER_URL=` | Optional explicit HTTPS resolver URL; no network fallback is enabled by default. |
| `DID_WEB_ALLOWED_HOSTS=` | Typed unique normalized hostname array; required for public DID fallback. |

## Complete supported value registry

Keys below use their existing environment names. This registry also covers
supported settings that previously existed in Compose or the production
example but had no native-installer input surface. Omitted values retain the
reviewed production/Compose default unless a default is stated above.

An **identifier** is a nonempty string of at most 128 ASCII letters, digits,
periods, underscores, colons or hyphens. Existing named identifiers and UUIDs
are both supported. Arrays are unique, limited to 128 entries and serialized
to the existing comma-separated runtime format. URLs must use HTTPS, contain
no user-info or fragment, and fit within 2,048 bytes. Exact origins have no
path, query or trailing slash. Provider configuration and referenced
organizations/profiles still require their existing live readiness checks;
configuration acceptance is not proof of credentials or remote availability.

| Keys | Input type and constraints |
| --- | --- |
| `KEYCLOAK_USER_REGISTRATION_ENABLED`, `KEYCLOAK_VERIFY_EMAIL`, `KEYCLOAK_RESET_PASSWORD_ENABLED`, `KEYCLOAK_SOCIAL_LOGIN_ENABLED`, `KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED`, `KEYCLOAK_SMTP_SSL`, `KEYCLOAK_SMTP_STARTTLS` | Booleans; dependencies described above. |
| `KEYCLOAK_SMTP_HOST` | Normalized lowercase mail hostname. |
| `KEYCLOAK_SMTP_PORT` | Integer 1–65,535; default 587. |
| `KEYCLOAK_SMTP_FROM` | Sender email address; explicitly required when SMTP is configured. With mail disabled, the renderer uses `noreply@` the canonical host. |
| `KEYCLOAK_SMTP_USERNAME`, `KEYCLOAK_SMTP_FROM_DISPLAY_NAME`, `MARTY_ORG_NAME` | Strings up to 256 bytes. Organization display name does not change its generated ID, slug or operator identity. |
| `ORGANIZATION_CREATION_ENABLED`, `CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER`, `CREDENTIAL_LOGIN_CREATE_USERS` | Booleans. Credential-login policy is independent of Keycloak self-registration. The two Keycloak-admin-dependent credential-login choices are refused for external OIDC. |
| `CREDENTIAL_LOGIN_POLICY_ID`, `CREDENTIAL_LOGIN_TRUST_PROFILE_ID`, `MARTY_DEFAULT_REVOCATION_PROFILE_ID` | Existing identifiers; changing these does not create the referenced policy or profile. |
| `UI_ADDITIONAL_BASE_URLS` | Array of exact HTTPS origins. Canonical origin remains unchanged. |
| `COOKIE_SAMESITE` | `lax`, `strict` or `none`; existing default `lax`. |
| `RATE_LIMIT_RPM` | Integer 1–1,000,000; existing default 300. |
| `ISSUANCE_OFFER_TTL_MINUTES`, `ISSUANCE_AUTH_SESSION_TTL_MINUTES` | Integers 1–525,600; existing defaults 10,080 and 60. |
| `ALLOWED_REDIRECT_URIS` | Array of explicit HTTPS redirect URLs. |
| `CREDENTIAL_LOGIN_LISSI_DEEP_LINK_TEMPLATE`, `CREDENTIAL_LOGIN_LISSI_ANDROID_DEEP_LINK_TEMPLATE`, `CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE`, `CREDENTIAL_LOGIN_LISSI_IOS_UNIVERSAL_LINK_TEMPLATE` | Wallet link template strings up to 4,096 bytes; `{oid4vp_uri}`, HTTPS or the supported wallet/intent schemes. |
| `CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE`, `CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE`, `CREDENTIAL_LOGIN_SPRUCEKIT_IOS_DEEP_LINK_TEMPLATE`, `CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE` | Same wallet-template rules. |
| `CREDENTIAL_LOGIN_LISSI_ANDROID_PACKAGE`, `CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE` | Dotted Android package names up to 256 bytes. |
| `CANVAS_PORTABLE_INTEGRATION_ENABLED`, `CANVAS_MIRROR_WORKER_ENABLED`, `CANVAS_ALLOW_PRIVATE_BASE_URLS`, `CANVAS_CREDENTIALS_RECIPIENT_HASHED`, `CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS`, `CANVAS_MIRROR_WORKER_RETRY_FAILED`, `CANVAS_MIRROR_WORKER_RUN_ON_STARTUP` | Booleans with the dependency requirements above. |
| `CANVAS_CREDENTIALS_PROVIDER` | `bridge`, `badgr_api` or `canvas_credentials_api`. Enabled production portable/mirror modes require a real API provider. |
| `CANVAS_CREDENTIALS_ASSERTION_SCOPE` | `badgeclasses` or `issuers`. |
| `CANVAS_CREDENTIALS_ISSUER_ID`, `CANVAS_CREDENTIALS_BADGECLASS_ID`, `CANVAS_MIRROR_WORKER_ORGANIZATION_ID`, `CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID` | Existing identifiers. |
| `CANVAS_PILOT_ORGANIZATION_IDS`, `CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS` | Arrays of existing identifiers. |
| `CANVAS_CREDENTIALS_API_BASE_URL`, `CANVAS_CREDENTIALS_PUBLISH_URL`, `CANVAS_CREDENTIALS_STATUS_SYNC_URL`, `CANVAS_CREDENTIALS_PROVENANCE_BASE_URL`, `CANVAS_LTI_EXPERIENCE_BASE_URL`, `CANVAS_OAUTH_COMPLETION_REDIRECT_URL`, `CANVAS_MIRROR_ALERT_WEBHOOK_URL` | Explicit HTTPS URLs. Unspecified LTI experience and OAuth completion URLs follow the generated canonical frontend instead of an example hostname. |
| `CANVAS_PRIVATE_ORIGIN_ALLOWLIST`, `CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST`, `CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST` | Arrays of exact HTTPS origins. |
| `CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE`, `MIP_CREDENTIAL_STATUS_URL_TEMPLATE` | HTTPS URL templates for the existing runtime substitution contract. |
| `CANVAS_CREDENTIALS_ASSERTION_NARRATIVE` | String up to 2,048 bytes. |
| `CANVAS_LTI_TOOL_ISSUER_DID`, `CANVAS_LTI_TOOL_ACTIVE_KID` | DID/verification-method strings up to 2,048 bytes. The active key must belong to the supplied tool DID. |
| `CANVAS_LTI_TOOL_PUBLIC_JWKS` | Public JSON object with 1–16 RSA/RS256 keys, unique `kid`, public `n`/`e`, optional `use: "sig"`, and no private parameters. Moduli are 2,048–8,192 bits; exponent is 3 or 65,537. The active key must appear in this set. |
| `CANVAS_BINDING_READINESS_MAX_AGE_SECONDS`, `CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS`, `CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS`, `CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS`, `CANVAS_SYNC_WORKER_LEASE_SECONDS`, `CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS`, `CANVAS_SYNC_WORKER_POLL_SECONDS` | Integers 1–86,400. Portable production Canvas requires a job timeout of exactly 600 seconds. |
| `CANVAS_MIRROR_WORKER_BATCH_LIMIT`, `CANVAS_MIRROR_FAILURE_WARNING_ATTEMPTS`, `CANVAS_MIRROR_FAILURE_CRITICAL_ATTEMPTS`, `CANVAS_BACKGROUND_ROSTER_BATCH_SIZE`, `CANVAS_BACKGROUND_ROSTER_MAX_SIZE`, `CANVAS_SYNC_WORKER_BATCH_SIZE`, `CANVAS_SYNC_SCHEDULE_LIMIT`, `CANVAS_OAUTH_REVOCATION_BATCH_SIZE` | Integers 1–1,000,000. |
| `CANVAS_MIRROR_ALERT_WEBHOOK_TIMEOUT_SECONDS` | Integer 1–20. |
| `DID_PUBLIC_FALLBACK_ENABLED`, `DID_WEB_ALLOWED_HOSTS`, `UNIVERSAL_RESOLVER_URL` | Boolean, hostname array and optional HTTPS URL respectively. No public fallback without an explicit hostname allowlist. |
| `PASSPORT_NATIVE_HTTP_ENABLED`, `PASSPORT_NATIVE_GATEWAY_ENABLED`, `PASSPORT_NATIVE_FLOW_ENABLED`, `PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED`, `PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED`, `PASSPORT_KMS_ARTIFACTS_ENABLED`, `PASSPORT_KMS_CALLBACKS_ENABLED` | Booleans. Gateway/Flow/signing/KMS choices require native Passport HTTP. Passport requires either the imported tenant keyring or internal service authentication; those modes are mutually exclusive. The installer-generated internal service token remains with its existing owner. |
| `PERSONALIZATION_BUREAU_URL`, `PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID` | HTTPS provider URL and existing identifier. Configured bureau submission requires native Passport, the imported bureau API key and a callback profile when KMS callbacks are enabled. |
| `APPLICATION_TEMPLATE_MIGRATION_MAP` | JSON object of existing source template identifiers to destination identifiers, at most 128 entries. This does not change the installation's migration profile or authorize an in-place installation upgrade. |
| `LOG_LEVEL` | `TRACE`, `DEBUG`, `INFO`, `WARN` or `ERROR`. |
| `COMPLIANCE_PROFILE_RUST_LOG`, `DEPLOYMENT_PROFILE_RUST_LOG`, `REVOCATION_PROFILE_RUST_LOG` | Existing Rust log-filter strings up to 1,024 bytes. |
| `CANVAS_LEGACY_EVENT_INGEST_ENABLED`, `CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS`, `DIDCOMM_ALLOW_PRIVATE_ENDPOINTS`, `DIDCOMM_ALLOW_PRIVATE_IPS`, `PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED` | Accepted only as `false`; see the explicit unsupported combinations below. |

For a fresh installation, `MARTY_ORG_NAME` reaches the managed identity
configurator, Organization bootstrap and Auth through the same canonical Compose
environment. It does not rename an existing organization or change the retained
organization ID, issuer DID or slug.

## Credential files and lifecycle custody

Only these names are accepted in `secret_files`. Secret contents never belong
in `values`, command-line arguments, generated public environment values or
diagnostic receipts. Each import is bounded to 65,536 bytes, ASCII, contains no
NUL/private-key material, and must not use a placeholder value. Scalar files
may end with a newline. The tenant keyring uses its existing JSON parser,
including duplicate-organization, duplicate-key and key-strength rejection.

| Secret name | Consumer and requirement |
| --- | --- |
| `google_client_id`, `google_client_secret` | Managed Keycloak configurator. Supply together; both required for enabled Google login. Configure the corresponding callback in the Google provider separately. |
| `google_analytics_measurement_id`, `google_site_verification` | Existing UI integration inputs. Optional and independent of user registration. GA4 identifiers must match `G-` followed by uppercase ASCII letters/digits; invalid IDs are refused before provisioning. |
| `smtp_password` | Managed Keycloak SMTP. Paired with `KEYCLOAK_SMTP_USERNAME`; the application mail adapter remains unavailable. |
| `canvas_credentials_shared_secret` | Existing Canvas bridge credential. It is not a Credentials API access token. |
| `canvas_credentials_api_token` | Existing issuance/issuance-native Credentials API token-file input. Required for an enabled global mirror worker; organization-managed provider secrets retain their separate existing onboarding/validation owner. |
| `passport_tenant_api_keys` | Native gateway, Flow and issuance-native Passport keyring. JSON object of organization identifiers to distinct API keys of at least 32 printable ASCII characters. Not combined with internal service authentication. |
| `personalization_bureau_api_key` | Issuance-native bureau client. Imported only for the explicitly selected provider. |

The installer hashes each selected input during preflight and binds its digest
and size in the immutable settings selection. The original storage owner
re-reads and verifies the source before an exclusive write into the private
installation's `secrets` directory, then publishes each scalar as mode `0444`.
Unselected optional files are explicitly empty; existing files are never
adopted or overwritten. Sources can be removed after successful import.

The retained input/selection records are mode `0600` under the private evidence
directory and are bound by the installation journal and every derived Compose
session. Subsequent operations verify the retained original secret bytes,
permissions, single-link identity and content hashes. ACME preparation retains
the exact selected file sizes, inode observations and settings digest; its
continuation cannot replace nonempty inputs with empty placeholders. Credential
generations carry these inputs as **Original** files, preserve their hashes and
reject altered content, source category or file mode. They are not renewable
key/certificate outputs.

## Invariants and explicit limitations

| Configuration owner | Settings that remain with that owner |
| --- | --- |
| Signed release and runtime contract | Image repositories/digests/tags, service commands, memory/resource profile, internal service URLs, ports, bind roots and container identity. Arbitrary `MARTY_*_MEMORY_LIMIT` or environment overrides are not accepted. |
| Hosting selection | Canonical origin, issuer DID, listener and certificate authority, OIDC callback identity, `UI_ENABLED_SECTIONS`, optional connector selection and its separate token custody. Additional UI origins do not provision DNS or certificates. |
| Credential/bootstrap owner | Generated organization ID/slug/domain, `operator@localhost` bootstrap identity, Keycloak realm/admin/client IDs, database/application credentials, initial operator password, migration profile, demo-user cleanup and canonical UI-origin replacement. Display names are configurable; identities are not rebound through this file. |
| Remote key custody | OpenBao/AWS key names and versions, TLS material, signing-grant authority, workload identities and private-key prohibitions. Existing foundation-file validation owns an external AWS foundation. |
| Transport/security contract | `GRPC_INSECURE_ALLOWED=false`, `GATEWAY_OBSERVE_CLIENT_IP=false`, private DIDComm endpoints disabled, no production HTTP-localhost Canvas exception, no portable legacy-event-ingest exception. |

An external OIDC foundation owns its own registration, email and social login.
Managed `KEYCLOAK_*` settings, Google login credentials, SMTP credentials and
the two Keycloak-admin-dependent credential-login choices are rejected for that
foundation instead of being silently ignored. The existing AWS foundation has
explicit AWS signing-grant authority support, including Canvas and Passport;
configuration support does not claim that provider's runtime qualification.

`PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED=true` is rejected because this
self-host Compose package contains neither the required
`passport-provider-ingress` service nor its
`PASSPORT_PROVIDER_INGRESS_SERVICE_URL`. The shipped native Passport
gateway/Flow/issuance service configuration is available independently. No
external signer, local passport artifact key, self-signed document mode or
local callback-secret bypass is introduced.

Production marketing pages are determined by the selected UI release audience
and production deployment package. This application-policy file does not
change a customer image into the production-site image. Hosted private
commerce extensions likewise require their separately shipped implementation.

Legacy journals without a settings-selection marker remain readable and keep
their already retained environment. No default is retroactively applied to an
installed realm. The optional-input inventory expanded from six historical
files to nine; a historical six-file ACME preparation is not adopted as a fresh
nine-file preparation, and a partial new selection is rejected. Continue an
existing installation with its exact source-pinned operator. Cross-version
installation migration is outside this fresh-install settings interface.

Implementation owners: `installer_settings.rs` (typed schema, dependencies and
custody), `installer_application_env.rs` (canonical rendering),
`installer_state.rs` (exclusive import and journal binding),
`installer_acme_preparation.rs` (exact continuation boundary), and
`installer_generation_binding.rs` (generation preservation). Focused tests
cover negative input/dependency cases, record and secret drift, file links and
modes, default registration, native CLI/bootstrap forwarding, legacy selection
behavior, retained generations and nonempty ACME input preservation.
