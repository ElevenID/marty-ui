# Optional passkey login

Passkeys extend the existing `11id` theme and Keycloak login. Password, Google,
Open Badge credential presentation and recovery remain available. A passkey
authenticates the same Keycloak account and does not confer badge claims or
application permissions.

## Configuration

The existing Keycloak configurator owns these settings. On the qualified
Keycloak 26.8.x image, select `KEYCLOAK_PASSKEYS_ENABLED=true` and an explicit
`KEYCLOAK_PASSKEY_RP_ID` containing the stable public authentication hostname.
Do not use a URL, port, path or internal container hostname. Serve authentication
over HTTPS; ensure the chosen RP ID is valid for its public origin. Test realms
must use their own scope. Installer application JSON accepts a boolean for the
enable setting and a lowercase hostname for the RP ID.

An omitted/empty enable setting preserves existing policy and supports older
installations without introducing 26.8-only API settings. Explicit management on
an unqualified version fails. Enabling sets discoverable credentials and user
verification to required, ES256/RS256, no attestation, unrestricted attachment,
conditional autofill and an explicit passkey button. The configurator verifies
each effective field and enables optional WebAuthn Register Passwordless.
It refuses to replace a different explicitly configured RP ID. This is not a
migration facility for existing credentials enrolled using an implicit RP ID;
inventory those credentials and their effective public scope before enablement.

Set `KEYCLOAK_PASSKEYS_ENABLED=false` to disable the native login integration.
This retains enrolled credentials, passwordless policy, provider links and
required actions. Re-enable using the same RP ID. Changing RP ID requires a
separate migration/enrollment design. Never delete credentials as rollback.

## Account lifecycle and qualification

Users should enroll only from a trusted authenticated account, with appropriate
fresh authentication. Keep email verification and existing linking policies.
Encourage a second passkey and a verified recovery method; second-factor recovery
codes alone must not be assumed to recover a passwordless account. Password/email
fallback retains its existing security characteristics.

Inspect the customized browser flow's MFA behavior: the upstream default can skip
conditional 2FA after passkey login. Privileged step-up must retain its intended
assurance. The current theme inherits the installed version's `passkeys.ftl` and
JavaScript instead of maintaining a separate implementation.

Before rollout, qualify actual password, Google and Open Badge login, enrollment
against the same account subject, cancellation, credential removal, recovery and
authorization. Use virtual-authenticator integration tests plus real Windows
Hello, mobile, security-key and cross-device checks. Source/template tests alone
do not establish a working deployed journey. Existing runtime deployment holds
apply; no enablement on a held deployment is authorized by these instructions.

References: [Keycloak 26.8 passkeys](https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/authentication/passkeys.adoc),
[WebAuthn policy and enrollment](https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/authentication/webauthn.adoc).
