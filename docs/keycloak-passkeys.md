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

With managed passkeys enabled, the authenticated profile offers **Create a
passkey** when the session has a trusted Keycloak account binding. For OIDC
sessions with a trusted ID token, the
application uses a same-origin, cookie-authenticated JSON POST to
`/v1/auth/passkeys/enroll`, then follows Keycloak's passwordless registration
required action through the existing PKCE callback. Keycloak receives an ID-token
hint and requires fresh authentication. The callback independently checks the
original subject and still-valid application session before returning to the
profile; it retains that session's roles and organization context. AIA
cancellation returns without claiming enrollment succeeded.

Open Badge credential-login sessions use Keycloak's native enrollment email,
including when token exchange is disabled. Account resolution retains the trusted
Keycloak subject separately from application IDs and validated OIDC claims. A
request requires a verified sign-in within the previous five minutes; the service
rechecks that the same Keycloak account is enabled and its verified email still
matches. Only the passwordless registration action is sent, with a five-minute
signed link and a registered client return URI. The application returns an email
confirmation and never exposes the action token. Keycloak confirms the mailbox
and owns registration; no local password is required and no application session
or role context is replaced.

This path requires the existing managed Keycloak admin adapter and working realm
SMTP. After an upgrade, sign in through Open Badge again to retain the explicit
account binding. Unbound sessions cannot select an account by supplying an email
or application user ID. Existing login methods remain usable. Credential
management, last-method safeguards and complete provider/packaged-image journeys
remain rollout gates until implemented and verified.

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
[WebAuthn policy and enrollment](https://github.com/keycloak/keycloak/blob/26.8.0/docs/documentation/server_admin/topics/authentication/webauthn.adoc),
[native enrollment email API](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/services/resources/admin/UserResource.java),
[signed action handling](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/authentication/actiontoken/execactions/ExecuteActionsActionTokenHandler.java).
