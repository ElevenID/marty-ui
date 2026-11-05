# Optional passkey login

Passkeys extend the existing `11id` theme and Keycloak login. Password, Google,
Open Badge credential presentation and recovery remain available. A passkey
authenticates the same Keycloak account and does not confer badge claims or
application permissions.

## Configuration

The existing Keycloak configurator owns these settings. On the qualified
Keycloak 26.8.0 image, select `KEYCLOAK_PASSKEYS_ENABLED=true` and an explicit
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
or application user ID. Existing login methods remain usable.

The profile also offers **Manage passkeys**, using the managed public issuer's
native Account Console. Confirm the account displayed there before changing
credentials. The console owns naming, additional registration and removal, and
its own authentication and assurance checks; the link does not replace the Marty
session or transfer its authorization. External OIDC, disabled and impersonated
sessions do not receive this link.

The packaged Keycloak image includes `keycloak/passkey-provider`. It preserves
native WebAuthn validation and credential storage and changes passwordless
credential metadata only while managed passkeys are enabled. Native Account API
and delete-credential AIA removal are refused unless another stored passkey or
a local password remains and its authenticator is enabled in the applicable
browser flow. Google links, Badge access, OTP and email alone do not count as
proven recovery methods for this decision. A local password is not mandatory:
enrolling a second passkey permits removal. Unknown/federated storage without
a local user row is denied for removal. Explicit administrator deletion retains
its privileged semantics and must follow operator recovery policy.

The guard locks the local user row through the Keycloak transaction and reads
credential rows with database locks, preventing two native removal requests from
each counting the other's credential as a remaining method. Provisioning checks
the selected passwordless factory's priority and lifecycle protocol marker before
enabling managed passkeys. A stock upstream image alone cannot satisfy that gate.
The image remains pinned to Keycloak26.8.0; qualify this internal SPI and JPA
contract again on any upgrade. The disposable packaged qualification now covers
two clustered Keycloak instances sharing PostgreSQL and remote KMS, native email
and password enrollment, Account Console, native action cancellation and deletion,
cross-node last-method protection, fresh surviving-key/password authentication,
configured OTP, expired-tab recovery, and server rejection of invalid signatures,
wrong origins/RP scope, missing user verification, replayed assertions and
unknown/deleted credentials. For origin/RP/verification cases the virtual test key
re-signs the altered assertion, distinguishing context validation from signature
validation. Rejections retain password fallback and assigned native realm roles;
they do not establish Marty organization or Badge authorization end to end.
The combined proof also covers cookie rotation, CIBA and KMS-loss/custody checks.
The CI image lane runs this
composite proof against its freshly built images. This is synthetic-account and
virtual-device evidence; actual Google/Open Badge application journeys and
physical/cross-device behavior remain rollout gates.

Google's provider prompt defaults to `select_account` when it is unset or empty;
the configurator preserves an explicit provider prompt. This keeps Marty's fresh
Keycloak authentication request (`prompt=consent login`, `max_age=0`) while
preventing the unsupported `login` value from being forwarded to Google. The
native redirect test covers passkeys enabled and disabled and stops before
contacting Google. It does not establish a completed Google sign-in. Operators
with an explicit prompt must keep it within Google's supported `none`, `consent`
and `select_account` values, subject to [Google's prompt rules](https://developers.google.com/identity/openid-connect/openid-connect#prompt).

Users should enroll only from a trusted authenticated account, with appropriate
fresh authentication. Keep email verification and existing linking policies.
Encourage a second passkey and a verified recovery method; second-factor recovery
codes alone must not be assumed to recover a passwordless account. Password/email
fallback retains its existing security characteristics.

If a device is lost, sign in using a retained method and verify that method in a
fresh browser session before removing the lost credential. The removal guard
checks stored credentials and enabled authenticators; it cannot establish that
the user still possesses another device or remembers a stored password. Keep
credential labels clear and confirm the account shown in the native console.

Use the existing **Forgot password** flow when password/email recovery is
available. Captured-mail browser qualification covers reset and a fresh login as
the same subject with passkeys enabled and disabled. The custom update-password
form retains the exact account username and its password-manager autocomplete
metadata. This does not replace the realm's email verification or MFA policy.

For a user who cannot use any remaining login method, the authorized tenant
recovery operator must verify the request under the organization's existing
identity-recovery policy and identify the immutable Keycloak user ID. When the
stored, verified mailbox remains a trusted recovery channel, use native
`execute-actions-email` for that exact user with only
`webauthn-register-passwordless`, a short lifetime (300 seconds), the managed
client and a registered return URL. This is a privileged control-plane operation;
the unauthenticated user cannot invoke Marty's enrollment endpoint. Native
Keycloak confirms the mailbox and owns enrollment. Never expose the action token
in support replies, logs or application responses. If the mailbox or identity
cannot be verified, escalate to the tenant's recovery owner; do not delete
credentials, change the subject, create a duplicate account or infer trust from
an unverified presentation to unlock the account. After recovery, verify fresh
application login, subject and authorization before retiring confirmed lost keys.

Management uses the native Account Console and application-initiated actions.
Keycloak26.8 deprecates direct Account REST credential deletion in favor of
`delete_credential` AIA. Native AIA uses the required action's configured maximum
authentication age; credential deletion also checks the applicable authentication
level. Keep those settings under the realm flow owner's policy. The direct REST
endpoint used in concurrent-removal tests is not a separate fresh-authentication
flow and is not the management API offered by Marty. Qualification of aged
sessions and privileged step-up remains required before rollout.

Inspect the customized browser flow's MFA behavior: the upstream default can skip
conditional 2FA after passkey login. For a policy that requires enrolled users to
enter OTP after either a passkey or a password, Keycloak26.8 documents disabling
only **Condition - credential** in **Browser - Conditional 2FA**. Retain the
enrolled-user and organization conditions, and require the intended OTP execution.
Apply such a policy through the realm's existing flow owner; passkey provisioning
does not rewrite authentication flows. Privileged step-up must retain its intended
assurance. The current theme inherits the installed version's `passkeys.ftl` and
JavaScript instead of maintaining a separate implementation.

For a repeatable application regression, run
`scripts/probe_keycloak_passkey_application.py --help`. This opt-in CLI starts
17 real Marty services on the disposable packaged Keycloak/PostgreSQL/Redis/KMS
network. It generates test credentials and accounts, applies native migrations,
and checks password login, Origin rejection, native enrollment for the original
subject, password retention, logout and fresh passkey login with unchanged
application identity and authorization. Add `--administrator` to exercise the
seeded administrator. Workload certificates use independent non-exportable
Transit keys and exact SPIFFE role identities; sensitive RPCs use workload mTLS.
This remains a local development stack with a Chrome virtual authenticator.

Supply explicit cached Keycloak, OpenBao, application and Nginx images, a built
application UI directory, and a new private output directory outside the checkout.
The application image's `marty.source` label must match the UI manifest's
`source_sha`; the runner compares runtime source content with that revision.
Build the application image from `services/Dockerfile`'s runtime and default
service binaries, also including the same-source `marty-migration-bootstrap`
binary and native Issuance/Flow migration SQL under
`/app/passport-native-migrations/{issuance,flow}`. This fixture image is a test
artifact, not a qualified release image. The runner never executes the base
Compose stack: it reads its resolved configuration using generated inputs and
discards global mounts, published ports and container names. Test services use
owned names, resource limits, read-only filesystems, temporary data and cleanup
in `finally`; only the test front door binds a dynamic loopback port.

The output directory contains synthetic secrets and private failure diagnostics;
keep it private. `qualification-complete.json` is written only after the
application journey, parent KMS/custody checks and cleanup finish. Earlier result
files do not establish completion. This runner does not claim completed Google
or Open Badge login, physical devices or deployed qualification.

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
