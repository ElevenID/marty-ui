# Native passkey lifecycle guard

This version-matched Keycloak26.8.0 provider keeps native WebAuthn registration,
assertion verification, credential storage, Account Console and removal actions.
It overrides `keycloak-webauthn-passwordless` at priority100 to enforce the
remaining-method decision through `CredentialTypeMetadata.removeable`.
The canonical Keycloak Dockerfile builds and installs its separate JAR alongside
the existing remote-signing provider; it does not change signing custody.

For realms with passkeys enabled, removal requires another stored passwordless
credential or a local password with an enabled authenticator in the current
client's browser flow (falling back to the realm flow). Broker links, email, OTP
and custom credential presentations are not assumed to be recoverable. The local
JPA user row serializes concurrent native removals across instances until commit;
the subsequent credential query uses database locks rather than cached user data.
Non-local users or missing JPA support fail closed for removal. The upstream
metadata and semantics are retained when the realm passkeys flag is off.

Native assurance and permissions remain enforced. Administrator credential APIs
are privileged recovery operations outside this user self-service guard.
Changing realm/client flows, password availability or operator actions can still
make an account inaccessible and must retain their existing review controls.

The configurator verifies the selected factory's serverinfo `order:100` and
`operationalInfo.martyPasskeyLifecycleGuard:1` before enabling passkeys. This is
an implementation protocol marker, not evidence that an arbitrary new version or
database has been qualified.

Build with `mvn -B package` against the pinned Maven dependencies. For isolated
verification, set `MARTY_PASSKEY_TEST_IMAGE` to the pinned upstream26.8 image and
`MARTY_PASSKEY_PROVIDER_JAR` to the built JAR, then run
`py -3.12 -m pytest -q tests/test_keycloak_passkey_live.py`. The fixture mounts
only this provider and the theme; it does not require or weaken the remote KMS
image. It uses only synthetic accounts and non-relaying SMTP captures. Passing
these H2/virtual-device tests does not establish production PostgreSQL/cluster,
packaged remote-KMS, physical-device or real provider qualification.

Version-matched source contracts:
- [Native removal helper](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/authentication/requiredactions/util/CredentialDeleteHelper.java)
- [Native account credential API](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/services/resources/account/AccountCredentialResource.java)
- [Native passwordless provider](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/credential/WebAuthnPasswordlessCredentialProvider.java)
