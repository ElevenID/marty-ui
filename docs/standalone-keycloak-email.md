# Independent provider verification email

Use this with the independent provider's [credential renewal](standalone-keycloak-lifecycle.md)
and [TLS maintenance](standalone-keycloak-tls.md). Email delivery is a separate
qualification gate. A connected mailbox profile, SMTP authentication, or an
accepted send alone does not prove that the user's verification email arrived.

## Sender and spending boundary

Qualify the sending account before activating email. Resend's Free transactional
plan was published at $0/month with 3,000 emails/month, 100/day and three domains
on 2026-11-23. Verify the actual account plan and limits again; see
[current pricing](https://resend.com/pricing). Keep paid subscriptions,
pay-as-you-go and add-ons disabled. Check actual usage after delivery tests.

Use a dedicated sending subdomain, for example `notify.elevenidllc.com`.
Obtain its exact DNS records from the authenticated provider dashboard; do not
copy another account's DKIM key or assume an old provider's MX/SPF layout.
Check for existing records before adding anything. Publish sending CNAMEs as
DNS-only, and verify public DNS answers and the provider's verified status.
Leave apex mail routing and optional inbound email unchanged.

Create a sending-only API key restricted to that verified domain. Do not fall
back to full access or all domains when verification is still pending. Keep the
key out of chat, process arguments, environment variables and qualification
output. Stage private custody before creating a one-time credential; preserve
uncertain creation state instead of automatically creating another key.

For a browser-to-host transfer, the exercised deployment encrypted the key
inside the browser to a temporary owner public key, then decrypted it only in
the local custodian process. The custodian saved Windows-profile-encrypted
recovery and imported an owner-private Linux file through a process pipe.
It rehearsed recovery and retired the temporary transfer private key after
successful import. Profile-bound encryption is not proof of recovery after
loss of the profile or machine.

## SMTP and file-vault projection

[Resend's SMTP documentation](https://resend.com/docs/send-with-smtp) specifies
`smtp.resend.com`, username `resend`, and the scoped API key as password.
Port 465 uses implicit TLS. First qualify normal CA and hostname verification,
EHLO and authentication from the actual host, without sending a message.
Never disable certificate verification to make SMTP connect.

Keycloak supports an SMTP password reference through its
[file vault](https://www.keycloak.org/server/vault). Enable `vault=file` as a
build-time option and set the runtime vault directory. With the pinned 26.8.0
provider's normal non-optimized startup, selecting `KC_VAULT=file` causes the
standard configuration augmentation before startup. Preserve the authenticated
image and native signing-provider configuration; this is not permission to
patch an installed binary.

Example configuration:

```text
KC_VAULT=file
KC_VAULT_DIR=/run/identity-mail
KC_TLS_HOSTNAME_VERIFIER=DEFAULT
```

For realm `11id`, project the SMTP key as
`11id_resend-smtp-password` in that directory. The runtime projection can be
`0555` with its leaf `0444` beneath an owner-private `0700` ancestor, like the
existing provider projections. Mount only this directory into Keycloak,
read-only. Do not mount the owner recovery directory or a provider-wide API key.

Configure the realm's `smtpServer` with a vault reference:

```json
{
  "host": "smtp.resend.com",
  "port": "465",
  "ssl": "true",
  "starttls": "false",
  "auth": "true",
  "user": "resend",
  "password": "${vault.resend-smtp-password}",
  "from": "no-reply@notify.elevenidllc.com",
  "fromDisplayName": "ElevenID Identity"
}
```

Keep registration and password-reset exposure at the previously qualified
settings. Enable realm email verification. Change only the independent provider
when its configuration requires a restart, then repeat signed OIDC, password
and OTP, prior-consent reauthentication, PKCE/replay and logout checks.

## Native delivery and administrator setup

The native `POST /admin/realms/11id/testSMTPConnection` test sends to the
authenticated administrator's email, not an arbitrary `to` field. Use only the
authorized setup recipient. A temporary bootstrap administrator without an
email needs that contact configured first; this does not verify the recipient's
actual application account. Keep that account disabled through this test.

Verify inbox arrival, From/To, and receiving-system SPF, DKIM and DMARC results.
The SMTP test message is diagnostic and is not an enrollment link. Keep its
message ID, delivery headers and the native response status as sanitized
evidence. Do not capture message bodies containing action tokens in logs.

Once delivery is qualified and the operator has requested enrollment:

1. Inspect the exact target user and preserve the invitation boundary. Refuse
   unexpected existing credentials or a conflicting account state.
2. Enable that user for required actions, leaving `emailVerified=false`.
   Require `VERIFY_EMAIL`, `UPDATE_PASSWORD` and `CONFIGURE_TOTP`. Generate
   neither the person's password nor their authenticator secret in an agent.
3. Invoke native `PUT /admin/realms/11id/users/{id}/execute-actions-email`
   with those three actions. Use an explicit short lifespan, such as 900 seconds,
   and an already registered client and exact redirect URI. The built-in
   `account-console` can return to the provider's own account page while the
   application deployment is still being qualified.
4. Confirm actual invitation delivery without reading or exposing its action
   token. Let the person follow the link and complete the native forms. The
   native action-token handler verifies the email on successful link use;
   do not mark it verified from a profile lookup or from send acceptance.
5. Inspect the resulting account: enabled, verified email, no remaining required
   actions, and password plus OTP credential types. This metadata does not
   establish a real application OIDC round trip; qualify that separately.

If a send loses its response, retain the pending receipt and inspect actual
delivery before retrying. If an invitation expires, reissue only after checking
the user's current state and the existing send; do not send repeated invitations
on a timer. Update the encrypted credential/configuration backup and take a new
coordinated database backup after the person finishes. A dump from before their
password/OTP setup cannot prove recovery of their newly enrolled account.

Keep optional application notification email disabled until its separate sender,
delivery and rate-limit qualification passes. Provider enrollment email does
not automatically qualify that service or increase the shared free quota.
