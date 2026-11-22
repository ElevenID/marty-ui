# Application email with Resend

The native notification service can send plain-text application notifications
through Resend's HTTPS API. This is optional and works independently of the
login provider. It keeps mail delivery off the ElevenID host while retaining
notification policy and records in ElevenID.

The adapter is disabled by default. It does not provision an account, verify a
domain, configure billing, or send a test email during installation. Only an
explicit application notification request selects recipients and sends mail.

## Configure a fresh native installation

1. Configure the sending domain in Resend and verify its required DNS records.
   Select a bare sender address such as `notifications@example.com` on that
   domain. Create a sending API key limited to the intended domain where the
   provider supports that scope.
2. Put the API key in an owned, ordinary file with mode `0600`, beneath an owned
   directory with mode `0700`. The JSON and credential file stay outside the
   checkout. Do not put credentials in a public environment file or command.
3. Add the following to the installer's existing `--settings-file` input:

```json
{
  "schema": "elevenid.installer-application-settings/v1",
  "values": {
    "NOTIFICATION_EMAIL_PROVIDER": "resend",
    "NOTIFICATION_EMAIL_FROM": "notifications@example.com"
  },
  "secret_files": {
    "notification_resend_api_key": "/home/operator/marty-input/notification-resend-key"
  }
}
```

The secret is imported, fingerprinted and retained through the existing
immutable credential-generation owner. The runtime reads only
`NOTIFICATION_RESEND_API_KEY_FILE`; a raw API-key environment value is rejected.
The API key, raw provider errors and recipients are not copied into delivery
error messages. Selection records use application-settings-selection `v2` for
the eight optional inputs. Historical `v1` records retain their original seven
inputs; reading one does not require or create the new credential file.

The settings are for a fresh installation. This change does not introduce an
in-place email configuration or credential-rotation command. The selected
signed release must contain the adapter and still meet its normal installation
admission and qualification requirements.

## Runtime behavior

The adapter uses the fixed `https://api.resend.com/emails` endpoint and verifies
TLS using the normal HTTPS client. It follows no redirects and does not use
environment proxies. Each recipient gets a separate message containing the
notification subject and plain-text body, without exposing other recipients or
forwarding the notification's arbitrary metadata as mail content.

An email channel accepts at most 50 recipients per notification. Requests have
a 5-second connection timeout, a 10-second HTTP timeout and a 30-second overall
email-channel deadline. Content is limited to a 998-byte subject without control
characters and a 1 MiB body. The adapter uses a deterministic idempotency key for
each notification and recipient. Resend documents a 24-hour idempotency window;
this is not a durable deduplication guarantee beyond that window.

A successful result means Resend accepted the message and returned a valid
message identifier. Existing `success`/`delivered_at` fields record that provider
acceptance, not proof of inbox delivery. Invalid or oversized success responses
remain failures. Invalid credentials, recipient/content problems, rate limits,
provider failures and rejected redirects have distinct, redacted error codes.
An HTTP 409 response is retryable only when Resend identifies the same request
as still in progress. Reusing its idempotency key with a different payload is
reported as a nonretryable conflict. Sender-validation failures are reported
separately from API-key failures; provider error messages remain private.

There is no automatic email retry worker in this change. Transient errors mark
`should_retry`, but they do not silently schedule requests or create a billable
retry loop. Requesting another notification creates another notification ID;
application callers must not treat that operation as a retry of the original
message. Provider quotas and account billing settings still apply. Tests use
only local mock HTTP servers and synthetic credentials.

## Supabase authentication mail is separate

Supabase Auth owns its signup, verification and password-recovery messages.
Configure the email provider's SMTP settings in Supabase Auth, using a separate
credential from the application's sending key. ElevenID's notification adapter
does not configure Supabase or replace that connection. Likewise,
`KEYCLOAK_SMTP_*` and `smtp_password` configure only managed Keycloak and remain
invalid when external OIDC is selected.

If both channels use one Resend account, their sends consume that account's
quotas. Monitor combined authentication and application traffic when choosing
the provider plan. The default Supabase SMTP service has recipient and rate
restrictions and should not be assumed to support public adoption without a
custom SMTP provider.

## Provider references

- [Resend Send Email API](https://resend.com/docs/api-reference/emails/send-email)
- [Resend idempotency behavior](https://resend.com/docs/dashboard/emails/idempotency-keys)
- [Resend error codes](https://resend.com/docs/api-reference/errors)
- [Supabase custom SMTP](https://supabase.com/docs/guides/auth/auth-smtp)
