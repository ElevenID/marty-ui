# Independent Keycloak provider renewal

Use this driver for a separately operated Keycloak provider used through the
[external OIDC selection](installer-external-oidc.md). The provider has its own
database schema, OpenBao state, private input root and ingress. This driver
does not enroll an application installation or change its existing full
workload renewal contract. Qualify provider login and application acceptance
separately using [OIDC provider qualification](oidc-provider-qualification.md).
Qualify [verification-email delivery and administrator enrollment](standalone-keycloak-email.md)
before activating a real administrator.

## Preconditions

Run as the unprivileged Linux owner of an existing provider input root. Its
directory must be owned by that user with mode `0700`, without symlinked
ancestors. The expected retained files are:

| Path relative to input root | Purpose and mode |
| --- | --- |
| `marty-deploy` | Previously authenticated native operator, `0700` |
| `source/selfhost-prepared/` | Matching authenticated prepared release archive |
| `openbao-ca.crt` | Explicit CA for loopback OpenBao HTTPS, owner-owned regular file |
| `openbao-root.token` | Bootstrap-only root authority, `0600` |
| `runtime/` | Provider's existing read-only directory projection, `0555` |
| `runtime/keycloak_signing_kms_token` | Signing policy for retained master/11id keys, `0444` |
| `runtime/keycloak_{master,11id}_{cookie,ciba}_token` | Four existing JWE purpose tokens, `0444` |
| `runtime/keycloak_{master,11id}_rs256_cert` | Two public certificates, `0444` |
| `runtime/keycloak-{master,11id}-rs256.crt` | Existing certificate filenames read by the provider, `0444` |
| `runtime/{master,11id}-{cookie,ciba}.token` | Existing purpose filenames read by the provider, `0444` |

The outer owner-private directory protects the readable container projection.
Mount only that projection into Keycloak, read-only. Mount neither bootstrap
root nor renewal AppRole credentials into the provider. Bind OpenBao only to
loopback on the host. Its HTTPS CA must be checked on every API call.

Acquire and verify the native operator and matching archive through the
existing signed release workflow first. Write `lifecycle-config.json` as an
owner-private `0600` file, replacing every illustrative value:

```json
{
  "schema": "elevenid.standalone-keycloak-lifecycle/v1",
  "endpoint": "https://127.0.0.1:18210",
  "operator_sha256": "SHA256_FROM_VERIFIED_SIGNED_INVENTORY",
  "operator_source_sha": "EXACT_PROTECTED_RELEASE_SOURCE_SHA",
  "operator_release_tag": "EXACT_AUTHENTICATED_RELEASE_TAG"
}
```

The driver rechecks the binary digest and compiled source/tag identity before
operation. A digest copied from an unauthenticated download is insufficient.
Keep the Python driver and its shared modules at the reviewed checkpoint.

## Enroll and qualify

From the reviewed source directory:

```sh
python3 scripts/standalone_keycloak_lifecycle.py --state-root /home/operator/login-identity bootstrap
python3 scripts/standalone_keycloak_lifecycle.py --state-root /home/operator/login-identity renew
python3 scripts/standalone_keycloak_lifecycle.py --state-root /home/operator/login-identity rotate-secret-id
```

Bootstrap refuses an existing auth mount, operator policy or leaf role. It
compares all five existing purpose policies with the authenticated native
policy producer before creating authority. An incomplete bootstrap remains
recorded for operator recovery instead of overwriting remote state.

The renewal AppRole has a seven-day SecretID and an eight-hour hard cap on its
login tokens. Renewal leaves have an eight-hour explicit maximum, no periodic
extension, no default policy, and no parent-token dependency. The exact token
role allowlist contains the five retained provider policies. The renewer
cannot edit that role or any policy, create/rotate/export keys, or mint through
another token endpoint. OpenBao 2.5 cannot encode a nested array constraint for
the JSON `policies` parameter. The token role bounds its values, and native
minting plus publication validation require exactly one expected purpose per
returned token. Other mint parameters have explicit value constraints.

Test the actual server before retiring bootstrap authority:

1. Verify all five issued leaves are orphan service tokens with the expected
   single policy, no identity/default policies, and actual explicit maximum
   `28800`. Check returned metadata, not only role configuration.
2. Verify root and foreign policy requests fail, and that periodic tokens,
   longer TTLs, missing hard caps, role/policy edits, unrelated key reads and
   key rotation are denied. Some token-role settings override requested
   parameters; verify the resulting token excludes default policy even when
   the request asks to include it. Revoke any known probe tokens afterward.
3. Verify SecretID rotation accepts the replacement and rejects the old
   credential. Check that the replacement has the same role and policy scope.
4. Repeat real browser S256 login, RS256 verification, password and OTP claims,
   fresh session `auth_time` with prior consent, code replay rejection and
   provider logout after the new files are active.
5. Preserve and rehearse recovery of the updated authority, database dump,
   OpenBao snapshot, listener TLS identity and unseal material. Verify an
   offline owner recovery route before revoking the bootstrap root token.

No private signing key is exported. The native producer signs CSRs for the
retained version-one remote keys and issues bounded purpose tokens. All
replacement inputs are staged and validated before publication. Each file is
replaced atomically. Old/new purpose leaves can safely overlap because their
scope and key versions are identical. A failure does not emit a successful
renewal receipt.

## Schedule after qualification

`cycle` renews the provider and rotates its SecretID once the existing one is
at least two days old. Run it at least every four hours. Example user service,
with paths changed to the reviewed deployment:

```ini
[Unit]
Description=Renew independent ElevenID identity provider credentials

[Service]
Type=oneshot
UMask=0077
NoNewPrivileges=yes
ExecStart=/usr/bin/python3 /home/operator/provider-source/scripts/standalone_keycloak_lifecycle.py --state-root /home/operator/login-identity cycle
```

Example user timer:

```ini
[Unit]
Description=Schedule independent identity credential renewal

[Timer]
OnBootSec=1min
OnUnitActiveSec=4h
RandomizedDelaySec=5min
Persistent=true
Unit=elevenid-identity-renewal.service

[Install]
WantedBy=timers.target
```

Inspect existing units before installing. Run and inspect the exact service
once, then enable its timer. Verify the active timer, its next run, the actual
`last-renewal.json`, current issued token TTLs, and provider login. A passing
one-shot command does not prove an enabled scheduler. Qualify startup under
the host's existing service/WSL lifecycle without stopping unrelated workloads.

This driver does not renew the HTTPS origin/listener certificates or rotate
the PKI CA. Qualify their separate [TLS maintenance and recovery paths](standalone-keycloak-tls.md)
before production cutover. Keep expiry deadlines in the deployment record.

## Interrupted operations and offline recovery

Keep private `renewal/` state and the current runtime projection. Diagnostics
omit credentials and response bodies. `last-native-failure.json` records the
native exit code and diagnostic digest, and pending records retain the
operation boundary. A timer refuses to mint over a pending generation.

For a staged generation with returned inputs, explicitly resume:

```sh
python3 scripts/standalone_keycloak_lifecycle.py --state-root /home/operator/login-identity resume
```

This revalidates token scope, hard lifetime cap, certificate expiry and public
SPKI before completing publication. It does not mint a second generation.
The leaves and certificates must retain at least four hours and ten minutes
of validity to cover the next scheduled run and timer jitter. Older staged
inputs require owner recovery instead of a misleading successful receipt.
For a SecretID rotation with a recorded replacement and previous identity:

```sh
python3 scripts/standalone_keycloak_lifecycle.py --state-root /home/operator/login-identity resume-rotation
```

The replacement must pass the complete login contract before it is retained.
Already completed old-credential retirement is accepted only after a denied
old login. An unrelated current identity is preserved and causes refusal.

If a native mint or SecretID create lost its response, retain the pending
record and inspect actual remote state through the authorized recovery owner.
Do not delete the record and retry from an assumption that nothing happened.
Keep revoked/expired attempts and their disposition in the deployment audit.

After SecretID rotation, refresh the encrypted recovery copy. If the host is
offline beyond the seven-day SecretID lifetime, or the saved SecretID has
already been retired, use the tested offline unseal/recovery ceremony to
obtain temporary owner authority and replace only the renewal credential.
Preserve signing keys, realm database, scope policies and key versions.
Revoke temporary root authority after validating the replacement. Never
make the renewal credential permanent or relax the issued-token hard cap.
