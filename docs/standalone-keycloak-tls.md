# Independent provider TLS maintenance

This complements [purpose-token renewal](standalone-keycloak-lifecycle.md).
The independent provider has two separate TLS identities: the Keycloak HTTPS
origin used by the tunnel, and the OpenBao HTTPS listener used by Keycloak and
maintenance clients. Renewing signing-purpose tokens renews neither identity.
Keep both maintenance paths and their recovery evidence in the deployment
record before promoting an external OIDC provider.

## Keycloak origin certificate

Keep the origin private key in the provider's owner-private runtime directory.
Give a separate OpenBao Agent only a public CSR for that existing key, a
dedicated AppRole credential and the OpenBao public CA. Its writable output
contains only the public certificate. Mount neither the private key nor owner,
signing, database or tunnel credentials into this agent.

Use the already authenticated, digest-pinned OpenBao image. The following
template was exercised against OpenBao 2.5.5; do not assume a newer `pkiCert`
helper accepts a CSR on this release:

```gotemplate
{{ with secret "identity-tls/sign/origin" (printf "csr=%s" (file "/run/identity-agent/origin.csr")) "common_name=login.elevenidllc.com" "alt_names=identity-keycloak,localhost" "ip_sans=127.0.0.1" "ttl=720h" }}{{ .Data.certificate }}{{ end }}
```

Configure the existing PKI role to honor the explicit request names:
`use_csr_common_name=false`, `use_csr_sans=false`. Keep `allow_any_name=false`,
no subdomain wildcard, and the exact permitted DNS names. Preserve the other
qualified role settings. The CA and origin key stay unchanged.

The agent policy must contain only these capabilities:

| Exact path | Capabilities |
| --- | --- |
| `identity-tls/sign/origin` | `update` |
| `auth/token/lookup-self` | `read` |
| `auth/token/renew-self` | `update` |
| `auth/token/revoke-self` | `update` |

On the signing path require all five parameters and constrain their values:

| Parameter | Allowed values |
| --- | --- |
| `csr` | The exact retained-key CSR, with and without its final newline |
| `common_name` | `login.elevenidllc.com` |
| `alt_names` | `identity-keycloak,localhost` |
| `ip_sans` | `127.0.0.1` |
| `ttl` | `720h` |

Do not add a wildcard entry permitting other parameters. Pinning the CSR also
prevents a stolen agent credential from requesting this hostname for a
different private key. Keep the CSR itself in an owner-private regular file.

Use AppRole authentication without a token sink, with only this policy, no
default policy, nonperiodic service tokens, a one-hour initial token TTL and
an eight-hour explicit maximum. A permanent SecretID is an offline-startup
tradeoff, not a completed rotation lifecycle: record its revocation and
replacement owner and qualify rotation before selecting that arrangement for
production. An expiring SecretID requires an independently qualified rotation
schedule. Do not reuse the signing-renewal AppRole.

Example agent configuration, with deployment-specific paths and address:

```hcl
pid_file = "/tmp/identity-origin-agent.pid"
vault {
  address = "https://openbao:8200"
  ca_cert = "/run/identity-agent/openbao-ca.crt"
}
auto_auth {
  method "approle" {
    mount_path = "auth/identity-origin"
    config = {
      role_id_file_path = "/run/identity-agent/role-id"
      secret_id_file_path = "/run/identity-agent/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
}
template_config {
  exit_on_retry_failure = true
}
template {
  source = "/run/identity-agent/origin.ctmpl"
  destination = "/run/identity-output/origin.crt"
  perms = "0444"
  error_on_missing_key = true
}
```

The input directory and credentials are owner-private. The output directory
is readable by Keycloak beneath an owner-private ancestor. Run the agent with
a read-only root filesystem, all capabilities dropped, no-new-privileges,
bounded memory and a small private temporary filesystem. Give it no Docker
socket or host ports. Mount its input directory read-only and only its public
output directory writable. Use the provider's private network.

Before changing Keycloak, verify the rendered certificate's CA signature,
remaining lifetime, exact SANs and public-key match with the retained private
key. Mount the output directory into Keycloak read-only, retaining the existing
private-key mount, and select:

```text
KC_HTTPS_CERTIFICATE_FILE=/run/identity-origin/origin.crt
KC_HTTPS_CERTIFICATE_KEY_FILE=/run/identity/origin.key
KC_HTTPS_CERTIFICATES_RELOAD_PERIOD=60s
```

The initial configuration change requires a provider restart. Then restart
only the certificate agent and prove a new certificate serial is served with
normal hostname and CA verification while the Keycloak container's start time
is unchanged. The reload period must exceed 30 seconds; see the
[Keycloak TLS documentation](https://www.keycloak.org/server/enabletls).
Also prove rejected different CSR, names, SANs, TTL, extra parameters, owner
token creation, role editing and unrelated key access. Revoke probe tokens.
Repeat public password/OTP/consent, prior-consent reauthentication, signed
claims, PKCE/replay rejection and logout after renewal.

## OpenBao listener certificate

The signed `selfhost-tls-init` helper keeps the listener private key and CA
private key inside the KMS volume. Its ordinary invocation renews a leaf when
less than 30 days remain; `--rotate` forces renewal under the same retained CA.
It refuses a CA too close to expiry. CA replacement is a separate trust-anchor
migration and must not be attempted as ordinary leaf renewal.

First rehearse against a disposable restore of the exact provider snapshot and
listener TLS archive. Verify the existing CA before and after rotation, then
repeat actual signing and scoped-renewal operations. Use the exact selected
image and volume, confirmed from the target container's inspected mounts.

Example commands for the qualified rootless Docker owner, replacing the
illustrative image digest, volume and container with the verified selections:

```sh
docker run --rm --network none --user 0:0 \
  --security-opt no-new-privileges --memory 128m \
  -v PROVIDER_OPENBAO_VOLUME:/bao/data \
  --entrypoint /usr/local/bin/selfhost-tls-init \
  ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:VERIFIED_DIGEST --rotate
docker kill --signal HUP PROVIDER_OPENBAO_CONTAINER
```

The helper's container UID zero is inside the rootless engine; do not run a
host-root Docker daemon or mount unrelated volumes. The native helper needs
to maintain the volume's OpenBao ownership. Do not relax the `0700` TLS
directory or export its private keys to a workload mount.

OpenBao 2.5 reloads listener certificate/key files on SIGHUP at their original
configured paths; see its [versioned TCP listener documentation](https://openbao.org/docs/2.5.x/configuration/listener/tcp/).
Verify a changed served serial, unchanged container start time, retained CA and
successful authenticated signing/renewal after the signal. A successful helper
exit alone proves neither reload nor usable service. Ordinary scheduled checks
should use the non-forced helper and a cadence well inside the 30-day window.
Qualify and record the actual installed scheduler separately.

## Recovery and retirement gates

Preserve the database dump, current Raft snapshot, unseal material, retained
listener TLS archive, origin private key, agent configuration/credential and
purpose-renewal authority in encrypted owner custody. After any credential or
TLS change, refresh and rehearse that custody. A restored node must accept the
retained listener CA, sign with the retained realm key, renew the five scoped
purpose leaves and issue an origin certificate for the retained origin key.
Remove and verify all disposable recovery resources afterward.

Restoring a pre-revocation snapshot with its saved owner token demonstrates
offline snapshot recovery. It does not prove recovery of live administrative
authority after that token is revoked. Keep bootstrap retirement blocked until
the owner has qualified a supported administration/recovery route. Do not
enable deprecated unauthenticated root-generation endpoints to clear this gate.
