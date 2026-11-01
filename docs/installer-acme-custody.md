# ACME enrollment configuration and initial custody

The configuration and custody modules provide the installation owner's inputs
for ACME enrollment. They do not select an ACME source in the running ingress,
issue workload credentials, activate certificates, change the installed origin,
or migrate an existing key.

## Explicit enrollment inputs

`AcmeParameters::parse` accepts a bounded JSON object with duplicate-key and
unknown-field rejection. A staging example is:

```json
{
  "environment": "staging",
  "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "profile": "shortlived",
  "terms_url": "https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf",
  "terms_agreed": true
}
```

Production requires `environment: production` and the exact production
directory `https://acme-v02.api.letsencrypt.org/directory`. The first supported
profile is explicitly `shortlived`, including for DNS-only enrollment. There
is no implicit environment or agreement. The owner must verify that the
selected directory still advertises the recorded terms URL before account
registration, using the same prepared directory instance for that registration.
A changed agreement requires a new explicit customer decision.

`contact` is optional and absent by default. If supplied, it is one explicit
plain `mailto:` address, such as `mailto:owner+tls@example.com`. Nothing is
inferred from the installation operator's identity. Let's Encrypt ended expiry
emails and no longer retains ACME contact email with account data; supplied
addresses may receive an ISRG onboarding email. Account creation must not
require contact information to be echoed by the CA. See
[Let's Encrypt's service change](https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended/).

`BoundAcmeConfiguration::bind` reconstructs the exact recorded hosting choice
under the existing installation lock. The result includes the installation
UUID, hosting-selection digest, canonical DNS origin, optional explicit IP
entry origin, and all enrollment parameters. Initial enrollment requires
recorded direct hosting with the managed OpenBao foundation; legacy local
fallbacks, imported foundations and external proxy configurations are refused.
No certificate-source field in the saved hosting record is rewritten.

The owner serializes this binding into the enrollment journal and compares it
with a freshly bound configuration on each resume. A caller cannot deserialize
an arbitrary object into the admitted binding type.

## Three authority boundaries

For installation UUID `U`, write its canonical lowercase UUID without hyphens
as `u`. Environment `E` is exactly `staging` or `production`.

| Purpose | Resource or policy | Permitted operations |
| --- | --- | --- |
| ACME account | Transit key and policy `installer-acme-E-account-u` | Sign the exact supplied JWS input using version 1, SHA-256, internal hashing and JWS signature encoding. No key reads or CSR creation. |
| Ingress CSR | Policy `installer-acme-E-csr-u` | Read the retained ingress public-key metadata and create a CSR using version 1 and the exact admitted public template. No arbitrary signing. |
| Live TLS | Existing key and policy `installer-ingress-u` | Existing fixed-version TLS signing contract using a prehashed SHA-256 digest and ASN.1 signature encoding. No CSR or account signing. |

Staging and production have distinct account keys and policies even within one
installation. The retained ingress key can remain the same public identity
across these separate qualification attempts. Account and ingress SPKI must
differ. There is no account-key or certificate-key export path.

`AccountKeyBinding::bind` requires the environment-specific resource name,
original version 1, one retained public key, P-256 signing support, no derivation
or import, and disabled export, plaintext backup, automatic rotation and
deletion. The OpenBao metadata field for import provenance is `imported_key`.
Metadata must match independently retained SPKI; a returned certificate or CA
account response cannot choose it.

## Initial key and policy transaction

The internal `provision_initial` operation receives the existing
`LockedMaintenance`, bound configuration, already-retained ingress key, verified
OpenBao HTTPS client, and initial provisioning authority. It checks the exact
current configuration, ingress custody, and absence of the new account key
and policies before setup.

It writes and syncs `acme-custody-E-intent.json` before any remote mutation.
Then it creates the nonexportable account key, validates its public readback,
creates the two exact policies, verifies their readback and both retained keys,
and writes `acme-custody-E-result.json`. The public result binds the original
intent digest and recorded account SPKI. Tokens, SecretIDs and root credentials
are absent from both files.

An intent without a result is an explicit recovery hold. The operation never
retries key creation, adopts a preexisting unrecorded key, overwrites a policy
found during initial preflight, or deletes uncertain resources. A completed
record can be restored only through read-only verification of the same key,
configuration and exact policies. Drift is refused rather than repaired.

The custody operation returns `ProvisionedAcmeCustody` with public account
binding and policy names. The next credential owner must issue separate,
bounded credentials for the account and CSR policies. For a no-default
AppRole, each role must contain only its corresponding reviewed policy;
neither role receives the other's policy or root/provisioning authority. The
existing live TLS credential remains separate. Credential obtainment, renewal,
revocation and reboot recovery are not implemented by this setup operation.

## Verification boundary

Ordinary tests cover explicit environment/directory/terms admission, optional
contact, immutable hosting binding, custody flags, policy separation and an
incomplete transaction refusing before network access.

The opt-in
`official_openbao_proves_environment_scoped_custody_and_three_separate_authorities`
test uses the verified OpenBao 2.5.5 executable named by
`MARTY_TEST_OPENBAO_EXECUTABLE`. It creates an ephemeral loopback TLS server and
proves real account signing, exact ingress CSR creation, and existing TLS
signing with three separate tokens. It exercises cross-role, cross-environment,
parameter, rotation and export denials, as well as policy drift and unrecorded
key refusal. It never contacts a live ACME CA or creates cloud resources.
