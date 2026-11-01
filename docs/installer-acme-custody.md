# ACME enrollment configuration and initial custody

The configuration and custody modules provide the installation owner's inputs
for ACME enrollment. The [host transaction](installer-acme-host.md) connects them
to an explicitly selected ACME hosting source and the separately scoped
credential owner. Custody setup itself does not activate certificates, change
the installed origin, or migrate an existing key.

## Explicit enrollment inputs

`AcmeParameters::parse` accepts a bounded JSON object with duplicate-key and
unknown-field rejection. A staging example is:

```json
{
  "environment": "staging",
  "directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "profile": "shortlived",
  "terms_url": "https://letsencrypt.org/documents/LE-SA-v1.8-July-06-2026.pdf",
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

Resource names distinguish staging from production even for the same
installation identifier. The current host selection remains immutable: changing
its recorded environment is not an admitted operation. Fresh staging and
production trials therefore use separate installations. Account and ingress
SPKI must differ. There is no account-key or certificate-key export path.

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
binding and policy names. The [separate credential owner](installer-acme-credentials.md)
uses one narrow AppRole management policy per purpose and issues operation tokens
containing only the corresponding account or CSR policy. The owner roles cannot
sign or change custody, and the operation tokens cannot manage credentials. The
existing live TLS credential remains separate. Credential refresh and recovery
belong to that separate module, not this key/policy setup transaction.

## Fixed-container custody transaction

The rootless host never reads or chowns OpenBao state to obtain `root.token`.
`installer_acme_custody` also exposes a split API for the authenticated setup job:

1. `prepare_for_install(state, configuration, ingress, bao)` verifies the current
   hosting binding and public cluster identity without root. It durably records
   the original custody intent plus `acme-custody-E-plan.json` and returns a
   `CustodyResourcePlan` with retained ingress SPKI and the exact intent digest.
2. The fixed container helper admits those public bytes through
   `CustodyResourcePlan::parse_authenticated(bytes, expected_plan_sha256)`.
   The expected digest comes from the host's independent setup evidence. The
   helper calls `provision_resources(plan, bao, root)` without acquiring the
   host's flock. Resource names, versions, and exact policies are derived from
   the admitted plan; there are no policy or resource-name overrides.
3. `PublicCustodyOutput::write_public_transfer` writes exactly `plan.json` and
   `custody.json` as public 0600 files in an empty 0700 output folder. The result
   contains a strict whitelist of public Transit metadata and exact policy
   readback. It contains no private key, root token, RoleID, SecretID or workload
   token.
4. After authenticating the completed fixed job, image and transfer ownership,
   the host calls `admit_for_install(state, configuration, ingress, plan,
   transferred_path)`. It compares the exact saved intent and plan, reconstructs
   the admitted key binding, and records the public output plus the existing v1
   custody completion. It needs no bootstrap root authority and does not advance
   installer phase.

This public admission records the authenticated helper's observations. The next
credential transaction independently re-reads the actual account/ingress key
metadata and exact ACLs using scoped owner logins before returning usable
credentials. The two one-shot transactions therefore preserve the original
ingress SPKI, establish the new account SPKI exactly once, and keep root authority
inside the container throughout. Partial setup and unrecorded resources remain
explicit recovery holds; neither helper transaction repairs or replays them.

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

The separate credential integration proof also exercises this complete helper
split before credential provisioning: host intent, independently hash-admitted
public plan, actual OpenBao resource creation, public-only output transfer, and
host admission. Focused helper tests reject altered identities, environments,
agreements, unknown overrides, and non-public metadata in transferred output.
