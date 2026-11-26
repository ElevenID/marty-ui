# Verification before issuance

The `managed_sd_jwt_dcql_same_holder_v1` profile binds a saved credential
template to a managed SD-JWT/DCQL verification. Issuance reserves the complete
issuance intent before starting verification. Redemption requires fresh owner
evidence and a native holder proof from the same key that completed verification.

This profile supports one `SD_JWT_VC` output with `OID4VCI_PRE_AUTH`, an
authenticated initiating user, and a configured single-credential DCQL Flow.
The initiating user's membership authorizes starting that Flow; the wallet's
cryptographic proof establishes the holder relationship. An API key without a
user identity cannot initiate this profile. Templates using authorization code,
DIDComm delivery, application approval, renewal, JWT-VC, mdoc, or wallet format
variants are rejected when they select this prerequisite.

## Configure the owners

Apply the native Issuance and Credential Template migrations, then run versions
of Flow, Presentation Policy, Gateway, Credential Template and Issuance that
understand this profile. Keep the existing managed Policy owner channels and
authenticated Flow-to-Policy gRPC connection configured. Flow also needs its
existing managed HTTPS listener with a non-exportable TLS signing identity.

Roll out the updated Flow readers before the updated Policy producer. Policy now
retains the native verification observation at microsecond precision so a fresh
verification cannot appear to precede an intent created earlier in the same
second. Older Flow readers reject those precise observations. Valid historical
whole-second records remain readable; JWT epoch seconds derive from the same
sample, and strict intent ordering and exclusive deadlines remain enforced.

| Service | Setting | Purpose |
| --- | --- | --- |
| Flow and both native Issuance aliases | `FLOW_ISSUANCE_SERVICE_TOKEN_FILE` | Dedicated shared capability, at least 32 bytes, distinct from existing service, signing, webhook and issuance credentials. |
| Issuance | `FLOW_PREREQUISITE_OWNER_URL` | Fixed HTTPS origin of Flow's managed listener. Paths, credentials, fragments and query parameters are rejected. |
| Issuance | `FLOW_PREREQUISITE_OWNER_CA_FILE` | Explicit PEM CA bundle for that listener. |
| Flow | `MANAGED_AUTHORITY_HTTPS_ADDR` and `MANAGED_AUTHORITY_TLS_*` | Existing remote signer TLS configuration; no local private-key fallback. |

Issuer clients disable ambient proxies, redirects and system trust roots for
this owner channel. Partial configuration fails startup. Missing configuration
leaves ordinary issuance available while prerequisite issuance fails closed.
The raw token environment alternative is supported for the service token;
configuring both the token and its `_FILE` source is rejected.

For the existing beta Compose stack, add
`docker-compose.issuance-prerequisite.yml` after the base and beta files and
provide the dedicated token file. This opt-in overlay reuses the existing
Flow server certificate, non-exportable Transit key and workload CA. It mounts
the new capability only into Flow and both Issuance aliases and publishes no
owner port. The certificate must cover the configured `flow` hostname. Other
deployments can apply the same service settings and read-only secret mounts.

## Select the saved verification

Create or update a Presentation Policy with
`"prerequisite_evidence_profile": "managed_sd_jwt_dcql_v1"`. Its existing
managed-profile admission checks require supported SD-JWT/DCQL semantics,
holder binding, and governed issuer/trust/status authority. Activate the policy
and its Flow definition. Read the active policy's `policy_revision` through
`GET /v1/presentation-policies/{id}`. Copy the returned ID, version and content
digest unchanged; a matching ID alone is insufficient.

On a draft Credential Template, select an existing issuer identity and
compliance profile, one `SD_JWT_VC` format, `OID4VCI_PRE_AUTH`, no wallet variants,
and `validity_rules.renewable: false`. Add this configuration using real IDs and
the complete policy revision from readback:

```json
{
  "verification_prerequisite": {
    "profile": "managed_sd_jwt_dcql_same_holder_v1",
    "flow_definition_id": "saved-flow-id",
    "flow_definition_version": 1,
    "policy": {
      "id": "saved-policy-id",
      "version": 1,
      "content_digest": "sha256:<64 lowercase hexadecimal characters from policy readback>"
    },
    "verifier_issuer_did": "did:web:verifier.example",
    "ttl_seconds": 300
  }
}
```

The placeholder digest above is explanatory and will fail validation. The
allowed TTL is 60–900 seconds. It bounds the intent, verification and continuation;
the existing offer lifetime may shorten it further. Credential, holder and
authenticated owner deadlines also apply. A declared external-status lease is
an independent bound. Both its signed expiry and its own observation's configured
revocation grace can shorten the continuation even when the template TTL and
managed owner observations last longer. Omission on a sparse patch preserves the
selection. Explicit `null` is rejected. Once the template leaves
draft, its prerequisite cannot be removed or rebound; create a new version for
a new policy or Flow revision. Changing those owners requires an intentional
template version update because the frozen selection will otherwise fail.

The public create, update, readback and gRPC template contracts preserve this
configuration. Gateway also exposes the managed policy profile and its read-only
revision. Existing console API adapters retain these fields. Configuration uses
these APIs; there is no new console configuration wizard in this change.

## Initiate, verify, and redeem

Call `POST /v1/issuance` as the authenticated user with the saved template and
normal issuance claims. Supply no evidence, verification result or replacement
policy. The saved template determines whether the prerequisite applies.

The normal initiation response additionally contains `verification_prerequisite`:

```json
{
  "contract": "marty.issuance-prerequisite-start-response/v1",
  "intent_digest": "sha256:<digest>",
  "flow_instance_id": "reserved-instance-id",
  "request_uri": "https://verifier.example/v1/flows/instances/reserved-instance-id/request",
  "qr_data": "openid4vp://authorize?client_id=...&request_uri=...",
  "expires_at_epoch_micros": 1800000300000000
}
```

Present `qr_data` to the holder, complete the signed verification request, then
redeem the ordinary credential offer with the same holder key. The wallet launch
is checked to reference exactly the returned HTTPS request URI. Clients should
make this verification step visible before asking the holder to redeem. The
response contains no private Policy evidence, signing capability or standalone
pre-authorized code in Gateway's management projection.

Issuance acquires evidence directly from Flow's authenticated owner endpoint. It
checks the complete original issuance intent, policy revision, principal,
organization, Flow instance, native holder thumbprint and exclusive validity
deadline. Under the issuance transaction lock it samples a fresh database clock,
reserves a credential identity, and consumes the immutable continuation in the
same transaction that claims signing. Concurrent redemption has one winner.
A completed retry returns the existing credential; it cannot mint another
credential or renew the consumed authority. An expired or rejected prerequisite
requires a new issuance attempt and fresh verification.

## Database rollout and qualification

Issuance migration `0018_verification_prerequisites.sql` installs the immutable
intent, continuation and authorization-route guards. Credential Template
migration `0005_verification_prerequisite.sql` validates the policy shape and
requires those exact enabled guards before writing prerequisite templates.
Additive Issuance migration `0020_verification_prerequisite_template_locks.sql`
retains the invoker trigger and delegates its two exact template row locks to a
narrow source-owner function. This permits a restricted Issuance LOGIN to hold
the required locks without receiving template UPDATE authority. Credential
Template migration `0006_verification_prerequisite_template_locks.sql` pins the
revised guard and the helper's exact body, owner, security mode, search path and
closed ACL. The historical migration bytes remain unchanged.
Startup checks validate the deployed trigger/function/constraint shapes;
disabled or replaced enforcement is rejected. The private
`prerequisite1_*` storage status keeps unaware readers from treating a guarded
template as an ordinary active template. Public lifecycle values remain the
standard draft/active/deprecated/archived values.

Deployment must install the Issuance guards before enabling templates. An older
writer cannot omit the intent, retarget the immutable dataset, attach an
authorization session, or reset a consumed signing claim. Rolling back binaries
does not remove the database guards. Do not drop them to make an older binary
accept these records.

The existing retention transaction preserves active prerequisites and in-flight
signing rows, including their events and credentials. It may remove a consumed
continuation only for a terminal parent whose immutable intent and continuation
have both expired. The guard locks the actual parent, checks its exact binding,
then samples the database clock. Eligible continuation and parent cleanup occurs
in one retention transaction. Expired authority cannot be reopened or reused,
and unrelated legacy retention continues normally.

The focused Flow database test covers authenticated owner routing, idempotent
concurrent starts, exact selection, immutable private context, signed wallet
request progress and expiry while row-locked. Issuance tests cover missing and
changed intent, unsupported writers, exact owner response parsing, native holder
binding and continuation consumption. The joined
`live_keyless_managed_policy_evidence` fixture executes native Policy verification,
Flow evidence persistence, the real HTTPS acquisition client, PostgreSQL signing
claims and `HttpCredentialBuilder` with an isolated non-exportable OpenBao
Ed25519 key. It checks positive issuance, wrong holder, absent completion, replay,
concurrent signing and expiry during a lock wait. Its issuer-signed HTTPS status
list exercises a shorter external lease while the managed owner observations
remain valid, proving that external expiry reaches the signing admission check.
Native clock tests also cover an older external observation whose configured
revocation grace ends before the managed owner's freshness window.
CI selects the database and KMS-backed obligations explicitly so an ignored test
cannot count as qualification.

These tests qualify this profile's component composition. They do not establish
installed-wallet interoperability, deployment acceptance or an official external
conformance result. The wider crypto capability plan retains its independent
profile and interoperability gates.
