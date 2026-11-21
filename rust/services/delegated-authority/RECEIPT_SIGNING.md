# Managed delegated decision receipt signing

## Status and scope

`HttpManagedDelegatedReceiptSigner` implements the existing
`DelegatedDecisionReceiptSigner` boundary. It resolves an explicitly configured
managed issuer key, signs through Signing Keys, and independently verifies the
returned ES256 or Ed25519 signature against the configured public key. It holds
no private key and never accepts issuer, provider URI, key reference, JWK or
signing authority from a delegated-use command.

This batch does not select the adapter in an executable delegated-use host,
expose a use route, change human command-host roles, advertise public delegated
capabilities, provision a provider key, or enable a deployment. The default
Signing Keys origin set and public key-purpose catalog remain unchanged.

The wire receipt continues to use the pinned Protocol profile
`urn:marty:delegated-decision-receipt:v1` and JWS type
`mip-delegated-decision+jws`. `DELEGATED_DECISION_JWS` is an internal Signing Keys
profile selector; it does not define a new Protocol wire profile.

## Explicit configuration

A future host must construct one `ManagedDelegatedReceiptKey` from trusted
configuration containing the nonnil tenant UUID, complete typed issuer
principal, issuer DID verification-method ID, exact provider key reference,
algorithm (`ES256` or `EdDSA`) and minimal public JWK. The constructor accepts
only EC/P-256 public coordinates or a strong canonical Ed25519 public key.
It rejects private fields, mismatched key types, malformed points and a `kid`
outside the configured issuer DID.

Construct `HttpManagedDelegatedReceiptSigner::new` with:

- A fixed HTTPS Signing Keys root origin, with no credentials, path, query or
  fragment. Normal TLS certificate validation is mandatory. There is no
  production plaintext mode, redirect following, proxy discovery or automatic
  retry.
- A resolver credential corresponding to the existing
  `SIGNING_KEYS_INTERNAL_API_KEY`, and a **different** signing credential
  corresponding to `SIGNING_KEYS_ISSUER_SIGN_KEY` (or its existing `_FILE`
  source). Each supplied credential must be 32–1024 nonspace ASCII bytes.
- The configured public-key/tenant/issuer pin.
- A real `GrantMinter` explicitly selected using
  `GrantAuthority::minter(SigningOrigin::DelegatedDecision, ...)`. A
  GatewayService, issuance, wallet-request or demo-holder minter is rejected
  before a signing request is sent.

No environment variables for the future delegated-use host are invented here;
its eventual startup code must load and validate the above values. No adapter
constructor is called by an existing production host in this batch.

The existing internal API key also protects internal configuration operations;
this adapter does not create a resolver-only network role. Before a live host is
selected, its credential provisioning must account for that existing authority
and introduce a narrower resolver role if the deployment requires it. The
separate receipt MAC origin is still mandatory and cannot be replaced by the
resolver or issuer-sign API credential.

### Signing Keys verification gate

`MARTY_DELEGATED_RECEIPT_SIGNING_ENABLED=true` installs the dedicated origin in
Signing Keys' existing signing-grant verifier. Absent or `false` preserves the
original origin set. Other nonempty values fail startup configuration parsing.
Enabling this switch alone does not create a receipt key, issuer profile,
credential or public endpoint.

For OpenBao, use the existing `MARTY_SIGNING_GRANT_PROVIDER=openbao-transit`
selection (also the existing default), mounted HTTPS `BAO_ADDR`, `BAO_CACERT`
when required, and `SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE`. Provision the new,
non-exportable MAC key named exactly:

```
marty-sign-grant-delegated-decision-v1
```

The delegated-use process needs a distinct mounted mint token with update
permission only for
`transit/hmac/marty-sign-grant-delegated-decision-v1/sha2-256`.
Signing Keys' verification token needs update permission for
`transit/verify/marty-sign-grant-delegated-decision-v1/sha2-256` in addition to
its existing verify permissions. Mint and verify policies must stay separate;
the receipt signer must not inherit another origin's mint permission. The
existing token-file reader reloads the scoped credential for each operation.
This batch does not provision keys or policies or reuse the signing key as a
MAC key.

For AWS, set `MARTY_SIGNING_GRANT_PROVIDER=aws-kms` and the existing absolute
`MARTY_SIGNING_GRANT_AWS_CONFIG_FILE`. Its
`marty.aws-signing-grant-authorities/v1` object accepts the optional additional
field `keys.delegated_decision`. Supply a distinct immutable regional KMS key
ARN. The configuration decoder rejects duplicate origin ARNs, unknown or
duplicate fields and invalid ARNs. Selecting the receipt verifier without this
field fails; legacy configurations may omit it. IAM mint/verify authority must
be restricted to this key and the appropriate MAC operation. The provider
selection never falls back to another origin.

### Receipt signing key and issuer profile

Explicitly register a remote-custody service and receipt-only key under the
correct tenant. The standard `managed-openbao-transit` projection and its
automatic key prefixes are unchanged; they do not gain this purpose. A separate
registered OpenBao service uses its own scoped provider authentication through
the existing encrypted registry-auth mechanism. Other supported remote custody
providers follow their existing credential and key-registration rules.

The required binding is:

| Field | Required value |
| --- | --- |
| Service `key_purposes` | Explicitly includes `delegated_decision_signing` |
| Service `credential_formats` | Explicitly includes `mip-delegated-decision+jws`; wildcard is insufficient |
| Key reference's registered purposes | Exactly `["delegated_decision_signing"]` |
| Active issuer profile `key_purpose` | `delegated_decision_signing` |
| Active issuer profile `credential_format` | `DELEGATED_DECISION_JWS` |
| Algorithm | Configured `ES256` or `EdDSA`, consistent across all bindings |
| Tenant, issuer DID, verification-method ID and key reference | Exact configured values |
| DID method public key, provider public key and configured public JWK | Same public key |

Service normalization can derive the receipt wire format only when that
purpose was explicitly requested. Registry writes reject a key binding that
mixes receipt signing with another purpose. Profile validation and the final
service-signing kernel both reject receipt-key reuse for other purposes,
missing bindings, unsupported algorithms and absent explicit wire capability.
The receipt profile is excluded from the existing public issuer-identity
selection; the public purpose catalog does not acquire a new entry.

Do not repoint an existing pin silently during rotation. Provision and validate
the replacement profile/key separately, then select its complete pin in trusted
host configuration. A current resolver response that changes any pinned value,
revokes the profile or falls back to public DID discovery is denied.

## Boundaries enforced during a call

The adapter first resolves through the existing authenticated
`/internal/compat/resolve-issuer-did` endpoint. It validates the active
organization-scoped profile, resolver provenance, exact purpose and public key.
It resolves again after receipt preparation so an earlier key resolution cannot
hide a changed profile. Signing Keys repeats current profile, key and registry
checks in its existing issuer-signing path.

Before minting, both the adapter and shared signing-grant purpose guard parse
the exact `base64url(header).base64url(payload)` input. They reject duplicate
JSON members, unknown fields, malformed or noncanonical encodings, unsafe
numbers, mismatched issuer/key/tenant/receipt ID, inconsistent grant and domain
bindings, and invalid evidence/time relationships. PERMIT requires ACTIVE grant
status; DENY is a signed policy outcome, not an authorization to perform the
operation. The decoder validates transcript structure and correspondence; it
does not replace source authentication, verified proof creation or Cedar
evaluation.

The dedicated grant binds origin, route, receipt ID, tenant, issuer DID, key
reference, purpose, algorithm and SHA-256 of the exact input. It authorizes only
`/internal/compat/issuer-dids/sign`. Existing gateway, issuance and Flow origins
cannot authorize the receipt purpose. Signing Keys consumes the one-use grant
through the existing Redis store before provider signing, and checks the
consumed grant against the final key/payload binding at the KMS boundary.

The adapter also validates the returned issuer, `kid`, algorithm, public key and
payload length, then cryptographically verifies the signature over the exact
input. ES256 DER and raw transcoding must agree; output uses the JOSE 64-byte
form with low-S normalization. Ed25519 verification uses strict verification
and the pinned strong canonical public key. Shape-only, substituted-key or
invalid-signature responses fail. Responses are limited to 256 KiB and each
HTTP operation has a five-second deadline.

There is no automatic retry after a timeout, provider error or replay denial.
The retained FINALIZE_USE owner must keep its existing command reservation and
reconcile uncertainty according to that retained-command contract. A signing
failure must not trigger a fresh command identifier, grant or policy evaluation
that could turn a retained DENY into PERMIT.

The current profile observations are not a distributed transaction with
external authorities. The finalization owner must still recheck grant revision,
proof/status/domain freshness, current policy source and receipt deadline before
its atomic retained-result/reuse-guard commit. The signature provides evidence
of an evaluated decision; it does not attest that a downstream side effect
occurred.

## Validation and remaining qualification

Local tests cover the receipt-purpose guard, default-off configuration,
exclusive registry/profile/final-key bindings, and the HTTP adapter with real
ES256 and Ed25519 signatures. Negative cases cover origin substitution, tenant,
issuer and key changes, revoked profiles, public fallback, malformed transcripts,
invalid or substituted signatures, replay denial and single-attempt uncertain
responses. Tests use generated in-memory keys and synthetic transcripts; the
production constructor never accepts local private keys or test minters.

The HTTP fixture models the existing Signing Keys contract and the replay-denial
response. It does not constitute a live OpenBao/AWS or Redis receipt-origin
qualification. That managed deployment test, scoped IAM/Transit policies,
operator-owned provisioning, and executable host composition remain required
before selecting this adapter for live traffic. No public capability
qualification is claimed by these local tests.
