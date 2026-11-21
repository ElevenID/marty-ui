# Owned machine credential authority

`PgOwnedMachineJwtVcAuthoritySource` supplies the concrete
`MachineJwtVcAuthoritySource` used by Delegated Authority's
`MartyNestedJwtVcMachineCredentialVerifier`. It composes the actual Trust Profile
and Issuance PostgreSQL owners and durably retains their exact observations.
This is an opt-in internal composition library. It installs no executable,
public endpoint, proof ingress, protocol advertisement, or production rollout.

## Exact selected profile

The only accepted securing profile is `MartyNestedVc2JwtV1`
(`marty_nested_vc2_jwt_v1`). Its issuer algorithms are ES256 and EdDSA, and its
credential identifier is the canonical lower-case `urn:uuid:<uuid>` already
registered on the full machine. The surrounding credential verifier still
authenticates the issuer signature, the original holder VP signature, subject,
key, nonce, audience, types and signed validity. A source observation alone does
not authenticate a credential or grant authority to execute an operation.

| Owner | Authoritative facts read |
| --- | --- |
| Trust Profile | Current tenant profile, configuration, purposes, lifecycle, issuer entity, issuer relationship, exact public key and separately selected credential-type grants. |
| Issuance | Exact stored credential bytes and hash, current lifecycle, immutable originating transaction correspondence, original template, issuer, subject, reserved identifier, selected nested format and validity. |
| Machine credential source | Exact private observations, complete derived machine scope, selected credential digest, observation times, shortest deadline and committed historical evidence. |

This source does not look up an issuer or key identifier on the network. Those
identifiers select records in the configured owners. It cannot insert an issuer,
change a Trust Profile, administer a credential, or manufacture a full machine.

## Explicit Trust Profile permission

The selected profile must be active and compliant, include `CREDENTIAL_ISSUER`,
support `VC_JWT`, permit the selected algorithm and issuer, and contain exactly
one current registered key matching the protected `kid`. The issuer relationship
must be trusted with a positive trust level. Issuer revocation, suspension,
future validity, expiry, duplicate identities or key ambiguity fail closed.
Removing the key from the authoritative current public-key list invalidates a
subsequent observation of that key.

Each signed non-base credential type needs an explicit relationship metadata
grant in this independent namespace:

```json
{
  "marty_nested_vc2_jwt_v1_authorizations": [
    "MachineCredential",
    "RuntimeMembership"
  ]
}
```

The existing Trust Profile application requires current `trusted-issuer:create`
or `trusted-issuer:edit` permission to create or edit this relationship. Its
metadata validator checks this namespace as well as the existing SD-JWT and
wallet namespaces. Empty or absent grants authorize no types. Duplicate,
unbounded, malformed or base-only grants are rejected. Generic issuer trust and
existing `marty_credential_authorizations_v1` SD-JWT grants cannot authorize a
nested machine credential.

The new owner reads one coherent graph **after** acquiring its dedicated
revision-row lock. Its revision digest covers the existing complete credential
authority basis and these nested grants. A changed or unsupported configuration
still advances the independently named revision before the decision fails.
Existing SD-JWT and wallet authority revisions are unchanged. No public key,
permission or metadata is copied into a shadow issuer registry.

External OCSP, CRL or status-list requirements, custom trust sources, external
verification policy references and other unsupported configuration fail closed.
The selected source always applies live owner status with no stale cache or soft
failure fallback. A Trust Profile that requires `nbf` also requires it in the
stored nested issuer credential.

## Issuance provenance and current status

`PgMachineJwtVcStatusAuthority` joins the actual issued credential to its
originating transaction in one current database statement. It requires the
matching tenant, template, original reserved credential ID, completed issuance
status and issuance time. Stored issuer/subject, signed issuer/subject, protected
key ID and algorithm, exact compact digest, transaction type and credential
types must agree. Stored hash mismatch, orphaned or incomplete issuance,
unrecognized state, missing signed expiration, expired credential or future
status updates fail closed.

The original transaction must select one of Marty's existing nested JWT payload
format identifiers. An explicit `VC_JWT_DIRECT_V1` transaction, a direct JOSE
profile record, a managed SD-JWT artifact or an arbitrary JWT is rejected. The
code explicitly invokes Core's nested profile parser; it does not detect or
fallback between profiles from a submitted token's shape.

This bounded owner supports its own credential lifecycle without external status
references. A nonempty status-list entry, configured revocation-profile reference
or signed `credentialStatus` is unsupported. A credential with any of those
requirements needs a separately qualified status adapter. `SUSPENDED` and
`REVOKED` observations remain negative facts and never produce positive machine
credential authority.

## Durable evidence and deadlines

Every positive source result contains an evidence reference under
`urn:marty:machine-credential-source:sha256:`. Before returning it, the source
commits exact serialized bytes and the corresponding JSON document. The record
contains the complete derived scope, issuer/key selection, exact credential
digest, complete Trust Profile decision basis and revision, original issuance
correspondence, current lifecycle and original time bounds. It excludes raw
credentials, bearer presentations and private keys.

All owner observations are bounded to 30 seconds, and the final deadline is the
earliest original request window, owner window, issuer expiry, signed credential
expiry and stored credential expiry. The enclosing machine verifier additionally
constrains the proof, key, MAP and other selected evidence. Neither waiting for a
lock nor completing retention renews a timestamp. Clocks are checked after owner
calls and after the final evidence COMMIT.

The source's SQL query phases have bounded waits. Only the final transaction
COMMIT is shielded in a narrow spawned task. If an enclosing verifier timeout
cancels the caller during COMMIT, that transaction finishes, the caller obtains
no positive result, and the source performs no automatic retry. A deferred
database trigger independently rejects retention whose original deadline
expires before COMMIT. Audit updates, deletes and truncation are rejected.

Historical retrieval returns a distinct private history type, including the
original bytes and retained timestamp. It has no conversion into current
authority. Access to history must be authorized by the consuming host. A
historical active observation remains historical after credential revocation,
issuer removal, policy changes or machine suspension.

## Installation and privilege separation

Apply Trust Profile migration
`0004_machine_jwt_vc_authority_revisions.sql` through its existing owner migration
chain. Run this crate's `run_migrations` with a separately privileged installation
connection. It applies `0001_machine_credential_source.sql` once and records its
exact migration digest; an unexpected preexisting schema or changed recorded
migration is rejected. Existing migrations are not rewritten.

The runtime constructor accepts three distinct, non-owner connections:

| Connection | Minimum table permissions |
| --- | --- |
| Trust reader | `SELECT` on Trust Profile's `trust_profiles`, `issuer_entities`, `trust_profile_issuers`; `SELECT, INSERT, UPDATE` only on `machine_jwt_vc_authority_revisions`. |
| Issuance reader | `SELECT` on Issuance's `issued_credentials` and `issuance_transactions`. |
| Source evidence writer | `SELECT` on the source's `schema_migrations`; `SELECT, INSERT` on its `observations`. |

Each connection needs `USAGE` on its named schema. Runtime roles must not own
schemas/tables, create objects, inherit a privileged role, hold replication
privileges or membership in PostgreSQL's predefined `pg_` roles, use a
security-definer shortcut, or access unrelated business tables. Column-only privileges are
checked too. `session_user` must equal `current_user`; a privileged login cannot
qualify by temporarily using `SET ROLE` and then regain writes with `RESET ROLE`.
The constructor and every source resolution check effective
permissions, stored migration digest, exact guard function bodies, complete
trigger shapes, exact named evidence checks and the primary key. Removing or
weakening an audit guard or expanding a runtime role causes a subsequent
operation to fail closed.

```rust,ignore
let authority = Arc::new(
    PgOwnedMachineJwtVcAuthoritySource::connect(
        trust_reader_pool,
        issuance_reader_pool,
        source_evidence_writer_pool,
    ).await?,
);
let credentials = Arc::new(
    MartyNestedJwtVcMachineCredentialVerifier::new(authority),
);
```

The host must obtain these pools from trusted deployment configuration and
compose the current full-machine/MAP source, any MAP-required attestation,
machine authorization, original Flow challenge and aggregate audit. Passing a
pool or constructing this library does not authenticate a network caller or
qualify the deployed owner channels.

## Validation

The unit contract test checks strict independent type grants. The PostgreSQL
tests create fresh owned databases, run the actual owner migration chains,
provision separate runtime roles and generate ephemeral P-256/Ed25519 key pairs.
They exercise both real issuer/holder signatures against the resolved owner key,
current revocation and profile/issuer/key changes, exact artifact and issuance
correspondence, cross-tenant rejection, revision changes, privilege drift,
retention immutability, delayed COMMIT expiry, and caller cancellation during a
live COMMIT.

The composed gate test uses actual Organization machine registration/MAP state,
actual Trust Profile and Issuance credential owners, actual Organization Cedar
policy records, MMF evaluation, source evidence and aggregate machine audit.
The original Flow challenge and grant/authority/lifecycle are fixture inputs;
the grant is intentionally pending because this test exercises machine proof,
not approval or operation authorization. It proves that the new source owners
compose into the concrete cryptographic machine gate. It does not qualify
consent, a deployed proof ingress, an attestation service or a final-use host.

From `rust/`, with an explicitly disposable PostgreSQL administrative URL:

```sh
MACHINE_CREDENTIAL_SOURCE_TEST_DATABASE_URL=postgresql://... \
  cargo test --locked --offline -p marty-machine-credential-source --lib \
  -- --ignored --test-threads=1
```

The tests use created database/role names made only from fixed prefixes and
fresh UUID hex. They do not connect to a production issuer, reuse production
keys, claim hosted environment qualification, or dispatch GitHub Actions.
