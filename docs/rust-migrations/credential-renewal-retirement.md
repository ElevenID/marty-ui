# Credential renewal: remaining DIDComm caller and frozen evidence

This is reference evidence, not a native renewal implementation or a deployment
approval. DIDComm KMS corrections remain outside this migration slice.

## Why the Python owner is still reachable

`POST /v1/issued-credentials/{credential_id}/renew` remains a legacy gateway
operation. In the pinned Credentials `services/issuance/infrastructure/api/routes.py`,
`renew_issued_credential` (6595) calls the real `initiate_issuance` (6655) with
the original HTTP request, including its idempotency header. Template wallet
configuration can therefore invoke the real automatic DIDComm projector and
delivery helper even after standalone initiation and direct-delivery cutover.
The route attaches renewal/application links only after initiation returns
(6673–6675). Do not remove its reachable encryption/policy/startup requirements
based only on gateway ownership counts.

Base, self-hosted, and Kubernetes legacy issuance consumers also remain a
separate retirement boundary; beta-native selection alone does not migrate
those profiles. Shared Canvas claim/delivery helpers are used by issuance and
other remaining routes, not only the eight migrated operations. This does not
expand the task to all 58 remaining gateway routes.

## Reproducible, bounded reference

`contracts/credential-renewal-python-reference.json` records 31 scenarios with
complete public response bodies, ordered owner/port/repository observations,
and complete transaction, credential, delivery-record, and event snapshots.
The 22 distinct snapshots are losslessly interned by canonical-JSON SHA256;
`#/states/<hash>` references do not omit unchanged fields.

The script verifies ten source blobs at Credentials commit
`87eae30788924921a42848425d315e2f33f7ae41`, including unchanged routes blob
`6b3a7fa0e169862e815bcb6bca64b0b21a5adf6a`, eight imported module origins,
and the actual nonempty native binary SHA256 list for `marty-rs==0.1.60`.
This deliberately preserves the older consumer contract; Credentials PR #275's
later removal of unused decrypt/unpack wrappers does not replace this oracle.

Actual FastAPI routing, API-key authentication, tenant checks, renewal,
initiation/idempotency, projector, direct delivery, renewal finalizer, and
revocation functions execute unchanged. `sys.setprofile` observes their entries;
the repository observer delegates to the original `InMemoryIssuanceRepository`.
That repository copies transaction snapshots but shares stored credential
objects: this is **not PostgreSQL persistence or concurrency qualification**.

Clock/seed, organization/template gRPC, issuer context, credential builder/signer,
status allocation/publication, DID resolution/endpoint policy, and wallet
HTTP/TLS are controlled ports. Original prepared policy and Core packing and
encryption execute with fixed, synthetic X25519 fixtures in both modes. No real
signing key, operator environment, network wallet, TLS trust, or KMS is tested.
Public fixture vectors are recorded constants, not Python key derivation. The
Rust-ownership guard remains unchanged, and exact live replay still matches all
31 cases after this fixture-only replacement.
Actual socket connections/name resolution are denied after the event loop is
created; caught attempts also fail the capture. Import-time environment is
cleared. Five actual clock owners are frozen; timestamps are retained, not
normalized. Only the independently generated Core message UUID is validated
then represented as `$core-message-id`.

Default, repo-local CI guards require neither another checkout nor an installed
legacy native binding:

```text
python -m pytest tests/test_credential_renewal_reference.py
```

Explicit live replay requires the pinned checkout and its Python dependencies,
including the recorded native binding. It is not a default CI gate and does not
silently skip missing prerequisites:

```text
python scripts/capture_credential_renewal_reference.py PATH_TO_PINNED_CREDENTIALS --check
```

Two fresh final captures matched the entire document, including every state
hash. Earlier exploratory captures differed in delivery-record creation time;
freezing the executing delivery-record clock corrected the harness, not the
legacy behavior. Matching counts alone were not accepted as reproducibility.

## Findings retained without silently fixing the oracle

- **RENEWAL-001 — link-after-finalization:** both automatic encryption modes
  enter `_finalize_credential_renewal` with no source credential or application
  link. Delivery issues the new credential; the source remains active, reverse
  renewal linking is absent, and the issued event has no application ID. The
  outer renewal route then attaches transaction links too late. By contrast,
  an ordinary renewal followed by actual direct delivery sees both links in
  the finalizer, revokes the source, and records both credential links. The
  capture preserves this distinction; a governed correction must be explicit
  in the Rust target and tested through the shared owner with PostgreSQL.
- **RENEWAL-002 — refused-delivery projection:** controlled HTTP 503 is returned
  from the actual delivery helper as a failure result, not raised. The renewal
  response remains HTTP 200 with the wallet endpoint URI, while the transaction
  remains pending and no credential/event/delivery record is finalized. A
  missing subject instead yields a pending URI with no send. This differs from
  older projector-only fixtures whose controlled callback raises an exception;
  those fixtures do not establish the real helper's returned-failure behavior.
- Pure and mixed DIDComm wallets retain HTTP 422 for keyed initiation, after
  organization/template/revocation validation reads but before reservation,
  issuer work, signing, encryption, or delivery. Ordinary keyed retry preserves
  the full offer and state; changed source claims produce conflict. The changed
  claims are an explicit scenario input mutation, not a retry side effect.
- Auth/tenant/not-found/status/eligibility guards retain full error DTOs and
  unchanged state. Eligibility includes exact window boundary, one microsecond
  before it, and already-expired source credentials. Direct signing selector
  and malformed idempotency header rejection remain visible.

## Smallest next native slice

Add a typed renewal eligibility/source snapshot and renewal admission owner;
reuse the existing `InitiationHttpService::initiate_authorized`, shared
initiation/projector, Postgres repository, and lifecycle finalizer rather than
creating another delivery graph. Existing `credential_lifecycle.rs` renewal
finalization and repository tests qualify post-issuance linking only, not this
HTTP admission flow. Adjudicate RENEWAL-001/002 explicitly before binding the
new owner to the frozen route. Qualify real persistence, headers/tenant/error
projection, both encryption modes, and link/revocation ordering, then select
only the renewal operation. Delete remaining Python owners only after the
supported consumer/profile audit is closed. No Core or KMS redesign is part of
this reference capture.
