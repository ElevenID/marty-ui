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

## Native candidate implementation (not activated)

`credential_renewal.rs` now implements typed source eligibility and the candidate
HTTP owner. It reuses management authentication/tenant response projection and
the existing initiation reservation/projector split. The internal trusted
renewal context is not deserializable public input: it changes only persisted
source/application links, not canonical request hashing or application-claim
resolution. `PostgresCredentialRepository` supplies the source snapshot and
atomic link binding. Neither gateway selection nor production startup/routing
is changed by this candidate implementation.

The governed Rust target intentionally corrects both findings above. Links exist
before delivery (RENEWAL-001); refused/uncertain delivery uses the existing
shared native pending URI (RENEWAL-002). The immutable Python reference still
records the old outcomes. Both encryption modes and pure/mixed keyed rejection
are retained; there is no alternate crypto owner or KMS redesign.

Binding an old unlinked reservation is restricted to pending, unclaimed work
with no issued credential or delivery record and no prior application link.
An exact existing source/application binding can replay; a different source,
application, or idempotency hash cannot overwrite it. A disappeared reservation
retains the legacy named 503 response instead of being mislabeled a 409 conflict.
This deliberately prevents relabeling an already-completed ordinary issuance
whose request hash happens to match a renewal request.

The shared finalizer validates the persisted successor transaction, tenant,
source, and nonconflicting reverse link before external status publication.
Local source/reverse-link updates are checked and committed together. Recovery
accepts an inactive source only when it is revoked and already points to this
exact successor, whose tenant, transaction, and reverse link also match. It does
not allow unrelated revoked credentials, suspended sources, or partial links.
An empty source successor string retains Python's absent-link semantics.

Qualification completed for the candidate admission and repository scope:

- `credential_renewal_behavior`: 29 frozen HTTP scenarios through actual native
  admission/projector with controlled repository/delivery ports; complete DTOs,
  ordered guard reads, complete typed admission transactions, exact ordinary
  idempotency hashes, and declared early-link/pending-URI corrections. Two
  ordinary-then-direct scenarios belong to the separate real delivery gate.
- `renewal_postgres_binding_and_same_successor_recovery_are_fenced`: actual
  published-schema repository/finalizer with explicitly seeded historical rows
  and a controlled authenticated HTTP status publisher. Negative cases preserve
  scoped organization transaction, credential, delivery, and event table
  snapshots; exact same-successor recovery completes pending
  event/delivery projection without republishing revocation. A barrier forces
  two concurrent distinct successors through publication; two external attempts
  are observed but only one atomic database successor wins. This is **not** an
  at-most-once external publication guarantee or an actual wallet-send test.
  This gate has no Canvas application fixture and does not qualify application
  or evidence drift effects. The credential-and-delivery rejection case does
  not independently isolate delivery-only exclusion: the published delivery
  schema requires a credential foreign key.
- `didcomm_renewal_http_composes_real_delivery_and_renewal_links`: eight cases
  cover automatic success, refused delivery, missing holder, and ordinary then
  direct delivery in both encryption modes. These execute the candidate service
  router, fresh admission/reservation, PostgreSQL claim/finalizer, HTTPS wallet,
  and Core encryption/decryption. Historical source rows, control-plane and
  signing peers, status publisher, clock, and seed remain controlled. Actual
  persisted renewal links are checked while the signer is held, before transport;
  this is not a database observation at wallet capture time. Refused delivery
  retains the prepared successor's reverse prelink while leaving the source
  unchanged, without publication, issuance event, or resend. This is not a
  packaged-main or gateway routing qualification.
- Combined qualification passes all 17 DIDComm tests, all 400 issuance library
  tests (including the trusted-context/hash/claim-order guard), three renewal
  HTTP tests, and three initiation HTTP tests. The final configured renewal
  run passes the repository gate, eight-case real delivery gate, and rejected
  publisher-request counter guard together. Strict library/test Clippy, all 19
  workspace package formatting checks, and 155 repository-local reference/CI
  guards pass. These results do not authorize Python deletion or establish
  packaged-main/gateway renewal routing.

## Remaining activation work

Wire the same candidate owner into the complete native HTTP service and qualify
the exact gateway operation. Select
only renewal after review; do not substitute another delivery graph or switch
sibling operations. Delete remaining Python owners only after the
supported consumer/profile audit is closed. No Core or KMS redesign is part of
this migration slice.
