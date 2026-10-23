# Authenticated offline verification ingestion

## Contract and evidence boundary

`offline-verification-ingest.v1` is a Rust Organization service contract for
durably accepting the native verifier's privacy-minimized offline reports. It
uses the existing `organization_service.audit_events` PostgreSQL store, the
existing gateway API-key authentication, and the existing Organization service
token boundary. It does not introduce an in-memory collector, a second event
store, or another credential verifier.

The native wire source is pinned to
[`ElevenID/marty-verifier@29e35854d0a34bcd0cc943453ea5d426246b383b`](https://github.com/ElevenID/marty-verifier/tree/29e35854d0a34bcd0cc943453ea5d426246b383b):

- [`crates/marty-reporting/src/events.rs`](https://github.com/ElevenID/marty-verifier/blob/29e35854d0a34bcd0cc943453ea5d426246b383b/crates/marty-reporting/src/events.rs)
  defines the event envelope and verification payload.
- [`crates/marty-reporting/src/reporter.rs`](https://github.com/ElevenID/marty-verifier/blob/29e35854d0a34bcd0cc943453ea5d426246b383b/crates/marty-reporting/src/reporter.rs)
  sends `{"events":[...]}` with a bearer API key and acknowledges its pending
  queue after any successful HTTP status.
- [`src-tauri/src/state.rs`](https://github.com/ElevenID/marty-verifier/blob/29e35854d0a34bcd0cc943453ea5d426246b383b/src-tauri/src/state.rs)
  constructs the reporter without assigning an organization, device, or
  hardware identity. Those event fields are currently null.

The synthetic request in `contracts/offline-verification-ingest.json` freezes
that wire shape for regression tests. It is not deployment or verification
evidence. A receipt proves that an authenticated API key submitted a particular
client-reported result and the server committed it. It does not attest a physical
device, prove a credential was verified correctly, or independently verify the
credential's trust chain.

## Public API and authorization

Let `base` be `/v1/organizations/{organization_id}/offline-verification-events`.
The gateway routes all three operations to the Rust Organization service.

| Operation | Successful response | Purpose |
|---|---|---|
| `GET base` | 200 capability DTO | Confirm this contract and the exact authenticated organization and producer. |
| `POST base` | 200 acknowledgement with immutable receipts | Validate and commit the entire event batch before acknowledging it. |
| `GET base/{verification_id}` | 200 exact receipt | Read one persisted receipt owned by the same organization and API key. |

All three operations require a live, organization-scoped API key with the
explicit `audit:write` scope. The corresponding gateway permission is
`audit:ingest`. `audit:read`, the compatibility scope `admin:full`, and human
membership do not grant ingestion or receipt access. Deployment-profile keys
are rejected because this native wire format supplies no authenticated profile
binding.

The server derives `organization_id` and `producer_id` from the gateway's
authenticated API-key principal. The producer is the API-key UUID. The
Organization service verifies its service token and exact forwarded permission
and tenant, then locks and checks the persisted key row for organization,
expiry, enablement, revocation, explicit scope, and organization scope type.
The lock remains held until the transaction completes, including receipt reads.
Caller-supplied authority cannot replace this identity.

The dedicated receipt endpoint is restricted to the submitting key. A different
key in the same organization receives 404 for that endpoint; another tenant is
rejected with 403. The existing organization audit views retain their existing
authorization over the shared, privacy-minimized audit data. Authentication,
scope, malformed payload, ID conflict, missing receipt,
and persistence failure produce 401, 403, 400, 409, 404, and 503 respectively.
Contract responses use `Cache-Control: no-store`; errors contain fixed codes
and do not echo payloads, tokens, or database errors.

## Privacy and immutable identity

The public pure Rust model in `offline_audit.rs` is the allowlist used before
hashing, persistence, and stored-receipt validation. Unknown fields are rejected
at the batch, event, and payload levels. An event accepts only:

- Version-4 event and verification UUIDs; a timestamp at most five minutes in
  the future; the fixed `verification` event and payload type.
- An enumerated credential type and result, `offline_verified: true`, optional
  two- or three-letter jurisdiction, and enumerated trust-chain category.
- Optional bounded processing time and a boolean biometric result.
- Null `device_id`, `hardware_tier`, `org_id`, and `biometric_score` fields.

No credential, disclosed claims, subject name, portrait, raw biometric data,
biometric score, free-form error text, or payload authority is accepted. Past
timestamps remain possible for offline queues; a receipt is not a trusted clock
attestation. Batches must contain 1–100 events and fit the 128 KiB body limit.
Repeated event or verification IDs within a batch are rejected.

`payload_sha256` is SHA-256 over the UTF-8 JSON serialization of the typed Rust
event, including its envelope. The stable field order is the declaration order
in `OfflineVerificationEvent` and `OfflineVerificationPayload`; UUIDs and UTC
timestamps use their Rust serializer representation. It is not a digest of the
original request text. Different incoming JSON field order has the same digest.

Receipts include only the contract kind, server audit UUID, authenticated
organization and producer UUIDs, event and verification UUIDs, digest, receive
time, and allowlisted event. The server stores that receipt in
`audit_events.metadata.offline_receipt` with event type
`offline_verification.reported` and actor `api_key:{producer_id}`.

Migration `0002_offline_audit_receipts.sql` adds partial unique indexes for
**organization + event ID** and **organization + verification ID**. It runs
under the existing Organization migration transaction and advisory lock.
Startup schema validation requires the indexes. Other audit event types retain
their existing behavior.

An identical retry by the same producer returns the original immutable receipt
with `accepted: 0` and `duplicates: 1`. Changing the payload, reusing either ID
with a different pairing, or submitting an existing ID through another key
returns 409. Key rotation cannot re-account or take ownership of prior events;
there is no automatic cross-key replay or receipt transfer contract. Database
uniqueness also protects concurrent submissions through different keys. Any
failure rolls back the whole batch, including new events that preceded a
conflicting one. The server reads inserted rows back and commits before emitting
a successful acknowledgement.

## D09 deployed receiver adapter

The recorder's `demos/offline-audit-client.js` is a thin contract adapter. Native
Tauri actions still perform offline verification, buffering, reconnection, and
the actual upload. The adapter reads and replays the real receipt; it cannot
substitute a local HTTP receiver or synthesize a successful native result.

An authorized D09 run requires these inputs in addition to its existing pinned
native application, fixture generator, and release evidence:

| Environment variable | Requirement |
|---|---|
| `DEMO_RELEASE_PROBE_URL` | Existing release probe, as a canonical HTTPS URL. |
| `MARTY_DEMO_AUDIT_ENDPOINT` | Canonical HTTPS URL with the same origin as that probe and the exact organization ingestion path. |
| `MARTY_DEMO_AUDIT_ORGANIZATION_ID` | Exact organization UUID for the authorized API key. |
| `MARTY_DEMO_AUDIT_API_KEY` | Explicitly scoped `audit:write` gateway API key. |

Endpoint preflight rejects URL credentials, queries, fragments, IP literals,
local host names, redirects, and a different origin. API keys remain in the
runtime closure and isolated native configuration, are registered as redaction
values, and are absent from retained evidence. Only the owned native runtime is
retired. D09 does not delete deployed receipts or organization resources.

Before the native action, the adapter reads the deployed capability and confirms
that unauthenticated and wrong-organization reads are rejected. It requires an
empty isolated native history and queue. After the visible offline result it
binds the exact new native verification ID and timestamp. Before reconnection,
the queue must hold one event and the deployed receipt must be absent.

After the real native reconnect action, an empty queue alone is insufficient.
D09 reads the exact deployed receipt, verifies its organization, producer,
native verification ID, DTC/valid/X509/offline fields, times, allowlist, and
digest, then replays that exact minimal event. The replay must return one
duplicate, zero new accepts, and the identical receipt; another read must still
match. Only then is the synchronization assertion marked PASS. The retained
`native-offline-audit-receipt.json` contains this bounded evidence and the
observed native queue transition.

The accompanying native `marty-reporting` patch adds an explicit
`api_acknowledgement: "offline-verification-ingest.v1"` policy. It authenticates
the same endpoint's capability and validates the complete bounded receipt batch
before acknowledging any local queue IDs. D09 requires this native configuration
capability and verifies the saved policy; old binaries are refused before the
scenario. The receiver and native client share a frozen wire fixture and digest,
and the client reuses its existing event serializer for correlation. Generic
native API and presigned object-store status contracts remain separate and
cannot qualify this scenario.

## Focused verification and release status

From `rust/`, run:

```sh
cargo test -j2 -p marty-organization --lib offline_audit
cargo test -j2 -p marty-organization --test offline_audit_http --test permission_catalog
cargo test -j2 -p marty-gateway --lib offline_audit
```

The PostgreSQL tests are explicitly ignored by default and must be selected for
this feature's qualification. They fail if their connection is missing or does
not name a loopback database beginning with `marty_offline_audit_test`. They run
the real migration and Axum service against PostgreSQL, create only random
test-owned organizations and keys, and retire their own rows:

```sh
OFFLINE_AUDIT_POSTGRES_TEST_URL=postgres://test-user@127.0.0.1:5432/marty_offline_audit_test \
  cargo test -j2 -p marty-organization --test offline_audit_postgres -- --ignored
```

The three database cases cover concurrent exact replay plus reconnect readback,
conflict rollback, and key/tenant/expiry/revocation/profile authorization,
including cross-key ID reuse and concurrent cross-key submission. Recorder
regressions run directly with Node:

```sh
node test/offlineAuditClient.test.js
node test/offlineFacilityVerification.test.js
node test/offlineInstanceIsolation.test.js
node test/nativeFixtureRetention.test.js
```

Local tests qualify these contracts; they do not establish deployed service,
approved native runtime, or release-video success. Full D09 qualification remains
NOT_RUN until the changed gateway and Organization service are deployed under
the approved release and the actual native journey completes with retained
evidence. The pinned native source originally cleared its queue after any HTTP
2xx response. The accompanying native patch closes that behavior for this
durable ingestion contract, while this server commits before returning 200 and
D09 independently requires exact readback. The new native binary and both
deployed services still require the fresh release qualification.
