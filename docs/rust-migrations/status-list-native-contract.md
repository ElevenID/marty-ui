# Status-list native-kernel contract

## Scope

`marty-core/marty-status` is the sole implementation of Token Status List and
Bitstring Status List shape, mutation, compression, and encoded subject/claim
generation. The Rust revocation-profile service owns transport mapping,
PostgreSQL allocation records, tenant scoping, Redis status-list bytes, and
publication orchestration.

## Preserved service contract

- Existing Redis records retain their IDs, keys, raw status bytes, sizes,
  versions, timestamps, and allocation counters. The released Redis counter is
  imported as a nondecreasing floor so an upgrade cannot reuse an index.
- Credential-to-index allocation rows are immutable scope tombstones. Profile
  deletion does not erase them, so a stable credential ID cannot later be
  rebound to another organization, profile, or status-list format.
- Allocation high-water marks also survive profile deletion, preventing index
  reuse if an archived profile identity is restored.
- During the compatibility release, both the legacy identity-less endpoint and
  the credential-aware reservation endpoint use the same PostgreSQL counter.
  Legacy calls receive synthetic owners and retain their released one-index-per-
  call behavior without racing the durable allocator.
- Token lists remain eight bits per entry by default and preserve all values
  from 0 through 255.
- Bitstring lists remain one bit per entry, with index zero in the most
  significant bit.
- The new internal HTTP `/reserve-index` request requires `credential_id`.
  Repeating that ID in the same organization/profile/format returns the same
  index; attempting to reuse it in another scope fails closed.
- The existing `/allocate-index` HTTP and gRPC contracts remain available only
  for a two-phase rolling upgrade. Credentials moves to `/reserve-index` before
  those identity-less compatibility routes are retired.
- Publication routes, tenant boundaries, status mutation behavior, and
  canonical publication URLs are unchanged.
- The existing 131,072-entry default satisfies the W3C privacy floor.

## Corrected standards behavior

- Token Status List bytes use the canonical zlib-wrapped DEFLATE encoding.
- W3C `encodedList` values use GZIP and the required `u` base64url multibase
  prefix. The prior Python path incorrectly emitted zlib bytes without the
  multibase prefix.
- Persisted bytes are length-checked by Rust before every mutation, lookup, or
  publication. Malformed state fails closed.

## Native and rollback behavior

The Rust service imports the canonical `marty-status` crate directly. Native
diagnostics are available at `/health/native-backend`. There is no Python
mutation, compression, transport, persistence, or orchestration fallback.
Rollback redeploys the preceding immutable image and never selects a second
runtime implementation.

## Allocation durability

Allocation ownership is durable in PostgreSQL, not Redis. A migration
backfills issued credential/status metadata and initializes per-scope counters.
New reservations use a global credential advisory lock plus a profile-row lock,
with uniqueness constraints on both credential identity and scope/index. This
makes concurrent retries atomic and process-crash recovery deterministic while
leaving Redis responsible only for status-list publication state and the
upgrade compatibility floor.

## Deletion inventory

The superseded Python status-list and revocation-profile service directory is
deleted after the Rust service contract, beta cutover, and soak gate. Rust now
owns the HTTP/gRPC, PostgreSQL, Redis, migration, and status-list implementation.
