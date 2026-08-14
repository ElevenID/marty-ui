# Status-list native-kernel contract

## Scope

`marty-core/marty-status` is the sole implementation of Token Status List and
Bitstring Status List allocation shape, mutation, compression, and encoded
subject/claim generation. The revocation-profile service continues to own HTTP
and gRPC mapping, Redis persistence, tenant scoping, allocation records, and
publication orchestration until the Phase 3 Rust service cutover.

## Preserved service contract

- Existing Redis records retain their IDs, keys, raw status bytes, sizes,
  versions, timestamps, and allocation counters.
- Token lists remain eight bits per entry by default and preserve all values
  from 0 through 255.
- Bitstring lists remain one bit per entry, with index zero in the most
  significant bit.
- REST and gRPC routes, schemas, status codes, tenant boundaries, and canonical
  publication URLs are unchanged.
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

## Deletion inventory

The superseded Python status-list and revocation-profile service directory is
deleted after the Rust service contract, beta cutover, and soak gate. Rust now
owns the HTTP/gRPC, PostgreSQL, Redis, migration, and status-list implementation.
