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

The service refuses to start unless `_marty_rs` reports the `status_list`
capability and exposes raw-byte constructors plus canonical encoders. Native
diagnostics are available at `/health/native-backend`. There is no Python
mutation or compression fallback. Rollback redeploys the preceding immutable
beta image and never selects a second runtime implementation.

## Deletion inventory

This slice removes Python bit mutation and zlib/base64 status encoding from
`services/revocation_profile/status_list_manager.py`. Redis and API adapters
remain intentionally. The remaining Python service is deleted only after the
separate Rust revocation-service contract, beta cutover, and soak gate pass.
