# External observation bytes to the core journal

Status: implemented decoder and core-side composition, not a mounted public
Gateway route. No production authority adapter, scope provisioning, startup
migration, EvidenceFact conversion, approval or worker cutover is enabled.

## Enforced path

`external_observation_wire::decode_submission` accepts original HTTP body bytes
and headers. `external_observation_ingress::submit_observation` calls that decoder
before acquiring a database connection, then passes the typed observation and
its already-checked idempotency identity to the transactional journal.

The caller supplies `ProducerIdentity` only after successful Common Gateway
API-key authentication. The decoder never creates a principal, reads an API key,
or trusts forwarded organization/key/scope headers. The journal independently
loads and locks canonical authority and applies the admission kernel. Valid
syntax does not authorize a claim, verify an assertion or permit issuance.

The connector continues to use only the Common Gateway with its own scoped API
key. It must not import these core modules or access the journal's database.

## Original-byte validation

The envelope is one object with exactly the seven candidate-schema fields.
Unknown fields, duplicate names (including Unicode-escaped equivalents), missing
fields, arrays in place of objects, invalid UTF-8, unpaired surrogates, and trailing
non-whitespace data are rejected. Do not pre-parse into `serde_json::Value`:
ordinary object decoding would already have lost duplicate member information.

Revision, sequence and timestamp fields require positive integer JSON tokens
within JavaScript's safe integer range. Numeric strings, decimal/exponent tokens
for these fields, zero and unsafe values are rejected. Effective time cannot
exceed observation time. Claim numbers are finite and bounded by the same safe
magnitude; integer tokens are checked before conversion. Decimal claims retain
the admission kernel's IEEE-754 representation, not arbitrary decimal precision.
Nonzero underflow to zero is rejected.

The production service enables `serde_json`'s `raw_value` and `arbitrary_precision`
features. Claim values therefore use borrowed raw tokens, not a generic number
visitor that might confuse an actual object with serde's private number-map
representation. Arrays, objects and fabricated private number/raw-value objects
are rejected. This uses existing production features, not a new dependency.

Claims are a nonempty object with at most 32 unique ASCII names, each at most 128
bytes. Strings must be nonempty, at most 512 UTF-8 bytes, and free of Unicode
control characters. The binding's exact allowlist, reserved-name rules, types,
and numeric ranges are still applied by core admission, including on retries.

The whole original body, including whitespace, is bounded to 65,536 bytes.
JSON Schema cannot express all lexical constraints: duplicate members, byte
limits, integer-token spelling and header rules belong to the byte decoder.

## Headers and framing

Require one `Content-Type: application/json`; an optional single UTF-8 charset
parameter is accepted. Other media types/parameters and repeated values fail.
Content encoding must be absent or a single `identity` value. No compressed-body
expansion is performed. `Idempotency-Key` must occur exactly once and equal the
original observation ID without whitespace, comma joining or substitution.

Duplicate Content-Length/Transfer-Encoding values, combined length/transfer
framing, mismatched declared length, unsupported transfer coding and declared
trailers are rejected. The only supported transfer value here is `chunked` after
the HTTP server has decoded its framing. This does not replace HTTP server or
reverse-proxy request-smuggling defenses.

All returned errors are fixed codes/messages. They contain no parser diagnostic,
raw claim, URL, header value or credential. API error responses must preserve
that redaction when the public handler is implemented.

## Test composition

The focused PostgreSQL harness compiles these exact production modules with the
workspace's existing dependency declarations and feature overrides. Its lock
check still requires every resolved registry version/checksum to be present in
the production lockfile. It adds no core source dependency to the connector.

The existing journal fixture and all its tests remain byte-for-byte unchanged.
The isolated harness appends a child test module to a temporary copy of that
fixture, so new byte-to-journal cases reuse the existing private synthetic
authority and real PostgreSQL setup rather than duplicate a second adapter.

Tests cover raw duplicates, escaped aliases, private-number-object spoofing,
header ambiguity, UTF-8 bounds, numeric limits, semantic retries, no database
access on malformed input, ignored identity headers, current scope/revocation
checks and binding claim restrictions. Synthetic fixture identities are not
proof of real Gateway API-key authentication. No live HTTP endpoint or streaming
body enforcement is asserted by these tests.

## Remaining activation gates

Before mounting a public route, implement the canonical authority/revocation
adapter, administrator-controlled grants/bindings, public scope provisioning and
reviewed schema migration. The real Gateway must authenticate the API key before
invocation, bound body streaming before allocation, reject unsupported request
methods/trailers and forward only authenticated identity. Prove tenant, source,
scope, revocation, idempotency and audit behavior through that actual route.

A receipt remains an unsigned producer attestation. Explicit evidence-policy
admission and isolated OB3/network-denial acceptance are still required before
switching the Canvas worker or deleting its old implementation.
