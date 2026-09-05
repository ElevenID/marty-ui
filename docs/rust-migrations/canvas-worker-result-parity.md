# Canvas worker lossless result projection

## Frozen source and reproduced gap

Credentials PR #259 merged at `85329f647c1d8c51ad709f1eed97cedcb3bb6464`.
Its result oracle observes Python worker blob
`b516ed3d0855f16e9ec899a452a22df49d2cafe5`. The copied fixture
`contracts/canvas-worker-result-oracle.json` is byte-identical to that protected
fixture (Git blob `e3d831c653a3833c3e05a5c0bd3699e104e97cc4`).

Before this fix, the Rust replay on UI base
`1866528ab859ea7007ca34671ad80a62131fd79d` reproduced 34 mismatches: positive
integers beyond u64 were omitted instead of retained, and negative integers
below i64 were omitted instead of clamped to zero, across all 17 allowed fields.
Comparing serialized output with the original expected JSON text is essential:
parsing both sides through a lossy numeric representation can hide rounding.

## Implementation boundary

`CanvasSyncResult` carries validated raw JSON values from the processor port,
through the existing `safe_result` allowlist, to the lease-fenced PostgreSQL
completion write. It is a JSON object, not a JSON-encoded string at rest.
Native typed processor results use one conversion helper. Any JSON-facing
processor must deserialize the original bytes directly into `CanvasSyncResult`,
not round-trip incoming counters through `serde_json::Value` first.

The projection retains booleans and null, clamps negative integer lexemes to
zero, preserves positive integer digits, and truncates strings at 200 Unicode
code points. Floats (including integral and exponent forms), arrays, objects and
unknown fields remain omitted. Object member order is not a behavioral contract.

Only the `raw_value` feature is requested by issuance. Do not enable global
`arbitrary_precision` as a shortcut: the reviewed serde_json implementation
changes generic Number serialization to a private struct representation, which
would broaden the change into consumers of shared JSON/CBOR/crypto dependencies.
No dependency version, core pin, lockfile, cryptographic implementation,
deployment routing, database schema or Python runtime changes are needed here.

## Evidence and remaining gates

- The actual Rust projection replays all 483 field/value JSON cases, plus the
  empty and complete allowlist cases, without skipping large-number vectors.
- The existing worker behavior tests and all 244 issuance library tests passed
  locally on Rust 1.95.0 after the fix.
- The full local issuance package test command and all-target Clippy with
  warnings denied passed. Database-dependent tests in the package-wide run
  self-skip without their URLs; the separate worker PostgreSQL run below is
  the actual database evidence. The protected Python worker suites were rerun
  after merge and all 587 tests passed.
- The actual PostgreSQL worker contract passed on an isolated PostgreSQL 15
  instance. It now verifies that `18446744073709551617` survives the production
  repository write exactly, a large negative clamps to zero, boolean/string
  types survive, and the unlisted provider payload is absent. Existing lease,
  scheduler, recovery and generation-CAS assertions remain in that test.
- PR CI, protected merge review, and broader regression checks still govern
  landing. Windows runs do not execute the Unix signal test; Linux CI must.

This is result-projection evidence, not whole-worker parity. Non-JSON Python
host values, malformed Unicode/number inputs, full cycle/error/lease/provider
behavior, all-consumer routing, browser acceptance and the governed soak remain
subject to the whole-worker contract. This change does not authorize Python
deletion, activate the candidate, or modify the already-claimed v1.1.215 release.
