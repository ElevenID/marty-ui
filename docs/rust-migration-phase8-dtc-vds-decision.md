# Phase 8 DTC and VDS-NC decision

**Decision date:** 2026-08-13

**Decision:** Retain DTC and VDS-NC, with one canonical Rust implementation for
each protocol capability.

## DTC

The DTC service remains because its gRPC lifecycle, storage, access control,
external signer integration, and advertised travel-document behavior are live
contracts. Its deterministic create, normalization, signing preparation,
signature assembly, local signing, trust-chain verification, temporal checks,
and governed lifecycle-status decisions are owned by
`marty-core/marty-verification/src/dtc`.

The Marty DTC engine may retain only:

- gRPC request and response mapping;
- access-key checking and record/blob persistence;
- configuration and logging;
- calls to an external document signer; and
- mapping normalized native results to the existing protobuf contract.

It may not create an unsigned raw-payload substitute, sign or verify in Python,
or continue after the required native operation fails. The completed cutover is
recorded by ElevenID/Marty PR 30.

## VDS-NC

VDS-NC remains because it is used by visa/CMC adapters and is an advertised
document-verification capability. Canonical profile construction,
canonicalization, barcode format/error-correction policy, signing input,
signature verification, parsing, printed-field consistency, and temporal
validation are owned by:

- `marty-core/marty-oid4vci/src/formats/vds_nc_profile.rs`; and
- `marty-core/marty-verification/src/verification/vds_nc.rs`.

Marty may retain DTOs, enum/exception compatibility, visa-field mapping, provider
selection, and result mapping. Those adapters call the fail-closed native
surface and do not reproduce a VDS-NC algorithm. The completed cutover is
recorded by ElevenID/Marty PR 29.

## Verification and removal evidence

- Native DTC and VDS-NC tests cover create/sign/verify, altered payloads,
  unsupported algorithms, trust material, profile dates, field consistency,
  and malformed envelopes.
- Marty adapter tests assert missing native capabilities fail closed.
- Retired Python document-verification engines were removed by ElevenID/Marty
  PR 34.
- Repository audits found no remaining Python DTC or VDS-NC cryptographic
  implementation; the remaining Python paths are the adapter boundaries above.

Roadmap-wide beta observation, dependency cleanup, and source-boundary
enforcement remain part of Phase 9. Production and persistent self-host
deployment are outside this decision.
