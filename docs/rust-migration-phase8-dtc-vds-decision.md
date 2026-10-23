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

## Current managed-signing qualification

The April `KMS_GAP_ANALYSIS.md` backlog is retired; its full historical text is
recoverable at UI commit `956bfa2985ef3e9854fe22cac089f190da0327ee`. Keep the
following VDS-NC acceptance intent with existing Rust owners. This mapping is a
requirements inventory, not a new claim that each path or provider is qualified.

| Historical backlog | Current owner and retained requirement |
| --- | --- |
| VDSNC-RUST-001 through 003 | Core format/profile contracts: payload/header structure, canonicalization, algorithm policy, canonical `vds_nc` spelling and API-edge aliases, stable credential IDs and signed-output serialization; preserve other credential formats. |
| VDSNC-RUST-004 through 006 | Core format implementation and external signer: deterministic preparation and assembly, explicit DER/raw signature normalization, and positive/malformed/unsupported-algorithm vectors. Production signing uses managed KMS references; local issuer JWK signing is retired. |
| VDSNC-RUST-007 and 008 | Maintained Core public bindings and UI Rust issuance: compose canonical preparation/assembly/verification instead of duplicating cryptography or restoring the retired Python issuer. Qualify the actual supported format-dispatch path. |
| VDSNC-RUST-009 | UI Rust signing-keys and gateway: resolve `vdsnc_signing` against format, algorithm, tenant and country/authority namespace; reject incompatible registrations and selection. |
| VDSNC-RUST-010 | Core verification plus Rust verifier/trust adapters: valid and altered payloads, wrong key, validity window and expired/revoked key/status decisions, canonicalization and printed-field consistency. |
| VDSNC-RUST-011 | Rust provider adapters and format interop: qualify OpenBao/AWS/Azure/GCP signature encodings only for supported combinations. Mocked DER/raw matrices are useful regressions, not live cloud-provider acceptance. |
| VDSNC-RUST-012 | UI/integration release owners: actual managed issuance, holder presentation and verification using exact reviewed dependencies/artifacts, with rollout observation and failure/recovery acceptance. Do not restore a Python or local-signing emergency fallback. |

Preserve the advertised `jwt_vc_json`, `dc+sd-jwt`, `mso_mdoc` and `zk_mdoc`
format behavior and their separate managed signer, trust and holder-proof
requirements. Existing native verification vectors and adapter tests remain;
retiring a checklist does not close missing end-to-end or physical-device gates.
The historical DTC/local-signing descriptions above do not authorize local
issuer custody in current production service builds. Current key boundaries are
set by the [remote KMS hardening plan](remote-kms-hardening-plan.md).
