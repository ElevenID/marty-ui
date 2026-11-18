# Marty Delegated Authority Service

This crate is the authoritative lifecycle owner for the optional Marty Delegated Authority v1 capability.

## Scope
- Organization-scoped DelegationGrant records.
- Immutable grant terms and SHA-256 terms digest.
- Pending, active, suspended, revoked, and time-derived expired states.
- Explicit consent-evidence verification before activation.
- Revision-checked compare-and-swap lifecycle updates.
- Single-hop grants only; v1 rejects subdelegation.

## Deliberate boundaries
This crate does not implement commerce, checkout, payment, inventory, merchant adapters, or order execution. It does not trust agent-supplied consent booleans or domain constraint results.

Cedar evaluation, authenticated agent proof verification, production JWS signing/verification, public Gateway routing, and PostgreSQL repository wiring remain separate integration milestones. ConsentEvidenceVerifier is an explicit fail-closed port; production composition must provide a real verifier. Do not wire an allow-all implementation.

## Contract
The serialized grant model follows schemas/delegated-authority/v1/delegation-grant.json in marty-protocol. Semantic validation is additional to JSON Schema validation. The terms digest uses deterministic serialization of the fixed v1 struct; cross-language canonicalization must be frozen before interoperability qualification.

## Qualification status
Initial lifecycle/domain implementation. Not production-qualified and not yet exposed through the public Gateway.
