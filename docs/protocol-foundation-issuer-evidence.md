# Governed issuer evidence and bounded control-plane retrieval

This change implements the presentation-policy portion of the W02/W03
foundation work. It builds on the existing issuer-key-resolution crate and
MMF outbound HTTP client.

## Issuer authority

The signing registry already validates the issuer organization, exact DID,
credential format, key purpose, algorithm, active identity, DID document
controller and assertion method. Invalid registry bindings cannot fall back to
public resolution. Public DID transport is deployment configured.

The presentation kernel now retains that resolution result as
`ResolvedIssuerKey`, including the issuer identity and provenance, instead of
discarding everything except the JWK. A successful SD-JWT or governed VC-JWT
signature produces `AuthenticatedIssuerEvidence` only when the verified issuer
exactly matches the selected authority and the key belongs to the current
verifier trust-profile and organization context.

Issuer identifiers are compared exactly for persisted relationship and system
override key selection. The old helper lowercased entire identifiers and removed
trailing slashes, including case-sensitive DID and URL paths. A top-level
unscoped `issuer_public_jwk` is no longer a selection authority. Persisted issuer
relationships and issuer-keyed overrides remain supported. If an explicit
profile key cannot be selected, the kernel denies verification instead of
switching to public discovery. An explicitly configured system override also
prevents a mismatching key from falling back to the relationship key.

Provenance records the trust profile, verifier organization, issuer organization
when registry scoped, key selection mechanism, resolver source, retrieval time
and source content digest when available. Signature authentication remains
separate from trust-profile acceptance and credential status.

The orchestrator uses the authenticated principal for trust and status checks.
Provenance stays outside Core's strict policy-facts schema. Evaluation results
include optional `authenticated_issuer` evidence only for a uniquely matched,
signature-verified credential result. Caller request context and facts-only
evaluation cannot supply this evidence.

The new evidence object has explicit canonical response bounds: issuer and key
identifiers contain 1–2048 Unicode scalar values, algorithm 1–64, provenance
source 1–256, and issuer organization 1–128. Optional fields may be absent.
Profile and verifier organization identifiers are typed UUIDs. Source content
digests contain exactly 64 lowercase hexadecimal characters. Retrieval times
are calendar-valid RFC3339 strings of at most 64 ASCII characters; the producer
requires a `T` or `t` separator, years 0001–9999 and seconds 00–59. Malformed or
oversized new evidence fails verification instead of being truncated or
published. These bounds do not rewrite stored profiles or change the permitted
cryptographic algorithms. Protocol schemas and generated DTOs are coordinated
in the matching marty-protocol foundation change.

This typed evidence currently covers the governed JOSE paths. Existing Data
Integrity authorization and mdoc certificate-fingerprint evidence retain their
format-specific contracts; this change does not invent an SD-JWT certificate
trust mechanism.

## Retrieval policy

Presentation-policy's two configured control-plane reads now use the same MMF
bounded outbound client already used by trust-registry synchronization.

| Purpose | Destination owner | Redirects | Body bound | Freshness |
| --- | --- | --- | --- | --- |
| Trust-profile document | Explicit deployment service URL | Rejected | 2 MiB | Fetch on every verification |
| Credential lifecycle status | Explicit deployment URL template | Rejected | 64 KiB | Fetch on every lookup |

The shared client enforces the configured request timeout and checks both
declared content length and streamed bytes. These internal endpoints explicitly
permit customer-operated HTTP and private-address services. They are not an
adapter for credential-supplied remote URLs. Trust-profile base URLs reject
embedded credentials, queries and fragments. The status template permits one
encoded credential identifier in its path or query; it cannot determine the
destination host. Exact `.` and `..` identifiers are skipped because URL parsers
normalize them as path traversal segments. Existing service and tenant headers are preserved and are
never forwarded through a redirect.

Public DID retrieval and public registry synchronization retain their existing
owners and destination controls. No new cache, microservice, remote KMS
requirement or CI orchestration layer is introduced.

## Behavioral checks

- Signed SD-JWT success retains exact issuer/key/profile/tenant provenance.
- A valid signature with a different issuer, profile or tenant is rejected
  without claims or authenticated issuer evidence.
- Exact Unicode length limits are accepted; overlong identifiers and malformed
  provenance cannot produce authenticated claims or response evidence.
- Case or trailing-slash variants cannot select a different issuer's key.
- Unscoped keys and configured key mismatches cannot authorize public discovery.
- Real registry integration retains source digest/time and tenant binding;
  existing wrong-tenant, inactive, wrong-pin and unauthorized-method cases deny.
- Result projection requires a unique signature-verified credential and never
  accepts caller-supplied provenance.
- Actual HTTP stubs verify redirect refusal, bounds with fixed and streamed
  bodies, dependency timeouts and invalid endpoint templates.

The implementation was prepared against marty-ui main
`f39ba0628f41cfcb081afadcc9294ac821038941`. Runtime dependency upgrades and
published qualification evidence are coordinated separately from this scoped
consumer change.

Validation on Rust 1.97.1 passed: all 58 tests across the library and the
`control_plane_behavior`, `native_kernel_behavior`,
`scoped_registry_verification`, and `verification_behavior` integration suites.
Rustfmt and `git diff --check` also pass. The native run used the unchanged
locked dependency revisions through locally mirrored original Git objects.
This validates the scoped consumer change; it is not protocol certification or
release qualification for a future combined dependency upgrade.

```sh
cargo test --locked -p marty-presentation-policy --lib \
  --test native_kernel_behavior --test scoped_registry_verification \
  --test verification_behavior --test control_plane_behavior
```
