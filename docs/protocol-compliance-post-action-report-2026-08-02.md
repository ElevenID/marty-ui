# Protocol compliance post-action report — 2026-08-02

## Scope and conclusion

The official-test integration exposed real boundary defects; it was not treated
as a collection of fixtures to satisfy. Imported official suites remain pinned
and unmodified. Marty adapters configure organizations and products through the
published gateway API, then point the upstream runner at the resulting public
protocol endpoints.

The audit found no acceptable reason for a test to select a custody provider,
KMS key, signing service, or issuer-profile identifier. Public issuance and
signed verification inputs are organization ID plus issuer DID. The resolver
selects one active, compatible issuer profile, and that profile delegates
signing to its configured custody service. KMS is custody, not the public
signing API.

## Findings and corrective actions

1. Credential templates cached private custody-routing state. This made key
   rotation unsafe and let downstream services depend on resolver internals.
   Templates now retain only the issuer DID and algorithm; all other signing
   state is resolved at use time.
2. Flow, gateway, and credential-template callers unpacked private nested
   issuer-profile and signing-service fields. Those callers now consume only
   the resolver's public DID result.
3. An incomplete SD-JWT request could receive a fabricated VCT. The fallback
   was removed; incomplete requests fail validation.
4. The credential-template gRPC adapter implemented six mutation RPCs that had
   no production callers and did not carry end-user organization/RBAC context.
   Those implementations were deleted. Template writes use the gateway REST
   boundary exclusively; the internal gRPC adapter is read-only.
5. Shared gRPC authentication was optional in production. All gRPC server and
   client construction now fails at startup outside development/test when a
   strong service token is unavailable. Docker Compose uses a dedicated secret
   file, and Kubernetes injects the same dedicated Secret value.
6. The Oracle Kubernetes reference manifest does not yet deploy every service
   present in the self-hosted production stack, including revocation-profile,
   device-registration, and event-stream. It must not be presented as a full
   protocol-conformance deployment until those workloads and their authenticated
   service contracts are added and exercised end to end.

## What the tests do and do not prove

The official protocol runners prove wire behavior for the profiles they
exercise. They do not prove Marty's organization membership, RBAC, tenant
isolation, UI routing, audit records, or key-custody architecture. Those are
separate Marty acceptance obligations.

The official runners use disposable organizations and real public protocol
paths. A distinct two-organization adversarial matrix must continue to test
resource-ID substitution, issuer-DID ambiguity, cross-tenant reads and writes,
policy/template/flow/result isolation, and leakage. Browser smoke tests must
continue to prove the UI reaches those same gateway paths rather than internal
service endpoints.

Marty Protocol remains the schema contract for public resource shapes. Internal
implementation types are deliberately not exposed. Schema drift checks must run
against the pinned contract revision used by the release; a differently owned
or stale mirror is not evidence of conformance.

## Compatibility policy

Marty is pre-1.0 and generally supports the latest protocol behavior without a
legacy compatibility promise. Open Badges 2 is the one explicit short-lived
exception: it remains available while tracked by
[ElevenID/marty-ui#260](https://github.com/ElevenID/marty-ui/issues/260), with a
2026-09-01 review and planned 2026-10-01 removal. This exception must not be
used to preserve unrelated legacy SSI, signing, API, or storage paths.

## Remaining evidence required

- Complete and keep updateable the official OID4VP verifier and HAIP verifier
  lanes without patching upstream tests.
- Complete W3C VC Data Model v2 coverage through the supported public VC API,
  including native JSON-LD Data Integrity issuance and negative verification.
- Complete EUDI reference-wallet interoperability, including replay, tampered
  signature, and expired-request failures.
- Run the full two-organization adversarial matrix and browser-driven issuance
  and verification journeys against the exact immutable release artifacts.
- Complete the Oracle Kubernetes service set and run the same public-path smoke
  tests used for the self-hosted production stack.
- Reconcile any Marty Protocol mirror drift so one pinned release contract is
  authoritative and reproducible.

Until that evidence is green, public claims must distinguish native official
coverage, adapted official coverage, and Marty-owned regression coverage.
