# Verification evidence and policy boundaries

This change extends the frozen policy/query binding in PR1845. Credential
cryptography and policy decisions remain in Marty Core. UI services resolve
governed metadata, preserve the complete wallet response, and project evidence
into the canonical Core contracts.

## Authenticated credential identity

Template requirements are matched against authenticated credential types, never
copied from the requested policy into verified facts. SD-JWT uses its signed
`vct`; mdoc uses the verified document type; W3C credentials use their verified
`type` values. Comparison is exact. Credential-template metadata is resolved via
the owning service using a service token and the policy organization. The
resolver checks both returned identity and tenant. Inline accepted credential
types remain alternatives; they do not become invented template identifiers.

## Frozen query and response

Flow and the verifier use the same bounded response-association contract. Every
response item must belong to a requested query, every requested query must be
represented, and duplicate or unreferenced tokens are rejected. DCQL identifiers
and Presentation Exchange definition/descriptor identifiers are checked before
verification. Native authenticated evidence must then satisfy the requested
format, type, claims, algorithms, and verifier binding.

The supported Presentation Exchange subset maps a scalar token at `$` or a
token-array entry at `$[index]`. Nested credential envelopes and unsupported
query extensions fail closed. SD-JWT/DCQL retains the foundation's stricter
opaque native producer: one saved required credential, one response token,
exact VCT and selected scalar claims, signed subject and holder binding, with
validity checked again after all awaited resolution. Other DCQL formats use
explicit credential queries with type metadata and exact object claim paths.
Unsupported query-set or claim-set semantics fail closed. These restrictions
prevent unimplemented query semantics from becoming an allow decision.

The current service policy permits **one presentation**. A response containing
multiple distinct tokens is fully associated. The strict SD-JWT/DCQL producer
rejects it as unsupported. General Presentation Exchange handling authenticates
each item and passes the actual token count to Core, which denies it under that
policy. Evaluating the same credential against several trust profiles does not
increase that count.

## Profile and authorization evidence

Each candidate records the exact trust-profile ID that was resolved and
evaluated. Requirement-specific profiles override the policy default. A caller
cannot replace either through request context. Several profile candidates may
exist for one credential; a denied alternative does not veto a satisfied one.
Configured SD-JWT issuer and holder algorithm allowlists are enforced during
native verification.

When a trust profile links a credential-verification PolicySet, the organization
service supplies its current, tenant-bound source through an authenticated
internal route. The verifier requires the exact ID, active lifecycle,
`CREDENTIAL_VERIFICATION` type, and `MIP/1.0` schema. It compiles the enabled Cedar
documents and records a source digest with the candidate authorization result.
Unavailable, mismatched, empty, or invalid linked policy source fails closed.
There is no implicit business-policy preset when no PolicySet is linked.

A non-null `PresentationPolicy.compliance_profile_id` is currently unsupported
and is rejected at creation/activation and evaluation, including previously
saved policies. A signed `_compliance_code` is a credential claim; it cannot
establish resolved ComplianceProfile authority. Supporting that selector
requires a future typed, governed resolution contract.

## Deployment and policy validation

Presentation-policy resolves metadata using `CREDENTIAL_TEMPLATE_SERVICE_URL`
(default `http://credential-template:8003`) and `ORGANIZATION_SERVICE_URL`
(default `http://organization:8002`) with its configured service token. Internal
metadata routes require configured service authentication and tenant-scoped
reads. They expose public type metadata or configured policy source only.

Saved predicate fallback and supported-circuit fields reach Core unchanged.
Creation and activation use Core's policy validator. Unsupported proof-based
predicate capabilities fail closed; supported raw predicates are evaluated over
authenticated claim values according to the configured fallback policy.

The dependency pins are Marty Core
`a11313be1fdb6035c11c87b42b4120e395d63aba` and the microservices framework
`d8b8d8583203c31a1a5cd6b513a6068e6c416b6d`. Regression suites use actual signed
credentials to check type confusion, profile substitution, algorithm mismatch,
configured Cedar denials, frozen query mismatch, and the presentation-count
limit, with separate authenticated-route and response-association checks.
