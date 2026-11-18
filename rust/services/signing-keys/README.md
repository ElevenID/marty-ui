# Marty signing-keys service

This Rust executable is the canonical owner of the signing-key service HTTP
surface as it is extracted from the API gateway. It owns health, diagnostics,
key-purpose metadata, provider-capability metadata, and provider-native signing,
public-key discovery, and connectivity probes for OpenBao/Vault Transit, AWS
KMS, Azure Key Vault, and GCP Cloud KMS. It also owns service-registration
validation, provider-reference policy, validator bridges, and live capability
probes. It is also the single owner of signing-service type metadata, registry
normalization and routing, key-purpose binding validation, and the durable
organization registry stored in the existing Redis keyspace. It also owns
issuer-profile normalization, attestation policy validation, KMS binding
compatibility, duplicate repair, tuple selection, and durable profile storage.
Python retains tenant authorization and KMS/DID orchestration. Later slices move
audit and compliance behavior behind the same public routes.
Certificate inspection and expiry decisions, certificate sidecars, public-only
JWKS mutation, DID document publication, and atomic did:web slug ownership are
already canonical here and use the existing Redis keyspace.

Behavioral contracts live in `tests/fixtures` and are exercised through the
Axum router. The gateway may proxy requests and apply user authorization, but
must not maintain another copy of the key or provider decisions.

The `/internal/kms/*`, `/internal/config/validate`, `/internal/registry/*`, and
`/internal/profiles/*` routes are service-to-service compatibility endpoints.
Provider credentials are accepted only on those internal calls, never returned,
and provider errors are bounded before crossing the service boundary. ECDSA
signatures retain the provider-native value while optional JOSE/P1363 output is
derived by the canonical `marty-oid4vci` normalizer.

Credential issuance sends the verification method and public JWK used by native
credential preparation as `verification_method_id` and `expected_public_jwk` to
`/internal/compat/issuer-dids/sign` (also exposed at the signing-keys alias).
Signing Keys checks these against fresh DID/profile resolution before calling
the signing provider. A changed method or public key fails closed, including
rotation under the same managed key reference. Expected key material must be
public-only; supplying an expected key requires its verification method.

These fields are optional for existing callers. They protect the canonical Rust
credential client's prepared binding; they are not additional authorization
claims in the signing grant. Every signing call still requires the existing
short-lived, one-use grant bound to tenant, DID, key reference, purpose,
algorithm, and payload. A grant is consumed before the prepared-binding check,
so a failed binding requires a fresh grant rather than replaying the old one.

Deploy Signing Keys with these fields supported before deploying the issuance
client that sends them; older servers reject unknown request fields. The check
is a snapshot before signing, so native credential assembly must still verify
the returned signature against its prepared public key to detect a provider
rotation between the final public-key read and signing.
