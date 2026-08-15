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
