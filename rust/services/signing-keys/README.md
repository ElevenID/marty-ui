# Marty signing-keys service

This Rust executable is the canonical owner of the signing-key service HTTP
surface as it is extracted from the API gateway. It owns health, diagnostics,
key-purpose metadata, provider-capability metadata, and provider-native signing,
public-key discovery, and connectivity probes for OpenBao/Vault Transit, AWS
KMS, Azure Key Vault, and GCP Cloud KMS. Later slices move registry persistence,
certificate/JWKS/DID publication, issuer profiles, audit, and compliance
behavior behind the same public routes.

Behavioral contracts live in `tests/fixtures` and are exercised through the
Axum router. The gateway may proxy requests and apply user authorization, but
must not maintain another copy of the key or provider decisions.

The `/internal/kms/*` routes are service-to-service compatibility endpoints.
Provider credentials are accepted only on those internal calls, never returned,
and provider errors are bounded before crossing the service boundary. ECDSA
signatures retain the provider-native value while optional JOSE/P1363 output is
derived by the canonical `marty-oid4vci` normalizer.
