# Marty signing-keys service

This Rust executable is the canonical owner of the signing-key service HTTP
surface as it is extracted from the API gateway. The first cutover owns health,
diagnostics, key-purpose metadata, and provider-capability metadata. Later
slices move registry persistence, KMS adapters, signing, certificate/JWKS/DID
publication, issuer profiles, audit, and compliance behavior behind the same
public routes.

Behavioral contracts live in `tests/fixtures` and are exercised through the
Axum router. The gateway may proxy requests and apply user authorization, but
must not maintain another copy of the key or provider decisions.
