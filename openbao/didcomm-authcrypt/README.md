# Marty OpenBao cryptography extension

This Go plugin keeps DIDComm, HAIP and Keycloak JWE keys inside OpenBao's
storage and process boundary. It requires transactional storage for key
creation and rotation; file-backed OpenBao storage is rejected. The host
application receives public references or completed cryptographic results,
never private key material.

The Keycloak direct-JWE API is staged for a pinned Keycloak 26.8.0 source
change. Mount the plugin at `didcomm` and use these paths:

| Operation | Path | Request | Response |
| --- | --- | --- | --- |
| Create or read current | `keycloak/keys/{realm}/{purpose}` | empty POST or GET | realm, purpose, version, kid, alg, enc |
| Rotate | `keycloak/keys/{realm}/{purpose}/rotate` | empty POST | new public reference |
| Read old version | `keycloak/keys/{realm}/{purpose}/versions/{version}` | GET | public reference |
| Encrypt | `keycloak/jwe/encode/{realm}/{purpose}/{version}` | POST `plaintext_base64` | compact `jwe` |
| Authenticate and decrypt | `keycloak/jwe/decode/{realm}/{purpose}/{version}` | POST `jwe` | `plaintext_base64` |

`purpose` is exactly `cookie` or `ciba`. Each realm and purpose gets a
separate 512-bit CEK and 128-bit random version ID. The plugin emits compact
`dir` / `A256CBC-HS512` JWE with a protected versioned `kid`. Decryption
requires the exact realm, purpose, version, algorithm and authenticated
header; old versions remain available for session continuity after rotation.
The shared content-encryption primitive is also used by DIDComm, but key
namespaces and authorizations remain separate.

Issue a scoped OpenBao token per realm and purpose. A consumer token needs
only `read` on its current public reference and `update` on the exact
versioned encode/decode paths. Key creation and rotation require separate
privileges. The disposable live probe verifies this policy split.

The API and local OpenBao proof do **not** make Keycloak KMS-only yet.
Keycloak 26.8.0's `RestartLoginCookie` and CIBA request-ID paths call a
direct JWE helper that requires encoded local keys. A pinned source-built
Keycloak change must call these remote endpoints, preserve login/session,
CIBA, rotation and outage behavior, and pass the PostgreSQL custody gate
before the extension can be shipped for OIDC. An exact-image installed
proof and real provider acceptance remain separate release gates.
