# Keycloak 25 KMS provider bootstrap proof

This module is a fail-closed bootstrap proof, not a deployable OIDC provider.
The four factories override Keycloak 25.0.6's generated key factories under
their existing IDs with a higher `order()`. They never generate, import, or
load a private key. Every attempted key operation fails until the complete
remote crypto implementation replaces `FailClosedKeyFactory.create`.

On a fresh disposable Keycloak 25.0.6 instance, this JAR allowed the master
realm to start with all four expected KeyProvider components and no
`privateKey` or `secret` entries in `COMPONENT_CONFIG`. A token request failed
closed with HTTP 500; a second database scan still found no key material.
Do not add this JAR to a production Keycloak image or the protected passport
fixture. The completed extension must cover remote RSA signing, encryption,
HMAC and AES behavior required by Keycloak; handle versioned public keys and
rotation; support both `master` and `11id`; and pass the PostgreSQL custody
verifier plus connected login, refresh and JWKS tests.

The build must pin Keycloak to exactly 25.0.6. Its `keys` SPI is internal and
may change between releases. Keycloak's Admin REST component representation
omits secret config fields, so the acceptance gate must inspect the database
directly; an empty Admin REST `config` map does not establish KMS custody.

Build the proof module with `mvn -B -q -DskipTests package` in this directory
using Java 17 or later. The pinned dependencies have `provided` scope; the
resulting JAR contains only this module's classes and service registration.
