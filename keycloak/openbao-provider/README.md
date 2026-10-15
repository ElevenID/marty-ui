# Keycloak 25 KMS provider bootstrap proof

This module is an incomplete KMS-only OIDC integration, not a deployable
provider. Four factories override Keycloak 25.0.6's generated key factories
under their existing IDs with a higher `order()`. They never generate,
import, or load a private key. RS256 and HS512 signing and verification use
version-pinned, non-exportable OpenBao Transit keys. RSA-OAEP and AES remain
fail closed until their remote operations are implemented and qualified.

On a fresh disposable Keycloak 25.0.6 instance, this JAR allowed the master
realm to start with all four expected KeyProvider components and no
`privateKey` or `secret` entries in `COMPONENT_CONFIG`. A live disposable
HTTPS OpenBao probe then issued a master-realm RS256 token, verified it with
Keycloak's JWKS, and found zero private rows after issuance. Invalidating the
scoped OpenBao token made subsequent issuance fail with HTTP 500, again with
zero private rows. The probe provisions its CA and leaf certificate inside
OpenBao; only public certificates leave that boundary.

Do not add this JAR to a production Keycloak image or the protected passport
fixture. The completed extension must cover remote RSA-OAEP and AES behavior
required by Keycloak; handle versioned public keys and rotation; support both
`master` and `11id`; and pass the PostgreSQL custody verifier plus connected
login, session and refresh tests.

The build must pin Keycloak to exactly 25.0.6. Its `keys` SPI is internal and
may change between releases. Keycloak's Admin REST component representation
omits secret config fields, so the acceptance gate must inspect the database
directly; an empty Admin REST `config` map does not establish KMS custody.

Build the proof module with `mvn -B -q -DskipTests package` in this directory
using Java 17 or later. The pinned dependencies have `provided` scope; the
resulting JAR contains only this module's classes and service registration.
From the repository root, run `python scripts/probe_keycloak_remote_rs256.py`
with Python's `cryptography` package and Docker available. The probe uses
disposable Docker resources and prints neither tokens nor key material.
