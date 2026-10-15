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
PostgreSQL 15 and HTTPS OpenBao probe then created `11id` and issued RS256
tokens in both realms. It checked realm issuers, distinct remote RSA public keys, and each
signature against the corresponding Keycloak JWKS. Two successive refresh
grants in each realm also issued independently verified RS256 tokens. Direct
database scans after startup, realm creation, and issuance found zero private-key or
generated-secret rows. The read-only PostgreSQL custody gate passed after
issuance and again after KMS-loss denial. Invalidating the scoped OpenBao
token made issuance fail with HTTP 500 in both realms; refresh grants failed closed with
`invalid_grant`, and the database remained clear. The probe
provisions its CA and leaf certificates inside OpenBao; only public
certificates leave that boundary.

Do not add this JAR to a production Keycloak image or the protected passport
fixture. The completed extension must cover remote RSA-OAEP and AES behavior
required by Keycloak; handle versioned public keys and rotation; and pass the
PostgreSQL custody verifier in the installed stack plus connected browser login and session tests
for both realms. The two-realm direct-grant/refresh proof uses a disposable
PostgreSQL database, not the product's browser login or installed stack.

Run `python scripts/probe_keycloak_remote_rs256.py --require-browser` to
exercise an authorization-code login with PKCE and silent session reuse in
`11id`. This acceptance check currently fails closed at the initial login:
Keycloak 25.0.6 reports `Error encoding cookie` and `Failed to find key:
realm=11id algorithm=AES use=ENC`. The AES key provider intentionally returns
no local `SecretKey`. A remote AES cookie operation is required before browser
login can pass; the default probe continues to cover the proven signing and
refresh slice.

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
