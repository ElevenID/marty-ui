# Keycloak 25.0.6 remote KMS integration

This pinned, unshipped Keycloak build removes generated realm private-key and
secret custody. Four higher-order `keys` factories keep Keycloak's built-in
provider IDs without creating local material. RS256 and HS512 use
non-exportable OpenBao Transit keys. The RSA-OAEP and generic AES providers
still fail closed; their dependent features remain to be qualified.

Keycloak 25.0.6's `RestartLoginCookie` and CIBA request-ID classes directly
request `SecretKey` objects and call `TokenUtil.jweDirectEncode`, which
requires `Key.getEncoded()`. A provider SPI alone cannot make those calls
remote. This module includes the two upstream Apache-2.0 source classes,
patched to call `RemoteDirectJwe`. The Dockerfile builds the pinned provider
JAR and replaces only those classes in the pinned `keycloak-services` JAR.
The Java provider JAR excludes the duplicate upstream classes. The shared
`BaoHttp` client requires CA-verified HTTPS and reads scoped tokens from
files; it never reads an AES/HMAC CEK. The Go OpenBao plugin performs compact
`dir` / `A256CBC-HS512` JWE with distinct realm and `cookie`/`ciba` keys.

Build the two local images from the repository root:

```sh
docker build -f openbao/didcomm-authcrypt/Dockerfile -t marty-openbao-ha-probe:local .
docker build -f keycloak/openbao-provider/Dockerfile -t marty-keycloak-openbao:local .
```

Then run the disposable PostgreSQL 15, HTTPS OpenBao and Keycloak proof:

```sh
python scripts/probe_keycloak_remote_rs256.py --require-browser \
  --keycloak-image marty-keycloak-openbao:local \
  --openbao-image marty-openbao-ha-probe:local
```

The proof creates `master` and `11id` with separate RSA/HMAC identities,
checks direct-grant and successive refresh-token signatures against each
realm's JWKS, completes an `11id` authorization-code/PKCE browser login and
silent session reuse, and denies a new browser login after revoking its
separate OpenBao cookie token. Direct PostgreSQL scans and the read-only
Keycloak custody gate find no `privateKey` or generated `secret` rows after
bootstrap, realm creation, token issuance and KMS-loss denial. The probe
exports only public certificates and cleans its disposable containers.

This local proof does not qualify the installed stack. CIBA behavior has
been patched but has no connected acceptance proof; RSA-OAEP and other AES
flows may still fail closed. Master browser login, key rotation during
active sessions, exact-image deployment, broad provider controls, and
production cutover remain. Do not publish this image as fully KMS-only until
those paths pass with the exact artifact and database gate.
