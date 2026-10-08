#!/bin/sh
# Keep LF line endings; this script is executed directly inside Linux containers.
set -e

echo "=== OpenBao Initialization ==="
echo "Waiting for OpenBao at ${BAO_ADDR}..."

# Wait for OpenBao to be ready
until bao status -address="${BAO_ADDR}" 2>/dev/null | grep -q "Sealed.*false"; do
    echo "  waiting..."
    sleep 2
done

echo "OpenBao is ready."

export VAULT_ADDR="${BAO_ADDR}"
export VAULT_TOKEN="${BAO_TOKEN}"

if [ "${DIDCOMM_KMS_PLUGIN_REQUIRED:-false}" = "true" ]; then
    plugin=/plugins/openbao-didcomm-authcrypt
    if [ ! -x "${plugin}" ]; then
        echo "Required DIDComm OpenBao plugin binary is missing."
        exit 1
    fi
    plugin_sha="$(sha256sum "${plugin}" | cut -d ' ' -f 1)"
    catalog_sha="$(bao plugin info -address="${BAO_ADDR}" -field=sha256 secret openbao-didcomm-authcrypt 2>/dev/null || true)"
    if [ -n "${catalog_sha}" ] && [ "${catalog_sha}" != "${plugin_sha}" ]; then
        echo "DIDComm plugin catalog hash differs from the packaged binary; coordinate a plugin upgrade."
        exit 1
    fi
    if [ -z "${catalog_sha}" ]; then
        bao plugin register -address="${BAO_ADDR}" -sha256="${plugin_sha}" secret openbao-didcomm-authcrypt
    fi
    if ! bao secrets list -address="${BAO_ADDR}" | grep -q '^didcomm/'; then
        bao secrets enable -address="${BAO_ADDR}" -path=didcomm openbao-didcomm-authcrypt
    fi
fi
if [ "${DIDCOMM_KMS_PLUGIN_REQUIRED:-false}" = "true" ] || [ "${DIDCOMM_KMS_POLICY_ONLY:-false}" = "true" ]; then
    if ! bao secrets list -address="${BAO_ADDR}" | grep -q '^didcomm/'; then
        echo "DIDComm plugin must be mounted at didcomm/ before issuing its workload policy." >&2
        exit 1
    fi
    # Runtime Issuance may read only public sender metadata and request a
    # complete envelope. Key creation, rotation and deletion stay with the
    # bootstrap/operator token; no private-key export path is granted.
    bao policy write -address="${BAO_ADDR}" didcomm-issuance - <<'POLICY'
path "didcomm/keys/+/+/versions/+" {
  capabilities = ["read"]
}
path "didcomm/pack/+/+/+" {
  capabilities = ["update"]
}
POLICY
fi

# ── Transit Engine (credential signing, encryption) ──────────────────

if bao secrets list -address="${BAO_ADDR}" 2>/dev/null | grep -q "^transit/"; then
    echo "Transit engine already enabled."
else
    echo "Enabling Transit secrets engine..."
    bao secrets enable -address="${BAO_ADDR}" transit
fi

# Create issuer signing keys (ECDSA P-256 for SD-JWT/mDL, RSA for legacy)
echo "Creating credential signing keys..."

# Primary issuer key (ECDSA P-256) — used for SD-JWT-VC, mDL, OID4VCI
bao write -address="${BAO_ADDR}" -f transit/keys/cred-issuer-marty-es256 \
    type=ecdsa-p256 2>/dev/null || echo "  cred-issuer-marty-es256 already exists"

# Secondary issuer key (ECDSA P-384) — for higher-assurance credentials
bao write -address="${BAO_ADDR}" -f transit/keys/cred-issuer-marty-es384 \
    type=ecdsa-p384 2>/dev/null || echo "  cred-issuer-marty-es384 already exists"

# RSA issuer key — for legacy VCs and SOD signing
bao write -address="${BAO_ADDR}" -f transit/keys/cred-issuer-marty-rs256 \
    type=rsa-2048 2>/dev/null || echo "  cred-issuer-marty-rs256 already exists"

# Purpose-bound RSA key for Canvas LTI tool assertions
bao write -address="${BAO_ADDR}" -f transit/keys/lti-tool-marty-rs256 \
    type=rsa-2048 2>/dev/null || echo "  lti-tool-marty-rs256 already exists"

# Purpose-bound ECDSA key for signed OID4VP authorization requests
bao write -address="${BAO_ADDR}" -f transit/keys/oid4vp-verifier-marty-es256 \
    type=ecdsa-p256 2>/dev/null || echo "  oid4vp-verifier-marty-es256 already exists"

# EdDSA key — for DID-based credential issuance
bao write -address="${BAO_ADDR}" -f transit/keys/cred-issuer-marty-eddsa \
    type=ed25519 2>/dev/null || echo "  cred-issuer-marty-eddsa already exists"

# Document Signer Certificate (DSC) key for eMRTD/DTC
bao write -address="${BAO_ADDR}" -f transit/keys/cred-dsc-marty-primary \
    type=ecdsa-p256 2>/dev/null || echo "  cred-dsc-marty-primary already exists"

# Encryption key for backup/data-at-rest
bao write -address="${BAO_ADDR}" -f transit/keys/cred-encrypt-marty-aes \
    type=aes256-gcm96 2>/dev/null || echo "  cred-encrypt-marty-aes already exists"

# Authentication session signing key
bao write -address="${BAO_ADDR}" -f transit/keys/auth-session-es256 \
    type=ecdsa-p256 2>/dev/null || echo "  auth-session-es256 already exists"

# Purpose-bound, non-exportable envelope keys.  Keep these separate from
# credential encryption so ciphertext cannot be replayed across domains.
bao write -address="${BAO_ADDR}" -f transit/keys/flow-response-envelope-marty-aes256 \
    type=aes256-gcm96 exportable=false 2>/dev/null || echo "  flow-response-envelope-marty-aes256 already exists"
bao write -address="${BAO_ADDR}" -f transit/keys/integration-secret-envelope-marty-aes256 \
    type=aes256-gcm96 exportable=false allow_plaintext_backup=false 2>/dev/null || \
    echo "  integration-secret-envelope-marty-aes256 already exists"
if [ "$(bao read -address="${BAO_ADDR}" -field=type transit/keys/integration-secret-envelope-marty-aes256 2>/dev/null)" != "aes256-gcm96" ] || \
   [ "$(bao read -address="${BAO_ADDR}" -field=exportable transit/keys/integration-secret-envelope-marty-aes256 2>/dev/null)" != "false" ] || \
   [ "$(bao read -address="${BAO_ADDR}" -field=allow_plaintext_backup transit/keys/integration-secret-envelope-marty-aes256 2>/dev/null)" != "false" ]; then
    echo "Integration-secret Transit key must exist as a non-exportable AES-GCM key" >&2
    exit 1
fi
bao write -address="${BAO_ADDR}" -f transit/keys/passport-artifact-marty-aes256 \
    type=aes256-gcm96 exportable=false 2>/dev/null || echo "  passport-artifact-marty-aes256 already exists"
if [ "$(bao read -address="${BAO_ADDR}" -field=type transit/keys/passport-artifact-marty-aes256 2>/dev/null)" != "aes256-gcm96" ] || \
   [ "$(bao read -address="${BAO_ADDR}" -field=exportable transit/keys/passport-artifact-marty-aes256 2>/dev/null)" != "false" ]; then
    echo "Passport artifact Transit key must exist as a non-exportable AES-GCM key" >&2
    exit 1
fi
bao write -address="${BAO_ADDR}" transit/keys/passport-bureau-callback-marty-hmac \
    type=hmac key_size=32 exportable=false 2>/dev/null || echo "  passport-bureau-callback-marty-hmac already exists"
if [ "$(bao read -address="${BAO_ADDR}" -field=type transit/keys/passport-bureau-callback-marty-hmac 2>/dev/null)" != "hmac" ] || \
   [ "$(bao read -address="${BAO_ADDR}" -field=exportable transit/keys/passport-bureau-callback-marty-hmac 2>/dev/null)" != "false" ]; then
    echo "Passport callback Transit key must exist as a non-exportable HMAC key" >&2
    exit 1
fi
bao write -address="${BAO_ADDR}" -f transit/keys/notification-webhook-envelope-marty-aes256 \
    type=aes256-gcm96 exportable=false 2>/dev/null || echo "  notification-webhook-envelope-marty-aes256 already exists"

# ── PKI Engine (certificate authority) ───────────────────────────────

if bao secrets list -address="${BAO_ADDR}" 2>/dev/null | grep -q "^pki/"; then
    echo "PKI engine already enabled."
else
    echo "Enabling PKI secrets engine..."
    bao secrets enable -address="${BAO_ADDR}" pki
    bao secrets tune -address="${BAO_ADDR}" -max-lease-ttl=87600h pki
fi

# Generate root CA (CSCA equivalent for dev)
if bao read -address="${BAO_ADDR}" pki/cert/ca 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
    echo "Root CA already exists."
else
    echo "Generating root CA..."
    bao write -address="${BAO_ADDR}" pki/root/generate/internal \
        common_name="Marty Development CSCA" \
        ttl=87600h \
        key_type=ec \
        key_bits=256 2>/dev/null
fi

# Configure CA and CRL URLs
bao write -address="${BAO_ADDR}" pki/config/urls \
    issuing_certificates="${BAO_ADDR}/v1/pki/ca" \
    crl_distribution_points="${BAO_ADDR}/v1/pki/crl" 2>/dev/null

# Create DSC issuing role
bao write -address="${BAO_ADDR}" pki/roles/dsc \
    allowed_domains="marty.id,localhost" \
    allow_subdomains=true \
    max_ttl=8760h \
    key_type=ec \
    key_bits=256 \
    ou="Document Signer" \
    organization="Marty" 2>/dev/null || echo "  DSC role already exists"

# ── KV v2 Engine (secret storage) ────────────────────────────────────

if bao secrets list -address="${BAO_ADDR}" 2>/dev/null | grep -q "^secret/"; then
    echo "KV v2 engine already enabled (dev mode default)."
else
    echo "Enabling KV v2 secrets engine..."
    bao secrets enable -address="${BAO_ADDR}" -version=2 kv 2>/dev/null || true
fi

# ── Access Policy ────────────────────────────────────────────────────

echo "Writing credential service policy..."
bao policy write -address="${BAO_ADDR}" credential-service - <<'EOF'
# Transit: sign, verify, encrypt, decrypt with credential keys
path "transit/sign/cred-*" {
  capabilities = ["create", "update"]
}
path "transit/verify/cred-*" {
  capabilities = ["create", "update"]
}
path "transit/encrypt/cred-*" {
  capabilities = ["create", "update"]
}
path "transit/decrypt/cred-*" {
  capabilities = ["create", "update"]
}
path "transit/keys/cred-*" {
  capabilities = ["read"]
}
# Managed signing inventory filters names by tenant before reading public keys.
# OpenBao requires list on the collection path, not on transit/keys/cred-*.
path "transit/keys" {
  capabilities = ["list"]
}

# The VC-API bridge creates one non-exportable holder key per request and
# removes it after signing. Restrict lifecycle privileges to its namespace.
path "transit/keys/vcapi-holder-*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "transit/keys/vcapi-holder-*/config" {
  capabilities = ["create", "update"]
}
path "transit/sign/vcapi-holder-*" {
  capabilities = ["create", "update"]
}

# Purpose-bound protocol keys are deliberately outside the credential-key
# wildcard so a caller cannot substitute them across signing domains.
path "transit/sign/lti-tool-marty-rs256" {
  capabilities = ["create", "update"]
}
path "transit/verify/lti-tool-marty-rs256" {
  capabilities = ["create", "update"]
}
path "transit/keys/lti-tool-marty-rs256" {
  capabilities = ["read"]
}
path "transit/sign/oid4vp-verifier-marty-es256" {
  capabilities = ["create", "update"]
}
path "transit/verify/oid4vp-verifier-marty-es256" {
  capabilities = ["create", "update"]
}
path "transit/keys/oid4vp-verifier-marty-es256" {
  capabilities = ["read"]
}

# Transit: auth session keys
path "transit/sign/auth-*" {
  capabilities = ["create", "update"]
}
path "transit/verify/auth-*" {
  capabilities = ["create", "update"]
}
path "transit/keys/auth-*" {
  capabilities = ["read"]
}

# Purpose-bound envelope operations.  Key configuration remains operator-only.
path "transit/encrypt/flow-response-envelope-marty-aes256" {
  capabilities = ["create", "update"]
}
path "transit/decrypt/flow-response-envelope-marty-aes256" {
  capabilities = ["create", "update"]
}
path "transit/keys/flow-response-envelope-marty-aes256" {
  capabilities = ["read"]
}
path "transit/encrypt/integration-secret-envelope-marty-aes256" {
  capabilities = ["create", "update"]
}
path "transit/decrypt/integration-secret-envelope-marty-aes256" {
  capabilities = ["create", "update"]
}
path "transit/keys/integration-secret-envelope-marty-aes256" {
  capabilities = ["read"]
}
path "transit/encrypt/passport-artifact-marty-aes256" {
  capabilities = ["create", "update"]
}
path "transit/decrypt/passport-artifact-marty-aes256" {
  capabilities = ["create", "update"]
}
path "transit/keys/passport-artifact-marty-aes256" {
  capabilities = ["read"]
}
path "transit/hmac/passport-bureau-callback-marty-hmac" {
  capabilities = ["create", "update"]
}
path "transit/verify/passport-bureau-callback-marty-hmac" {
  capabilities = ["create", "update"]
}
path "transit/keys/passport-bureau-callback-marty-hmac" {
  capabilities = ["read"]
}
path "transit/encrypt/notification-webhook-envelope-marty-aes256" {
  capabilities = ["create", "update"]
}
path "transit/keys/notification-webhook-envelope-marty-aes256" {
  capabilities = ["read"]
}

# PKI: issue DSC certificates
path "pki/issue/dsc" {
  capabilities = ["create", "update"]
}
path "pki/cert/*" {
  capabilities = ["read"]
}

# KV: read secrets
path "secret/data/marty/*" {
  capabilities = ["read"]
}
EOF

echo "Writing managed signing-key policy..."
# A glob here also matches /import and /config. Limit accepted request fields
# to `type`, so neither imported key material nor export/backup settings can
# pass ACL evaluation. Empty rotate requests remain permitted. Keep this policy
# off the shared credential-service token.
bao policy write -address="${BAO_ADDR}" signing-keys-managed - <<'EOF'
path "transit/keys/cred-issuer-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "ed25519"] }
}
path "transit/keys/cred-dsc-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "rsa-2048", "ed25519"] }
}
path "transit/keys/cred-holder-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["ecdsa-p256", "ed25519"] }
}
path "transit/keys/cred-presenter-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["ecdsa-p256", "ed25519"] }
}
path "transit/keys/lti-tool-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["rsa-2048"] }
}
path "transit/keys/oid4vp-verifier-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["ecdsa-p256"] }
}
path "transit/sign/lti-tool-*" {
  capabilities = ["create", "update"]
}
path "transit/verify/lti-tool-*" {
  capabilities = ["create", "update"]
}
path "transit/sign/oid4vp-verifier-*" {
  capabilities = ["create", "update"]
}
path "transit/verify/oid4vp-verifier-*" {
  capabilities = ["create", "update"]
}
EOF

echo "Writing Notification webhook envelope policy..."
bao policy write -address="${BAO_ADDR}" notification-webhook-service - <<'EOF'
# Notification alone can encrypt/decrypt registered webhook HMAC secrets.
path "transit/encrypt/notification-webhook-envelope-marty-aes256" {
  capabilities = ["create", "update"]
}
path "transit/decrypt/notification-webhook-envelope-marty-aes256" {
  capabilities = ["create", "update"]
}
path "transit/keys/notification-webhook-envelope-marty-aes256" {
  capabilities = ["read"]
}
EOF

# The supported-consumer callback signer only needs to MAC canonical callback
# bytes. It cannot verify, read/export a transit key, or use generic signing.
echo "Writing isolated passport callback HMAC policy..."
bao policy write -address="${BAO_ADDR}" passport-callback-hmac-service - <<'EOF'
path "transit/hmac/passport-bureau-callback-marty-hmac" {
  capabilities = ["create", "update"]
}
EOF

# The supported physical-provider signer can additionally verify only scoped
# imported provider HMACs. It cannot generate provider MACs or read/export keys.
echo "Writing supported passport provider callback policy..."
bao policy write -address="${BAO_ADDR}" passport-provider-callback-service - <<'EOF'
path "transit/hmac/passport-bureau-callback-marty-hmac" {
  capabilities = ["create", "update"]
}
path "transit/verify/passport-provider-callback-*" {
  capabilities = ["create", "update"]
}
EOF

echo ""
echo "=== OpenBao Initialization Complete ==="
echo "Transit keys:"
bao list -address="${BAO_ADDR}" transit/keys 2>/dev/null || echo "  (none)"
echo ""
echo "PKI roles:"
bao list -address="${BAO_ADDR}" pki/roles 2>/dev/null || echo "  (none)"
echo ""
echo "KMS ready for credential operations."
