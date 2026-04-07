#!/bin/sh
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

echo ""
echo "=== OpenBao Initialization Complete ==="
echo "Transit keys:"
bao list -address="${BAO_ADDR}" transit/keys 2>/dev/null || echo "  (none)"
echo ""
echo "PKI roles:"
bao list -address="${BAO_ADDR}" pki/roles 2>/dev/null || echo "  (none)"
echo ""
echo "KMS ready for credential operations."
