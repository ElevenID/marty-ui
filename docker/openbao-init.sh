#!/bin/sh
# Keep LF line endings; this script is executed directly inside Linux containers.
set -e

# Shared by initial provisioning and explicit activation on persistent Raft.
# This path owns only the callback HMAC, its isolated policy and workload token.
ensure_passport_callback() {
    callback_path="transit/keys/passport-bureau-callback-marty-hmac"
    callback_file="${BAO_PASSPORT_CALLBACK_TOKEN_FILE:-}"
    if [ -n "${callback_file}" ] && [ -s "${callback_file}" ]; then
        callback_token="$(tr -d '\r' < "${callback_file}")"
        check_passport_callback_token "${callback_token}"
    fi
    if ! bao read -address="${BAO_ADDR}" -field=type "${callback_path}" >/dev/null 2>&1; then
        bao write -address="${BAO_ADDR}" "${callback_path}" type=hmac key_size=32 exportable=false >/dev/null
    fi
    if [ "$(bao read -address="${BAO_ADDR}" -field=type "${callback_path}")" != "hmac" ] ||
       [ "$(bao read -address="${BAO_ADDR}" -field=exportable "${callback_path}")" != "false" ]; then
        echo "Passport callback Transit key must be a non-exportable HMAC key" >&2
        exit 1
    fi
    bao policy write -address="${BAO_ADDR}" passport-callback-hmac-service - <<'CALLBACK_POLICY'
path "transit/hmac/passport-bureau-callback-marty-hmac" {
  capabilities = ["create", "update"]
}
CALLBACK_POLICY
    if [ -n "${callback_file}" ] && [ ! -s "${callback_file}" ]; then
        callback_new_token=""
        callback_tmp=""
        trap 'cleanup_passport_callback' 0
        trap 'exit 1' 1 2 15
        callback_token="$(bao token create -address="${BAO_ADDR}" -policy=passport-callback-hmac-service -no-default-policy -orphan -field=token 2>/dev/null)"
        callback_new_token="${callback_token}"
        if [ -z "${callback_token}" ]; then
            echo "Could not create passport callback token" >&2
            exit 1
        fi
        check_passport_callback_token "${callback_token}"
        mkdir -p "$(dirname "${callback_file}")"
        callback_tmp="$(mktemp "${callback_file}.XXXXXX")"
        printf '%s' "${callback_token}" > "${callback_tmp}"
        chmod 0444 "${callback_tmp}"
        mv -f "${callback_tmp}" "${callback_file}"
        callback_new_token=""
        callback_tmp=""
        trap - 0 1 2 15
    fi
    if [ -n "${callback_file}" ]; then chmod 0444 "${callback_file}"; fi
    unset callback_token
}

cleanup_passport_callback() {
    callback_exit=$?
    if [ -n "${callback_new_token:-}" ]; then
        if ! bao token revoke -address="${BAO_ADDR}" "${callback_new_token}" >/dev/null 2>&1; then
            echo "Could not revoke unpublished callback token; explicit custody recovery is required" >&2
            callback_exit=1
        fi
    fi
    if [ -n "${callback_tmp:-}" ]; then rm -f "${callback_tmp}"; fi
    return "${callback_exit}"
}

check_passport_callback_token() {
    callback_lookup="$(bao token lookup -address="${BAO_ADDR}" -format=json "$1" 2>/dev/null)"
    callback_compact="$(printf '%s' "${callback_lookup}" | tr -d '\r\n\t ')"
    callback_policies="$(printf '%s' "${callback_compact}" | sed -n 's/.*"policies":\(\[[^]]*\]\).*/\1/p')"
    callback_entity="$(printf '%s' "${callback_compact}" | sed -n 's/.*"entity_id":"\([^"]*\)".*/\1/p')"
    if [ "${callback_policies}" != '["passport-callback-hmac-service"]' ] || [ -n "${callback_entity}" ]; then
        echo "Passport callback token has unexpected authority; rotate it explicitly" >&2
        exit 1
    fi
}

if [ "${1:-}" = "--passport-callback-only" ]; then
    if [ "$#" -ne 1 ]; then echo "Unexpected callback provisioning arguments" >&2; exit 1; fi
    umask 077
    if [ -n "${BAO_PASSPORT_CALLBACK_OPERATOR_TOKEN_FILE:-}" ]; then
        BAO_TOKEN="$(cat "${BAO_PASSPORT_CALLBACK_OPERATOR_TOKEN_FILE}")"
    fi
    if [ -z "${BAO_TOKEN:-}" ] || [ -z "${BAO_PASSPORT_CALLBACK_TOKEN_FILE:-}" ]; then
        echo "Scoped callback provisioning requires operator custody and workload token destination" >&2
        exit 1
    fi
    case "${BAO_ADDR:-}" in https://*) ;; *) echo "Scoped callback provisioning requires TLS" >&2; exit 1 ;; esac
    if [ "${BAO_SKIP_VERIFY:-false}" != "false" ] || [ "${VAULT_SKIP_VERIFY:-false}" != "false" ] ||
       [ -z "${BAO_CACERT:-}" ] || ! grep -q '^-----BEGIN CERTIFICATE-----$' "${BAO_CACERT}" ||
       grep -q 'PRIVATE KEY' "${BAO_CACERT}"; then
        echo "Scoped callback provisioning requires verified TLS and a public CA" >&2
        exit 1
    fi
    export BAO_TOKEN VAULT_TOKEN="${BAO_TOKEN}"
    callback_status="$(bao status -address="${BAO_ADDR}" -format=json | tr -d '\r\n\t ')"
    case "${callback_status}" in *'"initialized":true'*) ;; *) echo "Callback KMS must be initialized" >&2; exit 1 ;; esac
    case "${callback_status}" in *'"sealed":false'*) ;; *) echo "Callback KMS must be unsealed" >&2; exit 1 ;; esac
    ensure_passport_callback
    exit 0
fi
if [ "$#" -ne 0 ]; then echo "Unexpected OpenBao initialization arguments" >&2; exit 1; fi

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
    if [ -n "${DIDCOMM_ISSUANCE_TOKEN_FILE:-}" ]; then
        token_dir="$(dirname "${DIDCOMM_ISSUANCE_TOKEN_FILE}")"
        mkdir -p "${token_dir}"
        umask 077
        token_temp="$(mktemp "${DIDCOMM_ISSUANCE_TOKEN_FILE}.XXXXXX")"
        if ! bao token create -address="${BAO_ADDR}" -policy=didcomm-issuance \
            -no-default-policy -orphan -field=token > "${token_temp}"; then
            rm -f "${token_temp}"
            echo "Could not create scoped DIDComm issuance token." >&2
            exit 1
        fi
        chmod 0444 "${token_temp}"
        mv -f "${token_temp}" "${DIDCOMM_ISSUANCE_TOKEN_FILE}"
    fi
fi

# ── Transit Engine (credential signing, encryption) ──────────────────

if bao secrets list -address="${BAO_ADDR}" 2>/dev/null | grep -q "^transit/"; then
    echo "Transit engine already enabled."
else
    echo "Enabling Transit secrets engine..."
    bao secrets enable -address="${BAO_ADDR}" transit
fi

# Rust migration bootstrap creates tenant-bound, non-exportable standard
# signing keys. Infrastructure initialization must not create global keys.

# Encryption key for backup/data-at-rest
bao write -address="${BAO_ADDR}" -f transit/keys/cred-encrypt-marty-aes \
    type=aes256-gcm96 2>/dev/null || echo "  cred-encrypt-marty-aes already exists"

# Authentication session signing key
bao write -address="${BAO_ADDR}" -f transit/keys/auth-session-es256 \
    type=ecdsa-p256 2>/dev/null || echo "  auth-session-es256 already exists"

# Purpose-bound, non-exportable envelope keys. Keep these separate from
# credential encryption so ciphertext cannot be replayed across domains.
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
ensure_passport_callback
# Signing authorization is separate from signing custody. Each producer gets
# one HMAC key and a mint-only policy; Signing Keys receives verify-only access.
grant_origins='gateway-service gateway-issuer-did flow-wallet issuance-credential issuance-canvas issuance-readiness issuance-passport'
for grant_origin in ${grant_origins}; do
    grant_key="marty-sign-grant-${grant_origin}-v1"
    bao write -address="${BAO_ADDR}" "transit/keys/${grant_key}" \
        type=hmac key_size=32 exportable=false allow_plaintext_backup=false 2>/dev/null || \
        echo "  ${grant_key} already exists"
    if [ "$(bao read -address="${BAO_ADDR}" -field=type "transit/keys/${grant_key}" 2>/dev/null)" != "hmac" ] || \
       [ "$(bao read -address="${BAO_ADDR}" -field=exportable "transit/keys/${grant_key}" 2>/dev/null)" != "false" ] || \
       [ "$(bao read -address="${BAO_ADDR}" -field=allow_plaintext_backup "transit/keys/${grant_key}" 2>/dev/null)" != "false" ]; then
        echo "Signing grant Transit key ${grant_key} must be non-exportable HMAC without plaintext backup" >&2
        exit 1
    fi
    bao policy write -address="${BAO_ADDR}" "sign-grant-mint-${grant_origin}" - <<EOF
path "transit/hmac/${grant_key}/sha2-256" {
  capabilities = ["update"]
}
EOF
done
for grant_origin in ${grant_origins}; do
    printf 'path "transit/verify/marty-sign-grant-%s-v1/sha2-256" { capabilities = ["update"] }\n' "${grant_origin}"
done | bao policy write -address="${BAO_ADDR}" sign-grant-verify -
if [ -n "${BAO_FLOW_GRANT_TOKEN_FILE:-}" ] || [ -n "${BAO_VERIFY_GRANT_TOKEN_FILE:-}" ] || [ -n "${BAO_GATEWAY_GRANT_TOKEN_FILE:-}" ] || [ -n "${BAO_GATEWAY_ISSUER_GRANT_TOKEN_FILE:-}" ] || [ -n "${BAO_ISSUANCE_CREDENTIAL_GRANT_TOKEN_FILE:-}" ] || [ -n "${BAO_ISSUANCE_CANVAS_GRANT_TOKEN_FILE:-}" ] || [ -n "${BAO_ISSUANCE_READINESS_GRANT_TOKEN_FILE:-}" ] || [ -n "${BAO_ISSUANCE_PASSPORT_GRANT_TOKEN_FILE:-}" ]; then
    [ -n "${BAO_FLOW_GRANT_TOKEN_FILE:-}" ] && [ -n "${BAO_VERIFY_GRANT_TOKEN_FILE:-}" ] && [ -n "${BAO_GATEWAY_GRANT_TOKEN_FILE:-}" ] && [ -n "${BAO_GATEWAY_ISSUER_GRANT_TOKEN_FILE:-}" ] && [ -n "${BAO_ISSUANCE_CREDENTIAL_GRANT_TOKEN_FILE:-}" ] && [ -n "${BAO_ISSUANCE_CANVAS_GRANT_TOKEN_FILE:-}" ] && [ -n "${BAO_ISSUANCE_READINESS_GRANT_TOKEN_FILE:-}" ] && [ -n "${BAO_ISSUANCE_PASSPORT_GRANT_TOKEN_FILE:-}" ] || {
        echo 'All scoped signing grant token paths are required.' >&2
        exit 1
    }
    mkdir -p "$(dirname "${BAO_FLOW_GRANT_TOKEN_FILE}")" "$(dirname "${BAO_VERIFY_GRANT_TOKEN_FILE}")" "$(dirname "${BAO_GATEWAY_GRANT_TOKEN_FILE}")" "$(dirname "${BAO_GATEWAY_ISSUER_GRANT_TOKEN_FILE}")"
    grant_token="$(bao token create -address="${BAO_ADDR}" -policy=sign-grant-mint-flow-wallet -no-default-policy -orphan -field=token)"
    [ -n "${grant_token}" ] || { echo 'Could not mint Flow signing grant token.' >&2; exit 1; }
    printf '%s\n' "${grant_token}" > "${BAO_FLOW_GRANT_TOKEN_FILE}"
    chmod 0444 "${BAO_FLOW_GRANT_TOKEN_FILE}"
    gateway_grant_token="$(bao token create -address="${BAO_ADDR}" -policy=sign-grant-mint-gateway-service -no-default-policy -orphan -field=token)"
    [ -n "${gateway_grant_token}" ] || { echo 'Could not mint Gateway signing grant token.' >&2; exit 1; }
    printf '%s\n' "${gateway_grant_token}" > "${BAO_GATEWAY_GRANT_TOKEN_FILE}"
    chmod 0444 "${BAO_GATEWAY_GRANT_TOKEN_FILE}"
    gateway_issuer_grant_token="$(bao token create -address="${BAO_ADDR}" -policy=sign-grant-mint-gateway-issuer-did -no-default-policy -orphan -field=token)"
    [ -n "${gateway_issuer_grant_token}" ] || { echo 'Could not mint Gateway issuer CSR grant token.' >&2; exit 1; }
    printf '%s\n' "${gateway_issuer_grant_token}" > "${BAO_GATEWAY_ISSUER_GRANT_TOKEN_FILE}"
    chmod 0444 "${BAO_GATEWAY_ISSUER_GRANT_TOKEN_FILE}"
    mint_issuance_grant_token() {
        grant_origin="$1"
        grant_file="$2"
        grant_token="$(bao token create -address="${BAO_ADDR}" -policy="sign-grant-mint-issuance-${grant_origin}" -no-default-policy -orphan -field=token)"
        [ -n "${grant_token}" ] || { echo "Could not mint Issuance ${grant_origin} signing grant token." >&2; exit 1; }
        mkdir -p "$(dirname "${grant_file}")"
        printf '%s\n' "${grant_token}" > "${grant_file}"
        chmod 0444 "${grant_file}"
    }
    mint_issuance_grant_token credential "${BAO_ISSUANCE_CREDENTIAL_GRANT_TOKEN_FILE}"
    mint_issuance_grant_token canvas "${BAO_ISSUANCE_CANVAS_GRANT_TOKEN_FILE}"
    mint_issuance_grant_token readiness "${BAO_ISSUANCE_READINESS_GRANT_TOKEN_FILE}"
    mint_issuance_grant_token passport "${BAO_ISSUANCE_PASSPORT_GRANT_TOKEN_FILE}"
    grant_verify_token="$(bao token create -address="${BAO_ADDR}" -policy=sign-grant-verify -no-default-policy -orphan -field=token)"
    [ -n "${grant_verify_token}" ] || { echo 'Could not mint signing grant verifier token.' >&2; exit 1; }
    printf '%s\n' "${grant_verify_token}" > "${BAO_VERIFY_GRANT_TOKEN_FILE}"
    chmod 0444 "${BAO_VERIFY_GRANT_TOKEN_FILE}"
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
path "transit/sign/lti-tool-*" {
  capabilities = ["create", "update"]
}
path "transit/verify/lti-tool-*" {
  capabilities = ["create", "update"]
}
path "transit/keys/lti-tool-*" {
  capabilities = ["read"]
}
path "transit/sign/oid4vp-verifier-*" {
  capabilities = ["create", "update"]
}
path "transit/verify/oid4vp-verifier-*" {
  capabilities = ["create", "update"]
}
path "transit/keys/oid4vp-verifier-*" {
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
  capabilities = ["create", "update", "read", "delete"]
  allowed_parameters = { "type" = ["ecdsa-p256", "ed25519"], "deletion_allowed" = [true, "true"] }
}
path "transit/keys/cred-holder-*/config" {
  capabilities = ["create", "update"]
}
path "transit/keys/cred-presenter-*" {
  capabilities = ["create", "update", "read", "delete"]
  allowed_parameters = { "type" = ["ecdsa-p256", "ed25519"], "deletion_allowed" = [true, "true"] }
}
path "transit/keys/cred-presenter-*/config" {
  capabilities = ["create", "update"]
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

# Database migrations alone may provision the fixed, tenant-bound standard
# signing keys. Runtime services must not receive this policy. Parameter
# allowlists prevent the wildcard paths from accepting imported material or
# changing export/backup settings through Transit subpaths.
echo "Writing migration-only KMS bootstrap policy..."
bao policy write -address="${BAO_ADDR}" kms-bootstrap - <<'EOF'
path "transit/keys/cred-issuer-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "ed25519"] }
}
path "transit/keys/cred-dsc-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["ecdsa-p256"] }
}
path "transit/keys/lti-tool-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["rsa-2048"] }
}
path "transit/keys/oid4vp-verifier-*" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["ecdsa-p256"] }
}
path "transit/keys/flow-response-envelope-marty-aes256" {
  capabilities = ["create", "update", "read"]
  allowed_parameters = { "type" = ["aes256-gcm96"], "exportable" = [false, "false"] }
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

if [ -n "${BAO_NOTIFICATION_TOKEN_FILE:-}" ]; then
    notification_token="$(bao token create -address="${BAO_ADDR}" -policy=notification-webhook-service -no-default-policy -orphan -field=token)"
    mkdir -p "$(dirname "${BAO_NOTIFICATION_TOKEN_FILE}")"
    printf '%s\n' "${notification_token}" > "${BAO_NOTIFICATION_TOKEN_FILE}"
    chmod 0444 "${BAO_NOTIFICATION_TOKEN_FILE}"
fi

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
