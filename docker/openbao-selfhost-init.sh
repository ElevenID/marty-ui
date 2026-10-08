#!/bin/sh
set -e

is_placeholder_secret_value() {
    value="$1"

    case "${value}" in
        change-me*|CHANGE_ME*|changeme*|replace-me*|REPLACE_ME*)
            return 0
            ;;
    esac

    return 1
}

BAO_ADDR="${BAO_ADDR:-http://openbao:8200}"
BAO_INIT_FILE="${BAO_INIT_FILE:-/bao/data/selfhost-init.json}"
BAO_ROOT_TOKEN_FILE="${BAO_ROOT_TOKEN_FILE:-/bao/data/root.token}"
BAO_UNSEAL_KEY_FILE="${BAO_UNSEAL_KEY_FILE:-/bao/data/unseal.key}"
BAO_SERVICE_TOKEN_FILE="${BAO_SERVICE_TOKEN_FILE:-/bao/runtime/credential-service.token}"
BAO_SIGNING_KEYS_TOKEN_FILE="${BAO_SIGNING_KEYS_TOKEN_FILE:-/bao/runtime/signing_keys_openbao_token}"
BAO_DIDCOMM_ISSUANCE_TOKEN_FILE="${BAO_DIDCOMM_ISSUANCE_TOKEN_FILE:-/bao/runtime/didcomm_issuance_openbao_token}"
BAO_NOTIFICATION_TOKEN_FILE="${BAO_NOTIFICATION_TOKEN_FILE:-/bao/runtime/notification-webhook-service.token}"
BAO_HAIP_TOKEN_FILE="${BAO_HAIP_TOKEN_FILE:-/bao/runtime/haip-kms.token}"
BAO_HAIP_POLICY_FILE="${BAO_HAIP_POLICY_FILE:-/scripts/openbao-haip-workload-policy.hcl}"

mkdir -p "$(dirname "${BAO_INIT_FILE}")" "$(dirname "${BAO_ROOT_TOKEN_FILE}")" "$(dirname "${BAO_UNSEAL_KEY_FILE}")" "$(dirname "${BAO_SERVICE_TOKEN_FILE}")" "$(dirname "${BAO_SIGNING_KEYS_TOKEN_FILE}")" "$(dirname "${BAO_DIDCOMM_ISSUANCE_TOKEN_FILE}")" "$(dirname "${BAO_NOTIFICATION_TOKEN_FILE}")" "$(dirname "${BAO_HAIP_TOKEN_FILE}")"

status_json() {
    bao status -address="${BAO_ADDR}" -format=json 2>/dev/null || true
}

json_compact() {
    printf '%s' "$1" | tr -d '\r\n\t '
}

json_field() {
    json_compact "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"
}

json_bool() {
    json_compact "$1" | sed -n "s/.*\"$2\":\(true\|false\).*/\1/p"
}

json_first_array_entry() {
    json_compact "$1" | sed -n "s/.*\"$2\":\[\"\([^\"]*\)\".*\].*/\1/p"
}

json_array_field() {
    json_compact "$1" | sed -n "s/.*\"$2\":\(\[[^]]*\]\).*/\1/p"
}

write_secret_file() {
    file_path="$1"
    file_value="$2"
    file_mode="$3"

    if [ -s "${file_path}" ] && [ "$(tr -d '\r' < "${file_path}")" = "${file_value}" ]; then
        chmod "${file_mode}" "${file_path}" 2>/dev/null || true
        return 0
    fi

    if [ -e "${file_path}" ]; then
        chmod u+w "${file_path}" 2>/dev/null || true
    fi
    printf '%s' "${file_value}" > "${file_path}"
    chmod "${file_mode}" "${file_path}"
}

echo "=== OpenBao Self-Host Bootstrap ==="
echo "Waiting for OpenBao at ${BAO_ADDR}..."

while :; do
    current_status="$(status_json)"
    if [ -n "${current_status}" ]; then
        break
    fi
    echo "  waiting..."
    sleep 2
done

initialized="$(json_bool "${current_status}" initialized)"
if [ "${initialized}" != "true" ]; then
    if [ -e "${BAO_INIT_FILE}" ]; then
        echo "OpenBao is uninitialized but initialization material already exists; use a clean KMS-only state directory." >&2
        exit 1
    fi
    echo "Initializing OpenBao..."
    bao operator init -address="${BAO_ADDR}" -key-shares=1 -key-threshold=1 -format=json > "${BAO_INIT_FILE}"
    chmod 0600 "${BAO_INIT_FILE}"
fi

init_json="$(tr -d '\r' < "${BAO_INIT_FILE}")"
unseal_key="$(json_first_array_entry "${init_json}" unseal_keys_b64)"
root_token="$(json_field "${init_json}" root_token)"

if [ -z "${unseal_key}" ] || [ -z "${root_token}" ]; then
    echo "Failed to parse OpenBao initialization material."
    exit 1
fi

write_secret_file "${BAO_UNSEAL_KEY_FILE}" "${unseal_key}" 0400
write_secret_file "${BAO_ROOT_TOKEN_FILE}" "${root_token}" 0400

current_status="$(status_json)"
sealed="$(json_bool "${current_status}" sealed)"
if [ "${sealed}" = "true" ]; then
    echo "Unsealing OpenBao..."
    bao operator unseal -address="${BAO_ADDR}" "${unseal_key}" >/dev/null
fi

export BAO_TOKEN="${root_token}"
export VAULT_TOKEN="${root_token}"

raft_ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if bao operator raft list-peers -address="${BAO_ADDR}" >/dev/null 2>&1; then
        raft_ready=1
        break
    fi
    sleep 1
done
if [ "${raft_ready}" != "1" ]; then
    echo "OpenBao Raft storage is required for transactional DIDComm and HAIP key custody." >&2
    exit 1
fi

/bin/sh /scripts/openbao-init.sh

service_token_missing=0
if [ ! -s "${BAO_SERVICE_TOKEN_FILE}" ]; then
    service_token_missing=1
elif is_placeholder_secret_value "$(tr -d '\r' < "${BAO_SERVICE_TOKEN_FILE}")"; then
    service_token_missing=1
fi

if [ "${service_token_missing}" != "1" ]; then
    existing_service_token="$(tr -d '\r' < "${BAO_SERVICE_TOKEN_FILE}")"
    if ! BAO_TOKEN="${existing_service_token}" bao token lookup -address="${BAO_ADDR}" >/dev/null 2>&1; then
        echo "Existing credential-service token is not accepted by OpenBao; minting a replacement..."
        service_token_missing=1
    elif ! BAO_TOKEN="${existing_service_token}" bao write -address="${BAO_ADDR}" transit/sign/cred-issuer-marty-es256 input=dGVzdA== >/dev/null 2>&1; then
        echo "Existing credential-service token cannot sign credential keys; minting a replacement..."
        service_token_missing=1
    fi
fi

if [ "${service_token_missing}" = "1" ]; then
    echo "Minting credential-service token..."
    token_json="$(bao token create -address="${BAO_ADDR}" -policy=credential-service -orphan -format=json)"
    service_token="$(json_field "${token_json}" client_token)"
    if [ -z "${service_token}" ]; then
        echo "Failed to mint credential-service token."
        exit 1
    fi
    write_secret_file "${BAO_SERVICE_TOKEN_FILE}" "${service_token}" 0444
else
    echo "Reusing credential-service token at ${BAO_SERVICE_TOKEN_FILE}"
fi

signing_token_missing=0
if [ ! -s "${BAO_SIGNING_KEYS_TOKEN_FILE}" ]; then
    signing_token_missing=1
elif is_placeholder_secret_value "$(tr -d '\r' < "${BAO_SIGNING_KEYS_TOKEN_FILE}")"; then
    signing_token_missing=1
fi

if [ "${signing_token_missing}" != "1" ]; then
    signing_token="$(tr -d '\r' < "${BAO_SIGNING_KEYS_TOKEN_FILE}")"
    if ! bao token lookup -address="${BAO_ADDR}" "${signing_token}" >/dev/null 2>&1; then
        echo "Existing signing-keys token is not accepted by OpenBao; rotate it explicitly." >&2
        exit 1
    fi
    signing_lookup="$(bao token lookup -address="${BAO_ADDR}" -format=json "${signing_token}")"
    signing_policies="$(json_array_field "${signing_lookup}" policies)"
    signing_entity_id="$(json_field "${signing_lookup}" entity_id)"
    case "${signing_policies}" in
        '["credential-service","signing-keys-managed"]'|'["signing-keys-managed","credential-service"]') ;;
        *)
            echo "Existing signing-keys token has unexpected policies; rotate it explicitly." >&2
            exit 1
            ;;
    esac
    if [ -n "${signing_entity_id}" ]; then
        echo "Existing signing-keys token has an unexpected identity; rotate it explicitly." >&2
        exit 1
    fi
    echo "Reusing signing-keys token at ${BAO_SIGNING_KEYS_TOKEN_FILE}"
else
    echo "Minting signing-keys token..."
    signing_token_json="$(bao token create -address="${BAO_ADDR}" -policy=credential-service -policy=signing-keys-managed -no-default-policy -orphan -format=json)"
    signing_token="$(json_field "${signing_token_json}" client_token)"
    if [ -z "${signing_token}" ]; then
        echo "Failed to mint signing-keys token." >&2
        exit 1
    fi
    write_secret_file "${BAO_SIGNING_KEYS_TOKEN_FILE}" "${signing_token}" 0444
fi

didcomm_token_missing=0
if [ ! -s "${BAO_DIDCOMM_ISSUANCE_TOKEN_FILE}" ]; then
    didcomm_token_missing=1
elif is_placeholder_secret_value "$(tr -d '\r' < "${BAO_DIDCOMM_ISSUANCE_TOKEN_FILE}")"; then
    didcomm_token_missing=1
fi
if [ "${didcomm_token_missing}" != "1" ]; then
    didcomm_token="$(tr -d '\r' < "${BAO_DIDCOMM_ISSUANCE_TOKEN_FILE}")"
    didcomm_lookup="$(bao token lookup -address="${BAO_ADDR}" -format=json "${didcomm_token}" 2>/dev/null)" || {
        echo "Existing DIDComm Issuance token is not accepted; rotate it explicitly." >&2
        exit 1
    }
    if [ "$(json_array_field "${didcomm_lookup}" policies)" != '["didcomm-issuance"]' ]; then
        echo "Existing DIDComm Issuance token has unexpected policies; rotate it explicitly." >&2
        exit 1
    fi
else
    didcomm_token_json="$(bao token create -address="${BAO_ADDR}" -policy=didcomm-issuance -no-default-policy -orphan -format=json)"
    didcomm_token="$(json_field "${didcomm_token_json}" client_token)"
    if [ -z "${didcomm_token}" ]; then
        echo "Failed to mint DIDComm Issuance token." >&2
        exit 1
    fi
    write_secret_file "${BAO_DIDCOMM_ISSUANCE_TOKEN_FILE}" "${didcomm_token}" 0444
fi

notification_token_missing=0
if [ ! -s "${BAO_NOTIFICATION_TOKEN_FILE}" ]; then
    notification_token_missing=1
elif is_placeholder_secret_value "$(tr -d '\r' < "${BAO_NOTIFICATION_TOKEN_FILE}")"; then
    notification_token_missing=1
fi

if [ "${notification_token_missing}" != "1" ]; then
    existing_notification_token="$(tr -d '\r' < "${BAO_NOTIFICATION_TOKEN_FILE}")"
    if ! BAO_TOKEN="${existing_notification_token}" bao token lookup -address="${BAO_ADDR}" >/dev/null 2>&1; then
        echo "Existing Notification OpenBao token is not accepted; minting a replacement..."
        notification_token_missing=1
    elif ! BAO_TOKEN="${existing_notification_token}" bao token capabilities -address="${BAO_ADDR}" transit/decrypt/notification-webhook-envelope-marty-aes256 2>/dev/null | grep -q "update"; then
        echo "Existing Notification OpenBao token lacks webhook decrypt permission; minting a replacement..."
        notification_token_missing=1
    fi
fi

if [ "${notification_token_missing}" = "1" ]; then
    echo "Minting Notification webhook OpenBao token..."
    notification_token_json="$(bao token create -address="${BAO_ADDR}" -policy=notification-webhook-service -orphan -format=json)"
    notification_token="$(json_field "${notification_token_json}" client_token)"
    if [ -z "${notification_token}" ]; then
        echo "Failed to mint Notification webhook OpenBao token."
        exit 1
    fi
    write_secret_file "${BAO_NOTIFICATION_TOKEN_FILE}" "${notification_token}" 0444
else
    echo "Reusing Notification webhook OpenBao token at ${BAO_NOTIFICATION_TOKEN_FILE}"
fi

if [ ! -r "${BAO_HAIP_POLICY_FILE}" ]; then
    echo "HAIP workload policy file is missing or unreadable." >&2
    exit 1
fi
bao policy write -address="${BAO_ADDR}" haip-response-service "${BAO_HAIP_POLICY_FILE}" >/dev/null

haip_token_missing=0
if [ ! -s "${BAO_HAIP_TOKEN_FILE}" ]; then
    haip_token_missing=1
elif is_placeholder_secret_value "$(tr -d '\r' < "${BAO_HAIP_TOKEN_FILE}")"; then
    haip_token_missing=1
fi

if [ "${haip_token_missing}" != "1" ]; then
    existing_haip_token="$(tr -d '\r' < "${BAO_HAIP_TOKEN_FILE}")"
    if ! bao token lookup -address="${BAO_ADDR}" "${existing_haip_token}" >/dev/null 2>&1; then
        echo "Existing HAIP workload token is not accepted by OpenBao; rotate it explicitly." >&2
        exit 1
    fi
    haip_lookup="$(bao token lookup -address="${BAO_ADDR}" -format=json "${existing_haip_token}")"
    haip_policies="$(json_array_field "${haip_lookup}" policies)"
    haip_entity_id="$(json_field "${haip_lookup}" entity_id)"
    if [ "${haip_policies}" != '["haip-response-service"]' ] ||
       [ -n "${haip_entity_id}" ]; then
        echo "Existing HAIP workload token does not have the dedicated policy alone; rotate it explicitly." >&2
        exit 1
    fi
    echo "Reusing HAIP workload token at ${BAO_HAIP_TOKEN_FILE}"
else
    echo "Minting HAIP workload token..."
    haip_token_json="$(bao token create -address="${BAO_ADDR}" -policy=haip-response-service -no-default-policy -orphan -format=json)"
    haip_token="$(json_field "${haip_token_json}" client_token)"
    if [ -z "${haip_token}" ]; then
        echo "Failed to mint HAIP workload token." >&2
        exit 1
    fi
    write_secret_file "${BAO_HAIP_TOKEN_FILE}" "${haip_token}" 0444
fi

echo "OpenBao self-host bootstrap complete."
