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

mkdir -p "$(dirname "${BAO_INIT_FILE}")" "$(dirname "${BAO_ROOT_TOKEN_FILE}")" "$(dirname "${BAO_UNSEAL_KEY_FILE}")" "$(dirname "${BAO_SERVICE_TOKEN_FILE}")"

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
    if [ ! -f "${BAO_INIT_FILE}" ]; then
        echo "Initializing OpenBao..."
        bao operator init -address="${BAO_ADDR}" -key-shares=1 -key-threshold=1 -format=json > "${BAO_INIT_FILE}"
        chmod 0600 "${BAO_INIT_FILE}"
    else
        echo "Using existing initialization material at ${BAO_INIT_FILE}"
    fi
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
    elif ! BAO_TOKEN="${existing_service_token}" bao write -address="${BAO_ADDR}" transit/sign/cred-issuer-marty-es256 input=dGVzdA >/dev/null 2>&1; then
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

echo "OpenBao self-host bootstrap complete."