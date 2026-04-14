#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)

is_placeholder_secret_value() {
    value="$1"

    case "${value}" in
        change-me*|CHANGE_ME*|changeme*|replace-me*|REPLACE_ME*)
            return 0
            ;;
    esac

    return 1
}

BAO_ADDR="${BAO_ADDR:-}"
BAO_TOKEN="${BAO_TOKEN:-}"
BAO_TOKEN_FILE="${BAO_TOKEN_FILE:-}"
SELFHOST_SECRET_DIR="${SELFHOST_SECRET_DIR:-${REPO_ROOT}/docker/secrets/selfhost.example}"
SERVICE_TOKEN_OUTPUT_FILE="${SERVICE_TOKEN_OUTPUT_FILE:-${SELFHOST_SECRET_DIR}/openbao_service_token}"

if [ -z "${BAO_ADDR}" ]; then
    echo "BAO_ADDR must be set to the external Vault/OpenBao address." >&2
    exit 1
fi

if [ -n "${BAO_TOKEN}" ] && [ -n "${BAO_TOKEN_FILE}" ]; then
    echo "Both BAO_TOKEN and BAO_TOKEN_FILE are set; choose one." >&2
    exit 1
fi

if [ -n "${BAO_TOKEN_FILE}" ]; then
    if [ ! -r "${BAO_TOKEN_FILE}" ]; then
        echo "BAO_TOKEN_FILE is not readable: ${BAO_TOKEN_FILE}" >&2
        exit 1
    fi
    BAO_TOKEN="$(tr -d '\r' < "${BAO_TOKEN_FILE}")"
fi

if [ -z "${BAO_TOKEN}" ] || is_placeholder_secret_value "${BAO_TOKEN}"; then
    echo "Provide a non-placeholder bootstrap token through BAO_TOKEN or BAO_TOKEN_FILE." >&2
    exit 1
fi

SERVICE_TOKEN_OUTPUT_DIR=$(dirname "${SERVICE_TOKEN_OUTPUT_FILE}")
SERVICE_TOKEN_OUTPUT_BASENAME=$(basename "${SERVICE_TOKEN_OUTPUT_FILE}")

mkdir -p "${SERVICE_TOKEN_OUTPUT_DIR}"

echo "Configuring external Vault/OpenBao at ${BAO_ADDR}..."

docker run --rm \
    -e BAO_ADDR="${BAO_ADDR}" \
    -e BAO_TOKEN="${BAO_TOKEN}" \
    -e SERVICE_TOKEN_OUTPUT_FILE="/work/${SERVICE_TOKEN_OUTPUT_BASENAME}" \
    -v "${REPO_ROOT}/docker/openbao-init.sh:/scripts/openbao-init.sh:ro" \
    -v "${SERVICE_TOKEN_OUTPUT_DIR}:/work" \
    quay.io/openbao/openbao:2 \
    /bin/sh -ec '
json_field() {
    printf "%s" "$1" | tr -d "\n" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

export VAULT_ADDR="$BAO_ADDR"
export VAULT_TOKEN="$BAO_TOKEN"

/bin/sh /scripts/openbao-init.sh

token_json="$(bao token create -address="$BAO_ADDR" -policy=credential-service -orphan -format=json)"
service_token="$(json_field "$token_json" client_token)"

if [ -z "$service_token" ]; then
    echo "Failed to mint credential-service token." >&2
    exit 1
fi

printf "%s" "$service_token" > "$SERVICE_TOKEN_OUTPUT_FILE"
chmod 0600 "$SERVICE_TOKEN_OUTPUT_FILE"
'

echo "Wrote scoped credential-service token to ${SERVICE_TOKEN_OUTPUT_FILE}"
echo "Use that file as the openbao_service_token secret in the self-host stack."