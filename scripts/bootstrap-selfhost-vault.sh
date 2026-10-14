#!/bin/sh
set -e
umask 077

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
BOOTSTRAP_TOKEN_OUTPUT_FILE="${BOOTSTRAP_TOKEN_OUTPUT_FILE:-${SELFHOST_SECRET_DIR}/openbao_bootstrap_token}"
SIGNING_KEYS_TOKEN_OUTPUT_FILE="${SIGNING_KEYS_TOKEN_OUTPUT_FILE:-${SELFHOST_SECRET_DIR}/signing_keys_openbao_token}"
DIDCOMM_ISSUANCE_TOKEN_OUTPUT_FILE="${DIDCOMM_ISSUANCE_TOKEN_OUTPUT_FILE:-${SELFHOST_SECRET_DIR}/didcomm_issuance_openbao_token}"
NOTIFICATION_TOKEN_OUTPUT_FILE="${NOTIFICATION_TOKEN_OUTPUT_FILE:-${SELFHOST_SECRET_DIR}/notification_openbao_token}"
PASSPORT_CALLBACK_TOKEN_OUTPUT_FILE="${PASSPORT_CALLBACK_TOKEN_OUTPUT_FILE:-${SELFHOST_SECRET_DIR}/passport_callback_signer_bao_token}"

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
BOOTSTRAP_TOKEN_OUTPUT_DIR=$(dirname "${BOOTSTRAP_TOKEN_OUTPUT_FILE}")
BOOTSTRAP_TOKEN_OUTPUT_BASENAME=$(basename "${BOOTSTRAP_TOKEN_OUTPUT_FILE}")
SIGNING_KEYS_TOKEN_OUTPUT_DIR=$(dirname "${SIGNING_KEYS_TOKEN_OUTPUT_FILE}")
SIGNING_KEYS_TOKEN_OUTPUT_BASENAME=$(basename "${SIGNING_KEYS_TOKEN_OUTPUT_FILE}")
DIDCOMM_ISSUANCE_TOKEN_OUTPUT_DIR=$(dirname "${DIDCOMM_ISSUANCE_TOKEN_OUTPUT_FILE}")
DIDCOMM_ISSUANCE_TOKEN_OUTPUT_BASENAME=$(basename "${DIDCOMM_ISSUANCE_TOKEN_OUTPUT_FILE}")
NOTIFICATION_TOKEN_OUTPUT_DIR=$(dirname "${NOTIFICATION_TOKEN_OUTPUT_FILE}")
NOTIFICATION_TOKEN_OUTPUT_BASENAME=$(basename "${NOTIFICATION_TOKEN_OUTPUT_FILE}")
PASSPORT_CALLBACK_TOKEN_OUTPUT_DIR=$(dirname "${PASSPORT_CALLBACK_TOKEN_OUTPUT_FILE}")
PASSPORT_CALLBACK_TOKEN_OUTPUT_BASENAME=$(basename "${PASSPORT_CALLBACK_TOKEN_OUTPUT_FILE}")

mkdir -p "${SELFHOST_SECRET_DIR}" "${SERVICE_TOKEN_OUTPUT_DIR}" "${BOOTSTRAP_TOKEN_OUTPUT_DIR}" "${SIGNING_KEYS_TOKEN_OUTPUT_DIR}" "${DIDCOMM_ISSUANCE_TOKEN_OUTPUT_DIR}" "${NOTIFICATION_TOKEN_OUTPUT_DIR}" "${PASSPORT_CALLBACK_TOKEN_OUTPUT_DIR}"
for output_dir in "${SELFHOST_SECRET_DIR}" "${SERVICE_TOKEN_OUTPUT_DIR}" "${BOOTSTRAP_TOKEN_OUTPUT_DIR}" "${SIGNING_KEYS_TOKEN_OUTPUT_DIR}" "${DIDCOMM_ISSUANCE_TOKEN_OUTPUT_DIR}" "${NOTIFICATION_TOKEN_OUTPUT_DIR}" "${PASSPORT_CALLBACK_TOKEN_OUTPUT_DIR}"; do
    if [ -L "${output_dir}" ] || [ ! -d "${output_dir}" ]; then
        echo "Scoped token output directory must be a real directory." >&2
        exit 1
    fi
    if [ "$(uname -s)" = "Linux" ]; then
        chmod 0700 "${output_dir}"
    fi
done

echo "Configuring external Vault/OpenBao at ${BAO_ADDR}..."
# Pass the token through Docker's inherited environment, not the process argv.
export BAO_TOKEN
if [ -n "${SELFHOST_BOOTSTRAP_CONTAINER_NAME:-}" ]; then
    case "${SELFHOST_BOOTSTRAP_CONTAINER_NAME}" in
        marty-selfhost-bootstrap-*-helper) ;;
        *) echo "Invalid disposable bootstrap container name." >&2; exit 1 ;;
    esac
    case "${SELFHOST_BOOTSTRAP_CONTAINER_NAME}" in
        *[!a-z0-9-]*) echo "Invalid disposable bootstrap container name." >&2; exit 1 ;;
    esac
    set -- --name "${SELFHOST_BOOTSTRAP_CONTAINER_NAME}" \
        --label "marty.selfhost.bootstrap-handoff=${SELFHOST_BOOTSTRAP_CONTAINER_NAME}"
else
    set --
fi
# The shipped Linux install uses an external, caller-owned private secret dir.
# The image's default UID cannot write it; the CLI itself needs no image-owned state.
if [ "$(uname -s)" = "Linux" ]; then
    set -- "$@" --user "$(id -u):$(id -g)"
fi

docker run --rm "$@" \
    -e BAO_ADDR="${BAO_ADDR}" \
    -e BAO_TOKEN \
    -e DIDCOMM_KMS_POLICY_ONLY=true \
    -e SERVICE_TOKEN_OUTPUT_FILE="/work-service/${SERVICE_TOKEN_OUTPUT_BASENAME}" \
    -e BOOTSTRAP_TOKEN_OUTPUT_FILE="/work-bootstrap/${BOOTSTRAP_TOKEN_OUTPUT_BASENAME}" \
    -e SIGNING_KEYS_TOKEN_OUTPUT_FILE="/work-signing/${SIGNING_KEYS_TOKEN_OUTPUT_BASENAME}" \
    -e DIDCOMM_ISSUANCE_TOKEN_OUTPUT_FILE="/work-didcomm/${DIDCOMM_ISSUANCE_TOKEN_OUTPUT_BASENAME}" \
    -e NOTIFICATION_TOKEN_OUTPUT_FILE="/work-notification/${NOTIFICATION_TOKEN_OUTPUT_BASENAME}" \
    -e PASSPORT_CALLBACK_TOKEN_OUTPUT_FILE="/work-callback/${PASSPORT_CALLBACK_TOKEN_OUTPUT_BASENAME}" \
    -e GRANT_TOKEN_OUTPUT_DIR=/work-grants \
    -v "${REPO_ROOT}/docker/openbao-init.sh:/scripts/openbao-init.sh:ro" \
    -v "${SERVICE_TOKEN_OUTPUT_DIR}:/work-service" \
    -v "${BOOTSTRAP_TOKEN_OUTPUT_DIR}:/work-bootstrap" \
    -v "${SIGNING_KEYS_TOKEN_OUTPUT_DIR}:/work-signing" \
    -v "${DIDCOMM_ISSUANCE_TOKEN_OUTPUT_DIR}:/work-didcomm" \
    -v "${NOTIFICATION_TOKEN_OUTPUT_DIR}:/work-notification" \
    -v "${PASSPORT_CALLBACK_TOKEN_OUTPUT_DIR}:/work-callback" \
    -v "${SELFHOST_SECRET_DIR}:/work-grants" \
    quay.io/openbao/openbao@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf \
    /bin/sh -ec '
umask 077
private_tmp=""
trap "rm -f -- \"\$private_tmp\"" EXIT HUP INT TERM
write_private_token() {
    output_file="$1"
    token_value="$2"
    output_dir="${output_file%/*}"
    if [ -L "$output_dir" ] || [ ! -d "$output_dir" ] ||
       [ -L "$output_file" ] || { [ -e "$output_file" ] && [ ! -f "$output_file" ]; }; then
        echo "Scoped token output path is unsafe." >&2
        exit 1
    fi
    private_tmp="$(mktemp "$output_dir/.openbao-token.XXXXXX")"
    chmod 0600 "$private_tmp"
    printf "%s" "$token_value" > "$private_tmp"
    mv -f "$private_tmp" "$output_file"
    private_tmp=""
}
json_field() {
    printf "%s" "$1" | tr -d "\n" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

export VAULT_ADDR="$BAO_ADDR"
export VAULT_TOKEN="$BAO_TOKEN"

/bin/sh /scripts/openbao-init.sh

write_grant_token() {
    grant_policy="$1"
    grant_file="$2"
    grant_json="$(bao token create -address="$BAO_ADDR" -policy="$grant_policy" -no-default-policy -orphan -format=json)"
    grant_token="$(json_field "$grant_json" client_token)"
    if [ -z "$grant_token" ]; then
        echo "Failed to mint $grant_policy token." >&2
        exit 1
    fi
    write_private_token "$grant_file" "$grant_token"
}
for grant_origin in gateway-service gateway-issuer-did flow-wallet issuance-credential issuance-canvas issuance-readiness issuance-passport; do
    grant_file_origin="$(printf "%s" "$grant_origin" | tr "-" "_")"
    write_grant_token "sign-grant-mint-$grant_origin" "$GRANT_TOKEN_OUTPUT_DIR/sign_grant_mint_${grant_file_origin}_token"
done
write_grant_token sign-grant-verify "$GRANT_TOKEN_OUTPUT_DIR/sign_grant_verify_token"

token_json="$(bao token create -address="$BAO_ADDR" -policy=credential-service -orphan -format=json)"
service_token="$(json_field "$token_json" client_token)"

if [ -z "$service_token" ]; then
    echo "Failed to mint credential-service token." >&2
    exit 1
fi

write_private_token "$SERVICE_TOKEN_OUTPUT_FILE" "$service_token"

bootstrap_token_json="$(bao token create -address="$BAO_ADDR" -policy=kms-bootstrap -no-default-policy -orphan -ttl=2h -renewable=false -format=json)"
bootstrap_token="$(json_field "$bootstrap_token_json" client_token)"
if [ -z "$bootstrap_token" ]; then
    echo "Failed to mint migration-only KMS bootstrap token." >&2
    exit 1
fi
write_private_token "$BOOTSTRAP_TOKEN_OUTPUT_FILE" "$bootstrap_token"

signing_token_json="$(bao token create -address="$BAO_ADDR" -policy=credential-service -policy=signing-keys-managed -no-default-policy -orphan -format=json)"
signing_token="$(json_field "$signing_token_json" client_token)"
if [ -z "$signing_token" ]; then
    echo "Failed to mint signing-keys OpenBao token." >&2
    exit 1
fi
write_private_token "$SIGNING_KEYS_TOKEN_OUTPUT_FILE" "$signing_token"

didcomm_token_json="$(bao token create -address="$BAO_ADDR" -policy=didcomm-issuance -no-default-policy -orphan -format=json)"
didcomm_token="$(json_field "$didcomm_token_json" client_token)"
if [ -z "$didcomm_token" ]; then
    echo "Failed to mint DIDComm Issuance OpenBao token." >&2
    exit 1
fi
write_private_token "$DIDCOMM_ISSUANCE_TOKEN_OUTPUT_FILE" "$didcomm_token"

notification_token_json="$(bao token create -address="$BAO_ADDR" -policy=notification-webhook-service -orphan -format=json)"
notification_token="$(json_field "$notification_token_json" client_token)"

if [ -z "$notification_token" ]; then
    echo "Failed to mint Notification webhook OpenBao token." >&2
    exit 1
fi

write_private_token "$NOTIFICATION_TOKEN_OUTPUT_FILE" "$notification_token"

callback_token_json="$(bao token create -address="$BAO_ADDR" -policy=passport-provider-callback-service -orphan -format=json)"
callback_token="$(json_field "$callback_token_json" client_token)"
if [ -z "$callback_token" ]; then
    echo "Failed to mint passport callback HMAC token." >&2
    exit 1
fi
write_private_token "$PASSPORT_CALLBACK_TOKEN_OUTPUT_FILE" "$callback_token"
'

echo "Wrote scoped credential-service token to ${SERVICE_TOKEN_OUTPUT_FILE}"
echo "Use that file as the openbao_service_token secret in the self-host stack."
echo "Wrote migration-only KMS bootstrap token to ${BOOTSTRAP_TOKEN_OUTPUT_FILE}"
echo "Wrote scoped signing-keys token to ${SIGNING_KEYS_TOKEN_OUTPUT_FILE}"
echo "Wrote scoped DIDComm Issuance token to ${DIDCOMM_ISSUANCE_TOKEN_OUTPUT_FILE}"
echo "Wrote scoped Notification webhook token to ${NOTIFICATION_TOKEN_OUTPUT_FILE}"
echo "Use that file as the notification_openbao_token secret in the self-host stack."
echo "Wrote scoped passport callback HMAC token to ${PASSPORT_CALLBACK_TOKEN_OUTPUT_FILE}"
echo "Wrote eight scoped signing-grant tokens to ${SELFHOST_SECRET_DIR}"
