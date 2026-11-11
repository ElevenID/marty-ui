#!/bin/sh
# Keep LF line endings; this script is executed directly inside Linux containers.

is_placeholder_secret_value() {
    value="$1"

    case "${value}" in
        change-me*|CHANGE_ME*|changeme*|replace-me*|REPLACE_ME*)
            return 0
            ;;
    esac

    return 1
}

load_secret_var() {
    var_name="$1"
    file_var_name="${var_name}_FILE"

    eval "current_value=\${${var_name}:-}"
    eval "file_path=\${${file_var_name}:-}"

    if [ -n "${current_value}" ] && [ -n "${file_path}" ]; then
        echo "Both ${var_name} and ${file_var_name} are set; choose one." >&2
        exit 1
    fi

    if [ -n "${file_path}" ]; then
        if [ ! -f "${file_path}" ]; then
            echo "Secret file for ${var_name} is not a regular file: ${file_path}" >&2
            exit 1
        fi

        if [ ! -r "${file_path}" ]; then
            echo "Secret file for ${var_name} is not readable: ${file_path}" >&2
            exit 1
        fi

        value="$(tr -d '\r' < "${file_path}")"
        export "${var_name}=${value}"
        unset "${file_var_name}"
    fi
}

require_secret_var() {
    var_name="$1"

    load_secret_var "${var_name}"
    eval "resolved_value=\${${var_name}:-}"
    if [ -z "${resolved_value}" ] || is_placeholder_secret_value "${resolved_value}"; then
        echo "${var_name} must be set to a non-placeholder secret value before startup." >&2
        exit 1
    fi
}

# Encode one URI component using only POSIX shell builtins. Keeping only RFC
# 3986 unreserved bytes also encodes a literal '%' instead of decoding a
# customer's password twice. The subshell keeps bytewise LC_ALL local.
encode_database_password() (
    LC_ALL=C
    export LC_ALL
    marty_password_remaining=$1
    while [ -n "$marty_password_remaining" ]; do
        marty_password_tail=${marty_password_remaining#?}
        marty_password_byte=${marty_password_remaining%"$marty_password_tail"}
        case "$marty_password_byte" in
            [a-zA-Z0-9.~_-]) printf '%s' "$marty_password_byte" ;;
            *) printf '%%%02X' "'$marty_password_byte" ;;
        esac
        marty_password_remaining=$marty_password_tail
    done
)

expand_database_url() {
    if [ -z "${DATABASE_URL_TEMPLATE:-}" ]; then
        return 0
    fi

    # Compose resolves $$ to $ before starting a container. Accept either
    # spelling for the one catalog-owned password slot; never evaluate shell
    # commands, additional variables or substitutions from configuration.
    marty_database_slot='${MARTY_DB_PASSWORD}'
    case "$DATABASE_URL_TEMPLATE" in
        *'$${MARTY_DB_PASSWORD}'*) marty_database_slot='$${MARTY_DB_PASSWORD}' ;;
    esac
    case "$DATABASE_URL_TEMPLATE" in
        *"$marty_database_slot"*)
            marty_database_prefix=${DATABASE_URL_TEMPLATE%%"$marty_database_slot"*}
            marty_database_suffix=${DATABASE_URL_TEMPLATE#*"$marty_database_slot"}
            ;;
        *)
            marty_database_prefix=$DATABASE_URL_TEMPLATE
            marty_database_suffix=
            ;;
    esac
    case "$marty_database_prefix$marty_database_suffix" in
        *'$'*|*'`'*)
            echo 'DATABASE_URL_TEMPLATE only supports the MARTY_DB_PASSWORD placeholder; use DATABASE_URL for a complete URI.' >&2
            exit 1
            ;;
    esac
    case "$DATABASE_URL_TEMPLATE" in
        *"$marty_database_slot"*)
            DATABASE_URL="$marty_database_prefix$(encode_database_password "${MARTY_DB_PASSWORD:-}")$marty_database_suffix"
            ;;
        *) DATABASE_URL=$DATABASE_URL_TEMPLATE ;;
    esac
    export DATABASE_URL
}

load_secret_env() {
    load_secret_var POSTGRES_PASSWORD
    load_secret_var KEYCLOAK_DB_PASSWORD
    load_secret_var MARTY_DB_PASSWORD
    load_secret_var KEYCLOAK_ADMIN_PASSWORD
    load_secret_var KC_DB_PASSWORD
    load_secret_var GOOGLE_CLIENT_ID
    load_secret_var GOOGLE_CLIENT_SECRET
    load_secret_var GOOGLE_ANALYTICS_MEASUREMENT_ID
    load_secret_var GOOGLE_SITE_VERIFICATION
    load_secret_var MARTY_API_CLIENT_SECRET
    load_secret_var OIDC_CLIENT_SECRET
    load_secret_var ISSUANCE_API_KEY
    load_secret_var TOKEN_HMAC_KEY
    load_secret_var SIGNING_KEYS_INTERNAL_API_KEY
    load_secret_var SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY
    load_secret_var SIGNING_KEYS_ISSUER_SIGN_KEY
    load_secret_var SIGNING_KEYS_INTEGRATION_SECRET_KEY
    load_secret_var VERIFICATION_GOVERNANCE_JSON
    load_secret_var GRPC_SERVICE_TOKEN
    load_secret_var FLOW_WEBHOOK_SECRET
    load_secret_var CANVAS_CREDENTIALS_SHARED_SECRET
    if [ "${PRESERVE_BAO_TOKEN_FILE:-}" != "1" ]; then
        load_secret_var BAO_TOKEN
    fi
    load_secret_var OPENBAO_SERVICE_TOKEN
    load_secret_var SMTP_PASSWORD
    load_secret_var CLOUDFLARE_TUNNEL_TOKEN
    expand_database_url
}

load_secret_env
