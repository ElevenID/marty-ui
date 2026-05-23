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

expand_template_var() {
    var_name="$1"
    template_var_name="${var_name}_TEMPLATE"

    eval "template_value=\${${template_var_name}:-}"
    if [ -z "${template_value}" ]; then
        return 0
    fi

    expanded_value="$(eval "printf '%s' \"${template_value}\"")"
    export "${var_name}=${expanded_value}"
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
    load_secret_var ISSUANCE_API_KEY
    load_secret_var CANVAS_CREDENTIALS_SHARED_SECRET
    load_secret_var CANVAS_CREDENTIALS_API_TOKEN
    load_secret_var BAO_TOKEN
    load_secret_var OPENBAO_SERVICE_TOKEN
    load_secret_var SMTP_PASSWORD
    load_secret_var SQUARE_ACCESS_TOKEN
    load_secret_var SQUARE_WEBHOOK_SIGNATURE_KEY
    load_secret_var CLOUDFLARE_TUNNEL_TOKEN
    load_secret_var LICENSE_KEY

    expand_template_var DATABASE_URL
}

load_secret_env
