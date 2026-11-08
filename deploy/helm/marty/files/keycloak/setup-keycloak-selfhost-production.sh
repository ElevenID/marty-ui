#!/usr/bin/env bash
set -euo pipefail

. /scripts/load-secrets-env.sh

require_secret_var KEYCLOAK_ADMIN_PASSWORD
require_secret_var MARTY_API_CLIENT_SECRET

if ! /scripts/setup-keycloak.sh; then
    if [[ "${KEYCLOAK_SETUP_STRICT:-false}" == "true" ]]; then
        echo "[ERROR] Keycloak setup failed and KEYCLOAK_SETUP_STRICT=true" >&2
        exit 1
    fi
    echo "[WARN] Keycloak setup returned non-zero; continuing self-host startup because KEYCLOAK_SETUP_STRICT is not true" >&2
fi

remove_demo_users="${KEYCLOAK_REMOVE_DEMO_USERS:-true}"
if [[ "${remove_demo_users,,}" != "true" ]]; then
    echo "[INFO] Skipping demo-user cleanup"
    exit 0
fi

realm="${KEYCLOAK_REALM:-11id}"
kcadm="${KCADM_PATH:-/opt/keycloak/bin/kcadm.sh}"

find_user_ids() {
    local email="$1"
    local payload row user_id found_email
    if ! payload="$("${kcadm}" get users -r "${realm}" -q "email=${email}" -q exact=true --fields id,email --format csv --noquotes)"; then
        echo "[ERROR] Keycloak demo-user lookup failed for ${email}" >&2
        return 1
    fi
    [[ -z "${payload}" ]] && return 0
    while IFS= read -r row; do
        user_id="${row%%,*}"
        found_email="${row#*,}"
        if [[ "${row}" != *,* || ! "${user_id}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ || "${found_email}" != "${email}" ]]; then
            echo "[ERROR] Unexpected Keycloak demo-user lookup result for ${email}" >&2
            return 1
        fi
        printf '%s\n' "${user_id}"
    done <<< "${payload}"
}

for email in \
    admin@marty.demo \
    canvas.admin@marty.demo \
    reviewer@marty.demo \
    vendor@marty.demo \
    john.doe@marty.demo \
    jane.smith@marty.demo \
    carlos.garcia@marty.demo \
    verifier@marty.demo
do
    user_ids="$(find_user_ids "${email}")"
    for user_id in ${user_ids}; do
        echo "[INFO] Removing demo Keycloak user ${email}"
        "${kcadm}" delete "users/${user_id}" -r "${realm}"
    done
done

echo "[INFO] Keycloak self-host production cleanup complete"
