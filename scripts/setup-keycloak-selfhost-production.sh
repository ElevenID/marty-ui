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

find_user_id() {
    local email="$1"
    local payload
    payload="$(${kcadm} get users -r "${realm}" -q "email=${email}" --fields id,email 2>/dev/null || true)"
    echo "${payload}" | tr -d '\n' | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

for email in \
    admin@marty.demo \
    vendor@marty.demo \
    john.doe@marty.demo \
    jane.smith@marty.demo \
    carlos.garcia@marty.demo \
    verifier@marty.demo
do
    user_id="$(find_user_id "${email}")"
    if [[ -n "${user_id}" ]]; then
        echo "[INFO] Removing demo Keycloak user ${email}"
        "${kcadm}" delete "users/${user_id}" -r "${realm}"
    fi
done

echo "[INFO] Keycloak self-host production cleanup complete"