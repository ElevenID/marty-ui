#!/bin/sh
set -e

PRESERVE_BAO_TOKEN_FILE=1
. /scripts/load-secrets-env.sh
unset PRESERVE_BAO_TOKEN_FILE

require_secret_var KEYCLOAK_ADMIN_PASSWORD
require_secret_var KC_DB_PASSWORD
if [ -z "${BAO_TOKEN_FILE:-}" ] || [ -n "${BAO_TOKEN:-}" ] || [ ! -r "${BAO_TOKEN_FILE}" ]; then
    echo "Keycloak requires a readable scoped BAO_TOKEN_FILE without BAO_TOKEN." >&2
    exit 1
fi

exec /opt/keycloak/bin/kc.sh "$@"
