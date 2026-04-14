#!/bin/sh
set -e

. /scripts/load-secrets-env.sh

require_secret_var KEYCLOAK_ADMIN_PASSWORD
require_secret_var KC_DB_PASSWORD

exec /opt/keycloak/bin/kc.sh "$@"