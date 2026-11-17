#!/bin/sh
set -e

PUBLIC_DOMAIN=${PUBLIC_DOMAIN:-prod.example.com}
UI_UPSTREAM=${UI_UPSTREAM:-ui:80}
GATEWAY_UPSTREAM=${GATEWAY_UPSTREAM:-gateway:8000}
FLOW_UPSTREAM=${FLOW_UPSTREAM:-flow:8011}
KEYCLOAK_UPSTREAM=${KEYCLOAK_UPSTREAM:-keycloak:8080}
SELFHOST_CONSOLE_ENABLED=${SELFHOST_CONSOLE_ENABLED-true}
case "$SELFHOST_CONSOLE_ENABLED" in
    true) CONSOLE_DISABLED=0 ;;
    false) CONSOLE_DISABLED=1 ;;
    *) echo "SELFHOST_CONSOLE_ENABLED must be true or false" >&2; exit 2 ;;
esac
export CONSOLE_DISABLED

echo "Configuring self-host nginx..."
echo "  PUBLIC_DOMAIN: ${PUBLIC_DOMAIN}"
echo "  UI_UPSTREAM: ${UI_UPSTREAM}"
echo "  GATEWAY_UPSTREAM: ${GATEWAY_UPSTREAM}"
echo "  FLOW_UPSTREAM: ${FLOW_UPSTREAM}"
echo "  KEYCLOAK_UPSTREAM: ${KEYCLOAK_UPSTREAM}"

envsubst '${PUBLIC_DOMAIN} ${UI_UPSTREAM} ${GATEWAY_UPSTREAM} ${FLOW_UPSTREAM} ${KEYCLOAK_UPSTREAM} ${CONSOLE_DISABLED}' \
  < /etc/nginx/conf.d/default.conf.template \
  > /etc/nginx/conf.d/default.conf

echo "Generated self-host nginx configuration"
nginx -t
