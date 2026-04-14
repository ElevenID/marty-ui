#!/bin/sh
set -e

PUBLIC_DOMAIN=${PUBLIC_DOMAIN:-prod.example.com}
UI_UPSTREAM=${UI_UPSTREAM:-ui:80}
GATEWAY_UPSTREAM=${GATEWAY_UPSTREAM:-gateway:8000}
KEYCLOAK_UPSTREAM=${KEYCLOAK_UPSTREAM:-keycloak:8080}

echo "Configuring self-host nginx..."
echo "  PUBLIC_DOMAIN: ${PUBLIC_DOMAIN}"
echo "  UI_UPSTREAM: ${UI_UPSTREAM}"
echo "  GATEWAY_UPSTREAM: ${GATEWAY_UPSTREAM}"
echo "  KEYCLOAK_UPSTREAM: ${KEYCLOAK_UPSTREAM}"

envsubst '${PUBLIC_DOMAIN} ${UI_UPSTREAM} ${GATEWAY_UPSTREAM} ${KEYCLOAK_UPSTREAM}' \
  < /etc/nginx/conf.d/default.conf.template \
  > /etc/nginx/conf.d/default.conf

echo "Generated self-host nginx configuration"
nginx -t