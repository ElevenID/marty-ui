#!/bin/sh
# Keep LF line endings; this script is executed directly inside Linux containers.
# Nginx Entrypoint Script for Cloudflare Tunnel
# ==============================================
# Substitutes environment variables in nginx config template

set -e

# Default values
PUBLIC_DOMAIN=${PUBLIC_DOMAIN:-beta.elevenidllc.com}
UI_DEV_PORT=${UI_DEV_PORT:-3000}
DOCS_DOMAIN=${DOCS_DOMAIN:-docs.elevenidllc.com}
GATEWAY_UPSTREAM=${GATEWAY_UPSTREAM:-marty-gateway:8000}

echo "Configuring nginx..."
echo "  PUBLIC_DOMAIN: ${PUBLIC_DOMAIN}"
echo "  UI_DEV_PORT: ${UI_DEV_PORT}"
echo "  DOCS_DOMAIN: ${DOCS_DOMAIN}"
echo "  GATEWAY_UPSTREAM: ${GATEWAY_UPSTREAM}"

# Substitute environment variables in template
envsubst '${PUBLIC_DOMAIN} ${UI_DEV_PORT} ${DOCS_DOMAIN} ${GATEWAY_UPSTREAM} ${CORS_ALLOWED_ORIGIN}' \
  < /etc/nginx/conf.d/default.conf.template \
  > /etc/nginx/conf.d/default.conf

echo "âœ“ Nginx configuration generated"

# Validate configuration
nginx -t
