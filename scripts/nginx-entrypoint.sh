#!/bin/sh
# Nginx Entrypoint Script for Cloudflare Tunnel
# ==============================================
# Substitutes environment variables in nginx config template

set -e

# Default values
PUBLIC_DOMAIN=${PUBLIC_DOMAIN:-beta.elevenidllc.com}
UI_DEV_PORT=${UI_DEV_PORT:-3000}
DOCS_DOMAIN=${DOCS_DOMAIN:-docs.elevenidllc.com}

echo "Configuring nginx..."
echo "  PUBLIC_DOMAIN: ${PUBLIC_DOMAIN}"
echo "  UI_DEV_PORT: ${UI_DEV_PORT}"
echo "  DOCS_DOMAIN: ${DOCS_DOMAIN}"

# Substitute environment variables in template
envsubst '${PUBLIC_DOMAIN} ${UI_DEV_PORT} ${DOCS_DOMAIN} ${CORS_ALLOWED_ORIGIN}' \
  < /etc/nginx/conf.d/default.conf.template \
  > /etc/nginx/conf.d/default.conf

echo "✓ Nginx configuration generated"

# Validate configuration
nginx -t
