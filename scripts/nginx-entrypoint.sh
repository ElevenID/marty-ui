#!/bin/sh
# Nginx Entrypoint Script for Cloudflare Tunnel
# ==============================================
# Substitutes environment variables in nginx config template

set -e

# Default values
PUBLIC_DOMAIN=${PUBLIC_DOMAIN:-beta.elevenidllc.com}
UI_DEV_PORT=${UI_DEV_PORT:-3000}

echo "Configuring nginx..."
echo "  PUBLIC_DOMAIN: ${PUBLIC_DOMAIN}"
echo "  UI_DEV_PORT: ${UI_DEV_PORT}"

# Substitute environment variables in template
envsubst '${PUBLIC_DOMAIN} ${UI_DEV_PORT}' \
  < /etc/nginx/conf.d/default.conf.template \
  > /etc/nginx/conf.d/default.conf

echo "✓ Nginx configuration generated"

# Test nginx configuration
nginx -t

# Start nginx
echo "Starting nginx..."
exec nginx -g 'daemon off;'
