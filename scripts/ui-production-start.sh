#!/bin/sh
set -eu

# Production assets remain prerendered. Only public UI settings are supplied at
# startup; billing credentials never belong in this configuration.
TARGET_DIR="/usr/share/nginx/html"
RUNTIME_CONFIG_PATH="${MARTY_UI_RUNTIME_CONFIG_PATH:-${TARGET_DIR}/runtime-config.js}"
. /scripts/load-secrets-env.sh
ga_measurement_id="${GOOGLE_ANALYTICS_MEASUREMENT_ID:-}"
site_verification="${GOOGLE_SITE_VERIFICATION:-}"
organization_creation_enabled="${ORGANIZATION_CREATION_ENABLED-false}"
case "${organization_creation_enabled}" in
    true|false) ;;
    *) echo 'ORGANIZATION_CREATION_ENABLED must be true or false' >&2; exit 1 ;;
esac
case "$ga_measurement_id" in
    *'
'*) echo 'GOOGLE_ANALYTICS_MEASUREMENT_ID must be a GA4 measurement identifier' >&2; exit 1 ;;
esac
if [ -n "$ga_measurement_id" ] && ! printf '%s' "$ga_measurement_id" | LC_ALL=C grep -Eq '^G-[A-Z0-9]+$'; then
    echo 'GOOGLE_ANALYTICS_MEASUREMENT_ID must be a GA4 measurement identifier' >&2
    exit 1
fi
case "$site_verification" in
    *'
'*) echo 'GOOGLE_SITE_VERIFICATION must be a single-line value' >&2; exit 1 ;;
esac

escape_html_attr() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/"/\&quot;/g' -e "s/'/\&#39;/g" \
        -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

verification_meta=""
if [ -n "$site_verification" ]; then
    verification_meta="<meta name=\"google-site-verification\" content=\"$(escape_html_attr "$site_verification")\" />"
fi
verification_replacement="$(printf '%s' "$verification_meta" | sed -e 's/[\\&|]/\\&/g')"

mkdir -p "$(dirname "$RUNTIME_CONFIG_PATH")"
cat > "${RUNTIME_CONFIG_PATH}.tmp" <<EOF
window.__MARTY_RUNTIME_CONFIG__ = Object.assign({}, window.__MARTY_RUNTIME_CONFIG__, {
  googleAnalyticsMeasurementId: '${ga_measurement_id}',
  organizationCreationEnabled: ${organization_creation_enabled}
});
EOF
mv "${RUNTIME_CONFIG_PATH}.tmp" "$RUNTIME_CONFIG_PATH"

# Each prerendered route has its own HTML head. Replace only our public meta
# value so a restart, update, or explicit empty value cannot retain stale data.
find "$TARGET_DIR" -type f -name '*.html' | while IFS= read -r html; do
    sed "s|<meta name=\"google-site-verification\"[^>]*>||g; s|</head>|${verification_replacement}</head>|g" \
        "$html" > "$html.tmp"
    mv "$html.tmp" "$html"
done
