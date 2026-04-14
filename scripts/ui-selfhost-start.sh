#!/bin/sh
set -eu

. /scripts/load-secrets-env.sh

SOURCE_DIR="/opt/marty-ui-static"
TARGET_DIR="/usr/share/nginx/html"
INDEX_FILE="${TARGET_DIR}/index.html"
RUNTIME_CONFIG_FILE="${TARGET_DIR}/runtime-config.js"

escape_html_attr() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&#39;/g" \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g'
}

escape_sed_replacement() {
    printf '%s' "$1" | sed -e 's/[\\/&|]/\\&/g'
}

escape_js_single_quoted() {
    printf '%s' "$1" | sed -e "s/'/'\"'\"'/g"
}

echo "Preparing self-host UI assets..."
rm -rf "${TARGET_DIR:?}/"*
cp -R "${SOURCE_DIR}/." "${TARGET_DIR}/"

ga_measurement_id="${GOOGLE_ANALYTICS_MEASUREMENT_ID:-}"
site_verification="${GOOGLE_SITE_VERIFICATION:-}"

cat > "${RUNTIME_CONFIG_FILE}" <<EOF
window.__MARTY_RUNTIME_CONFIG__ = Object.assign({}, window.__MARTY_RUNTIME_CONFIG__, {
  googleAnalyticsMeasurementId: '$(escape_js_single_quoted "${ga_measurement_id}")'
});
EOF

if [ -n "${site_verification}" ]; then
    site_verification_meta="<meta name=\"google-site-verification\" content=\"$(escape_html_attr "${site_verification}")\" />"
else
    site_verification_meta=""
fi

sed "s|<!-- SELFHOST_GOOGLE_SITE_VERIFICATION -->|$(escape_sed_replacement "${site_verification_meta}")|" \
    "${INDEX_FILE}" > "${INDEX_FILE}.tmp"
mv "${INDEX_FILE}.tmp" "${INDEX_FILE}"

echo "Self-host UI assets prepared"