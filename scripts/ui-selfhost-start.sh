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

ga_measurement_id="${GOOGLE_ANALYTICS_MEASUREMENT_ID:-}"
site_verification="${GOOGLE_SITE_VERIFICATION:-}"
canonical_origin="${UI_CANONICAL_ORIGIN:-}"
public_entry_origins="${UI_PUBLIC_ENTRY_ORIGINS:-[]}"

# These are public, journal-bound inputs, not arbitrary JavaScript. Accept only
# an empty/default value or the canonical single-alias JSON emitted by the
# installer. Browser-side validation and the edge's Host policy remain separate.
case "${canonical_origin}${public_entry_origins}" in
    *'
'*) echo 'UI hosting inputs must be single-line values' >&2; exit 1 ;;
esac
if [ -n "${canonical_origin}" ] && ! printf '%s' "${canonical_origin}" | LC_ALL=C grep -Eq '^https://[a-z0-9.-]+(:[0-9]+)?$'; then
    echo 'Invalid UI canonical origin' >&2
    exit 1
fi
case "${public_entry_origins}" in
    '[]') ;;
    *)
        if [ -z "${canonical_origin}" ] || ! printf '%s' "${public_entry_origins}" | LC_ALL=C grep -Eq '^\["https://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[[0-9a-f:]+\])(:[0-9]+)?"\]$'; then
            echo 'Invalid UI public entry origin' >&2
            exit 1
        fi
        ;;
esac

echo "Preparing self-host UI assets..."
rm -rf "${TARGET_DIR:?}/"*
cp -R "${SOURCE_DIR}/." "${TARGET_DIR}/"

cat > "${RUNTIME_CONFIG_FILE}" <<EOF
window.__MARTY_RUNTIME_CONFIG__ = Object.assign({}, window.__MARTY_RUNTIME_CONFIG__, {
  googleAnalyticsMeasurementId: '$(escape_js_single_quoted "${ga_measurement_id}")',
  hosting: {
    canonicalOrigin: '${canonical_origin}',
    publicEntryOrigins: ${public_entry_origins}
  }
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
