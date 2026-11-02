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
enabled_sections="${UI_ENABLED_SECTIONS-public,console}"

# One validated startup choice controls both the server and the client. Empty,
# duplicate and unknown values are errors, never an implicit enable-all mode.
case "${enabled_sections}" in
    public,console) sections_json='["public","console"]' ;;
    public) sections_json='["public"]' ;;
    console) sections_json='["console"]' ;;
    none) sections_json='[]' ;;
    *) echo 'UI_ENABLED_SECTIONS must be public,console, public, console, or none' >&2; exit 1 ;;
esac

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
rm -f "${TARGET_DIR}/.marty-ui-public-disabled" \
    "${TARGET_DIR}/.marty-ui-console-disabled" "${TARGET_DIR}/.marty-ui-disabled"
cp -R "${SOURCE_DIR}/." "${TARGET_DIR}/"

cat > "${RUNTIME_CONFIG_FILE}" <<EOF
window.__MARTY_RUNTIME_CONFIG__ = Object.assign({}, window.__MARTY_RUNTIME_CONFIG__, {
  googleAnalyticsMeasurementId: '$(escape_js_single_quoted "${ga_measurement_id}")',
  web: { enabled_sections: ${sections_json} },
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

# Nginx checks these markers for every HTML entry and its fallback. Removing
# the disabled entry documents also prevents direct /index.html access. Shared
# application assets stay available when either application is enabled.
case "${enabled_sections}" in
    console|none)
        rm -f "${INDEX_FILE}"
        : > "${TARGET_DIR}/.marty-ui-public-disabled"
        ;;
esac
case "${enabled_sections}" in
    public|none)
        rm -rf "${TARGET_DIR}/console"
        : > "${TARGET_DIR}/.marty-ui-console-disabled"
        ;;
esac
if [ "${enabled_sections}" = none ]; then
    rm -rf "${TARGET_DIR:?}/"*
    : > "${TARGET_DIR}/.marty-ui-disabled"
fi

echo "Self-host UI assets prepared"
