#!/bin/sh
# Operator-only import of an external bureau's HMAC key into non-exportable Transit.
# The ingress and callback signer never receive this source file.
set -eu

: "${BAO_ADDR:?set the private OpenBao address}"
: "${BAO_TOKEN:?set an operator token with Transit import permission}"
: "${PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID:?set the registered provider profile ID}"
: "${PASSPORT_PROVIDER_HMAC_SOURCE_FILE:?set a readable provider HMAC source file}"

profile=$PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID
case "$profile" in
    [A-Za-z0-9]*) ;;
    *) echo 'Invalid provider profile ID' >&2; exit 1 ;;
esac
case "$profile" in
    *[!A-Za-z0-9._-]*) echo 'Invalid provider profile ID' >&2; exit 1 ;;
esac
if [ "${#profile}" -lt 8 ] || [ "${#profile}" -gt 128 ]; then
    echo 'Invalid provider profile ID' >&2
    exit 1
fi
if [ ! -f "$PASSPORT_PROVIDER_HMAC_SOURCE_FILE" ] ||
   [ ! -r "$PASSPORT_PROVIDER_HMAC_SOURCE_FILE" ]; then
    echo 'Provider HMAC source file is unavailable' >&2
    exit 1
fi
size=$(wc -c < "$PASSPORT_PROVIDER_HMAC_SOURCE_FILE" | tr -d ' ')
if [ "$size" -lt 32 ] || [ "$size" -gt 4096 ]; then
    echo 'Provider HMAC source must contain 32 to 4096 exact key bytes' >&2
    exit 1
fi

key_name="passport-provider-callback-$(printf '%s' "$profile" | sha256sum | cut -d' ' -f1)"
mode=${PASSPORT_PROVIDER_HMAC_IMPORT_MODE:-create}
case "$mode" in
    create) ;;
    rotate) ;;
    *) echo 'Import mode must be create or rotate' >&2; exit 1 ;;
esac

# @/dev/stdin prevents placing even base64-encoded key material in process args.
if [ "$mode" = create ]; then
    base64 < "$PASSPORT_PROVIDER_HMAC_SOURCE_FILE" | tr -d '\r\n' |
        bao transit import "transit/keys/$key_name" @/dev/stdin type=hmac exportable=false >/dev/null
else
    base64 < "$PASSPORT_PROVIDER_HMAC_SOURCE_FILE" | tr -d '\r\n' |
        bao transit import-version "transit/keys/$key_name" @/dev/stdin >/dev/null
fi

if [ "$(bao read -field=type "transit/keys/$key_name")" != hmac ] ||
   [ "$(bao read -field=exportable "transit/keys/$key_name")" != false ]; then
    echo 'Imported provider HMAC key has unsafe attributes' >&2
    exit 1
fi
version=$(bao read -field=latest_version "transit/keys/$key_name")
case "$version" in
    ''|*[!0-9]*) echo 'Imported provider HMAC version is invalid' >&2; exit 1 ;;
esac
if [ "$version" -lt 1 ]; then
    echo 'Imported provider HMAC version is invalid' >&2
    exit 1
fi
printf 'Imported provider HMAC reference: %s version %s\n' "$key_name" "$version"
printf 'Set PASSPORT_PROVIDER_HMAC_KEY_VERSION=%s on provider ingress after provider coordination.\n' "$version"
