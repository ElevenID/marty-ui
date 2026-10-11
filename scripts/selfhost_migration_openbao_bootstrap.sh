#!/bin/sh
# Disposable root-only setup; no token values are logged or put in Compose env.
set -eu

if [ "${BAO_ADDR:-}" != "http://openbao:8200" ] ||
   [ ! -r /run/secrets/bao_root_token ] || [ ! -d /work/secrets ]; then
    echo "Disposable OpenBao bootstrap inputs are invalid" >&2
    exit 1
fi
if [ -e /work/secrets/bao_service_token ] ||
   [ -e /work/secrets/notification_openbao_token ]; then
    echo "Disposable scoped token output already exists" >&2
    exit 1
fi
BAO_TOKEN=$(cat /run/secrets/bao_root_token)
case "$BAO_TOKEN" in
    *[!0123456789abcdef]* | "") echo "Disposable root token is invalid" >&2; exit 1 ;;
esac
if [ "${#BAO_TOKEN}" -ne 64 ]; then
    echo "Disposable root token is invalid" >&2
    exit 1
fi
export BAO_TOKEN VAULT_TOKEN="$BAO_TOKEN" VAULT_ADDR="$BAO_ADDR"
/bin/sh /usr/local/bin/openbao-init >/dev/null

migration_token=$(bao token create -policy=credential-service -orphan -ttl=1h -renewable=false -field=token)
notification_token=$(bao token create -policy=notification-webhook-service -orphan -ttl=1h -renewable=false -field=token)
if [ -z "$migration_token" ] || [ -z "$notification_token" ] ||
   [ "$migration_token" = "$notification_token" ] ||
   [ "$migration_token" = "$BAO_TOKEN" ] ||
   [ "$notification_token" = "$BAO_TOKEN" ]; then
    echo "Distinct disposable scoped tokens were not minted" >&2
    exit 1
fi

capabilities() {
    token=$1
    path=$2
    BAO_TOKEN="$token" VAULT_TOKEN="$token" bao token capabilities "$path"
}
allows() {
    case ", $(capabilities "$1" "$2"), " in
        *", $3, "*) ;;
        *) echo "Disposable token lacks a required capability" >&2; exit 1 ;;
    esac
}
denies() {
    if [ "$(capabilities "$1" "$2")" != "deny" ]; then
        echo "Disposable token has excess capability" >&2
        exit 1
    fi
}
allows "$migration_token" transit/keys/cred-issuer-marty-es256 read
allows "$migration_token" transit/keys/notification-webhook-envelope-marty-aes256 read
denies "$migration_token" transit/decrypt/notification-webhook-envelope-marty-aes256
denies "$migration_token" auth/token/create
allows "$notification_token" transit/keys/notification-webhook-envelope-marty-aes256 read
allows "$notification_token" transit/encrypt/notification-webhook-envelope-marty-aes256 update
allows "$notification_token" transit/decrypt/notification-webhook-envelope-marty-aes256 update
denies "$notification_token" transit/sign/cred-issuer-marty-es256
denies "$notification_token" auth/token/create

umask 077
migration_tmp=$(mktemp /work/secrets/.bao_service_token.XXXXXX)
notification_tmp=$(mktemp /work/secrets/.notification_openbao_token.XXXXXX)
trap 'rm -f "$migration_tmp" "$notification_tmp"' EXIT HUP INT TERM
printf '%s' "$migration_token" > "$migration_tmp"
printf '%s' "$notification_token" > "$notification_tmp"
mv "$migration_tmp" /work/secrets/bao_service_token
mv "$notification_tmp" /work/secrets/notification_openbao_token
echo "Disposable OpenBao policies and scoped tokens ready"
