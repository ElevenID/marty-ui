#!/bin/sh
# Disposable root-only setup; no token values are logged or put in Compose env.
set -eu

if [ "${BAO_ADDR:-}" != "http://openbao:8200" ] ||
   [ ! -r /run/secrets/bao_root_token ] || [ ! -d /work/secrets ]; then
    echo "Disposable OpenBao bootstrap inputs are invalid" >&2
    exit 1
fi
if [ -e /work/secrets/bao_service_token ] ||
   [ -e /work/secrets/bao_bootstrap_token ] ||
   [ -e /work/secrets/notification_openbao_token ] ||
   [ -e /work/secrets/sign_grant_verify_token ] ||
   [ -e /work/secrets/signing_keys_openbao_token ]; then
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

service_token=$(bao token create -policy=credential-service -no-default-policy -orphan -ttl=1h -renewable=false -field=token)
bootstrap_token=$(bao token create -policy=kms-bootstrap -no-default-policy -orphan -ttl=1h -renewable=false -field=token)
notification_token=$(bao token create -policy=notification-webhook-service -orphan -ttl=1h -renewable=false -field=token)
grant_verify_token=$(bao token create -policy=sign-grant-verify -no-default-policy -orphan -ttl=1h -renewable=false -field=token)
signing_keys_token=$(bao token create -policy=credential-service -policy=signing-keys-managed -no-default-policy -orphan -ttl=1h -renewable=false -field=token)
if [ -z "$service_token" ] || [ -z "$bootstrap_token" ] || [ -z "$notification_token" ] || [ -z "$grant_verify_token" ] || [ -z "$signing_keys_token" ] ||
   [ "$service_token" = "$bootstrap_token" ] ||
   [ "$bootstrap_token" = "$notification_token" ] ||
   [ "$bootstrap_token" = "$grant_verify_token" ] ||
   [ "$bootstrap_token" = "$signing_keys_token" ] ||
   [ "$bootstrap_token" = "$BAO_TOKEN" ] ||
   [ "$service_token" = "$notification_token" ] ||
   [ "$grant_verify_token" = "$service_token" ] ||
   [ "$grant_verify_token" = "$notification_token" ] ||
   [ "$signing_keys_token" = "$service_token" ] ||
   [ "$signing_keys_token" = "$notification_token" ] ||
   [ "$signing_keys_token" = "$grant_verify_token" ] ||
   [ "$service_token" = "$BAO_TOKEN" ] ||
   [ "$notification_token" = "$BAO_TOKEN" ] ||
   [ "$grant_verify_token" = "$BAO_TOKEN" ] ||
   [ "$signing_keys_token" = "$BAO_TOKEN" ]; then
    echo "Distinct disposable scoped tokens were not minted" >&2
    exit 1
fi

capabilities() {
    token=$1
    path=$2
    # No-default-policy tokens cannot call capabilities-self. Query their ACLs
    # through the root-owned bootstrap process without mounting root elsewhere.
    bao token capabilities "$token" "$path"
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
allows "$bootstrap_token" transit/keys/cred-issuer-tenant-scope-probe create
allows "$bootstrap_token" transit/keys/flow-response-envelope-marty-aes256 create
denies "$bootstrap_token" transit/sign/cred-issuer-tenant-scope-probe
denies "$bootstrap_token" auth/token/create
allows "$service_token" transit/keys/cred-issuer-tenant-scope-probe read
denies "$service_token" transit/keys/flow-response-envelope-marty-aes256
allows "$notification_token" transit/keys/notification-webhook-envelope-marty-aes256 read
allows "$notification_token" transit/encrypt/notification-webhook-envelope-marty-aes256 update
allows "$notification_token" transit/decrypt/notification-webhook-envelope-marty-aes256 update
denies "$notification_token" transit/sign/cred-issuer-tenant-scope-probe
denies "$notification_token" auth/token/create
allows "$grant_verify_token" transit/verify/marty-sign-grant-issuance-credential-v1/sha2-256 update
denies "$grant_verify_token" transit/hmac/marty-sign-grant-issuance-credential-v1/sha2-256
denies "$grant_verify_token" auth/token/create
allows "$signing_keys_token" transit/keys/cred-issuer-tenant-scope-probe read
denies "$signing_keys_token" auth/token/create

rejects_write() {
    token=$1
    shift
    if result=$(BAO_TOKEN="$token" VAULT_TOKEN="$token" bao write "$@" 2>&1); then
        echo "Disposable token unexpectedly changed OpenBao key custody" >&2
        exit 1
    fi
    case "$result" in
        *"permission denied"*) ;;
        *) echo "Disposable custody denial was not an ACL denial" >&2; exit 1 ;;
    esac
}
rejects_write "$service_token" transit/keys/cred-issuer-marty-creation-probe type=ecdsa-p256
rejects_write "$bootstrap_token" transit/sign/cred-issuer-marty-creation-probe input=YQ==
rejects_write "$bootstrap_token" transit/keys/cred-issuer-marty-import-probe/import ciphertext=invalid

umask 077
migration_tmp=$(mktemp /work/secrets/.bao_service_token.XXXXXX)
bootstrap_tmp=$(mktemp /work/secrets/.bao_bootstrap_token.XXXXXX)
notification_tmp=$(mktemp /work/secrets/.notification_openbao_token.XXXXXX)
grant_verify_tmp=$(mktemp /work/secrets/.sign_grant_verify_token.XXXXXX)
signing_keys_tmp=$(mktemp /work/secrets/.signing_keys_openbao_token.XXXXXX)
trap 'rm -f "$migration_tmp" "$bootstrap_tmp" "$notification_tmp" "$grant_verify_tmp" "$signing_keys_tmp"' EXIT HUP INT TERM
printf '%s' "$service_token" > "$migration_tmp"
printf '%s' "$bootstrap_token" > "$bootstrap_tmp"
printf '%s' "$notification_token" > "$notification_tmp"
printf '%s' "$grant_verify_token" > "$grant_verify_tmp"
printf '%s' "$signing_keys_token" > "$signing_keys_tmp"
mv "$migration_tmp" /work/secrets/bao_service_token
mv "$bootstrap_tmp" /work/secrets/bao_bootstrap_token
mv "$notification_tmp" /work/secrets/notification_openbao_token
mv "$grant_verify_tmp" /work/secrets/sign_grant_verify_token
mv "$signing_keys_tmp" /work/secrets/signing_keys_openbao_token
echo "Disposable OpenBao policies and scoped tokens ready"
