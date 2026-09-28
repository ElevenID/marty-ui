#!/bin/sh
# Run only in a disposable, project-scoped OpenBao CLI container on the
# acceptance private network. The root token never enters Docker configuration.
set -eu

if [ "${BAO_ADDR:-}" != "http://openbao:8200" ]; then
    echo "Disposable OpenBao endpoint is invalid" >&2
    exit 1
fi
if [ ! -r /run/secrets/bao_root_token ] || [ ! -d /work/secrets ]; then
    echo "Disposable OpenBao bootstrap mounts are missing" >&2
    exit 1
fi
if [ -e /work/secrets/bao_token ] || [ -e /work/secrets/callback_signer_bao_token ]; then
    echo "Disposable OpenBao service tokens already exist" >&2
    exit 1
fi

BAO_TOKEN=$(cat /run/secrets/bao_root_token)
case "$BAO_TOKEN" in
    *[!0123456789abcdef]* | "")
        echo "Disposable OpenBao root token is invalid" >&2
        exit 1
        ;;
esac
if [ "${#BAO_TOKEN}" -ne 64 ]; then
    echo "Disposable OpenBao root token is invalid" >&2
    exit 1
fi
export BAO_TOKEN
export VAULT_ADDR="$BAO_ADDR"
export VAULT_TOKEN="$BAO_TOKEN"

# Reuse the ordinary Marty transit/key/policy initializer. Its development
# PKI root is not the passport CSCA; that certificate needs a managed profile.
/bin/sh /scripts/openbao-init.sh >&2

for spec in \
    cred-issuer-marty-es256:ecdsa-p256 \
    cred-issuer-marty-es384:ecdsa-p384 \
    cred-issuer-marty-rs256:rsa-2048 \
    lti-tool-marty-rs256:rsa-2048 \
    oid4vp-verifier-marty-es256:ecdsa-p256 \
    cred-issuer-marty-eddsa:ed25519 \
    cred-dsc-marty-primary:ecdsa-p256 \
    passport-artifact-marty-aes256:aes256-gcm96 \
    flow-response-envelope-marty-aes256:aes256-gcm96; do
    key=${spec%%:*}
    expected_type=${spec#*:}
    if [ "$(bao read -field=type "transit/keys/$key")" != "$expected_type" ] ||
       [ "$(bao read -field=exportable "transit/keys/$key")" != "false" ]; then
        echo "Disposable managed Transit key has unsafe attributes: $key" >&2
        exit 1
    fi
done
if [ "$(bao read -field=type transit/keys/passport-bureau-callback-marty-hmac)" != "hmac" ] ||
   [ "$(bao read -field=exportable transit/keys/passport-bureau-callback-marty-hmac)" != "false" ]; then
    echo "Disposable callback HMAC key has unsafe attributes" >&2
    exit 1
fi

umask 077
service_tmp=$(mktemp /work/secrets/.bao_token.XXXXXX)
callback_tmp=$(mktemp /work/secrets/.callback_signer_bao_token.XXXXXX)
trap 'rm -f "$service_tmp" "$callback_tmp"' EXIT HUP INT TERM
service_token=$(bao token create -policy=credential-service -orphan -ttl=2h -renewable=false -field=token)
callback_token=$(bao token create -policy=passport-callback-hmac-service -orphan -ttl=2h -renewable=false -field=token)
if [ -z "$service_token" ] || [ -z "$callback_token" ] ||
   [ "$service_token" = "$callback_token" ] ||
   [ "$service_token" = "$BAO_TOKEN" ] || [ "$callback_token" = "$BAO_TOKEN" ]; then
    echo "Disposable OpenBao token creation failed" >&2
    exit 1
fi
printf '%s' "$service_token" > "$service_tmp"
printf '%s' "$callback_token" > "$callback_tmp"

service_caps=$(BAO_TOKEN="$service_token" VAULT_TOKEN="$service_token" bao token capabilities transit/sign/cred-issuer-marty-es256)
callback_caps=$(BAO_TOKEN="$callback_token" VAULT_TOKEN="$callback_token" bao token capabilities transit/hmac/passport-bureau-callback-marty-hmac)
callback_key_caps=$(BAO_TOKEN="$callback_token" VAULT_TOKEN="$callback_token" bao token capabilities transit/keys/passport-bureau-callback-marty-hmac)
callback_verify_caps=$(BAO_TOKEN="$callback_token" VAULT_TOKEN="$callback_token" bao token capabilities transit/verify/passport-bureau-callback-marty-hmac)
callback_sign_caps=$(BAO_TOKEN="$callback_token" VAULT_TOKEN="$callback_token" bao token capabilities transit/sign/cred-issuer-marty-es256)
callback_create_caps=$(BAO_TOKEN="$callback_token" VAULT_TOKEN="$callback_token" bao token capabilities auth/token/create)
service_create_caps=$(BAO_TOKEN="$service_token" VAULT_TOKEN="$service_token" bao token capabilities auth/token/create)
case "$service_caps" in
    *create*update* | *update*create*) ;;
    *) echo "Disposable credential token cannot sign" >&2; exit 1 ;;
esac
case "$callback_caps" in
    "create, update" | "update, create") ;;
    *) echo "Disposable callback token cannot MAC" >&2; exit 1 ;;
esac
if [ "$callback_key_caps" != "deny" ] ||
   [ "$callback_verify_caps" != "deny" ] ||
   [ "$callback_sign_caps" != "deny" ] ||
   [ "$callback_create_caps" != "deny" ] ||
   [ "$service_create_caps" != "deny" ]; then
    echo "Disposable OpenBao service token has excess capabilities" >&2
    exit 1
fi

mv "$service_tmp" /work/secrets/bao_token
mv "$callback_tmp" /work/secrets/callback_signer_bao_token
chmod 0600 /work/secrets/bao_token /work/secrets/callback_signer_bao_token
echo "Disposable OpenBao transit and scoped tokens initialized"
