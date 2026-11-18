#!/bin/sh
# The disposable OpenBao root token is supplied as a project secret. Keep it
# out of the resolved Compose environment and Docker container configuration.
set -eu

token_file=/run/secrets/bao_root_token
if [ ! -r "$token_file" ]; then
    echo "Disposable OpenBao root token is missing" >&2
    exit 1
fi
BAO_DEV_ROOT_TOKEN_ID=$(cat "$token_file")
case "$BAO_DEV_ROOT_TOKEN_ID" in
    *[!0123456789abcdef]* | "")
        echo "Disposable OpenBao root token must be 64 lowercase hex characters" >&2
        exit 1
        ;;
esac
if [ "${#BAO_DEV_ROOT_TOKEN_ID}" -ne 64 ]; then
    echo "Disposable OpenBao root token must be 64 lowercase hex characters" >&2
    exit 1
fi
export BAO_DEV_ROOT_TOKEN_ID
export BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200
# OpenBao's dev banner prints the root token even with -dev-no-store-token.
# Suppress its output; Docker health and the exit status still report failure.
case "${PASSPORT_BAO_TLS_MODE:-database-probe}" in
    required)
        if [ ! -d /tmp/bao-tls ] || [ ! -d /bao/public-ca ] \
            || [ -e /bao/public-ca/ca.crt ] || [ -e /bao/public-ca/.ca.crt.tmp ]; then
            echo "Disposable OpenBao TLS tmpfs or public CA mount is missing" >&2
            exit 1
        fi
        /usr/local/bin/docker-entrypoint.sh server -dev -dev-no-store-token \
            -dev-tls -dev-tls-cert-dir=/tmp/bao-tls >/dev/null 2>&1 &
        bao_pid=$!
        trap 'kill "$bao_pid" 2>/dev/null || true' TERM INT EXIT
        count=0
        until [ -s /tmp/bao-tls/vault-ca.pem ]; do
            if ! kill -0 "$bao_pid" 2>/dev/null || [ "$count" -ge 20 ]; then
                echo "Disposable OpenBao TLS CA was not generated" >&2
                exit 1
            fi
            count=$((count + 1))
            sleep 1
        done
        if ! grep -q 'BEGIN CERTIFICATE' /tmp/bao-tls/vault-ca.pem \
            || grep -q 'PRIVATE KEY' /tmp/bao-tls/vault-ca.pem; then
            echo "Disposable OpenBao public CA is invalid" >&2
            exit 1
        fi
        cp /tmp/bao-tls/vault-ca.pem /bao/public-ca/.ca.crt.tmp
        chmod 0644 /bao/public-ca/.ca.crt.tmp
        mv /bao/public-ca/.ca.crt.tmp /bao/public-ca/ca.crt
        ;;
    database-probe)
        /usr/local/bin/docker-entrypoint.sh server -dev -dev-no-store-token >/dev/null 2>&1 &
        bao_pid=$!
        ;;
    *)
        echo "Disposable OpenBao TLS mode is invalid" >&2
        exit 1
        ;;
esac
trap 'kill "$bao_pid" 2>/dev/null || true' TERM INT
if wait "$bao_pid"; then
    exit 0
else
    status=$?
    echo "Disposable OpenBao exited with status $status" >&2
    exit "$status"
fi
