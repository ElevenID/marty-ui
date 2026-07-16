#!/bin/sh
set -e

if [ -r /app/load-secrets-env.sh ]; then
    . /app/load-secrets-env.sh
fi

if [ -n "${BAO_TOKEN:-}" ] && [ -n "${BAO_TOKEN_FILE:-}" ]; then
    echo "Both BAO_TOKEN and BAO_TOKEN_FILE are set; choose one." >&2
    exit 1
fi

if [ -z "${BAO_ADDR:-}" ]; then
    echo "BAO_ADDR must be set to a container-reachable external Vault/OpenBao address before startup." >&2
    exit 1
fi

if [ -n "${BAO_TOKEN_FILE:-}" ]; then
    echo "Waiting for OpenBao token file at ${BAO_TOKEN_FILE}..."
    while [ ! -s "${BAO_TOKEN_FILE}" ]; do
        sleep 2
    done
    if [ -z "${BAO_TOKEN:-}" ]; then
        export BAO_TOKEN="$(cat "${BAO_TOKEN_FILE}")"
    fi
fi

if [ -z "${BAO_TOKEN:-}" ]; then
    echo "A scoped vault token must be provided through BAO_TOKEN or BAO_TOKEN_FILE before startup." >&2
    exit 1
fi

if is_placeholder_secret_value "${BAO_TOKEN}"; then
    echo "BAO_TOKEN must be set to a non-placeholder scoped vault token before startup." >&2
    exit 1
fi

export VAULT_ADDR="${BAO_ADDR}"
export VAULT_TOKEN="${BAO_TOKEN}"

echo "Waiting for OpenBao health at ${BAO_ADDR}..."
until curl -sf "${BAO_ADDR}/v1/sys/health" >/dev/null 2>&1; do
    sleep 2
done

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec /app/entrypoint.sh
