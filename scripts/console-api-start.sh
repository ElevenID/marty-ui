#!/bin/sh
# Container runtime configuration for the independent console; no host setup.
set -eu

origin="${MARTY_SERVER_ORIGIN:-}"
if ! printf '%s\n' "$origin" | LC_ALL=C awk '
    NR == 1 && length($0) <= 2048 && $0 ~ /^https?:\/\/([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(:[0-9]+)?$/ { valid=1; next }
    { valid=0 }
    END { exit !(NR == 1 && valid) }
'; then
    echo 'MARTY_SERVER_ORIGIN must be an HTTP(S) origin without credentials, path, query or fragment' >&2
    exit 1
fi

authority="${origin#*://}"
port=""
case "$authority" in
    \[*\]:*) port="${authority##*:}" ;;
    \[*\]) ;;
    *:*) port="${authority##*:}" ;;
esac
if [ -n "$port" ] && ! printf '%s\n' "$port" | awk 'length($0) <= 5 && $0+0 >= 1 && $0+0 <= 65535 { valid=1 } END { exit !valid }'; then
    echo 'MARTY_SERVER_ORIGIN contains an invalid port' >&2
    exit 1
fi

case "$authority" in
    \[*\]*) host="${authority#\[}"; host="${host%%\]*}" ;;
    *) host="${authority%%:*}" ;;
esac
export MARTY_SERVER_ORIGIN="$origin" MARTY_SERVER_HOST="$host"
envsubst '${MARTY_SERVER_ORIGIN} ${MARTY_SERVER_HOST}' \
    < /etc/nginx/marty-console.conf.template > /etc/nginx/conf.d/default.conf
