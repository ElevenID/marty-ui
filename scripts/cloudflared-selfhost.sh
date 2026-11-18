#!/bin/sh
set -eu

token_file="${CLOUDFLARE_TUNNEL_TOKEN_FILE:-/run/secrets/cloudflare_tunnel_token}"

if [ ! -f "${token_file}" ]; then
	echo "Missing Cloudflare tunnel token file: ${token_file}" >&2
	exit 1
fi

token="$(tr -d '\r\n' < "${token_file}")"

if [ -z "${token}" ]; then
	echo "Cloudflare tunnel token file is empty: ${token_file}" >&2
	exit 1
fi

unset CLOUDFLARE_TUNNEL_TOKEN_FILE

TUNNEL_TOKEN="${token}"
export TUNNEL_TOKEN
unset token
exec cloudflared tunnel --no-autoupdate run
