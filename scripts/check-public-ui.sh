#!/bin/sh
set -eu

SCRIPT_DIR="${0%/*}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"

read_env() {
  key="$1"
  if [ -f "${ENV_FILE}" ]; then
    grep -E "^${key}=" "${ENV_FILE}" | tail -n 1 | cut -d'=' -f2-
  fi
}

PUBLIC_DOMAIN="${PUBLIC_DOMAIN:-$(read_env PUBLIC_DOMAIN)}"
UI_PORT="${UI_DEV_PORT:-$(read_env UI_DEV_PORT)}"
UI_PORT="${UI_PORT:-3002}"

CURL_TLS_ARGS=""
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*)
    # Git-for-Windows curl can fail public checks with CRYPT_E_NO_REVOCATION_CHECK.
    CURL_TLS_ARGS="--ssl-no-revoke"
    ;;
esac

if [ -z "${PUBLIC_DOMAIN}" ]; then
  echo "ERROR: PUBLIC_DOMAIN is not set (env or .env)."
  exit 1
fi

pass_count=0
fail_count=0

check_url() {
  label="$1"
  url="$2"
  expected_regex="$3"

  code=$(curl -s -L ${CURL_TLS_ARGS} --max-time 10 -o /dev/null -w "%{http_code}" "${url}" || true)
  if echo "${code}" | grep -Eq "${expected_regex}"; then
    echo "PASS | ${label} | ${url} | HTTP ${code}"
    pass_count=$((pass_count + 1))
  else
    echo "FAIL | ${label} | ${url} | HTTP ${code}"
    fail_count=$((fail_count + 1))
  fi
}

echo "Running public UI health checks..."

check_url "local-ui" "http://localhost:${UI_PORT}/" "^(200|301|302)$"
check_url "public-root" "https://${PUBLIC_DOMAIN}/" "^(200|301|302)$"
check_url "public-login" "https://${PUBLIC_DOMAIN}/login" "^(200|301|302)$"
check_url "public-auth-login" "https://${PUBLIC_DOMAIN}/v1/auth/login" "^(200|301|302)$"
check_url "public-auth-me" "https://${PUBLIC_DOMAIN}/v1/auth/me" "^(200|401)$"

if [ "${fail_count}" -gt 0 ]; then
  echo "Health check failed: ${fail_count} failing, ${pass_count} passing."
  exit 1
fi

echo "Health check passed: ${pass_count} passing, ${fail_count} failing."
