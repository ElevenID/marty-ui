#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?}"
: "${MARTY_API_CORE_URI:?}"
: "${MARTY_API_CORE_DIGEST:?}"
: "${MARTY_BLOG_URI:?}"
: "${MARTY_BLOG_DIGEST:?}"

download_verified() {
  local url="$1" digest="$2" output="$3"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]
  curl --fail --location --silent --show-error \
    --retry 3 --retry-all-errors --retry-delay 2 --retry-max-time 90 \
    --connect-timeout 10 --max-time 30 \
    "$url" --output "$output"
  printf '%s  %s\n' "${digest#sha256:}" "$output" | sha256sum --check --strict
}

download_verified "$MARTY_API_CORE_URI" "$MARTY_API_CORE_DIGEST" "$RUNNER_TEMP/marty-api-core.tgz"
download_verified "$MARTY_BLOG_URI" "$MARTY_BLOG_DIGEST" "$RUNNER_TEMP/marty-blog.tgz"
