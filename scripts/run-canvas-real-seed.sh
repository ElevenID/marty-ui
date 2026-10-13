#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
env_file="${1:-.env.tunnel.beta.local}"
[[ -f "$env_file" ]] || { echo "Canvas seed env file is missing: $env_file" >&2; exit 2; }
if grep -Eq '^DATABASE_URL=' "$env_file"; then
  echo "Remove DATABASE_URL from the Canvas seed env file; the runner uses the Compose database" >&2
  exit 2
fi

compose=(docker compose --env-file "$env_file"
  -f docker-compose.base.yml
  -f docker-compose.profile.dev.yml
  -f docker-compose.profile.tunnel.yml
  -f docker-compose.profile.canvas-real.yml)

# Docker Compose does not automatically pass shell-only overrides into `run`.
# Forward the same exported demo settings the former host process received.
forwarded=()
while IFS= read -r name; do
  case "$name" in
    CANVAS_DISPOSABLE_*) ;;
    CANVAS_*|MARTY_API_KEY|ISSUANCE_API_KEY|SIGNING_KEYS_INTERNAL_API_KEY|MARTY_ISSUER_DID|MARTY_ORG_ID|MARTY_ORG_SLUG|MARTY_MIGRATION_PROFILE|PUBLIC_API_URL|UI_BASE_URL)
      forwarded+=(--env "$name") ;;
  esac
done < <(compgen -e)

"${compose[@]}" run --rm --no-deps --user 0 \
  --env-from-file "$env_file" \
  "${forwarded[@]}" \
  --env MARTY_API_BASE_URL=http://gateway:8000 \
  --env ISSUANCE_INTERNAL_API_BASE_URL=http://issuance:8005 \
  --env CANVAS_API_BASE_URL=http://canvas-real:3000 \
  --env SIGNING_KEYS_INTERNAL_BASE_URL=http://signing-keys:8017/internal/signing-keys \
  --env SIGNING_KEYS_HOLDER_PROOF_BASE_URL=http://signing-keys:8017/internal/signing-keys \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  db-migrate /usr/local/bin/marty-canvas-demo-seed --env-file /dev/null
