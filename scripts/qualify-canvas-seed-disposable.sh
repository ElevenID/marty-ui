#!/usr/bin/env bash
set -euo pipefail

# A dedicated Compose project and network keep the Canvas seed away from beta
# and self-host production. Supply an env file created from the example.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
action="${1:-config}"
env_file="${2:-.env.canvas-disposable.local}"
project="${CANVAS_DISPOSABLE_PROJECT:-marty-canvas-disposable-local}"

if [[ ! "$project" =~ ^marty-canvas-disposable-[a-z0-9-]+$ ]]; then
  echo "CANVAS_DISPOSABLE_PROJECT must start with marty-canvas-disposable-" >&2
  exit 2
fi
if [[ ! -f "$env_file" ]]; then
  echo "Create $env_file from config/canvas/disposable-seed.env.example" >&2
  exit 2
fi
export CANVAS_DISPOSABLE_PROJECT="$project"

compose=(docker compose --env-file "$env_file" -p "$project"
  -f docker-compose.base.yml
  -f docker-compose.profile.dev.yml
  -f docker-compose.profile.canvas-real.yml
  -f docker-compose.profile.canvas-sandbox.yml
  -f docker-compose.profile.canvas-disposable.yml)

env_value() {
  local name="$1"
  sed -n "s/^${name}=//p" "$env_file" | tail -n 1 | tr -d '\r'
}

validate_disposable_endpoints() {
    [[ "$(env_value MARTY_API_BASE_URL)" == "http://gateway:8000" ]] || {
      echo "MARTY_API_BASE_URL must be http://gateway:8000" >&2; exit 2;
    }
    [[ "$(env_value ISSUANCE_INTERNAL_API_BASE_URL)" == "http://issuance:8005" ]] || {
      echo "ISSUANCE_INTERNAL_API_BASE_URL must be http://issuance:8005" >&2; exit 2;
    }
    [[ "$(env_value CANVAS_API_BASE_URL)" == "http://canvas-real:3000" ]] || {
      echo "CANVAS_API_BASE_URL must be http://canvas-real:3000" >&2; exit 2;
    }
    [[ "$(env_value CANVAS_CONNECTOR_BASE_URL)" == "http://localhost:${CANVAS_DISPOSABLE_CANVAS_PORT:-18088}" ]] || {
      echo "CANVAS_CONNECTOR_BASE_URL must target the disposable localhost bridge" >&2; exit 2;
    }
    [[ "$(env_value CANVAS_LTI_EXPERIENCE_BASE_URL)" == "http://localhost:5173" && "$(env_value UI_BASE_URL)" == "http://localhost:5173" ]] || {
      echo "Canvas launch UI must use the local disposable Vite server on localhost:5173" >&2; exit 2;
    }
    [[ "$(env_value CANVAS_INTEROPERABILITY_BADGE_VCT)" == "http://localhost:5173/credentials/canvas-interoperability-foundations-badge" ]] || {
      echo "Open Badge VCT must target the disposable local UI" >&2; exit 2;
    }
    [[ "$(env_value KC_HOSTNAME_PORT)" == "18180" && "$(env_value OIDC_ISSUER_URL_EXTERNAL)" == "http://localhost:18180/realms/11id" ]] || {
      echo "OIDC issuer must target the disposable local Keycloak" >&2; exit 2;
    }
    [[ "$(env_value OIDC_REDIRECT_URI)" == "http://localhost:5173/v1/auth/callback" && "$(env_value OIDC_POST_LOGOUT_REDIRECT_URI)" == "http://localhost:5173/" ]] || {
      echo "OIDC redirect URIs must target the disposable local UI" >&2; exit 2;
    }
    [[ "$(env_value PUBLIC_API_URL)" == "http://gateway:8000" ]] || {
      echo "PUBLIC_API_URL must be http://gateway:8000" >&2; exit 2;
    }
    [[ "$(env_value SIGNING_KEYS_INTERNAL_BASE_URL)" == "http://signing-keys:8017/internal/signing-keys" ]] || {
      echo "SIGNING_KEYS_INTERNAL_BASE_URL must target the disposable signing-keys service" >&2; exit 2;
    }
    [[ "$(env_value SIGNING_KEYS_HOLDER_PROOF_BASE_URL)" == "http://signing-keys:8017/internal/signing-keys" ]] || {
      echo "SIGNING_KEYS_HOLDER_PROOF_BASE_URL must target the disposable signing-keys service" >&2; exit 2;
    }
    [[ "$(env_value CANVAS_REAL_CONTAINER_NAME)" == "$project-canvas-real" ]] || {
      echo "CANVAS_REAL_CONTAINER_NAME must identify this disposable project" >&2; exit 2;
    }
    [[ -n "$(env_value CANVAS_CREDENTIALS_SHARED_SECRET)" ]] || {
      echo "A disposable CANVAS_CREDENTIALS_SHARED_SECRET is required; Docker inspect fallback is forbidden" >&2; exit 2;
    }
    if grep -Eq '^(DATABASE_URL|DATABASE_HOST|POSTGRES_HOST|MARTY_DB_HOST)=' "$env_file"; then
      echo "Do not override the migration image's project-local database connection" >&2
      exit 2
    fi
}

require_dedicated_daemon() {
  local container_id owner
  local containers
  containers="$(docker ps -q)"
  for container_id in $containers; do
    owner="$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$container_id")"
    [[ "$owner" == "$project" ]] || {
      echo "Refusing to start Canvas on a Docker daemon with another running project" >&2
      exit 2
    }
  done
}

case "$action" in
  config)
    "${compose[@]}" config --quiet
    echo "Disposable Compose project $project is valid"
    ;;
  up)
    validate_disposable_endpoints
    "${compose[@]}" config --quiet
    require_dedicated_daemon
    "${compose[@]}" up --build -d gateway issuance signing-keys canvas-real canvas-sandbox issuance-canvas-localhost-bridge
    ;;
  seed)
    validate_disposable_endpoints
    [[ "$(env_value MARTY_API_KEY)" != "" && "$(env_value MARTY_API_KEY)" != "replace-with-disposable-org-actor-key" ]] || {
      echo "Set MARTY_API_KEY to an organization actor key created in the disposable stack" >&2; exit 2;
    }
    canvas_id="$("${compose[@]}" ps -q canvas-real)"
    [[ -n "$canvas_id" ]] || { echo "Disposable Canvas is not running" >&2; exit 2; }
    [[ "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$canvas_id")" == "$project" ]] || {
      echo "Canvas container does not belong to the disposable project" >&2; exit 2;
    }
    "${compose[@]}" run --rm --no-deps --user 0 \
      --env-from-file "$env_file" \
      --volume /var/run/docker.sock:/var/run/docker.sock \
      db-migrate /usr/local/bin/marty-canvas-demo-seed --env-file /dev/null
    ;;
  down)
    "${compose[@]}" down --volumes
    ;;
  *)
    echo "Usage: $0 {config|up|seed|down} [disposable-env-file]" >&2
    exit 2
    ;;
esac
