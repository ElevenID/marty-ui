#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: smoke-verification-image.sh IMAGE dedicated|shared}"
mode="${2:?usage: smoke-verification-image.sh IMAGE dedicated|shared}"
case "$mode" in
  dedicated)
    dispatcher_args=()
    ;;
  shared)
    dispatcher_args=(
      --entrypoint /app/services/entrypoint.sh
      --env SERVICE_NAME=verification
    )
    ;;
  *)
    echo "unsupported verification image mode: $mode" >&2
    exit 64
    ;;
esac

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${mode}-$$"
network="verification-ci-${suffix}"
postgres="verification-postgres-${suffix}"
redis="verification-redis-${suffix}"
service="verification-service-${suffix}"

cleanup() {
  docker rm --force "$service" "$postgres" "$redis" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$network" >/dev/null
docker run --detach \
  --name "$postgres" \
  --network "$network" \
  --network-alias verification-postgres \
  --env POSTGRES_USER=marty \
  --env POSTGRES_PASSWORD=marty-test \
  --env POSTGRES_DB=marty \
  postgres:15-alpine@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f \
  >/dev/null
docker run --detach \
  --name "$redis" \
  --network "$network" \
  --network-alias verification-redis \
  redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2 \
  >/dev/null
for attempt in {1..60}; do
  if docker exec "$postgres" pg_isready --username marty --dbname marty >/dev/null \
    && docker exec "$redis" redis-cli ping | grep --fixed-strings --quiet PONG; then
    break
  fi
  if [[ "$attempt" == 60 ]]; then
    docker logs "$postgres"
    docker logs "$redis"
    exit 1
  fi
  sleep 0.5
done

database_url="postgresql://marty:marty-test@verification-postgres/marty"
for _ in 1 2; do
  docker run --rm \
    --network "$network" \
    --env DATABASE_URL="$database_url" \
    "${dispatcher_args[@]}" \
    "$image" migrate
done
test "$(docker exec "$postgres" psql --username marty --dbname marty --tuples-only --no-align \
  --command 'SELECT version_num FROM verification_service.alembic_version')" = "202608091200"

governance="$(jq --compact-output '.governance' \
  "$repository_root/contracts/verification-governance-behavior.json")"
docker run --detach \
  --name "$service" \
  --network "$network" \
  --env ENVIRONMENT=test \
  --env PUBLIC_BASE_URL=http://verification-service:8012 \
  --env REDIS_URL=redis://verification-redis:6379/3 \
  --env DATABASE_URL="$database_url" \
  --env VERIFICATION_CREDENTIALS_COMPAT_ENABLED=true \
  --env VERIFICATION_GOVERNANCE_JSON="$governance" \
  --env SIGNING_KEYS_INTERNAL_URL=http://gateway.invalid/internal/signing-keys \
  --env SIGNING_KEYS_INTERNAL_API_KEY=ci-only-resolver-key \
  --publish 127.0.0.1::8012 \
  "${dispatcher_args[@]}" \
  "$image" \
  >/dev/null
port="$(docker inspect \
  --format '{{(index (index .NetworkSettings.Ports "8012/tcp") 0).HostPort}}' \
  "$service")"
for attempt in {1..60}; do
  if curl --fail --silent "http://127.0.0.1:${port}/ready" \
      | jq --exit-status '.ready == true' >/dev/null \
    && curl --fail --silent "http://127.0.0.1:${port}/health" \
      | jq --exit-status '.service == "verification"' >/dev/null \
    && curl --fail --silent "http://127.0.0.1:${port}/v1/verification/health" \
      | jq --exit-status '.status == "healthy"' >/dev/null; then
    break
  fi
  if [[ "$attempt" == 60 ]]; then
    docker logs "$service"
    exit 1
  fi
  sleep 0.5
done

request="$(jq --compact-output \
  '{verifier_did:"did:web:verifier.example",presentation_definition:.definition}' \
  "$repository_root/contracts/verification-governance-behavior.json")"
session="$(curl --fail --silent \
  --header 'content-type: application/json' \
  --header 'x-api-key: purpose-scoped-test-key' \
  --data "$request" \
  "http://127.0.0.1:${port}/v1/verification/sessions")"
jq --exit-status \
  '.status == "pending" and .organization_id == "123e4567-e89b-42d3-a456-426614174000" and (.nonce | length > 40)' \
  <<<"$session" \
  >/dev/null
session_id="$(jq --raw-output '.id' <<<"$session")"
result="$(curl --fail --silent \
  --header 'content-type: application/json' \
  --header 'x-api-key: purpose-scoped-test-key' \
  --data '{"presentation":"header.payload.signature"}' \
  "http://127.0.0.1:${port}/v1/verification/sessions/${session_id}/submit")"
jq --exit-status \
  --arg session_id "$session_id" \
  '.valid == false and .decision == "FAIL"
    and .canonical_result.verification_id == ("verification:" + $session_id)
    and .canonical_result.context.transaction_id == ("transaction:" + $session_id)' \
  <<<"$result" \
  >/dev/null
curl --fail --silent \
  --header 'x-api-key: purpose-scoped-test-key' \
  "http://127.0.0.1:${port}/v1/verification/sessions/${session_id}" \
  | jq --exit-status '.status == "failed" and .nonce == ""' \
  >/dev/null
