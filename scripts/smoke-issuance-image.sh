#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: smoke-issuance-image.sh IMAGE}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
postgres_password="marty-test"
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
network="issuance-ci-${suffix}"
postgres="issuance-postgres-${suffix}"
service="issuance-service-${suffix}"

cleanup() {
  docker rm --force "$service" "$postgres" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$network" >/dev/null
docker run --detach \
  --name "$postgres" \
  --network "$network" \
  --network-alias issuance-postgres \
  --env POSTGRES_USER=marty \
  --env POSTGRES_PASSWORD="$postgres_password" \
  --env POSTGRES_DB=marty \
  postgres:15-alpine@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f \
  >/dev/null
for attempt in {1..60}; do
  if docker exec "$postgres" pg_isready \
    --host 127.0.0.1 --username marty --dbname marty >/dev/null; then
    break
  fi
  if [[ "$attempt" == 60 ]]; then
    docker logs "$postgres"
    exit 1
  fi
  sleep 0.5
done

docker exec --interactive --env PGPASSWORD="$postgres_password" "$postgres" \
  psql --host 127.0.0.1 --username marty --dbname marty --set ON_ERROR_STOP=1 \
  <"$repository_root/rust/services/issuance/tests/fixtures/oid4vci_migration_base.sql"

docker run --detach \
  --name "$service" \
  --network "$network" \
  --env ENVIRONMENT=test \
  --env TOKEN_HMAC_KEY=ci-only-token-hmac-key \
  --env GRPC_SERVICE_TOKEN=ci-only-grpc-service-token-at-least-32-bytes \
  --env INTEGRATION_SECRET_MASTER_KEY=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= \
  --env DATABASE_URL="postgresql://marty:${postgres_password}@issuance-postgres/marty" \
  --publish 127.0.0.1::8005 \
  "$image" \
  >/dev/null
port="$(docker inspect \
  --format '{{(index (index .NetworkSettings.Ports "8005/tcp") 0).HostPort}}' \
  "$service")"
for attempt in {1..60}; do
  if curl --fail --silent "http://127.0.0.1:${port}/health" \
    | grep --fixed-strings --quiet '"service":"issuance-service"'; then
    break
  fi
  if [[ "$attempt" == 60 ]]; then
    docker logs "$service"
    docker logs "$postgres"
    exit 1
  fi
  sleep 0.5
done

test "$(docker exec --env PGPASSWORD="$postgres_password" "$postgres" psql --host 127.0.0.1 --username marty --dbname marty --tuples-only --no-align \
  --command "SELECT count(*) FROM information_schema.columns WHERE table_schema='issuance_service' AND table_name IN ('issuance_transactions','authorization_sessions') AND column_name='access_token_expires_at' AND udt_name='timestamptz'")" = "2"
test "$(docker exec --env PGPASSWORD="$postgres_password" "$postgres" psql --host 127.0.0.1 --username marty --dbname marty --tuples-only --no-align \
  --command "SELECT count(*) FROM pg_indexes WHERE schemaname='issuance_service' AND indexname='ux_issuance_events_oid4vci_notification_id'")" = "1"
