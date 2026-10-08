#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: smoke-issuance-image.sh IMAGE}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
postgres_password="marty-test"
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
network="issuance-ci-${suffix}"
postgres="issuance-postgres-${suffix}"
service="issuance-service-${suffix}"
secret_service="issuance-secret-service-${suffix}"
secret_api_key="ci-only-signing-key-api-key-32-characters"
python_image="ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176"

cleanup() {
  docker rm --force "$service" "$secret_service" "$postgres" >/dev/null 2>&1 || true
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
docker exec "$postgres" psql --username marty --dbname marty --set ON_ERROR_STOP=1 \
  --command "CREATE TABLE issuance_service.organization_integration_secrets (id text PRIMARY KEY, organization_id text NOT NULL, provider text NOT NULL, purpose text NOT NULL, encrypted_secret_value text NOT NULL)" \
  >/dev/null

# The packaged API must prove its separate remote secret boundary at startup.
# This no-key test service checks the round trip; live Transit is qualified by
# the OpenBao integration tests.
docker run --detach \
  --name "$secret_service" \
  --network "$network" \
  --network-alias synthetic-secret-service \
  --env SYNTHETIC_API_KEY="$secret_api_key" \
  --mount "type=bind,source=$repository_root/scripts/synthetic_integration_secret_service.py,target=/verification/synthetic_integration_secret_service.py,readonly" \
  --entrypoint python \
  "$python_image" \
  //verification/synthetic_integration_secret_service.py \
  >/dev/null
for attempt in {1..60}; do
  if docker exec "$secret_service" python -c 'import socket; socket.create_connection(("127.0.0.1", 8017), 1).close()' >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" == 60 ]]; then
    docker logs "$secret_service"
    exit 1
  fi
  sleep 0.5
done

docker run --detach \
  --name "$service" \
  --network "$network" \
  --env SERVICE_NAME=issuance_native \
  --env ENVIRONMENT=test \
  --env TOKEN_HMAC_KEY=ci-only-token-hmac-key \
  --env GRPC_SERVICE_TOKEN=ci-only-grpc-service-token-at-least-32-bytes \
  --env SIGNING_KEYS_INTERNAL_API_KEY="$secret_api_key" \
  --env SIGNING_KEYS_INTERNAL_URL=http://synthetic-secret-service:8017/internal/signing-keys \
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
