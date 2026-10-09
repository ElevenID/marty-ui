#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: smoke-issuance-image.sh IMAGE}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
postgres_image="$(bash "$repository_root/scripts/ci/pull-pinned-dockerhub-image.sh" \
  postgres:15-alpine@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f)"
postgres_password="marty-test"
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
network="issuance-ci-${suffix}"
postgres="issuance-postgres-${suffix}"
service="issuance-service-${suffix}"
secret_service="issuance-secret-service-${suffix}"
secret_api_key="ci-only-signing-key-api-key-32-characters"
tls_dir="$(mktemp -d "$repository_root/.issuance-smoke-tls-XXXXXXXX")"
python_image="ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176"

cleanup() {
  docker rm --force "$service" "$secret_service" "$postgres" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -f -- "$tls_dir/ca.crt" "$tls_dir/ca.key" "$tls_dir/ca.srl" \
    "$tls_dir/tls.crt" "$tls_dir/tls.key" "$tls_dir/tls.csr" "$tls_dir/tls.ext"
  rmdir -- "$tls_dir" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -subj '/CN=Disposable Issuance Smoke CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$tls_dir/ca.key" -out "$tls_dir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
  -subj '/CN=synthetic-secret-service' \
  -keyout "$tls_dir/tls.key" -out "$tls_dir/tls.csr" >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:synthetic-secret-service' >"$tls_dir/tls.ext"
openssl x509 -req -in "$tls_dir/tls.csr" \
  -CA "$tls_dir/ca.crt" -CAkey "$tls_dir/ca.key" -CAcreateserial \
  -out "$tls_dir/tls.crt" -days 1 -sha256 -extfile "$tls_dir/tls.ext" \
  >/dev/null 2>&1

docker network create "$network" >/dev/null
docker run --detach \
  --name "$postgres" \
  --network "$network" \
  --network-alias issuance-postgres \
  --env POSTGRES_USER=marty \
  --env POSTGRES_PASSWORD="$postgres_password" \
  --env POSTGRES_DB=marty \
  "$postgres_image" \
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
  --env SYNTHETIC_TLS_CERT_FILE=/verification/tls/tls.crt \
  --env SYNTHETIC_TLS_KEY_FILE=/verification/tls/tls.key \
  --mount "type=bind,source=$repository_root/scripts/synthetic_integration_secret_service.py,target=/verification/synthetic_integration_secret_service.py,readonly" \
  --mount "type=bind,source=$tls_dir/tls.crt,target=/verification/tls/tls.crt,readonly" \
  --mount "type=bind,source=$tls_dir/tls.key,target=/verification/tls/tls.key,readonly" \
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
  --env INTEGRATION_SECRET_KMS_URL=https://synthetic-secret-service:8017/internal/signing-keys \
  --env INTEGRATION_SECRET_KMS_CA_FILE=/verification/tls/ca.crt \
  --mount "type=bind,source=$tls_dir/ca.crt,target=/verification/tls/ca.crt,readonly" \
  --env DATABASE_URL="postgresql://marty:${postgres_password}@issuance-postgres/marty" \
  --publish 127.0.0.1::8005 \
  "$image" \
  >/dev/null
port=""
for attempt in {1..60}; do
  port_mapping="$(docker port "$service" 8005/tcp 2>/dev/null || true)"
  port="${port_mapping##*:}"
  if [[ -n "$port_mapping" && "$port" =~ ^[0-9]+$ ]]; then
    break
  fi
  if [[ "$(docker inspect --format '{{.State.Running}}' "$service")" != true ]]; then
    break
  fi
  sleep 0.25
done
if [[ -z "$port_mapping" || ! "$port" =~ ^[0-9]+$ ]]; then
  docker inspect --format 'Issuance container state: {{.State.Status}}' "$service" || true
  docker logs "$service" || true
  docker logs "$secret_service" || true
  exit 1
fi
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
