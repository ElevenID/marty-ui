#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: smoke-issuance-image.sh IMAGE [SIGNING_KEYS_IMAGE]}"
signing_image="${2:-marty-signing-keys:ci}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${MARTY_TEST_SIGNING_KEYS_BAO_CONTAINER:-}" ]]; then
  python_command=(python3)
  child_bash=bash
  child_script="$repository_root/scripts/smoke-issuance-image.sh"
  if [[ "${OSTYPE:-}" == msys* ]]; then
    python_command=(py -3.12)
    child_bash="$(cygpath -w "$(command -v bash)")"
    child_script="$(cygpath -w "$child_script")"
  fi
  exec "${python_command[@]}" "$repository_root/scripts/with_disposable_event_stream_kms.py" \
    --image quay.io/openbao/openbao@sha256:6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878 \
    --profile signing-keys-image -- \
    "$child_bash" "$child_script" "$image" "$signing_image"
fi
postgres_image="$(bash "$repository_root/scripts/ci/pull-pinned-dockerhub-image.sh" \
  postgres:15-alpine@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f)"
redis_image="$(bash "$repository_root/scripts/ci/pull-pinned-dockerhub-image.sh" \
  redis:7.4-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99)"
postgres_password="marty-test"
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
network="issuance-ci-${suffix}"
postgres="issuance-postgres-${suffix}"
service="issuance-service-${suffix}"
secret_service="issuance-secret-service-${suffix}"
redis="issuance-redis-${suffix}"
secret_api_key="ci-only-signing-key-api-key-32-characters"
envelope_api_key="ci-only-dedicated-integration-secret-key-32-chars"
cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    docker logs "$secret_service" 2>/dev/null || true
    docker logs "$service" 2>/dev/null || true
  fi
  docker rm --force "$service" "$secret_service" "$redis" "$postgres" >/dev/null 2>&1 || true
  docker network disconnect --force "$network" "$MARTY_TEST_SIGNING_KEYS_BAO_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create --internal "$network" >/dev/null
docker network connect --alias synthetic-secret-service \
  "$network" "$MARTY_TEST_SIGNING_KEYS_BAO_CONTAINER"
docker run --detach \
  --name "$redis" --network "$network" --network-alias signing-redis \
  "$redis_image" >/dev/null
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
# The real Rust Signing Keys service serves HTTPS using a non-exportable
# Transit TLS key and encrypts the bound secret with a separate Transit key.
echo 'Starting keyless Signing Keys fixture' >&2
docker run --rm --network "container:$MARTY_TEST_SIGNING_KEYS_BAO_CONTAINER" \
  --entrypoint getent "$signing_image" hosts signing-redis >/dev/null
MSYS_NO_PATHCONV=1 docker run --detach \
  --name "$secret_service" \
  --network "container:$MARTY_TEST_SIGNING_KEYS_BAO_CONTAINER" \
  --env SIGNING_KEYS_INTERNAL_API_KEY="$secret_api_key" \
  --env SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY=ci-only-service-sign-gateway-key-32-chars \
  --env SIGNING_KEYS_ISSUER_SIGN_KEY=ci-only-issuer-sign-key-32-characters \
  --env SIGNING_KEYS_INTEGRATION_SECRET_KEY="$envelope_api_key" \
  --env ISSUER_BASE_URL=https://issuer.example \
  --env SIGNING_KEYS_REDIS_URL=redis://signing-redis:6379/2 \
  --env SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE=/verification/grant-token \
  --env BAO_ADDR=https://127.0.0.1:8200 \
  --env BAO_CACERT=/verification/bao-ca.crt \
  --env BAO_TOKEN_FILE=/verification/envelope-token \
  --env SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE=/verification/tls.crt \
  --env SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_ADDR=https://127.0.0.1:8200 \
  --env SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_CA_CERT_FILE=/verification/bao-ca.crt \
  --env SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_TOKEN_FILE=/verification/tls-token \
  --env SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_NAME="$MARTY_TEST_SIGNING_KEYS_TLS_KMS_KEY_NAME" \
  --env SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_VERSION=1 \
  --mount "type=bind,source=$MARTY_TEST_SIGNING_KEYS_TLS_CERT,target=/verification/tls.crt,readonly" \
  --mount "type=bind,source=$MARTY_TEST_SIGNING_KEYS_TLS_CA,target=/verification/workload-ca.crt,readonly" \
  --mount "type=bind,source=$MARTY_TEST_SIGNING_KEYS_TLS_KMS_CA,target=/verification/bao-ca.crt,readonly" \
  --mount "type=bind,source=$MARTY_TEST_SIGNING_KEYS_TLS_KMS_TOKEN_FILE,target=/verification/tls-token,readonly" \
  --mount "type=bind,source=$MARTY_TEST_SIGNING_KEYS_ENVELOPE_TOKEN_FILE,target=/verification/envelope-token,readonly" \
  --mount "type=bind,source=$MARTY_TEST_SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE,target=/verification/grant-token,readonly" \
  "$signing_image" \
  >/dev/null
for attempt in {1..60}; do
  if MSYS_NO_PATHCONV=1 docker exec "$secret_service" curl --fail --silent \
    --cacert /verification/workload-ca.crt https://localhost:8018/health >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" == 60 ]]; then
    docker logs "$secret_service"
    exit 1
  fi
  sleep 0.5
done
echo 'Keyless Signing Keys fixture is ready' >&2

# Startup/health here performs no signing. Unreachable grant authority and
# absent token files keep any unexpected sign attempt fail-closed; live OpenBao
# signing is qualified separately by the managed-route probes.
MSYS_NO_PATHCONV=1 docker run --detach \
  --name "$service" \
  --network "$network" \
  --env SERVICE_NAME=issuance_native \
  --env ENVIRONMENT=test \
  --env TOKEN_HMAC_KEY=ci-only-token-hmac-key \
  --env GRPC_SERVICE_TOKEN=ci-only-grpc-service-token-at-least-32-bytes \
  --env SIGNING_KEYS_INTERNAL_API_KEY="$secret_api_key" \
  --env SIGNING_KEYS_ISSUER_SIGN_KEY=ci-only-dedicated-issuer-sign-key-32-chars \
  --env SIGNING_KEYS_INTEGRATION_SECRET_KEY="$envelope_api_key" \
  --env BAO_ADDR=https://127.0.0.1:1 \
  --env ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN_FILE=/nonexistent/issuance-credential-grant \
  --env ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN_FILE=/nonexistent/issuance-canvas-grant \
  --env ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN_FILE=/nonexistent/issuance-readiness-grant \
  --env ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN_FILE=/nonexistent/issuance-passport-grant \
  --env SIGNING_KEYS_INTERNAL_URL=http://synthetic-secret-service:8017/internal/signing-keys \
  --env INTEGRATION_SECRET_KMS_URL=https://synthetic-secret-service:8018/internal \
  --env INTEGRATION_SECRET_KMS_CA_FILE=/verification/tls/ca.crt \
  --mount "type=bind,source=$MARTY_TEST_SIGNING_KEYS_TLS_CA,target=/verification/tls/ca.crt,readonly" \
  --env DATABASE_URL="postgresql://marty:${postgres_password}@issuance-postgres/marty" \
  "$image" \
  >/dev/null
for attempt in {1..60}; do
  if docker exec "$service" curl --fail --silent http://127.0.0.1:8005/health \
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
