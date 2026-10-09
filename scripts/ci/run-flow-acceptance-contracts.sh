#!/usr/bin/env bash
# PR-only Flow test-source owner; the protected merge group uses full Canvas.
set -euo pipefail
[[ $# == 0 && "${MARTY_CANVAS_FULL_QUALIFICATION:-0}" == 0 ]] || exit 2
artifacts="${RUNNER_TEMP:?}/rust-test-artifacts.json"
[[ -s "$artifacts" ]] || exit 1
find_artifact() {
  local package="$1" target="$2" profile="$3"
  local -a matches=()
  mapfile -t matches < <(jq -r --arg package "$package" --arg target "$target" --argjson test "$profile" '
    select(.reason == "compiler-artifact")
    | select(.package_id | contains("#" + $package + "@"))
    | select(.target.name == $target and .profile.test == $test)
    | select(.executable != null) | .executable
  ' "$artifacts" | sort -u)
  [[ ${#matches[@]} == 1 && -x "${matches[0]}" ]] || {
    echo "Missing or ambiguous Flow acceptance artifact: $package/$target" >&2
    return 1
  }
  printf '%s\n' "${matches[0]}"
}
flow_executable=$(find_artifact marty-flow-acceptance flow_published_schema_contract true)
issuance_binary=$(find_artifact marty-issuance-service marty-issuance-service false)
flow_binary=$(find_artifact marty-flow marty-flow false)
[[ "$(dirname "$issuance_binary")" == "$(dirname "$flow_binary")" ]] || exit 1
[[ "$flow_binary" == "$(dirname "$issuance_binary")/marty-flow" ]] || exit 1
[[ -x "${MARTY_BASE_COMPOSE_BINARY:?}" && -x "${MARTY_DIDCOMM_TEST_PYTHON:?}" ]] || exit 1
bash "$(dirname "${BASH_SOURCE[0]}")/list-flow-acceptance-cases.sh" "$flow_executable" >/dev/null

# The Flow target's shared fixture insists on these locally present images,
# starts exact-owned disposable containers and verifies their cleanup.
mapfile -t images < <(jq -er '.observed_postgres_image, .observed_image' \
  ../contracts/canvas-worker-consumer-range-oracle.json)
[[ ${#images[@]} == 2 ]] || exit 1
for image in "${images[@]}"; do
  [[ "$image" =~ ^[a-z0-9./_-]+@sha256:[a-f0-9]{64}$ ]] || exit 1
done
MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE="$(bash \
  "$(dirname "${BASH_SOURCE[0]}")/pull-pinned-dockerhub-image.sh" "${images[0]}")"
export MARTY_CANVAS_PUBLISHED_POSTGRES_IMAGE
docker pull "${images[1]}"
# The shared Redis fixture intentionally resolves a local tag to an immutable
# image ID; seed that exact tag from the reviewed digest rather than Docker Hub.
redis_image="$(bash "$(dirname "${BASH_SOURCE[0]}")/pull-pinned-dockerhub-image.sh" \
  redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2)"
docker tag "$redis_image" redis:7-alpine

log=$(mktemp "${RUNNER_TEMP}/flow-acceptance.XXXXXX")
trap 'rm -f -- "$log"' EXIT
MARTY_CANVAS_PUBLISHED_SCHEMA_TEST=1 \
MARTY_ISSUANCE_TEST_BINARY="$issuance_binary" \
  "$flow_executable" --nocapture --test-threads=4 2>&1 | tee "$log"
grep -Eq '^test result: ok\. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' "$log"
