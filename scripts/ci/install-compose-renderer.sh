#!/usr/bin/env bash
# Standalone config-only renderer. Never replace the Docker plugin or alter
# bundle compatibility/image-build tooling. Both CI consumers use this pin.
set -euo pipefail
[[ $# == 0 && -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]]
compose_renderer="$RUNNER_TEMP/compose-render-v5.4.0"
curl --fail --location --retry 3 \
  --output "$compose_renderer" \
  https://github.com/docker/compose/releases/download/v5.4.0/docker-compose-linux-x86_64
printf '%s  %s\n' \
  837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be \
  "$compose_renderer" | sha256sum --check --strict
chmod +x "$compose_renderer"
