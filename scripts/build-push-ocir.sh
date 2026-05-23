#!/bin/bash
# Compatibility wrapper. Prefer scripts/build-push-registry.sh for provider-neutral registries.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Warning: scripts/build-push-ocir.sh is deprecated; use scripts/build-push-registry.sh instead." >&2
exec "${SCRIPT_DIR}/build-push-registry.sh" "$@"
