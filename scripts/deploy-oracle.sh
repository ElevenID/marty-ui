#!/bin/bash
# Compatibility wrapper. Prefer scripts/deploy-kubernetes.sh for provider-neutral deployments.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Warning: scripts/deploy-oracle.sh is deprecated; use scripts/deploy-kubernetes.sh instead." >&2
exec "${SCRIPT_DIR}/deploy-kubernetes.sh" "$@"
