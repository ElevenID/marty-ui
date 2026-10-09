#!/usr/bin/env bash
# Print the selected, digest-pinned image reference. A cache miss falls back
# to the canonical Docker Hub image without weakening the requested digest.
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^([a-z0-9_-]+):([a-zA-Z0-9_.-]+)@sha256:([0-9a-f]{64})$ ]]; then
    echo 'Expected one digest-pinned Docker Hub official image reference' >&2
    exit 2
fi

canonical=$1
mirror="mirror.gcr.io/library/${canonical}"
if docker image inspect "$canonical" >/dev/null 2>&1; then
    printf '%s\n' "$canonical"
    exit 0
fi
if docker image inspect "$mirror" >/dev/null 2>&1; then
    printf '%s\n' "$mirror"
    exit 0
fi
if docker pull "$mirror" >&2; then
    printf '%s\n' "$mirror"
    exit 0
fi

echo 'Public cache unavailable; trying the canonical digest-pinned image' >&2
docker pull "$canonical" >&2
printf '%s\n' "$canonical"
