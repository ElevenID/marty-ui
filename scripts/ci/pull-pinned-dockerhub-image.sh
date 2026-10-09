#!/usr/bin/env bash
# Print the selected, digest-pinned image reference. A cache miss falls back
# to the canonical Docker Hub image without weakening the requested digest.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo 'Expected one approved digest-pinned Docker Hub image reference' >&2
    exit 2
fi

canonical=$1
if [[ "$canonical" == "moby/buildkit:buildx-stable-1@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea" ]]; then
    mirror="mirror.gcr.io/${canonical}"
elif [[ "$canonical" =~ ^([a-z0-9_-]+)(:[a-zA-Z0-9_.-]+)?@sha256:([0-9a-f]{64})$ ]]; then
    mirror="mirror.gcr.io/library/${canonical}"
else
    echo 'Expected one approved digest-pinned Docker Hub image reference' >&2
    exit 2
fi
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
