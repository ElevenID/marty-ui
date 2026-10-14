#!/usr/bin/env bash
# Retry only a public, digest-pinned OpenBao fetch; keep the exact image identity.
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^quay\.io/openbao/openbao@sha256:[0-9a-f]{64}$ ]]; then
    echo 'Expected one digest-pinned Quay OpenBao image reference' >&2
    exit 2
fi

for attempt in 1 2 3; do
    if timeout 120s docker pull "$1"; then
        exit 0
    fi
    if [[ "$attempt" -lt 3 ]]; then
        echo "Pinned OpenBao pull failed (attempt $attempt/3); retrying" >&2
        sleep "$((2 ** (attempt - 1)))"
    fi
done

echo 'Pinned OpenBao image unavailable after three attempts' >&2
exit 1
