#!/usr/bin/env bash
# Prefer Google's Docker Hub cache on ephemeral CI runners. Docker retains its
# canonical fallback, and digest-pinned references still require exact bytes.
set -euo pipefail

sudo python3 - <<'PY'
import json
import os
from pathlib import Path
import tempfile

path = Path('/etc/docker/daemon.json')
path.parent.mkdir(parents=True, exist_ok=True)
config = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
mirrors = config.setdefault('registry-mirrors', [])
if not isinstance(mirrors, list) or any(not isinstance(item, str) for item in mirrors):
    raise SystemExit('Docker registry-mirrors must be a list of strings')
if 'https://mirror.gcr.io' not in mirrors:
    mirrors.insert(0, 'https://mirror.gcr.io')
    with tempfile.NamedTemporaryFile(
        mode='w', encoding='utf-8', dir=path.parent, prefix='.daemon-', delete=False
    ) as temporary:
        json.dump(config, temporary, sort_keys=True)
        temporary.write('\n')
        temporary_path = temporary.name
    os.replace(temporary_path, path)
PY

# Registry mirrors are reloadable without restarting Docker or its service
# containers. Require the running daemon to confirm the new configuration.
sudo kill -HUP "$(pgrep -xo dockerd)"
for _ in {1..10}; do
    if docker info --format '{{json .RegistryConfig.Mirrors}}' | grep -Fq 'https://mirror.gcr.io'; then
        exit 0
    fi
    sleep 1
done
echo 'Docker daemon did not activate the registry mirror' >&2
exit 1
