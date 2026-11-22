#!/usr/bin/env python3
"""Synchronize the shell scripts bundled in the standalone Marty Helm chart."""

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = (
    "setup-keycloak.sh",
    "setup-keycloak-selfhost-production.sh",
    "load-secrets-env.sh",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Report stale or missing copies")
    args = parser.parse_args()

    destination = ROOT / "deploy/helm/marty/files/keycloak"
    stale = []
    for name in NAMES:
        source = ROOT / "scripts" / name
        target = destination / name
        if target.is_file() and target.read_bytes() == source.read_bytes():
            continue
        if args.check:
            stale.append(name)
        else:
            shutil.copy(source, target)

    if stale:
        parser.exit(
            1,
            f"Stale Helm scripts: {', '.join(stale)}. "
            "Run python scripts/sync_helm_keycloak_scripts.py.\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
