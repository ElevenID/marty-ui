#!/usr/bin/env python3
"""Inventory writable Compose mounts before a self-host backup/restore rehearsal.

This is a read-only source/artifact check. It does not make a live database
snapshot, export OpenBao, restore data, or qualify an upgrade.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


STATE_MOUNTS = {
    ("postgres", "/var/lib/postgresql/data"): "postgres",
    ("redis", "/data"): "redis",
    ("applicant", "/app/data"): "applicant",
}


def has_symlink_component(path: Path) -> bool:
    current = path
    while current != Path(current.anchor):
        if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
            return True
        current = current.parent
    return False


def recovery_scope(model: dict, state_root: Path, model_sha256: str) -> dict:
    """Reject any unaccounted writable Compose mount in the complete model."""
    if not state_root.is_absolute() or state_root == Path(state_root.anchor):
        raise ValueError("state root must be an absolute non-root directory")
    if has_symlink_component(state_root):
        raise ValueError("state root must not be a symlink")
    services = model.get("services")
    if not isinstance(services, dict) or not services:
        raise ValueError("complete Compose service model is required")
    observed: dict[tuple[str, str], str] = {}
    for service_name, service in services.items():
        if not isinstance(service_name, str) or not isinstance(service, dict):
            raise ValueError("invalid Compose service")
        mounts = service.get("volumes", [])
        if not isinstance(mounts, list):
            raise ValueError(f"invalid mounts for {service_name}")
        for mount in mounts:
            if not isinstance(mount, dict) or not isinstance(mount.get("target"), str):
                raise ValueError(f"invalid mount for {service_name}")
            read_only = mount.get("read_only", False)
            if not isinstance(read_only, bool):
                raise ValueError(f"invalid mount mode for {service_name}")
            if read_only:
                continue
            target = mount["target"]
            key = (service_name, target)
            if key not in STATE_MOUNTS or key in observed or mount.get("type") != "bind":
                raise ValueError(f"unaccounted writable mount: {service_name}:{target}")
            source = mount.get("source")
            if not isinstance(source, str) or not Path(source).is_absolute():
                raise ValueError(f"invalid state mount source: {service_name}:{target}")
            expected = state_root / STATE_MOUNTS[key]
            if has_symlink_component(expected) or Path(source) != expected:
                raise ValueError(f"state mount escaped backup root: {service_name}:{target}")
            observed[key] = STATE_MOUNTS[key]
    if set(observed) != set(STATE_MOUNTS):
        raise ValueError("required writable state mount is missing")
    return {
        "schema": "marty.selfhost-recovery-scope/v1",
        "qualification": "unqualified",
        "compose_model_sha256": model_sha256,
        "writable_bind_mounts": [
            {"service": service, "target": target, "state_subdir": observed[service, target]}
            for service, target in sorted(observed)
        ],
        "separate_recovery_inputs": ["OpenBao state/export", "operator secrets and environment"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-model", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    args = parser.parse_args()
    raw = args.compose_model.read_bytes()
    result = recovery_scope(json.loads(raw), args.state_root, hashlib.sha256(raw).hexdigest())
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
