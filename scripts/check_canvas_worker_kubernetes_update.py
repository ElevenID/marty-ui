"""Read-only image-update guard, not rollout or concurrent-operator qualification."""

from __future__ import annotations

import json
import math
import sys

MAX_DEPLOYMENT_BYTES = 1024 * 1024
REFUSAL = "Canvas worker image update refused; apply the reviewed full-manifest cutover first."


def _closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError()


def _finite_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError()
    return parsed


def validate_deployment(value: object, namespace: str) -> None:
    """Require the exact already-applied native launch; never disclose its data."""
    if not isinstance(value, dict) or value.get("apiVersion") != "apps/v1":
        raise ValueError()
    if value.get("kind") != "Deployment" or not namespace:
        raise ValueError()
    metadata = value.get("metadata")
    if not isinstance(metadata, dict) or (
        metadata.get("name") != "canvas-sync-worker"
        or metadata.get("namespace") != namespace
    ):
        raise ValueError()
    spec = value.get("spec")
    template = spec.get("template") if isinstance(spec, dict) else None
    pod = template.get("spec") if isinstance(template, dict) else None
    containers = pod.get("containers") if isinstance(pod, dict) else None
    if not isinstance(containers, list) or not containers:
        raise ValueError()
    names = set()
    worker = None
    for container in containers:
        name = container.get("name") if isinstance(container, dict) else None
        if not isinstance(name, str) or not name or name in names:
            raise ValueError()
        names.add(name)
        if name == "canvas-sync-worker":
            worker = container
    if worker is None or worker.get("command") != [
        "/usr/local/bin/marty-canvas-sync-worker"
    ]:
        raise ValueError()
    if "args" in worker and worker["args"] != []:
        raise ValueError()
    environment = worker.get("env")
    if not isinstance(environment, list):
        raise ValueError()
    entries = {}
    for entry in environment:
        name = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or name in entries:
            raise ValueError()
        entries[name] = entry
    for name, expected in (
        ("SERVICE_NAME", "canvas_sync_worker"),
        ("CANVAS_SYNC_PROCESSOR", ""),
    ):
        if entries.get(name) != {"name": name, "value": expected}:
            raise ValueError()


def check_bytes(data: bytes, namespace: str) -> None:
    if len(data) > MAX_DEPLOYMENT_BYTES:
        raise ValueError()
    validate_deployment(
        json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        ),
        namespace,
    )


def main() -> int:
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--namespace":
            raise ValueError()
        check_bytes(sys.stdin.buffer.read(MAX_DEPLOYMENT_BYTES + 1), sys.argv[2])
    except (ValueError, TypeError, RecursionError, OSError):
        print(REFUSAL, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
