"""Read-only Compose merge gate; no image pull, process launch, or deployment."""

import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BASE = "docker-compose.selfhost.prod.yml"
BUNDLE = "docker-compose.selfhost.bundle.override.yml"
WORKER = "canvas-sync-worker"


def render(*files):
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            os.devnull,
            *(argument for file in files for argument in ("-f", file)),
            "config",
            "--no-interpolate",
            "--no-env-resolution",
            "--no-path-resolution",
            # Unexpanded required image expressions are intentionally retained.
            # This proves merge preservation, not runtime configuration validity.
            "--no-consistency",
            "--format",
            "json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    return json.loads(result.stdout)


def assert_inherited_service(base, bundle, service):
    assert bundle["services"][service] == base["services"][service], (
        f"Bundle must preserve the complete unqualified Python {service} definition"
    )


def assert_published_issuance_preserved(base, bundle):
    original = base["services"]["issuance"]
    migration = base["services"]["issuance-migrations"]
    assert original["image"].startswith("${MARTY_ISSUANCE_IMAGE:?"), (
        "Unqualified issuance API must retain its immutable published image"
    )
    assert original["image"] == migration["image"]
    assert original["entrypoint"] == ["/bin/sh", "/app/load-openbao-token-and-start.sh"]
    assert original["command"][:4] == ["python", "-m", "uvicorn", "main:app"]
    for service in ("issuance", "issuance-migrations"):
        assert_inherited_service(base, bundle, service)


def assert_worker_preserved(base, bundle):
    original = base["services"][WORKER]
    assert original["image"].startswith("${MARTY_ISSUANCE_IMAGE:?"), (
        "Unqualified worker must retain the immutable published issuance image"
    )
    assert original["entrypoint"] == ["/bin/sh", "-c"]
    assert len(original["command"]) == 1
    assert original["command"][0].splitlines() == [
        ". /app/load-secrets-env.sh",
        "exec python -m issuance.canvas_worker",
    ]
    assert original["healthcheck"] == {"disable": True}
    assert not original.get("ports")
    assert original["restart"] == "unless-stopped"
    dependencies = original["depends_on"]
    assert set(dependencies) == {"db-migrate", "issuance-migrations"}
    assert all(
        dependency["condition"] == "service_completed_successfully"
        for dependency in dependencies.values()
    )
    # Compare the entire rendered worker, not selected fields: this also guards
    # file-secret bindings, source paths, URL-template escaping, configuration,
    # networks, and future additions against unintended bundle overrides.
    assert_inherited_service(base, bundle, WORKER)


def run():
    base, bundle = render(BASE), render(BASE, BUNDLE)
    assert_worker_preserved(base, bundle)
    assert_published_issuance_preserved(base, bundle)
    print(
        "Self-host bundle preserves immutable issuance API, migrations and Canvas worker"
    )


if __name__ == "__main__":
    run()
