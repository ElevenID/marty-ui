"""Read-only Compose merge gate; no image pull, process launch, or deployment."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BASE = "docker-compose.selfhost.prod.yml"
BUNDLE = "docker-compose.selfhost.bundle.override.yml"
WORKER = "canvas-sync-worker"


def environment_mapping(value):
    if isinstance(value, dict):
        return dict(value)
    assert isinstance(value, list)
    result = {}
    for item in value:
        assert isinstance(item, str)
        key, separator, content = item.partition("=")
        assert key and key not in result
        result[key] = content if separator else None
    return result


def assert_shared_rust_services(base, bundle):
    anchor = bundle["x-selfhost-service-image"]
    assert anchor["pull_policy"] == "always"
    assert "/services:${SELFHOST_IMAGE_TAG:?" in anchor["image"]
    checked = []
    for name, original in base["services"].items():
        build = original.get("build", {})
        dockerfile = build.get("dockerfile")
        if dockerfile == "services/Dockerfile":
            selector = environment_mapping(original.get("environment", {})).get(
                "SERVICE_NAME"
            ) or environment_mapping(build.get("args", {})).get("SERVICE_NAME")
        elif dockerfile == "rust/services/Dockerfile.ci":
            selector = build.get("target")
        else:
            continue
        assert isinstance(selector, str) and selector, f"Missing base selector: {name}"
        assert not original.get("command") and not original.get("entrypoint"), (
            f"Review explicit Rust launch override: {name}"
        )
        expected = deepcopy(original)
        del expected["build"]
        expected.update(image=anchor["image"], pull_policy=anchor["pull_policy"])
        expected["environment"] = environment_mapping(original.get("environment", {}))
        expected["environment"]["SERVICE_NAME"] = selector.replace("-", "_")
        actual = deepcopy(bundle["services"][name])
        actual["environment"] = environment_mapping(actual.get("environment", {}))
        assert actual == expected, (
            f"Bundle must preserve converted Rust service: {name}"
        )
        checked.append(name)
    assert checked, "No converted Rust services inspected"
    return checked


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
    converted = assert_shared_rust_services(base, bundle)
    print(
        "Self-host bundle preserves immutable issuance API, migrations and Canvas worker"
    )
    print(
        f"Self-host bundle preserves all {len(converted)} converted Rust service definitions"
    )


if __name__ == "__main__":
    run()
