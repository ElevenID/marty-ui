"""Read-only Compose merge gate; no image pull, process launch, or deployment."""

import argparse
from copy import deepcopy
from functools import partial
from itertools import product
import json
import os
from pathlib import Path
import re
import runpy
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BASE = "docker-compose.selfhost.prod.yml"
BUNDLE = "docker-compose.selfhost.bundle.override.yml"
WORKER = "canvas-sync-worker"
DEVELOPMENT_BASE = "docker-compose.base.yml"
CONFORMANCE_PROJECT = "marty-conformance-worker-config"
BETA_WORKER_ENVIRONMENT = {
    "GRPC_SERVICE_TOKEN": "${GRPC_SERVICE_TOKEN:?GRPC_SERVICE_TOKEN must be set for beta Rust services}",
}


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
        differences = sorted(
            field
            for field in actual.keys() | expected.keys()
            if field not in actual
            or field not in expected
            or actual[field] != expected[field]
        )
        assert actual == expected, (
            f"Bundle must preserve converted Rust service: {name}; "
            f"differing fields: {', '.join(differences)}"
        )
        checked.append(name)
    assert checked, "No converted Rust services inspected"
    return checked


def render(*files, profiles=(), project=None, compose_command=None):
    command = ["docker", "compose"] if compose_command is None else compose_command
    if (
        not isinstance(command, (list, tuple))
        or not command
        or not all(isinstance(part, str) and part for part in command)
    ):
        raise ValueError(
            "Compose command must be a nonempty argv sequence, not a shell string"
        )
    result = subprocess.run(
        [
            *command,
            *(["--project-name", project] if project else []),
            "--env-file",
            os.devnull,
            *(argument for file in files for argument in ("-f", file)),
            *(argument for profile in profiles for argument in ("--profile", profile)),
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


def assert_consumer_worker(base, actual, name, *, isolated=False, beta=False):
    """Only the reviewed container-name reset and beta gRPC token may differ."""
    expected = deepcopy(base["services"][WORKER])
    expected["environment"] = environment_mapping(expected.get("environment", {}))
    if isolated:
        expected.pop("container_name", None)
    if beta:
        expected["environment"].update(BETA_WORKER_ENVIRONMENT)
    observed = deepcopy(actual["services"][WORKER])
    observed["environment"] = environment_mapping(observed.get("environment", {}))
    differences = sorted(
        field
        for field in observed.keys() | expected.keys()
        if field not in observed
        or field not in expected
        or observed[field] != expected[field]
    )
    assert observed == expected, (
        f"Consumer must preserve complete Python worker: {name}; "
        f"differing fields: {', '.join(differences)}"
    )


def assert_base_worker_selection(base):
    worker = base["services"][WORKER]
    assert worker["image"].startswith("${MARTY_ISSUANCE_IMAGE:?")
    assert worker["image"] == base["services"]["issuance-migrations"]["image"]
    assert worker["command"] == ["python", "-m", "issuance.canvas_worker"]
    assert not worker.get("entrypoint")
    assert worker["environment"]["CANVAS_SYNC_PROCESSOR"] == (
        "${CANVAS_SYNC_PROCESSOR:-issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target}"
    )
    assert worker["healthcheck"] == {"disable": True}
    assert not worker.get("ports")
    assert worker["restart"] == "unless-stopped"
    assert set(worker["depends_on"]) == {"db-migrate", "issuance-migrations"}
    assert all(
        value["condition"] == "service_completed_successfully"
        for value in worker["depends_on"].values()
    )


def conformance_cases():
    owner = runpy.run_path(str(ROOT / "scripts/conformance_stack.py"))
    cases = []
    for released, haip, didcomm in product((False, True), repeat=3):
        command = owner["compose_command"](
            CONFORMANCE_PROJECT,
            use_ghcr=released,
            include_haip=haip,
            include_didcomm_authcrypt=didcomm,
        )
        files = [
            str(Path(command[index + 1]).relative_to(ROOT))
            for index, value in enumerate(command)
            if value == "--file"
        ]
        profiles = [
            command[index + 1]
            for index, value in enumerate(command)
            if value == "--profile"
        ]
        assert files[0] == DEVELOPMENT_BASE and files[-1] == owner["ISOLATION_FILE"]
        cases.append(
            {
                "name": f"conformance-released={released}-haip={haip}-didcomm={didcomm}",
                "files": files,
                "profiles": profiles,
            }
        )
    return cases


def catalog_cases():
    owner = runpy.run_path(str(ROOT / "packages/marty_devops/catalog.py"))
    catalog = owner["DeploymentCatalog"].load(ROOT)
    cases = []
    for name, stack in sorted(catalog.stacks.items()):
        if not stack.get("compose_files"):
            continue
        required = WORKER in catalog.running_services_for_stack(name)
        if not required and name != "selfhost-beta-tunnel":
            continue
        if not required:
            assert stack["operations"]["up"] == [
                "up",
                "-d",
                "--no-deps",
                "tunnel-nginx-proxy",
                "cloudflared-beta",
            ]
        cases.append(
            {
                "name": name,
                "files": stack["compose_files"],
                "profiles": stack.get("compose_profiles", []),
                "worker_required": required,
            }
        )
    assert cases and any(case["worker_required"] for case in cases)
    return cases


def beta_release_source_files():
    """Read only the runner's initial tracked layers, without executing PowerShell.

    This is not a PowerShell interpreter or a deployment-artifact gate. The
    runner's later generated release/image override appends are intentionally
    outside this source-only matrix; artifact and rollback gates own those.
    """
    source = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text(
        encoding="utf-8"
    )
    match = re.search(r"\$script:ComposeFiles = @\(\n(.*?)\n\)", source, re.DOTALL)
    assert match, "Missing beta runner Compose source list"
    files = []
    for line in match[1].splitlines():
        if not line.strip():
            continue
        entry = re.fullmatch(
            r'\s*\(Join-Path \$script:RepoRoot "(docker-compose[\w.-]*\.yml)"\)\s*,?\s*',
            line,
        )
        assert entry, (
            "Unsupported beta Compose source entry; review the renderer's literal "
            "source grammar before changing the runner's launch layers"
        )
        files.append(entry[1])
    assert files and files[0] == DEVELOPMENT_BASE and "docker-compose.beta.yml" in files
    return files


def assert_conformance_isolation(model):
    assert all(
        not service.get("container_name") for service in model["services"].values()
    )
    assert all(
        not service.get("ports")
        for name, service in model["services"].items()
        if name != "oidf-tls-proxy"
    )
    assert "oidf-tls-proxy" in model["services"], (
        "Conformance profile must actually be enabled"
    )
    assert (
        model["networks"]["marty-network"]["name"]
        == f"{CONFORMANCE_PROJECT}_marty-network"
    )
    bridge = model["networks"]["oidf-runner-network"]
    assert bridge["internal"] is True
    # Secret-free source rendering intentionally retains this project expression.
    assert (
        bridge["name"]
        == "${MARTY_CONFORMANCE_PROJECT:?set MARTY_CONFORMANCE_PROJECT}_oidf-runner"
    )
    assert all(
        resource["name"].startswith(f"{CONFORMANCE_PROJECT}_")
        for resource in model.get("volumes", {}).values()
    )


def assert_consumer_matrix(renderer=None):
    renderer = renderer or render
    base = renderer(DEVELOPMENT_BASE)
    assert_base_worker_selection(base)
    checked = []
    for case in conformance_cases():
        model = renderer(
            *case["files"], profiles=case["profiles"], project=CONFORMANCE_PROJECT
        )
        assert_consumer_worker(base, model, case["name"], isolated=True)
        assert_conformance_isolation(model)
        checked.append(case["name"])
    for case in catalog_cases():
        original = renderer(case["files"][0])
        model = renderer(*case["files"], profiles=case["profiles"])
        assert_consumer_worker(original, model, case["name"])
        checked.append(
            case["name"]
            + (
                " (definition only; tunnel-only up)"
                if not case["worker_required"]
                else ""
            )
        )
    for name, files in (
        ("base-beta", [DEVELOPMENT_BASE, "docker-compose.beta.yml"]),
        ("beta-release-tracked-sources", beta_release_source_files()),
    ):
        model = renderer(*files)
        assert_consumer_worker(base, model, name, beta=True)
        assert model["networks"]["marty-network"]["name"] == "elevenid-beta-network"
        checked.append(name)
    return checked


def run(suite="bundle", compose_command=None):
    if suite not in {"bundle", "consumers"}:
        raise ValueError("Unknown Compose gate suite")
    renderer = (
        render
        if compose_command is None
        else partial(render, compose_command=compose_command)
    )
    if suite == "consumers":
        consumers = assert_consumer_matrix(renderer)
        print(
            f"Canvas consumer matrix preserves complete Python worker definitions in {len(consumers)} conformance/catalog/beta compositions (configuration only)"
        )
        return
    # Keep the installed/older Compose bundle qualification independent from
    # the modern parser needed for no-interpolate source bind expressions.
    base, bundle = renderer(BASE), renderer(BASE, BUNDLE)
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("bundle", "consumers"), default="bundle")
    parser.add_argument(
        "--compose-command",
        nargs="+",
        help="Compose argv prefix; a standalone binary path or docker compose",
    )
    arguments = parser.parse_args()
    run(arguments.suite, arguments.compose_command)
