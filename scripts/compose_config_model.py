"""Shared read-only Compose model utilities; never starts or mutates workloads."""

from copy import deepcopy
import json
import os
import re
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT_BASE = "docker-compose.base.yml"
BASE = "docker-compose.selfhost.prod.yml"
BUNDLE = "docker-compose.selfhost.bundle.override.yml"


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



def native_dispatcher_model(service):
    """Canonicalize only the two independently observed empty-command forms.

    Installed Linux Compose 2.38.2 renders source `command: []` as JSON null;
    pinned 5.4 renders []. Both retain this exact nonempty dispatcher entrypoint.
    Source reset identity is independently guarded; never accept a missing key
    or normalize an executable/string/boolean into an empty command.
    """
    assert (
        environment_mapping(service.get("environment", {})).get("SERVICE_NAME")
        == "issuance_native"
    )
    assert service.get("entrypoint") == ["/app/services/entrypoint.sh"]
    assert "command" in service
    assert service["command"] is None or service["command"] == []
    result = deepcopy(service)
    result["command"] = []
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
        if name == "issuance-native":
            assert selector == "issuance_native"
            original = native_dispatcher_model(original)
        elif name in {"issuance", "issuance-migrations"}:
            assert selector == "issuance_native"
        else:
            assert not original.get("command") and not original.get("entrypoint"), (
                f"Review explicit Rust launch override: {name}"
            )
        expected = deepcopy(original)
        del expected["build"]
        expected.update(image=anchor["image"], pull_policy=anchor["pull_policy"])
        expected["environment"] = environment_mapping(original.get("environment", {}))
        expected["environment"]["SERVICE_NAME"] = selector.replace("-", "_")
        actual = deepcopy(bundle["services"][name])
        if name == "issuance-native":
            actual = native_dispatcher_model(actual)
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

