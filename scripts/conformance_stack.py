#!/usr/bin/env python3
"""Operate a clean, project-scoped interoperability stack on any Docker engine."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse


ROOT = Path(__file__).resolve().parents[1]
PROJECT = re.compile(r"^marty-conformance-[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])?$")
BASE_FILES = (
    "docker-compose.base.yml",
    "docker-compose.beta.yml",
    "docker-compose.profile.oidf.yml",
)
GHCR_FILE = "docker-compose.profile.ghcr.yml"
LOCAL_BUILD_FILE = "docker-compose.profile.local-build.yml"
IMMUTABLE_INFRA_FILE = "docker-compose.profile.conformance-images.yml"
HAIP_FILE = "docker-compose.profile.oidf-haip.yml"
DIDCOMM_AUTHCRYPT_FILE = "docker-compose.profile.issuance-native-authcrypt.yml"
NATIVE_FILE = "docker-compose.profile.conformance-native.yml"
NATIVE_IMAGES_FILE = "docker-compose.profile.issuance-native-images.yml"
NATIVE_CA_FILE = "docker-compose.profile.didcomm-native-conformance.yml"
LOCAL_SOURCE_MIGRATION_FILE = "docker-compose.profile.conformance-source-migration.yml"
ISOLATION_FILE = "docker-compose.profile.conformance.yml"
PUBLIC_PORT_SERVICES = {"oidf-tls-proxy"}
ONE_SHOT_SERVICES = {
    "db-migrate",
    "issuance-migrations",
    "keycloak-configurator",
    "openbao-init",
}
KMS_BOOTSTRAP_SERVICES = {"openbao-tls-init", "openbao-init", "openbao"}
PUBLIC_JWK_PRIVATE_PARAMETERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


def validate_project(project: str) -> str:
    if not PROJECT.fullmatch(project):
        raise ValueError(
            "project must match marty-conformance-<run-id> using lowercase letters, digits, and hyphens"
        )
    return project


def configure_project_environment(project: str) -> None:
    """Bind Compose interpolation to the same validated project as the CLI."""
    configured = os.environ.get("MARTY_CONFORMANCE_PROJECT", "").strip()
    if configured and configured != project:
        raise ValueError(
            "MARTY_CONFORMANCE_PROJECT conflicts with the validated --project value"
        )
    os.environ["MARTY_CONFORMANCE_PROJECT"] = project


def compose_command(
    project: str,
    *,
    include_haip: bool = False,
    include_didcomm_authcrypt: bool = False,
    use_ghcr: bool = True,
    issuance_owner: str = "native",
) -> list[str]:
    if issuance_owner not in {"legacy", "native"}:
        raise ValueError("issuance owner must be legacy or native")
    command = ["docker", "compose", "--project-name", validate_project(project)]
    files = [*BASE_FILES]
    if use_ghcr:
        # The released image overlay must follow the OIDF source-build
        # definition so its build reset also applies to the keyless edge.
        files.extend((GHCR_FILE, IMMUTABLE_INFRA_FILE))
    else:
        # The base stack defines the source-built Rust services. The UI is
        # deliberately supplied by a mode-specific profile because released
        # runs replace it with an immutable GHCR image. Without this profile,
        # --local-build cannot even render: the public TLS proxy depends on an
        # undefined ``ui`` service.
        files.insert(1, LOCAL_BUILD_FILE)
    if include_haip:
        files.append(HAIP_FILE)
    if issuance_owner == "native":
        files.append(NATIVE_FILE)
        if use_ghcr:
            files.append(NATIVE_IMAGES_FILE)
    migration_binary = os.environ.get("MARTY_CONFORMANCE_SOURCE_MIGRATION_BINARY", "").strip()
    if migration_binary:
        expected = os.environ.get("MARTY_CONFORMANCE_SOURCE_MIGRATION_SHA256", "").strip()
        volume_root = os.environ.get("MARTY_CONFORMANCE_SOURCE_VOLUME_ROOT", "").strip()
        if not use_ghcr or issuance_owner != "native" or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("local source migration requires native immutable-image mode and exact digest")
        if not volume_root or not Path(volume_root).is_absolute() or not Path(migration_binary).is_absolute():
            raise ValueError("local source migration requires absolute owned-volume paths")
        root = Path(volume_root).resolve(strict=True)
        raw_binary = Path(migration_binary)
        binary = raw_binary.resolve(strict=True)
        if (raw_binary.is_symlink() or not binary.is_file()
                or binary.name != "marty-issuance-service" or not binary.is_relative_to(root)):
            raise ValueError("local source migrator is outside the owned native binary volume")
        with binary.open("rb") as source:
            actual = hashlib.file_digest(source, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("local source migrator digest changed")
        files.append(LOCAL_SOURCE_MIGRATION_FILE)
    if include_didcomm_authcrypt:
        if issuance_owner != "native":
            raise ValueError("DIDComm authcrypt requires the native issuance owner")
        files.append(DIDCOMM_AUTHCRYPT_FILE)
    if issuance_owner == "native":
        files.append(NATIVE_CA_FILE)
    files.append(ISOLATION_FILE)
    for compose_file in files:
        command.extend(["--file", os.fspath(ROOT / compose_file)])
    command.extend(["--profile", "oidf"])
    return command


def rendered_config(
    project: str,
    *,
    include_haip: bool = False,
    include_didcomm_authcrypt: bool = False,
    use_ghcr: bool = True,
    issuance_owner: str = "native",
) -> dict[str, Any]:
    completed = subprocess.run(
        [
            *compose_command(
                project,
                include_haip=include_haip,
                include_didcomm_authcrypt=include_didcomm_authcrypt,
                use_ghcr=use_ghcr,
                issuance_owner=issuance_owner,
            ),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise ValueError(f"Compose configuration failed:\n{completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("Compose returned invalid JSON configuration") from error


def validate_isolation(config: dict[str, Any], project: str) -> list[int]:
    """Reject any resource that could collide with or reuse another project."""
    services = config.get("services", {})
    fixed = [
        name for name, service in services.items() if service.get("container_name")
    ]
    if fixed:
        raise ValueError(
            f"fixed container names defeat project isolation: {', '.join(sorted(fixed))}"
        )

    published: list[int] = []
    for name, service in services.items():
        ports = service.get("ports", [])
        if ports and name not in PUBLIC_PORT_SERVICES:
            raise ValueError(f"service {name} unexpectedly publishes a host port")
        for port in ports:
            value = port.get("published")
            if value is None:
                raise ValueError(f"service {name} must publish an explicit host port")
            published.append(int(value))
    if len(published) != len(set(published)):
        raise ValueError("conformance services publish duplicate host ports")

    for kind in ("networks", "volumes"):
        for name, resource in config.get(kind, {}).items():
            actual = resource.get("name", "")
            if not actual.startswith(f"{project}_"):
                raise ValueError(
                    f"{kind[:-1]} {name} is not scoped to project {project}: {actual}"
                )
    return published


def public_service_targets(config: dict[str, Any]) -> dict[str, list[int]]:
    """Return the actual container-side ports for approved public services.

    The conformance TLS listener deliberately follows the externally visible
    URL port so a runner on the scoped Docker bridge observes the same origin
    as a host-side browser. Consequently it is not safe to assume that the
    container target is always 443.
    """
    result: dict[str, list[int]] = {}
    services = config.get("services", {})
    for name in sorted(PUBLIC_PORT_SERVICES & services.keys()):
        targets: set[int] = set()
        for port in services[name].get("ports", []):
            target = port.get("target")
            if target is None:
                raise ValueError(
                    f"service {name} has a published port without a target"
                )
            targets.add(int(target))
        if targets:
            result[name] = sorted(targets)
    return result


def parse_compose_ps(payload: str) -> list[dict[str, Any]]:
    """Accept both array and newline-delimited Compose JSON output."""
    payload = payload.strip()
    if not payload:
        return []
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return [json.loads(line) for line in payload.splitlines() if line.strip()]
    if isinstance(parsed, dict):
        return [parsed]
    if not isinstance(parsed, list) or not all(
        isinstance(item, dict) for item in parsed
    ):
        raise ValueError("Compose ps returned an unexpected JSON shape")
    return parsed


def wait_for_one_shots(
    command: list[str],
    config: dict[str, Any],
    *,
    timeout_seconds: float = 300,
    poll_seconds: float = 2,
) -> None:
    """Require every initializer to finish successfully before testing."""
    expected = sorted(ONE_SHOT_SERVICES & config.get("services", {}).keys())
    if not expected:
        return
    deadline = time.monotonic() + timeout_seconds
    while True:
        completed = subprocess.run(
            [*command, "ps", "--all", "--format", "json", *expected],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        rows = parse_compose_ps(completed.stdout)
        states = {name: [] for name in expected}
        for row in rows:
            service = str(row.get("Service", ""))
            if service not in states:
                continue
            state = str(row.get("State", "")).lower()
            exit_code = int(row.get("ExitCode") or 0)
            if state in {"dead", "exited"} and exit_code != 0:
                raise ValueError(
                    f"one-shot service {service} exited with status {exit_code}"
                )
            states[service].append((state, exit_code))
        if all(
            values
            and all(state == "exited" and exit_code == 0 for state, exit_code in values)
            for values in states.values()
        ):
            return
        if time.monotonic() >= deadline:
            pending = ", ".join(
                name
                for name, values in states.items()
                if not values or values[-1][0] != "exited"
            )
            raise ValueError(f"timed out waiting for one-shot services: {pending}")
        time.sleep(poll_seconds)


def source_migration_container_before_up(project: str) -> str | None:
    """Distinguish a KMS-only resume from a previously run migrator."""
    selected = subprocess.check_output(
        ["docker", "ps", "--all", "--no-trunc", "--quiet", "--filter",
         f"label=com.docker.compose.project={project}", "--filter",
         "label=com.docker.compose.service=issuance-migrations"],
        text=True,
    ).split()
    if len(selected) > 1 or any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in selected):
        raise ValueError("prior issuance migration ownership is ambiguous")
    return selected[0] if selected else None


def attest_local_source_migration(
    project: str, config: dict[str, Any], *, resume: bool = False,
    preexisting_container_id: str | None = None,
) -> None:
    """Record the normal source-built issuance migrator's terminal owned run."""
    binary_value = os.environ.get("MARTY_CONFORMANCE_SOURCE_MIGRATION_BINARY", "").strip()
    if not binary_value:
        return
    source_revision = os.environ.get("MARTY_CONFORMANCE_SOURCE_REVISION", "").strip()
    receipt_value = os.environ.get("MARTY_CONFORMANCE_SOURCE_MIGRATION_RECEIPT", "").strip()
    volume_value = os.environ.get("MARTY_CONFORMANCE_SOURCE_VOLUME_ROOT", "").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source_revision) or not receipt_value:
        raise ValueError("local source migrator lacks revision or private receipt binding")
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != source_revision:
        raise ValueError("local source migrator does not match the running product source")
    volume = Path(volume_value).resolve(strict=True)
    receipt = Path(receipt_value)
    if (not receipt.is_absolute() or receipt.is_symlink()
            or not receipt.resolve().is_relative_to(volume)):
        raise ValueError("local migration receipt must be in the owned volume")
    ids = project_container_ids(project)
    rows = json.loads(subprocess.check_output(["docker", "inspect", *ids])) if ids else []
    selected = [row for row in rows if row["Config"]["Labels"].get(
        "com.docker.compose.project") == project and row["Config"]["Labels"].get(
        "com.docker.compose.service") == "issuance-migrations"]
    if len(selected) != 1:
        raise ValueError("exact owned issuance migration container was not found")
    row = selected[0]
    intended = config["services"]["issuance-migrations"]
    entrypoint = ["/usr/local/bin/marty-issuance-service"]
    arguments = ["migrate"]
    mounts = [mount for mount in row["Mounts"] if mount["Destination"] ==
              "/usr/local/bin/marty-issuance-service"]
    binary = str(Path(binary_value).resolve(strict=True))
    with Path(binary).open("rb") as source:
        terminal_digest = hashlib.file_digest(source, "sha256").hexdigest()
    if (row["Id"] not in ids
            or intended.get("entrypoint") != entrypoint or intended.get("command") != arguments
            or row["Config"].get("Entrypoint") != entrypoint
            or row["Config"].get("Cmd") != arguments
            or row.get("Path") != entrypoint[0] or row.get("Args") != arguments
            or row["State"]["Status"] != "exited" or row["State"]["ExitCode"] != 0
            or row["State"].get("OOMKilled") is not False
            or terminal_digest != os.environ["MARTY_CONFORMANCE_SOURCE_MIGRATION_SHA256"]
            or row["Config"]["Image"] != intended["image"]
            or len(mounts) != 1 or mounts[0]["RW"]
            or mounts[0]["Source"] != binary):
        raise ValueError("source-built issuance migrator did not complete in the owned project")
    migrations = ROOT / "rust/services/issuance/migrations"
    inputs = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted(migrations.glob("*.sql"))}
    if not inputs:
        raise ValueError("current source has no issuance migration inputs")
    proof = {"schema": "marty.local-source-issuance-migration/v1",
             "project": project, "sourceRevision": source_revision,
             "binarySha256": os.environ["MARTY_CONFORMANCE_SOURCE_MIGRATION_SHA256"],
             "containerId": row["Id"], "image": row["Config"]["Image"],
             "exitCode": 0, "migrations": inputs, "releaseQualified": False}
    if receipt.exists():
        if (not resume or preexisting_container_id != row["Id"]
                or json.loads(receipt.read_text(encoding="utf-8")) != proof):
            raise ValueError("local migration receipt changed or belongs to another operation")
        return
    if preexisting_container_id is not None:
        raise ValueError("prior local migrator lacks its original migration receipt")
    receipt.parent.mkdir(parents=True, exist_ok=True)
    with receipt.open("x", encoding="utf-8") as output:
        json.dump(proof, output, sort_keys=True)
        output.write("\n")
    receipt.chmod(0o600)


def project_container_ids(project: str) -> list[str]:
    completed = subprocess.run(
        [
            "docker",
            "ps",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in completed.stdout.splitlines() if line]


def issuer_did_identity(command: list[str]) -> dict[str, Any]:
    """Resolve the conformance verifier's public DID through the org registry.

    The query executes with curl inside the exact owned running gateway. Read its
    runtime environment in memory and pass the credential only through stdin,
    never command arguments or output. Return only public DID material.
    """
    project = validate_project(command[command.index("--project-name") + 1])
    selected = subprocess.run(
        [*command, "ps", "--all", "--quiet", "gateway"],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=30,
    )
    ids = selected.stdout.split()
    if selected.returncode or len(ids) != 1 or not re.fullmatch(r"[a-f0-9]{64}", ids[0]):
        raise ValueError("gateway identity query requires exactly one scoped container")
    inspected = subprocess.run(
        ["docker", "container", "inspect", ids[0]],
        capture_output=True, text=True, check=False, timeout=30,
    )
    try:
        rows = json.loads(inspected.stdout)
        if inspected.returncode or len(rows) != 1:
            raise ValueError("gateway inspection failed")
        row = rows[0]
        labels = row["Config"]["Labels"]
        if (labels.get("com.docker.compose.project") != project
                or labels.get("com.docker.compose.service") != "gateway"
                or row["State"].get("Running") is not True):
            raise ValueError("gateway container is foreign or inactive")
        values = dict(item.split("=", 1) for item in row["Config"]["Env"])
        api_key = values["SIGNING_KEYS_INTERNAL_API_KEY"]
        if not api_key or "\n" in api_key or "\r" in api_key:
            raise ValueError("gateway credential is invalid")
    except (KeyError, TypeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("gateway identity query requires its owned running container") from error
    issuer_did = (values.get("OID4VP_ISSUER_DID") or values.get("MARTY_ISSUER_DID") or "").strip()
    if not issuer_did:
        domain = values.get("PUBLIC_DOMAIN", "").strip()
        if not domain:
            domain = urlparse(values.get("PUBLIC_API_URL", "http://localhost:8000")).netloc
        authority = domain.strip("/").replace(":", "%3A").replace("/", ":")
        issuer_did = f"did:web:{authority}:orgs:{values.get('MARTY_ORG_SLUG', 'marty').strip() or 'marty'}"
    query = urlencode({
        "organization_id": values.get("MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001"),
        "issuer_did": issuer_did, "key_purpose": "oid4vp_request_signing", "algorithm": "ES256",
    })
    # The native image supplies curl, not a Python interpreter. Keep credentials
    # in memory/stdin; neither the Docker/curl argv nor errors contain the key.
    curl_config = "\n".join([
        "url = " + json.dumps("http://127.0.0.1:8000/internal/signing-keys/resolve-issuer-did?" + query),
        "header = " + json.dumps("X-Api-Key: " + api_key),
        'header = "Accept: application/json"', "silent", "show-error", "fail", "max-time = 15", "",
    ])
    completed = subprocess.run(
        [*command, "exec", "-T", "gateway", "curl", "--config", "-"],
        cwd=ROOT, input=curl_config, capture_output=True, text=True, check=False, timeout=30,
    )
    if completed.returncode:
        raise ValueError("could not resolve issuer DID identity: gateway identity query failed")
    try:
        payload = json.loads(completed.stdout)
        if payload.get("issuer_did") != issuer_did:
            raise ValueError("issuer DID response did not match the configured public identity")
        identity = {name: payload.get(name) for name in (
            "issuer_did", "verification_method_id", "public_jwk", "did_document", "key_purpose", "algorithm",
        )}
    except (AttributeError, json.JSONDecodeError) as error:
        raise ValueError("issuer DID identity response was not JSON") from error
    public_jwk = identity.get("public_jwk") if isinstance(identity, dict) else None
    if (
        not isinstance(identity, dict)
        or not isinstance(identity.get("issuer_did"), str)
        or not isinstance(identity.get("verification_method_id"), str)
        or identity.get("key_purpose") != "oid4vp_request_signing"
        or identity.get("algorithm") != "ES256"
        or not isinstance(public_jwk, dict)
        or public_jwk.get("kty") != "EC"
        or public_jwk.get("crv") != "P-256"
        or not isinstance(public_jwk.get("x"), str)
        or not isinstance(public_jwk.get("y"), str)
        or PUBLIC_JWK_PRIVATE_PARAMETERS.intersection(public_jwk)
    ):
        raise ValueError(
            "issuer DID did not resolve to the expected public ES256 identity"
        )
    return identity


def container_project(container_id: str) -> str:
    completed = subprocess.run(
        [
            "docker",
            "inspect",
            "--format",
            '{{ index .Config.Labels "com.docker.compose.project" }}',
            container_id,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def assert_ports_available(
    ports: list[int], project: str, *, resume: bool = False
) -> None:
    for port in ports:
        completed = subprocess.run(
            ["docker", "ps", "--quiet", "--filter", f"publish={port}"],
            capture_output=True,
            text=True,
            check=True,
        )
        owners = [line for line in completed.stdout.splitlines() if line]
        foreign = [
            container_id
            for container_id in owners
            if container_project(container_id) != project
        ]
        if foreign:
            raise ValueError(
                f"host port {port} is already published; choose a different conformance port"
            )
    if project_container_ids(project) and not resume:
        raise ValueError(
            f"project {project} already has containers; use the exact down command before starting a fresh run"
        )


def local_build_arguments() -> list[str]:
    """The Rust migration image has no external Python wheel build inputs."""
    return []


def configure_oidf_internal_tls_port() -> None:
    """Keep the bridge listener identical to the published HTTPS origin.

    Docker port publishing applies only to host traffic. The separately
    composed official runner reaches the TLS proxy over its narrow bridge, so
    the proxy itself must listen on the URL's port. The helper derives that
    value once and rejects contradictory operator configuration.
    """
    value = os.environ.get("OIDF_PUBLIC_BASE_URL", "").strip()
    if not value:
        # Compose owns the required-variable diagnostic. Keeping this helper a
        # no-op until an OIDF origin is supplied lets non-rendering commands
        # retain their narrower project-safety validation.
        return
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("OIDF_PUBLIC_BASE_URL must be an absolute HTTPS URL")
    port = str(parsed.port or 443)
    configured = os.environ.get("OIDF_INTERNAL_TLS_PORT", "").strip()
    if configured and configured != port:
        raise ValueError(
            "OIDF_INTERNAL_TLS_PORT must equal the port in OIDF_PUBLIC_BASE_URL"
        )
    os.environ["OIDF_INTERNAL_TLS_PORT"] = port


def emit_service_logs(command: list[str]) -> int:
    """Emit complete, timestamped project logs without terminal color codes."""
    return subprocess.run(
        [*command, "logs", "--no-color", "--timestamps"],
        cwd=ROOT,
        check=False,
    ).returncode


def runtime_up_arguments(
    command: list[str], config: dict[str, Any], project: str, *, resume: bool,
    runner=None,
) -> list[str]:
    """Resume verified KMS custody without repeating its fresh-Raft ceremony."""
    arguments = ["up", "--detach", "--no-build"]
    if not resume:
        return arguments
    runner = runner or subprocess.run
    try:
        image_ids: dict[str, str] = {}
        for service in sorted(KMS_BOOTSTRAP_SERVICES):
            image = config["services"][service]["image"]
            if image not in image_ids:
                resolved = runner(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", image],
                    capture_output=True, text=True, check=False, timeout=30,
                )
                image_id = resolved.stdout.strip()
                if resolved.returncode or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                    raise ValueError("KMS bootstrap configured image cannot be resolved")
                image_ids[image] = image_id
            selected = runner(
                ["docker", "ps", "--all", "--no-trunc", "--quiet", "--filter",
                 f"label=com.docker.compose.project={project}", "--filter",
                 f"label=com.docker.compose.service={service}"],
                capture_output=True, text=True, check=False, timeout=30,
            )
            ids = selected.stdout.split()
            if (selected.returncode or len(ids) != 1
                    or not re.fullmatch(r"[0-9a-f]{64}", ids[0])):
                raise ValueError("KMS bootstrap ownership is missing or ambiguous")
            inspected = runner(
                ["docker", "container", "inspect", ids[0]],
                capture_output=True, text=True, check=False, timeout=30,
            )
            if inspected.returncode:
                raise ValueError("KMS bootstrap identity cannot be inspected")
            rows = json.loads(inspected.stdout)
            if not isinstance(rows, list) or len(rows) != 1:
                raise ValueError("KMS bootstrap identity is ambiguous")
            row = rows[0]
            labels = row["Config"].get("Labels") or {}
            state = row["State"]
            if (row["Id"] != ids[0]
                    or labels.get("com.docker.compose.project") != project
                    or labels.get("com.docker.compose.service") != service
                    or row["Config"]["Image"] != image
                    or row["Image"] != image_ids[image]
                    or state.get("OOMKilled") is not False):
                raise ValueError("KMS bootstrap identity differs from the exact project")
            if service == "openbao":
                complete = (state.get("Status") == "running"
                            and state.get("Running") is True
                            and state.get("Health", {}).get("Status") == "healthy")
            else:
                complete = (state.get("Status") == "exited"
                            and state.get("ExitCode") == 0)
            if not complete:
                raise ValueError("KMS bootstrap is incomplete or unhealthy; use a fresh disposable project")
        profiles = {command[i + 1] for i, part in enumerate(command[:-1])
                    if part == "--profile"}
        services = [name for name, service in config["services"].items()
                    if name not in KMS_BOOTSTRAP_SERVICES
                    and (not service.get("profiles")
                         or "*" in profiles or profiles.intersection(service["profiles"]))]
        if not services:
            raise ValueError("KMS resume has no selected runtime services")
        # Every runtime service remains explicitly selected, preserving its
        # migration/health ordering. --no-deps prevents Compose from starting
        # the completed bootstrap dependencies again, or recreating OpenBao.
        return [*arguments, "--no-deps", *sorted(services)]
    except (KeyError, TypeError, AttributeError, OSError,
            subprocess.SubprocessError, json.JSONDecodeError):
        raise ValueError("KMS bootstrap resume verification failed") from None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--project",
        default=os.environ.get("MARTY_CONFORMANCE_PROJECT", ""),
        help="unique marty-conformance-<run-id> project name",
    )
    parser.add_argument(
        "--haip",
        action="store_true",
        help="enable the isolated HAIP verifier profile; requires a certificate for the configured KMS-backed issuer profile",
    )
    parser.add_argument(
        "--didcomm-authcrypt",
        action="store_true",
        help="mount the exact deployment-owned DIDComm authcrypt policy directory into issuance only",
    )
    parser.add_argument(
        "--issuance-owner",
        choices=("legacy", "native"),
        default="native",
        help=(
            "native is the product default; the historical legacy value only "
            "omits conformance-specific native overlays and does not reverse "
            "the base composition's native ownership"
        ),
    )
    parser.add_argument("--stack-manifest", type=Path)
    parser.add_argument("--stack-checksums", type=Path)
    parser.add_argument(
        "--release-ui-revision",
        help="full UI source revision bound by the authenticated stack manifest",
    )
    parser.add_argument(
        "--local-build",
        action="store_true",
        help="build the checked-out source; never certification-grade evidence",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="resume the exact project after verifying successful KMS bootstrap",
    )
    parser.add_argument(
        "command",
        choices=(
            "bootstrap-reviewer",
            "issuer-did-identity",
            "config",
            "up",
            "ps",
            "logs",
            "ports",
            "down",
        ),
    )
    args = parser.parse_args()
    project = validate_project(args.project)
    configure_project_environment(project)
    configure_oidf_internal_tls_port()
    command = compose_command(
        project,
        include_haip=args.haip,
        include_didcomm_authcrypt=args.didcomm_authcrypt,
        use_ghcr=not args.local_build,
        issuance_owner=args.issuance_owner,
    )

    if args.command == "down":
        # The validated project name and Compose labels precisely scope this
        # destructive operation; no container names, globs, or shared volumes
        # are used.
        return subprocess.run(
            [*command, "down", "--volumes", "--remove-orphans"], cwd=ROOT, check=False
        ).returncode

    config = rendered_config(
        project,
        include_haip=args.haip,
        include_didcomm_authcrypt=args.didcomm_authcrypt,
        use_ghcr=not args.local_build,
        issuance_owner=args.issuance_owner,
    )
    ports = validate_isolation(config, project)
    native = None
    if args.issuance_owner == "native":
        native = runpy.run_path(str(ROOT / "scripts/conformance_native.py"))
        native["validate_model"](
            config,
            project=project,
            authcrypt=args.didcomm_authcrypt,
            local_build=args.local_build,
        )
    if args.command == "config":
        print(json.dumps(config, indent=2, sort_keys=True))
        return 0
    if args.command == "issuer-did-identity":
        if not project_container_ids(project):
            raise ValueError(
                "issuer-did-identity requires an existing exact conformance project"
            )
        print(json.dumps(issuer_did_identity(command), sort_keys=True))
        return 0
    if args.command == "up":
        assert_ports_available(ports, project, resume=args.resume)
        prior_migrator = (source_migration_container_before_up(project)
                          if os.environ.get("MARTY_CONFORMANCE_SOURCE_MIGRATION_BINARY", "").strip()
                          else None)
        native_plan = None
        native_image = (
            config["services"]["issuance-native"]["image"] if native else None
        )
        if native:
            if args.local_build:
                native["validate_capabilities"](
                    json.loads(
                        (ROOT / native["CAPABILITY_PATH"]).read_text(encoding="utf-8")
                    )
                )
            else:
                if not all(
                    (
                        args.stack_manifest,
                        args.stack_checksums,
                        args.release_ui_revision,
                    )
                ):
                    raise ValueError(
                        "Released native conformance requires stack manifest, checksums and exact release UI revision"
                    )
                native_plan = native["verify_release"](
                    args.stack_manifest,
                    args.stack_checksums,
                    args.release_ui_revision,
                    native_image,
                )
        if args.local_build:
            build_result = subprocess.run(
                [*command, "build", *local_build_arguments()], cwd=ROOT, check=False
            )
            if build_result.returncode:
                return build_result.returncode
            if native:
                native["probe_image"](native_image, project, plan=None)
            up_result = subprocess.run(
                # Keycloak configuration is intentionally a one-shot service.
                # Compose's --wait treats its successful exit as an error even
                # after every long-running service becomes healthy.
                [*command, *runtime_up_arguments(command, config, project, resume=args.resume)],
                cwd=ROOT,
                check=False,
            )
            if up_result.returncode:
                return up_result.returncode
            wait_for_one_shots(command, config)
            attest_local_source_migration(
                project, config, resume=args.resume, preexisting_container_id=prior_migrator,
            )
            return 0
        # Keycloak configuration and database migration are successful
        # one-shot services. Compose --wait reports those intentional exits
        # as failures, so released images use the same explicit detached
        # lifecycle as a local build. Readiness belongs to the suite driver,
        # which probes the real public endpoint before starting a test plan.
        if native:
            pulled = subprocess.run(
                ["docker", "pull", native_image],
                cwd=ROOT,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if pulled.returncode:
                return pulled.returncode
            native["probe_image"](native_image, project, plan=native_plan)
        up_result = subprocess.run(
            [*command, *runtime_up_arguments(command, config, project, resume=args.resume)],
            cwd=ROOT, check=False
        )
        if up_result.returncode:
            return up_result.returncode
        wait_for_one_shots(command, config)
        attest_local_source_migration(
            project, config, resume=args.resume, preexisting_container_id=prior_migrator,
        )
        return 0
    if args.command == "bootstrap-reviewer":
        if not project_container_ids(project):
            raise ValueError(
                "bootstrap-reviewer requires an existing exact conformance project"
            )
        return subprocess.run(
            [
                *command,
                "up",
                "--detach",
                "--force-recreate",
                "--no-deps",
                "keycloak-configurator",
            ],
            cwd=ROOT,
            check=False,
        ).returncode
    if args.command == "ports":
        for service, targets in public_service_targets(config).items():
            for target in targets:
                subprocess.run(
                    [*command, "port", service, str(target)], cwd=ROOT, check=True
                )
        return 0
    if args.command == "logs":
        return emit_service_logs(command)
    return subprocess.run([*command, "ps"], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Conformance stack error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
