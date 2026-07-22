#!/usr/bin/env python3
"""Operate a clean, project-scoped interoperability stack on any Docker engine."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
PROJECT = re.compile(r"^marty-conformance-[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])?$")
BASE_FILES = (
    "docker-compose.base.yml",
    "docker-compose.profile.oidf.yml",
)
GHCR_FILE = "docker-compose.profile.ghcr.yml"
IMMUTABLE_INFRA_FILE = "docker-compose.profile.conformance-images.yml"
W3C_FILE = "docker-compose.profile.w3c-vc.yml"
HAIP_FILE = "docker-compose.profile.oidf-haip.yml"
ISOLATION_FILE = "docker-compose.profile.conformance.yml"
PUBLIC_PORT_SERVICES = {"oidf-tls-proxy"}
ONE_SHOT_SERVICES = {
    "db-migrate",
    "issuance-migrations",
    "keycloak-configurator",
    "openbao-init",
}
PUBLIC_JWK_PRIVATE_PARAMETERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
LOCAL_BUILD_ARGS = (
    "MARTY_RS_URI",
    "MARTY_RS_DIGEST",
    "MARTY_COMMON_URI",
    "MARTY_COMMON_DIGEST",
)


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
    include_w3c: bool = False,
    use_ghcr: bool = True,
) -> list[str]:
    command = ["docker", "compose", "--project-name", validate_project(project)]
    files = [*BASE_FILES]
    if use_ghcr:
        files.insert(1, GHCR_FILE)
        files.insert(2, IMMUTABLE_INFRA_FILE)
    if include_haip:
        files.append(HAIP_FILE)
    if include_w3c:
        files.append(W3C_FILE)
    files.append(ISOLATION_FILE)
    for compose_file in files:
        command.extend(["--file", os.fspath(ROOT / compose_file)])
    command.extend(["--profile", "oidf"])
    return command


def rendered_config(
    project: str,
    *,
    include_haip: bool = False,
    include_w3c: bool = False,
    use_ghcr: bool = True,
) -> dict[str, Any]:
    completed = subprocess.run(
        [
            *compose_command(
                project,
                include_haip=include_haip,
                include_w3c=include_w3c,
                use_ghcr=use_ghcr,
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


def project_container_ids(project: str) -> list[str]:
    completed = subprocess.run(
        [
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in completed.stdout.splitlines() if line]


def issuer_profile_identity(command: list[str]) -> dict[str, Any]:
    """Resolve the conformance verifier's public identity through its profile.

    The query executes inside the gateway container, so the internal API key is
    read from that service's environment and is never copied to the host command
    line or output. Only public DID material crosses the container boundary.
    """
    script = """
import json
import os
import urllib.parse
import urllib.request

profile_id = os.environ.get("OID4VP_ISSUER_PROFILE_ID", "ip-marty-oid4vp-verifier")
organization_id = os.environ.get("MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001")
api_key = os.environ["SIGNING_KEYS_INTERNAL_API_KEY"]
query = urllib.parse.urlencode({"organization_id": organization_id})
request = urllib.request.Request(
    f"http://127.0.0.1:8000/internal/signing-keys/issuer-profiles/{urllib.parse.quote(profile_id, safe='')}/identity?{query}",
    headers={"X-Api-Key": api_key, "Accept": "application/json"},
)
with urllib.request.urlopen(request, timeout=15) as response:
    payload = json.loads(response.read().decode("utf-8"))
if payload.get("issuer_profile_id") != profile_id:
    raise RuntimeError("issuer-profile identity response did not match the configured profile")
print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
""".strip()
    completed = subprocess.run(
        [*command, "exec", "-T", "gateway", "python", "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or "gateway identity query failed"
        raise ValueError(f"could not resolve issuer-profile identity: {detail}")
    try:
        identity = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("issuer-profile identity response was not JSON") from exc
    public_jwk = identity.get("public_jwk") if isinstance(identity, dict) else None
    if (
        not isinstance(identity, dict)
        or not isinstance(identity.get("issuer_profile_id"), str)
        or not identity.get("issuer_profile_id")
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
            "issuer profile did not resolve to the expected public ES256 DID identity"
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
    """Return explicit immutable bootstrap build arguments for source runs."""
    missing = [
        name for name in LOCAL_BUILD_ARGS if not os.environ.get(name, "").strip()
    ]
    if missing:
        raise ValueError(
            "--local-build requires published, digest-pinned bootstrap artifacts: "
            + ", ".join(missing)
        )
    values: list[str] = []
    for name in LOCAL_BUILD_ARGS:
        values.extend(["--build-arg", f"{name}={os.environ[name]}"])
    return values


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--project",
        default=os.environ.get("MARTY_CONFORMANCE_PROJECT", ""),
        help="unique marty-conformance-<run-id> project name",
    )
    parser.add_argument("--include-w3c", action="store_true")
    parser.add_argument(
        "--haip",
        action="store_true",
        help="enable the isolated HAIP verifier profile; requires a certificate for the configured KMS-backed issuer profile",
    )
    parser.add_argument(
        "--local-build",
        action="store_true",
        help="build the checked-out source; never certification-grade evidence",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="resume only the exact project after an interrupted up command",
    )
    parser.add_argument(
        "command",
        choices=(
            "bootstrap-reviewer",
            "issuer-profile-identity",
            "config",
            "up",
            "ps",
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
        include_w3c=args.include_w3c,
        use_ghcr=not args.local_build,
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
        include_w3c=args.include_w3c,
        use_ghcr=not args.local_build,
    )
    ports = validate_isolation(config, project)
    if args.command == "config":
        print(json.dumps(config, indent=2, sort_keys=True))
        return 0
    if args.command == "issuer-profile-identity":
        if not project_container_ids(project):
            raise ValueError(
                "issuer-profile-identity requires an existing exact conformance project"
            )
        print(json.dumps(issuer_profile_identity(command), sort_keys=True))
        return 0
    if args.command == "up":
        assert_ports_available(ports, project, resume=args.resume)
        if args.local_build:
            build_result = subprocess.run(
                [*command, "build", *local_build_arguments()], cwd=ROOT, check=False
            )
            if build_result.returncode:
                return build_result.returncode
            up_result = subprocess.run(
                # Keycloak configuration is intentionally a one-shot service.
                # Compose's --wait treats its successful exit as an error even
                # after every long-running service becomes healthy.
                [*command, "up", "--detach", "--no-build"],
                cwd=ROOT,
                check=False,
            )
            if up_result.returncode:
                return up_result.returncode
            wait_for_one_shots(command, config)
            return 0
        # Keycloak configuration and database migration are successful
        # one-shot services. Compose --wait reports those intentional exits
        # as failures, so released images use the same explicit detached
        # lifecycle as a local build. Readiness belongs to the suite driver,
        # which probes the real public endpoint before starting a test plan.
        up_result = subprocess.run(
            [*command, "up", "--detach", "--no-build"], cwd=ROOT, check=False
        )
        if up_result.returncode:
            return up_result.returncode
        wait_for_one_shots(command, config)
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
    return subprocess.run([*command, "ps"], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Conformance stack error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
