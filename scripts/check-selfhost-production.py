#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages"))

from marty_common.licensing import (  # pylint: disable=import-error
    LicenseValidationError,
    is_placeholder_value,
    validate_runtime_license_from_env,
)


class CheckError(RuntimeError):
    """Raised when a self-host production check fails."""


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


def load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def read_required_secret(path: Path, label: str) -> str:
    if not path.exists():
        raise CheckError(f"{label} file is missing: {path}")

    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise CheckError(f"{label} file is empty: {path}")
    if is_placeholder_value(value):
        raise CheckError(f"{label} still uses a shipped placeholder value: {path}")
    return value


def run_compose_command(env_file: Path, compose_file: Path, *extra_args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(env_file),
            "-f",
            str(compose_file),
            *extra_args,
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def ensure_compose_config(env_file: Path, compose_file: Path) -> None:
    result = run_compose_command(env_file, compose_file, "config")
    if result.returncode != 0:
        error_output = (result.stderr or result.stdout).strip()
        raise CheckError(f"{compose_file.name} config failed: {error_output}")


def parse_compose_ps_output(raw_output: str) -> list[dict[str, Any]]:
    stripped = raw_output.strip()
    if not stripped:
        return []

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        entries: list[dict[str, Any]] = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
        return entries

    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return parsed
    raise CheckError("docker compose ps returned an unsupported JSON payload.")


def get_compose_services(env_file: Path, compose_file: Path) -> list[dict[str, Any]]:
    result = run_compose_command(env_file, compose_file, "ps", "--format", "json")
    if result.returncode != 0:
        error_output = (result.stderr or result.stdout).strip()
        raise CheckError(f"{compose_file.name} ps failed: {error_output}")
    return parse_compose_ps_output(result.stdout)


def validate_license(env_values: dict[str, str], secret_dir: Path) -> str:
    claims = validate_runtime_license_from_env(
        {
            **env_values,
            "LICENSE_KEY_FILE": str(secret_dir / "license_key"),
            "LICENSE_PUBLIC_KEY_FILE": str(secret_dir / "license_public_key"),
        }
    )
    if claims is None:
        raise CheckError("License enforcement is disabled; no runtime license validation occurred.")
    products = ",".join(claims.entitled_products) or "<none>"
    return (
        f"subject={claims.sub} plan_tier={claims.plan_tier or 'none'} "
        f"products={products} expires_at={claims.expires_at.isoformat().replace('+00:00', 'Z')}"
    )


def validate_tunnel_token(secret_dir: Path) -> str:
    token = read_required_secret(secret_dir / "cloudflare_tunnel_token", "Cloudflare tunnel token")
    return f"token_length={len(token)}"


def validate_openbao(env_values: dict[str, str], secret_dir: Path, env_file: Path, compose_file: Path) -> str:
    read_required_secret(secret_dir / "openbao_service_token", "OpenBao service token")
    services = get_compose_services(env_file, compose_file)
    openbao_service = next((entry for entry in services if entry.get("Service") == "openbao"), None)
    if openbao_service is None:
        raise CheckError("Standalone OpenBao service is not running in Docker Compose.")
    if openbao_service.get("State") != "running":
        raise CheckError(f"Standalone OpenBao state is {openbao_service.get('State', 'unknown')}.")
    if openbao_service.get("Health") and openbao_service.get("Health") != "healthy":
        raise CheckError(f"Standalone OpenBao health is {openbao_service.get('Health')}.")

    host_port = int(env_values.get("SELFHOST_OPENBAO_HOST_PORT", "18200"))
    health_url = f"http://127.0.0.1:{host_port}/v1/sys/health?standbyok=true&perfstandbyok=true"
    try:
        with urllib.request.urlopen(health_url, timeout=5) as response:  # noqa: S310 - localhost operator health check
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise CheckError(f"OpenBao health endpoint returned HTTP {exc.code}: {body}") from exc
    except OSError as exc:
        raise CheckError(f"OpenBao health endpoint is unreachable at {health_url}: {exc}") from exc

    if not payload.get("initialized"):
        raise CheckError("OpenBao reports initialized=false.")
    if payload.get("sealed"):
        raise CheckError("OpenBao reports sealed=true.")

    return f"state={openbao_service.get('State')} health={openbao_service.get('Health') or 'n/a'} port={host_port}"


def validate_main_stack(env_file: Path, compose_file: Path) -> str:
    services = get_compose_services(env_file, compose_file)
    if not services:
        raise CheckError("Main self-host production stack is not running.")

    service_map = {entry.get("Service"): entry for entry in services}
    required_services = ("postgres", "redis", "keycloak", "gateway", "ui", "edge", "cloudflared")
    missing_services = [service for service in required_services if service not in service_map]
    if missing_services:
        raise CheckError("Missing expected running services: " + ", ".join(sorted(missing_services)))

    unhealthy: list[str] = []
    for service_name in required_services:
        service = service_map[service_name]
        state = str(service.get("State", ""))
        health = str(service.get("Health", ""))
        if state != "running":
            unhealthy.append(f"{service_name}=state:{state or 'unknown'}")
            continue
        if health and health != "healthy":
            unhealthy.append(f"{service_name}=health:{health}")

    if unhealthy:
        raise CheckError("Unhealthy services: " + ", ".join(unhealthy))

    return "services=" + ",".join(required_services)


def run_check(name: str, checker) -> CheckResult:
    try:
        detail = checker()
        return CheckResult(name=name, ok=True, detail=detail)
    except (CheckError, LicenseValidationError) as exc:
        return CheckResult(name=name, ok=False, detail=str(exc))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the self-host production deployment state.")
    parser.add_argument("--env-file", default=str(REPO_ROOT / ".env.selfhost.production.local"))
    parser.add_argument("--prod-compose-file", default=str(REPO_ROOT / "docker-compose.selfhost.prod.yml"))
    parser.add_argument("--openbao-compose-file", default=str(REPO_ROOT / "docker-compose.selfhost.openbao.yml"))
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    env_file = Path(args.env_file).expanduser().resolve()
    prod_compose_file = Path(args.prod_compose_file).expanduser().resolve()
    openbao_compose_file = Path(args.openbao_compose_file).expanduser().resolve()

    if not env_file.exists():
        raise SystemExit(f"Self-host env file does not exist: {env_file}")

    env_values = load_env_file(env_file)
    secret_dir_value = env_values.get("SELFHOST_SECRET_DIR", "").strip()
    if not secret_dir_value:
        raise SystemExit("SELFHOST_SECRET_DIR is missing from the self-host env file.")
    secret_dir = Path(secret_dir_value).expanduser().resolve()

    compose_config_results = [
        run_check("openbao-compose-config", lambda: (ensure_compose_config(env_file, openbao_compose_file) or openbao_compose_file.name)),
        run_check("prod-compose-config", lambda: (ensure_compose_config(env_file, prod_compose_file) or prod_compose_file.name)),
    ]
    validation_results = [
        run_check("license", lambda: validate_license(env_values, secret_dir)),
        run_check("cloudflare-tunnel-token", lambda: validate_tunnel_token(secret_dir)),
        run_check("openbao", lambda: validate_openbao(env_values, secret_dir, env_file, openbao_compose_file)),
        run_check("prod-compose-health", lambda: validate_main_stack(env_file, prod_compose_file)),
    ]

    results = compose_config_results + validation_results
    for result in results:
        status = "[OK]" if result.ok else "[FAIL]"
        print(f"{status} {result.name}: {result.detail}")

    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())