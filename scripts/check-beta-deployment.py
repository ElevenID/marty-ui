#!/usr/bin/env python3
"""Validate the isolated ElevenID beta deployment and its public routes."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


BETA_PROJECT = "elevenid-beta"
BETA_UI_PROJECT = "elevenid-beta-ui"
REQUIRED_SERVICES = (
    "postgres",
    "redis",
    "openbao",
    "keycloak",
    "gateway",
    "auth",
    "organization",
    "issuance",
    "event-stream",
    "applicant",
    "canvas-real",
    "canvas-sandbox",
    "waltid-nginx",
    "docs",
    "nginx-proxy",
    "cloudflared",
)


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip().strip('"').strip("'")
    return values


def service_container(project: str, service: str) -> dict[str, object] | None:
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            f"label=com.docker.compose.service={service}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    container_ids = result.stdout.split()
    if len(container_ids) != 1:
        return None
    inspected = subprocess.run(
        ["docker", "inspect", container_ids[0]],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(inspected.stdout)[0]


def container_ready(record: dict[str, object]) -> tuple[bool, str]:
    state = record["State"]
    assert isinstance(state, dict)
    runtime = str(state.get("Status", "unknown"))
    health_record = state.get("Health")
    health = health_record.get("Status", "none") if isinstance(health_record, dict) else "none"
    return runtime == "running" and health in {"none", "healthy"}, f"{runtime}/{health}"


def http_ready(url: str) -> tuple[bool, str]:
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-cache", "User-Agent": "elevenid-beta-health/1"},
    )
    last_error = "unknown error"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                status = response.status
            return 200 <= status < 300, f"HTTP {status}"
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
            if attempt < 2:
                time.sleep(2)
    return False, last_error


def homepage_ready(url: str) -> tuple[bool, str]:
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-cache", "User-Agent": "elevenid-beta-health/1"},
    )
    last_error = "unknown error"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                status = response.status
                body = response.read().decode("utf-8", errors="replace")
            if not 200 <= status < 300:
                return False, f"HTTP {status}"
            if "Welcome to nginx" in body:
                return False, "default Nginx welcome page"
            if "ElevenID" not in body:
                return False, "expected ElevenID content is missing"
            return True, f"HTTP {status}, ElevenID content present"
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
            if attempt < 2:
                time.sleep(2)
    return False, last_error


def oidc_discovery_ready(url: str, expected_issuer: str) -> tuple[bool, str]:
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-cache", "User-Agent": "elevenid-beta-health/1"},
    )
    last_error = "unknown error"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                status = response.status
                body = response.read(1_048_577)
            if not 200 <= status < 300:
                return False, f"HTTP {status}"
            if len(body) > 1_048_576:
                return False, "discovery document exceeds 1 MiB"
            payload = json.loads(body)
            issuer = str(payload.get("issuer") or "").rstrip("/") if isinstance(payload, dict) else ""
            expected = expected_issuer.rstrip("/")
            if issuer != expected:
                return False, f"issuer mismatch: expected {expected}, got {issuer or '<missing>'}"
            jwks_uri = str(payload.get("jwks_uri") or "")
            if not jwks_uri.startswith(f"{expected}/"):
                return False, "jwks_uri is outside the canonical issuer"
            return True, f"HTTP {status}, canonical issuer"
        except (json.JSONDecodeError, TypeError, ValueError, urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
            if attempt < 2:
                time.sleep(2)
    return False, last_error


def internal_oidc_discovery_ready(
    auth_container_id: str,
    expected_issuer: str,
) -> tuple[bool, str]:
    probe = (
        "import json,os,urllib.request;"
        "base=os.environ['OIDC_ISSUER_URL'].rstrip('/');"
        "doc=json.load(urllib.request.urlopen(base+'/.well-known/openid-configuration',timeout=10));"
        "print(json.dumps({'issuer':doc.get('issuer'),'jwks_uri':doc.get('jwks_uri')}))"
    )
    try:
        result = subprocess.run(
            ["docker", "exec", auth_container_id, "python", "-c", probe],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return False, f"internal discovery probe failed: {type(exc).__name__}"
    issuer = str(payload.get("issuer") or "").rstrip("/") if isinstance(payload, dict) else ""
    expected = expected_issuer.rstrip("/")
    if issuer != expected:
        return False, f"internal issuer mismatch: expected {expected}, got {issuer or '<missing>'}"
    jwks_uri = str(payload.get("jwks_uri") or "")
    if not jwks_uri.startswith(f"{expected}/"):
        return False, "internal jwks_uri is outside the canonical issuer"
    return True, "canonical issuer"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, required=True)
    args = parser.parse_args()
    if not args.env_file.is_file():
        print(f"[FAIL] beta-env: missing {args.env_file}")
        return 1

    failures: list[str] = []
    auth_record: dict[str, object] | None = None
    for service in REQUIRED_SERVICES:
        record = service_container(BETA_PROJECT, service)
        if record is None:
            failures.append(f"container {BETA_PROJECT}/{service} is missing or duplicated")
            continue
        ready, detail = container_ready(record)
        print(f"[{'OK' if ready else 'FAIL'}] beta-container: {service}={detail}")
        if not ready:
            failures.append(f"container {service} is {detail}")
        if service == "auth":
            auth_record = record

    ui_record = service_container(BETA_UI_PROJECT, "ui-prod")
    if ui_record is None:
        failures.append(f"container {BETA_UI_PROJECT}/ui-prod is missing or duplicated")
    else:
        ready, detail = container_ready(ui_record)
        print(f"[{'OK' if ready else 'FAIL'}] beta-ui-container: ui-prod={detail}")
        if not ready:
            failures.append(f"UI container is {detail}")

    environment = read_env(args.env_file)
    domain = environment.get("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    realm = environment.get("KEYCLOAK_REALM", "11id")
    homepage_url = f"https://{domain}/"
    ready, detail = homepage_ready(homepage_url)
    print(f"[{'OK' if ready else 'FAIL'}] beta-homepage: {homepage_url} {detail}")
    if not ready:
        failures.append(f"public homepage {homepage_url} failed: {detail}")

    for route in ("/ready",):
        url = f"https://{domain}{route}"
        ready, detail = http_ready(url)
        print(f"[{'OK' if ready else 'FAIL'}] beta-public: {url} {detail}")
        if not ready:
            failures.append(f"public route {url} failed: {detail}")

    issuer = f"https://{domain}/realms/{realm}"
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    ready, detail = oidc_discovery_ready(discovery_url, issuer)
    print(f"[{'OK' if ready else 'FAIL'}] beta-oidc: {discovery_url} {detail}")
    if not ready:
        failures.append(f"public OIDC discovery {discovery_url} failed: {detail}")

    auth_container_id = str(auth_record.get("Id") or "") if auth_record else ""
    if not auth_container_id:
        ready, detail = False, "auth container is unavailable"
    else:
        ready, detail = internal_oidc_discovery_ready(auth_container_id, issuer)
    print(f"[{'OK' if ready else 'FAIL'}] beta-oidc-internal: {detail}")
    if not ready:
        failures.append(f"internal OIDC discovery failed: {detail}")

    if failures:
        print("Beta deployment check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"Beta deployment is healthy: services={len(REQUIRED_SERVICES) + 1} domain={domain}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
