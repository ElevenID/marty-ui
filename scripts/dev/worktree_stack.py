#!/usr/bin/env python3
"""Run a small, worktree-owned local stack without touching shared Marty stacks.

This is a development aid, not release or protected acceptance evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
PORT_OFFSETS = {
    "WT_GATEWAY_PORT": 0,
    "WT_UI_PORT": 1,
    "WT_POSTGRES_PORT": 2,
    "WT_REDIS_PORT": 3,
    "WT_KEYCLOAK_PORT": 4,
    "WT_OPENBAO_PORT": 5,
    "WT_MAILPIT_PORT": 6,
    "WT_SMTP_PORT": 7,
}
WHEEL_NAMES = ("MARTY_RS", "MARTY_VERIFICATION", "MARTY_ISO18013")


def identity(root: Path) -> tuple[str, int]:
    canonical = str(root.resolve())
    if os.name == "nt":
        canonical = canonical.casefold()
    canonical = canonical.encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return f"marty-wt-{digest[:12]}", 24000 + (int(digest[:8], 16) % 500) * 10


def environment(root: Path, project: str, port_base: int) -> dict[str, str]:
    # Avoid importing production/service credentials from an ambient shell.
    safe_host_names = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "HOME",
        "HOMEDRIVE", "HOMEPATH", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA", "DOCKER_CONFIG",
    }
    env = {key: value for key, value in os.environ.items()
           if key.upper() in safe_host_names}
    for name, offset in PORT_OFFSETS.items():
        env[name] = str(port_base + offset)
    gateway = f"http://127.0.0.1:{env['WT_GATEWAY_PORT']}"
    ui = f"http://127.0.0.1:{env['WT_UI_PORT']}"
    env.update({
        "COMPOSE_DISABLE_ENV_FILE": "1",
        "MARTY_RUNTIME_CONFIG_ROOT": str(root),
        "MARTY_NETWORK_NAME": f"{project}-network",
        "PUBLIC_API_URL": gateway,
        "UI_BASE_URL": ui,
        "CORS_ORIGINS": ui,
        "KC_HOSTNAME": "127.0.0.1",
        "KC_HOSTNAME_PORT": env["WT_KEYCLOAK_PORT"],
        "OIDC_ISSUER_URL_EXTERNAL": f"http://127.0.0.1:{env['WT_KEYCLOAK_PORT']}/realms/11id",
        "OIDC_REDIRECT_URI": f"{ui}/v1/auth/callback",
        "OIDC_POST_LOGOUT_REDIRECT_URI": f"{ui}/",
    })
    # The base file requires these even when only PostgreSQL/Redis are started.
    # Deliberately invalid values prevent this helper from becoming a release
    # migration/image path by accident.
    for name in WHEEL_NAMES:
        env[f"{name}_URI"] = "file:///worktree-dev-infra-only"
        env[f"{name}_DIGEST"] = "0" * 64
    return env


def compose_command(root: Path, project: str) -> list[str]:
    return [
        "docker", "compose", "--project-name", project,
        "--project-directory", str(root),
        "-f", str(root / "docker-compose.base.yml"),
        "-f", str(root / "docker-compose.profile.dev.yml"),
        "-f", str(root / "docker-compose.worktree-dev.yml"),
    ]


def validate_config(command: list[str], env: dict[str, str]) -> None:
    result = subprocess.run([*command, "config", "--format", "json"],
                            env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        raise SystemExit("Worktree Compose configuration failed to render")
    config = json.loads(result.stdout)
    services = config["services"]
    if config["networks"]["marty-network"]["name"] != env["MARTY_NETWORK_NAME"]:
        raise SystemExit("Worktree network is not project-owned")
    project = command[command.index("--project-name") + 1]
    if any(not volume["name"].startswith(f"{project}_")
           for volume in config.get("volumes", {}).values()):
        raise SystemExit("Worktree volume is not project-owned")
    published = {
        "postgres": ("WT_POSTGRES_PORT", 5432),
        "redis": ("WT_REDIS_PORT", 6379),
        "keycloak": ("WT_KEYCLOAK_PORT", 8080),
        "mailpit": (("WT_MAILPIT_PORT", 8025), ("WT_SMTP_PORT", 1025)),
        "openbao": ("WT_OPENBAO_PORT", 8200),
        "gateway": ("WT_GATEWAY_PORT", 8000),
    }
    for service, config in services.items():
        expected = published.get(service, ())
        if expected and isinstance(expected[0], str):
            expected = (expected,)
        actual = {(str(port.get("published")), int(port["target"]), port.get("host_ip"))
                  for port in config.get("ports", [])}
        wanted = {(env[name], target, "127.0.0.1") for name, target in expected}
        if actual != wanted:
            raise SystemExit(f"Unexpected host publication in {service}; refusing to start")


def require_free_ports(env: dict[str, str]) -> None:
    for name in PORT_OFFSETS:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", int(env[name])))
            except OSError as exc:
                raise SystemExit(f"{name} is in use; choose another --port-base") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("config", "up", "ps", "down", "ui"))
    parser.add_argument("--port-base", type=int)
    args = parser.parse_args()
    project, default_base = identity(ROOT)
    port_base = args.port_base if args.port_base is not None else default_base
    if not 1024 <= port_base <= 65528:
        parser.error("--port-base must leave eight usable ports in 1024..65535")
    env = environment(ROOT, project, port_base)
    command = compose_command(ROOT, project)
    validate_config(command, env)
    if args.action == "config":
        print(f"project={project} root={ROOT} port_base={port_base}")
        return 0
    if args.action == "ui":
        if not (ROOT / "ui" / "node_modules" / "vite").exists():
            raise SystemExit("Install this worktree's UI dependencies first: cd ui && npm ci")
        env["VITE_PORT"] = env["WT_UI_PORT"]
        env["VITE_API_URL"] = f"http://127.0.0.1:{env['WT_GATEWAY_PORT']}"
        env["VITE_DEV_PROXY_TARGET"] = env["VITE_API_URL"]
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if npm is None:
            raise SystemExit("npm is not installed")
        return subprocess.call([npm, "run", "dev", "--", "--host", "127.0.0.1",
                                "--strictPort"], cwd=ROOT / "ui", env=env)
    if args.action == "up":
        existing = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
            env=env, text=True, capture_output=True, check=True,
        ).stdout.strip()
        if not existing:
            require_free_ports(env)
        result = subprocess.call([*command, "up", "-d", "--wait", "postgres", "redis"], env=env)
        if result:
            return result
        print(f"Isolated {project}: PostgreSQL 127.0.0.1:{env['WT_POSTGRES_PORT']}, "
              f"Redis 127.0.0.1:{env['WT_REDIS_PORT']}")
        return 0
    return subprocess.call([*command, args.action], env=env)


if __name__ == "__main__":
    sys.exit(main())
