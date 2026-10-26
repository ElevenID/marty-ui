#!/usr/bin/env python3
"""Exercise the real edge without a console; this is not backend qualification."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "nginx@sha256:582c496ccf79d8aa6f8203a79d32aaf7ffd8b13362c60a701a2f9ac64886c93d"


def docker(*arguments: str) -> str:
    result = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError("Docker fixture operation failed: " + arguments[0])
    return result.stdout.strip()


def request(base: str, path: str) -> tuple[int, str]:
    result = subprocess.run(
        ["docker", "exec", base, "wget", "-Y", "off", "-S", "-O", "-",
         "--header", "X-API-Key: mk_test_edge-fixture", "http://127.0.0.1" + path],
        capture_output=True, text=True, timeout=5,
    )
    codes = re.findall(r"HTTP/1\.[01]\s+(\d{3})", result.stderr)
    if not codes:
        raise OSError("Edge HTTP fixture did not return a status")
    return int(codes[-1]), result.stdout


def probe() -> dict:
    nonce = uuid4().hex[:16]
    label = "marty.api-only-edge-probe=" + nonce
    prefix = "marty-api-edge-" + nonce
    state = Path(tempfile.mkdtemp(prefix=prefix + "-"))
    owned: list[str] = []
    network: str | None = None
    failure: Exception | None = None
    cleanup_failures: list[str] = []
    checked: list[str] = []
    try:
        docker("image", "inspect", IMAGE, "--format", "{{.Id}}")
        network = docker("network", "create", "--internal", "--label", label, prefix)
        for source, target in [
            ("docker/nginx-selfhost.prod.conf.template", "edge.template"),
            ("scripts/nginx-entrypoint-selfhost.sh", "render.sh"),
        ]:
            (state / target).write_bytes((ROOT / source).read_bytes().replace(b"\r\n", b"\n"))
        (state / "backend.conf").write_text(
            'server { listen 80; location = /health/ready { return 503; } '
            'location / { default_type application/json; '
            'return 200 \'{"fixture":"backend","uri":"$request_uri",'
            '"key":"$http_x_api_key"}\'; } }\n', encoding="utf-8")

        def create(role: str, *arguments: str) -> str:
            identity = docker("create", "--name", prefix + "-" + role, "--label", label,
                              "--network", network, *arguments)
            if not re.fullmatch(r"[a-f0-9]{64}", identity):
                raise RuntimeError("Docker fixture returned an invalid container identity")
            owned.append(identity)
            return identity

        backend = create(
            "backend", "--network-alias", "backend", "--mount",
            f"type=bind,source={state / 'backend.conf'},target=/etc/nginx/conf.d/default.conf,readonly",
            "--entrypoint", "nginx", IMAGE, "-g", "daemon off;",
        )
        docker("start", backend)

        def edge(role: str, enabled: str | None) -> tuple[str, str]:
            environment = {
                "PUBLIC_DOMAIN": "probe.example.invalid", "GATEWAY_UPSTREAM": "backend:80",
                "FLOW_UPSTREAM": "backend:80", "KEYCLOAK_UPSTREAM": "backend:80",
                "UI_UPSTREAM": "backend:80" if enabled is None else "absent-ui:80",
                "CANVAS_REAL_PUBLIC_HOST": "canvas.example.invalid",
                "CANVAS_SANDBOX_PUBLIC_HOST": "sandbox.example.invalid",
            }
            if enabled is not None:
                environment["SELFHOST_CONSOLE_ENABLED"] = enabled
            flags = [item for key, value in environment.items() for item in ("--env", key + "=" + value)]
            identity = create(
                role, *flags, "--mount",
                f"type=bind,source={state / 'edge.template'},target=/etc/nginx/conf.d/default.conf.template,readonly",
                "--mount", f"type=bind,source={state / 'render.sh'},target=/probe/render.sh,readonly",
                "--entrypoint", "/bin/sh", IMAGE, "-c",
                "/bin/sh /probe/render.sh && exec nginx -g 'daemon off;'",
            )
            docker("start", identity)
            if enabled not in (None, "true", "false"):
                if docker("wait", identity) != "2":
                    raise RuntimeError("Invalid console flag did not fail closed")
                return identity, ""
            base = identity
            deadline = time.monotonic() + 15
            while True:
                try:
                    if request(base, "/ready")[0] == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("Edge fixture readiness deadline exceeded")
                time.sleep(0.1)
            return identity, base

        _, base = edge("disabled", "false")
        for path in ("/ready", "/v1/api-keys?organization_id=fixture", "/openapi.json",
                     "/docs", "/redoc", "/.well-known/openid-credential-issuer", "/credentials/example"):
            status, body = request(base, path)
            if status != 200 or json.loads(body) != {
                "fixture": "backend", "uri": path, "key": "mk_test_edge-fixture",
            }:
                raise RuntimeError("API route did not reach its upstream: " + path)
            checked.append(path)
        if request(base, "/health/ready")[0] != 503:
            raise RuntimeError("Edge concealed failed upstream readiness")
        for path in ("/", "/console", "/console/org", "/canvas/lti/experience", "/.well-known/ai-plugin.json"):
            if request(base, path)[0] != 404:
                raise RuntimeError("Console-disabled route attempted UI fallback: " + path)
        _, enabled = edge("default", None)
        if request(enabled, "/")[0] != 200:
            raise RuntimeError("Default console routing regressed")
        edge("invalid", "invalid")
        edge("empty", "")
    except Exception as error:
        failure = error
        logs = {}
        for identity in owned:
            try:
                result = subprocess.run(["docker", "logs", "--tail", "20", identity],
                                        capture_output=True, text=True, timeout=10)
                logs[identity] = (result.stdout + result.stderr)[-10000:]
            except Exception:
                logs[identity] = "fixture logs unavailable"
        (state / "failure.json").write_text(json.dumps({"error": str(error), "logs": logs}), encoding="utf-8")
    finally:
        for identity in reversed(owned):
            try:
                docker("rm", "--force", identity)
            except Exception:
                cleanup_failures.append(identity)
        if network:
            try:
                docker("network", "rm", network)
            except Exception:
                cleanup_failures.append(network)
        try:
            if (docker("ps", "--all", "--quiet", "--filter", "label=" + label)
                    or docker("network", "ls", "--quiet", "--filter", "label=" + label)):
                cleanup_failures.append("owned resources still registered")
        except Exception:
            cleanup_failures.append("owned resource absence could not be verified")
    if failure or cleanup_failures:
        raise RuntimeError(f"Edge probe failed; preserved diagnostics at {state}; cleanup failures={len(cleanup_failures)}") from failure
    shutil.rmtree(state)
    return {"image": IMAGE, "api_routes": checked, "console_absent": True,
            "ui_routes_404": True, "default_console_preserved": True,
            "failed_readiness_preserved": True, "invalid_flag_rejected": True,
            "owned_teardown_verified": True, "backend_qualification": False}


if __name__ == "__main__":
    try:
        print(json.dumps(probe(), sort_keys=True))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
