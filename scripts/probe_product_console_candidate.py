#!/usr/bin/env python3
"""Exercise the exact console image against an isolated public-API fixture.

This proves image startup and proxy behavior, not compatibility with a Marty
server or a complete authentication and credential journey.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path
from uuid import uuid4

PYTHON = "python@sha256:fd95fa221297a88e1cf49c55ec1828edd7c5a428187e67b5d1805692d11588db"
BACKEND = """import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        status=503 if self.path=='/health/ready' else 401 if self.path=='/v1/denied' else 200
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'path':self.path,'key':self.headers.get('X-API-Key','')}).encode())
ThreadingHTTPServer(('0.0.0.0',8000),Handler).serve_forever()
"""
CLIENT = """import json,sys,urllib.request,urllib.error
request=urllib.request.Request(sys.argv[1],headers={'X-API-Key':'mk_candidate_probe'})
try: response=urllib.request.urlopen(request,timeout=4)
except urllib.error.HTTPError as error: response=error
print(json.dumps({'status':response.code,'body':response.read().decode()}))
"""


def docker(*args: str) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            timeout=90, check=False)
    if result.returncode:
        raise RuntimeError(f"Docker operation failed: {args[0]}: {result.stderr[-500:]}")
    return result.stdout.strip()


def probe(image: str) -> dict:
    if re.fullmatch(r"ghcr\.io/elevenid/marty-console/ui@sha256:[0-9a-f]{64}", image) is None:
        raise ValueError("console image must be the exact product digest")
    nonce = uuid4().hex[:12]
    prefix = "marty-product-console-" + nonce
    label = "marty.product-console-probe=" + nonce
    network = None
    containers: list[str] = []
    checks: list[str] = []
    error = None
    cleanup_errors: list[str] = []
    console = None
    try:
        docker("image", "inspect", image)
        docker("image", "inspect", PYTHON)
        network = docker("network", "create", "--internal", "--label", label,
                         prefix)

        def create(role: str, *args: str) -> str:
            identity = docker("create", "--name", prefix + "-" + role,
                              "--label", label, "--network", network, *args)
            if not re.fullmatch(r"[0-9a-f]{64}", identity):
                raise RuntimeError("container identity differs")
            containers.append(identity)
            return identity

        backend = create("backend", "--network-alias", "backend", PYTHON,
                         "python", "-B", "-c", BACKEND)
        client = create("client", PYTHON, "sleep", "infinity")
        docker("start", backend, client)

        def request(path: str) -> dict:
            response = docker("exec", client, "python", "-c", CLIENT,
                              "http://console" + path)
            return json.loads(response)

        console = create(
            "console", "--network-alias", "console",
            "--tmpfs", "/etc/nginx/conf.d:rw,nosuid,size=1m",
            "--tmpfs", "/var/cache/nginx:rw,nosuid,size=8m",
            "--tmpfs", "/var/run:rw,nosuid,size=1m",
            "--env", "MARTY_SERVER_ORIGIN=http://backend:8000", image,
        )
        docker("start", console)
        deadline = time.monotonic() + 20
        while True:
            try:
                if request("/")["status"] == 200:
                    checks.append("real_console_assets_served")
                    break
            except (RuntimeError, ValueError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("candidate console did not serve assets")
            time.sleep(0.2)
        for path, status in (("/v1/profiles?next=a%2Fb", 200),
                             ("/realms/example", 200),
                             ("/.well-known/openid-configuration", 200),
                             ("/v1/denied", 401),
                             ("/health/ready", 503)):
            response = request(path)
            body = json.loads(response["body"])
            if response["status"] != status or body["path"] != path \
                    or body["key"] != "mk_candidate_probe":
                raise RuntimeError("candidate console proxy mismatch: " + path)
            checks.append(path)
        invalid = create("invalid-origin", "--env",
                         "MARTY_SERVER_ORIGIN=http://user@backend:8000", image)
        docker("start", invalid)
        if docker("wait", invalid) != "1":
            raise RuntimeError("candidate accepted invalid server origin")
        checks.append("invalid_origin_rejected")
    except Exception as failure:
        error = str(failure)
        if console:
            diagnosis = subprocess.run(
                ["docker", "logs", console], capture_output=True, text=True,
                timeout=10, check=False,
            )
            error += "; console logs: " + (diagnosis.stdout + diagnosis.stderr)[-700:]
    finally:
        for identity in reversed(containers):
            try:
                docker("rm", "-f", identity)
            except Exception as failure:
                cleanup_errors.append(str(failure))
        if network:
            try:
                docker("network", "rm", network)
            except Exception as failure:
                cleanup_errors.append(str(failure))
    result = {
        "schema": "marty.product-console-candidate-fixture-probe/v1",
        "image": image,
        "claim_scope": "candidate_console_routing_against_fixture_only",
        "checks": checks,
        "cleanup_complete": not cleanup_errors,
        "result": "pass" if error is None and not cleanup_errors else "fail",
    }
    if error:
        result["error"] = error
    if cleanup_errors:
        result["cleanup_errors"] = cleanup_errors
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.image)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    if result["result"] != "pass":
        raise SystemExit(result.get("error", "candidate probe cleanup failed"))


if __name__ == "__main__":
    main()
