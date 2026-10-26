#!/usr/bin/env python3
"""Local source probe for console routing/TLS, not release qualification."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
NGINX = "nginx:1.29.1-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8"
PYTHON = (
    "python@sha256:fd95fa221297a88e1cf49c55ec1828edd7c5a428187e67b5d1805692d11588db"
)
BACKEND = """import json, ssl, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self): self.respond()
    def do_POST(self): self.respond()
    def respond(self):
        payload = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
        status = 503 if self.path == '/health/ready' else 401 if self.path == '/v1/denied' else 200
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        if self.path == '/v1/cookie': self.send_header('Set-Cookie', 'sessionId=fixture; Path=/; HttpOnly; SameSite=Lax')
        self.end_headers()
        self.wfile.write(json.dumps(dict(path=self.path, method=self.command, payload=payload,
            key=self.headers.get('X-API-Key', ''), cookie=self.headers.get('Cookie', ''))).encode())
plain = ThreadingHTTPServer(('0.0.0.0', 8000), Handler)
secure = ThreadingHTTPServer(('0.0.0.0', 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/fixture/cert.pem', '/fixture/key.pem')
secure.socket = context.wrap_socket(secure.socket, server_side=True)
threading.Thread(target=secure.serve_forever, daemon=True).start()
plain.serve_forever()
"""
CLIENT = """import json, sys, urllib.request, urllib.error
value = json.loads(sys.argv[1])
data = value.get('data')
request = urllib.request.Request(value['url'], data=None if data is None else data.encode(), headers=value.get('headers', {}))
try: response = urllib.request.urlopen(request, timeout=8)
except urllib.error.HTTPError as error: response = error
print(json.dumps(dict(status=response.code, headers={key.lower():value for key,value in response.headers.items()}, body=response.read().decode())))
"""


def docker(*args: str) -> str:
    result = subprocess.run(
        ["docker", *args], check=False, capture_output=True, text=True, timeout=90
    )
    if result.returncode:
        raise RuntimeError("Docker source probe failed: " + args[0])
    return result.stdout.strip()


def certificate(directory: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "backend")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("backend")]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def probe(output: Path, assets_dir: Path | None = None) -> dict:
    if output.exists():
        raise ValueError("probe output must be a new owned directory")
    output.mkdir(parents=True)
    output = output.resolve()
    nonce = uuid4().hex
    label = "marty.independent-console-source=" + nonce
    prefix = "marty-console-source-" + nonce[:12]
    owned = []
    network = None
    cleanup = []
    failure = None
    result = {}
    try:
        for image in (NGINX, PYTHON):
            docker("image", "inspect", image)
        certificate(output)
        (output / "backend.py").write_text(BACKEND, encoding="utf-8", newline="\n")
        (output / "render.sh").write_bytes(
            (ROOT / "scripts/console-api-start.sh").read_bytes().replace(b"\r\n", b"\n")
        )
        (output / "console.template").write_bytes(
            (ROOT / "docker/nginx-console.conf.template").read_bytes()
        )
        assets = assets_dir.resolve() if assets_dir is not None else output / "static"
        if assets_dir is None:
            (assets / "console").mkdir(parents=True)
            (assets / "index.html").write_text("public fixture")
            (assets / "console/index.html").write_text("console fixture")
        if (
            not (assets / "index.html").is_file()
            or not (assets / "console/index.html").is_file()
        ):
            raise ValueError(
                "console assets must contain both application entry documents"
            )
        expected_console = (assets / "console/index.html").read_bytes().decode("utf-8")
        network = docker("network", "create", "--internal", "--label", label, prefix)

        def create(role: str, *args: str) -> str:
            identity = docker(
                "create",
                "--name",
                prefix + "-" + role,
                "--label",
                label,
                "--network",
                network,
                *args,
            )
            if not re.fullmatch(r"[0-9a-f]{64}", identity):
                raise RuntimeError("probe container identity is invalid")
            owned.append(identity)
            (output / "ownership.json").write_text(
                json.dumps({"label": label, "network": network, "containers": owned}),
                encoding="utf-8",
            )
            return identity

        backend = create(
            "backend",
            "--network-alias",
            "backend",
            "--network-alias",
            "wrong-host",
            "--read-only",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--mount",
            f"type=bind,src={output},dst=/fixture,readonly",
            PYTHON,
            "python",
            "-B",
            "/fixture/backend.py",
        )
        docker("start", backend)
        deadline = time.monotonic() + 15
        while True:
            try:
                docker(
                    "exec",
                    backend,
                    "python",
                    "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2).read()",
                )
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("backend source fixture did not start") from None
                time.sleep(0.1)

        def request(alias: str, path: str, **kwargs) -> dict:
            return json.loads(
                docker(
                    "exec",
                    backend,
                    "python",
                    "-c",
                    CLIENT,
                    json.dumps({"url": "http://" + alias + path, **kwargs}),
                )
            )

        def console(role: str, origin: str, *, trusted=False, invalid=False) -> str:
            flags = [
                "--network-alias",
                role,
                "--env",
                "MARTY_SERVER_ORIGIN=" + origin,
                "--read-only",
                "--tmpfs",
                "/etc/nginx/conf.d:rw,nosuid,size=1m",
                "--tmpfs",
                "/var/cache/nginx:rw,nosuid,size=8m",
                "--tmpfs",
                "/var/run:rw,nosuid,size=1m",
                "--mount",
                f"type=bind,src={assets},dst=/usr/share/nginx/html,readonly",
                "--mount",
                f"type=bind,src={output / 'render.sh'},dst=/fixture/render.sh,readonly",
                "--mount",
                f"type=bind,src={output / 'console.template'},dst=/etc/nginx/marty-console.conf.template,readonly",
            ]
            if trusted:
                flags += [
                    "--mount",
                    f"type=bind,src={output / 'cert.pem'},dst=/etc/ssl/cert.pem,readonly",
                ]
            identity = create(
                role,
                *flags,
                "--entrypoint",
                "/bin/sh",
                NGINX,
                "-c",
                'sh /fixture/render.sh && exec nginx -g "daemon off;"',
            )
            docker("start", identity)
            if invalid:
                if docker("wait", identity) != "1":
                    raise RuntimeError("invalid server origin was accepted")
                return role
            deadline = time.monotonic() + 20
            while True:
                try:
                    if request(role, "/")["status"] == 200:
                        return role
                except (RuntimeError, json.JSONDecodeError):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("console source fixture did not start")
                time.sleep(0.1)

        plain = console("plain", "http://backend:8000")
        for path in (
            "/v1/profiles?next=a%2Fb",
            "/openapi.json",
            "/docs",
            "/realms/example",
            "/.well-known/openid-configuration",
            "/v1/not-static.js",
        ):
            response = request(
                plain,
                path,
                headers={"X-API-Key": "mk_test_console", "Cookie": "sessionId=fixture"},
            )
            body = json.loads(response["body"])
            if (
                response["status"] != 200
                or body["path"] != path
                or body["key"] != "mk_test_console"
                or body["cookie"] != "sessionId=fixture"
            ):
                raise RuntimeError("console did not preserve public API request")
        posted = request(
            plain,
            "/v1/profiles",
            data='{"name":"fixture"}',
            headers={"Content-Type": "application/json"},
        )
        if json.loads(posted["body"])["payload"] != '{"name":"fixture"}':
            raise RuntimeError("console changed request payload")
        if (
            request(plain, "/health/ready")["status"] != 503
            or request(plain, "/v1/denied")["status"] != 401
        ):
            raise RuntimeError("console hid upstream failure")
        if (
            request(plain, "/console/organization")["body"] != expected_console
            or request(plain, "/locales/missing.json")["status"] != 404
        ):
            raise RuntimeError("console static routing regressed")
        if "HttpOnly" not in request(plain, "/v1/cookie")["headers"].get(
            "set-cookie", ""
        ):
            raise RuntimeError("console changed auth cookie attributes")
        untrusted = console("untrusted", "https://backend:8443")
        if request(untrusted, "/v1/profiles")["status"] != 502:
            raise RuntimeError("console accepted an untrusted TLS certificate")
        trusted = console("trusted", "https://backend:8443", trusted=True)
        if request(trusted, "/v1/profiles")["status"] != 200:
            raise RuntimeError("console rejected configured trust")
        wrong = console("wrong", "https://wrong-host:8443", trusted=True)
        if request(wrong, "/v1/profiles")["status"] != 502:
            raise RuntimeError("console skipped TLS hostname verification")
        absent = console("absent", "http://no-server.invalid:8000")
        if request(absent, "/console")["status"] != 200:
            raise RuntimeError("console startup required a local server")
        invalid = [
            "",
            "https://user:password@example.com",
            "https://example.com/path",
            "https://example.com?x=1",
            "https://example.com#x",
            "https://example.com\ninjected",
            "https://example.com:65536",
        ]
        for index, origin in enumerate(invalid):
            console("invalid-" + str(index), origin, invalid=True)
        result = {
            "public_api_paths": 6,
            "payload_and_auth_preserved": True,
            "upstream_failures_preserved": True,
            "tls_verified": True,
            "hostname_verified": True,
            "invalid_origins_rejected": len(invalid),
            "console_starts_without_local_server": True,
            "compiled_assets": assets_dir is not None,
            "backend_business_qualification": False,
        }
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        failure = error
        logs = {}
        for identity in owned:
            try:
                log = subprocess.run(
                    ["docker", "logs", "--tail", "15", identity],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                logs[identity] = (log.stdout + log.stderr)[-10000:]
            except (OSError, subprocess.SubprocessError):
                logs[identity] = "fixture log unavailable"
        (output / "failure.json").write_text(
            json.dumps({"error": str(error), "logs": logs}), encoding="utf-8"
        )
    finally:
        for identity in reversed(owned):
            try:
                docker("stop", "--time", "2", identity)
                docker("rm", identity)
            except (RuntimeError, subprocess.SubprocessError):
                cleanup.append(identity)
        if network:
            try:
                docker("network", "rm", network)
            except (RuntimeError, subprocess.SubprocessError):
                cleanup.append(network)
        try:
            if docker("ps", "--all", "--quiet", "--filter", "label=" + label) or docker(
                "network", "ls", "--quiet", "--filter", "label=" + label
            ):
                cleanup.append("owned resources remain")
        except (OSError, RuntimeError, subprocess.SubprocessError):
            cleanup.append("owned resource absence could not be verified")
        result["owned_teardown_verified"] = not cleanup
        (output / "result.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
    if failure or cleanup:
        raise RuntimeError(
            f"console source probe failed; diagnostics at {output}; cleanup failures={len(cleanup)}"
        ) from failure
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--assets-dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(probe(args.output, args.assets_dir), sort_keys=True))
