"""Containerized crawler-route integration against the production Nginx image."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import uuid
from pathlib import Path

UI_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = UI_ROOT.parent
LOCAL_NGINX: Path | None = None
PINNED_NGINX_IMAGE = (
    "nginx:1.29.1-alpine@"
    "sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8"
)
CRAWLER_FILES = {
    "robots.txt": ("text/plain", "User-agent: *\nSitemap: https://elevenidllc.com/sitemap.xml\n"),
    "sitemap.xml": ("application/xml", '<?xml version="1.0"?><urlset/>'),
    "sitemap-index.xml": ("application/xml", '<?xml version="1.0"?><sitemapindex/>'),
    "sitemap-0.xml": ("application/xml", '<?xml version="1.0"?><urlset/>'),
}
SECURITY_HEADERS = {
    "x-frame-options": "SAMEORIGIN",
    "x-content-type-options": "nosniff",
    "x-xss-protection": "1; mode=block",
    "referrer-policy": "strict-origin-when-cross-origin",
}
SECTION_FILES = {
    "index.html": '<!doctype html><html><head><!-- SELFHOST_GOOGLE_SITE_VERIFICATION --></head><body>customer application fixture</body></html>',
    "console/index.html": '<!doctype html><html><body>customer console fixture</body></html>',
    "assets/application.js": 'window.customerFixture = true;\n',
    "assets/application.css": 'body { color: black; }\n',
    "locales/en/common.json": '{"fixture":"shared translation"}',
    "config.json": '{"fixture":"shared config"}',
    "manifest.json": '{"name":"customer fixture"}',
    "favicon.svg": '<svg xmlns="http://www.w3.org/2000/svg"/>',
}
CONSOLE_ALIASES = {
    "/catalog": "/console/applicant/catalog",
    "/credentials": "/console/applicant/credentials",
    "/my-applications": "/console/applicant/applications",
    "/my-documents": "/console/applicant/devices",
    "/console-handoff/org/setup": "/console/org/setup",
}


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def write_image_context(root: Path, config: Path, html: dict[str, str]) -> None:
    root.mkdir()
    shutil.copy2(config, root / "default.conf")
    html_root = root / "html"
    html_root.mkdir()
    for name, content in html.items():
        path = html_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
    (root / "Dockerfile").write_text(
        f"FROM {PINNED_NGINX_IMAGE}\n"
        "RUN rm -f /etc/nginx/conf.d/default.conf\n"
        "COPY default.conf /etc/nginx/conf.d/default.conf\n"
        "COPY html/ /usr/share/nginx/html/\n",
        encoding="utf-8",
    )


class NginxContainerFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("docker") is None:
            raise RuntimeError(
                "docker is required; this integration test must not skip"
            )
        docker("info")

        for path in (UI_ROOT / "Dockerfile.prod", REPO_ROOT / "docker/ui.Dockerfile"):
            serving_images = re.findall(r"^FROM (nginx:\S+)(?: AS runtime-base)?$",
                                        path.read_text(encoding="utf-8"), re.MULTILINE)
            if serving_images != [PINNED_NGINX_IMAGE]:
                raise AssertionError(f"integration image must exactly match {path}: {serving_images!r}")

        cls.identifier = f"marty-crawler-{uuid.uuid4().hex[:12]}"
        cls.network = cls.identifier
        cls.images: list[str] = []
        cls.containers: list[str] = []
        cls.temporary = tempfile.TemporaryDirectory(
            prefix=f".{cls.identifier}-", dir=UI_ROOT
        )
        cls.root = Path(cls.temporary.name)

        docker("network", "create", cls.network)
        try:
            gateway_root = cls.root / "gateway"
            gateway_root.mkdir()
            (gateway_root / "default.conf").write_text(
                "server {\n"
                "  listen 8000;\n"
                "  location /v1/ { default_type application/json; "
                "return 401 '{\"fixture\":\"gateway\",\"status\":401}'; }\n"
                "  location /auth/ { default_type application/json; "
                "return 401 '{\"fixture\":\"gateway\",\"status\":401}'; }\n"
                "  location /api/ { default_type application/json; "
                "return 503 '{\"fixture\":\"gateway\",\"status\":503}'; }\n"
                "  location = /openapi.json { default_type application/json; "
                "return 200 '{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"gateway fixture\",\"version\":\"test\"},\"paths\":{}}'; }\n"
                "  location / { default_type application/json; "
                "return 503 '{\"fixture\":\"gateway\",\"status\":503}'; }\n"
                "}\n",
                encoding="utf-8",
            )
            (gateway_root / "Dockerfile").write_text(
                f"FROM {PINNED_NGINX_IMAGE}\n"
                "RUN rm -f /etc/nginx/conf.d/default.conf\n"
                "COPY default.conf /etc/nginx/conf.d/default.conf\n",
                encoding="utf-8",
            )
            gateway_image = f"{cls.identifier}-gateway"
            cls.images.append(gateway_image)
            docker("build", "--quiet", "--tag", gateway_image, str(gateway_root))
            gateway_container = f"{cls.identifier}-gateway"
            cls.containers.append(gateway_container)
            docker(
                "run",
                "--detach",
                "--name",
                gateway_container,
                "--network",
                cls.network,
                "--network-alias",
                "gateway",
                "--network-alias",
                "gateway.marty-prod.svc.cluster.local",
                gateway_image,
            )
        except BaseException:
            cls._cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls._cleanup()

    @classmethod
    def _cleanup(cls) -> None:
        for container in reversed(getattr(cls, "containers", [])):
            docker("rm", "--force", container, check=False)
        for image in reversed(getattr(cls, "images", [])):
            docker("image", "rm", "--force", image, check=False)
        if hasattr(cls, "network"):
            docker("network", "rm", cls.network, check=False)
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def start_ui(self, config_name: str, config_path: Path | None = None) -> tuple[str, int]:
        variant = config_name.removeprefix("nginx.").removesuffix(".conf")
        context = self.root / variant
        write_image_context(
            context,
            config_path or UI_ROOT / config_name,
            {
                "index.html": "<h1>marketing fixture</h1>",
                "docs/index.html": "<h1>docs fixture</h1>",
                "console/index.html": "<h1>console fixture</h1>",
                "locales/de/marketing.json": '{"navigation":{"home":"Startseite"}}',
                **{name: content for name, (_, content) in CRAWLER_FILES.items()},
            },
        )
        image = f"{self.identifier}-{variant}"
        container = f"{self.identifier}-{variant}"
        self.images.append(image)
        self.containers.append(container)
        docker("build", "--quiet", "--tag", image, str(context))
        docker(
            "run",
            "--detach",
            "--name",
            container,
            "--network",
            self.network,
            "--publish",
            "127.0.0.1::80",
            image,
        )
        ports = json.loads(
            docker(
                "inspect", "--format", "{{json .NetworkSettings.Ports}}", container
            ).stdout
        )
        port = int(ports["80/tcp"][0]["HostPort"])
        for _ in range(100):
            running = docker(
                "inspect", "--format", "{{.State.Running}}", container
            ).stdout.strip()
            if running != "true":
                raise RuntimeError(docker("logs", container, check=False).stderr)
            try:
                self.request(port, "/")
                return container, port
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"{container} did not accept connections")

    @staticmethod
    def request(
        port: int, path: str, method: str = "GET"
    ) -> tuple[int, dict[str, str], str]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request(method, path, headers={"User-Agent": "Googlebot"})
            response = connection.getresponse()
            headers = {name.lower(): value for name, value in response.getheaders()}
            return response.status, headers, response.read().decode("utf-8")
        finally:
            connection.close()

    def assert_security_headers(self, headers: dict[str, str]) -> None:
        for name, expected in SECURITY_HEADERS.items():
            self.assertEqual(headers.get(name), expected, name)
        self.assertIn("nginx/1.29.1", headers.get("server", ""))


class NginxCrawlerRouteContract(NginxContainerFixture):

    def verify_config(self, config_name: str) -> None:
        container, port = self.start_ui(config_name)

        for name, (content_type, content) in CRAWLER_FILES.items():
            for suffix in ("", "?source=contract"):
                with self.subTest(config=config_name, path=name + suffix):
                    status, headers, body = self.request(port, f"/{name}{suffix}")
                    self.assertEqual(status, 200)
                    self.assertTrue(headers["content-type"].startswith(content_type))
                    self.assertNotIn("location", headers)
                    self.assertEqual(body, content)
                    self.assert_security_headers(headers)
                    head_status = self.request(port, f"/{name}{suffix}", "HEAD")[0]
                    self.assertEqual(head_status, 200)

        for path in ("/sitemap-99.xml",):
            status, headers, body = self.request(port, path)
            self.assertEqual(status, 404)
            self.assertNotIn("marketing fixture", body)
            self.assert_security_headers(headers)
            self.assertEqual(self.request(port, path, "HEAD")[0], 404)

        for name in CRAWLER_FILES:
            docker("exec", container, "rm", f"/usr/share/nginx/html/{name}")
            status, headers, body = self.request(port, f"/{name}?missing=1")
            self.assertEqual(status, 404)
            self.assertNotIn("marketing fixture", body)
            self.assert_security_headers(headers)
            self.assertEqual(self.request(port, f"/{name}", "HEAD")[0], 404)

        for path in ("/sitemap-unknown.xml", "/sitemap.xml/extra", "/robots.txt/extra"):
            status, _, body = self.request(port, path)
            self.assertEqual(status, 200)
            self.assertIn("marketing fixture", body)

        for path in ("/", "/product", "/demos", "/demos/"):
            status, _, body = self.request(port, path)
            self.assertEqual(status, 200)
            self.assertIn("marketing fixture", body)
        status, headers, body = self.request(port, "/locales/de/marketing.json")
        self.assertEqual(status, 200)
        self.assertTrue(headers["content-type"].startswith("application/json"))
        self.assertEqual(json.loads(body)["navigation"]["home"], "Startseite")
        status, headers, body = self.request(port, "/locales/de/missing.json")
        self.assertEqual(status, 404)
        self.assertNotIn("marketing fixture", body)
        self.assert_security_headers(headers)
        status, headers, body = self.request(port, "/openapi.yaml")
        self.assertEqual(status, 308)
        self.assertEqual(headers["location"], "/openapi.json")
        self.assertNotIn("marketing fixture", body)
        status, headers, _ = self.request(port, "/docs")
        self.assertEqual(status, 301)
        self.assertEqual(headers["location"], "/docs/")
        status, _, body = self.request(port, "/docs/")
        self.assertEqual(status, 200)
        self.assertIn("docs fixture", body)
        for path in ("/console", "/console/credentials"):
            status, _, body = self.request(port, path)
            self.assertEqual(status, 200)
            self.assertIn("console fixture", body)

        if config_name == "nginx.prod.conf":
            for path, expected in (
                ("/v1/private-fixture", 401),
                ("/auth/private-fixture", 401),
                ("/api/failure-fixture", 503),
                ("/openapi.json", 200),
                ("/ready", 503),
            ):
                with self.subTest(path=path):
                    status, headers, body = self.request(port, path)
                    self.assertEqual(status, expected)
                    self.assertIn("gateway", body)
                    self.assert_security_headers(headers)
        else:
            status, headers, body = self.request(port, "/openapi.json")
            self.assertEqual(status, 503)
            self.assertEqual(json.loads(body)["error"], "openapi_gateway_proxy_required")
            for path in ("/ready", "/health/ready"):
                status, headers, body = self.request(port, path)
                self.assertEqual(status, 503)
                self.assertIn("readiness_not_proxied", body)
                self.assert_security_headers(headers)

    def test_production_and_static_configs(self) -> None:
        for config_name in ("nginx.prod.conf", "nginx.spa.conf"):
            with self.subTest(config=config_name):
                self.verify_config(config_name)

    def test_development_docs_redirect_preserves_origin(self) -> None:
        _, port = self.start_ui("nginx.dev.conf")
        status, headers, _ = self.request(port, "/docs")
        self.assertEqual(status, 301)
        self.assertEqual(headers["location"], "/docs/")
        status, _, body = self.request(port, "/docs/")
        self.assertEqual(status, 200)
        self.assertIn("docs fixture", body)

    def test_oke_mounted_config_serves_gateway_schema_instead_of_spa(self) -> None:
        manifest = (UI_ROOT.parent / "k8s/oracle/08-ui.yaml").read_text(encoding="utf-8")
        block = manifest.split("  default.conf: |\n", 1)[1].split("\n---", 1)[0]
        # Use the actual mounted configuration, substituting only the test DNS
        # infrastructure. The fixture carries the real Kubernetes service alias.
        config = textwrap.dedent(block).replace(
            "kube-dns.kube-system.svc.cluster.local", "127.0.0.11"
        )
        config_path = self.root / "nginx.oke.conf"
        config_path.write_text(config, encoding="utf-8")
        _, port = self.start_ui("nginx.oke.conf", config_path)
        status, headers, body = self.request(port, "/openapi.json")
        self.assertEqual(status, 200)
        self.assertTrue(headers["content-type"].startswith("application/json"))
        self.assertEqual(json.loads(body)["openapi"], "3.1.0")
        self.assertNotIn("marketing fixture", body)
        status, headers, _ = self.request(port, "/openapi.yaml")
        self.assertEqual(status, 308)
        self.assertEqual(headers["location"], "/openapi.json")


class LocalSectionNginx:
    """Optional developer adapter; CI always uses the pinned Docker image.

    Only filesystem locations, the listener port, and the fixture upstream are
    substituted. The actual startup hooks and both server route policies run.
    """

    def __init__(self, binary: Path):
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
            raise RuntimeError("the local Nginx adapter is forbidden in CI")
        if not binary.is_file():
            raise RuntimeError(f"local Nginx executable is missing: {binary}")
        self.binary = binary
        self.temporary = tempfile.TemporaryDirectory(prefix="marty-nginx-sections-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)
        self.processes: list[subprocess.Popen] = []
        self.version = subprocess.run([str(binary), "-v"], check=True, capture_output=True, text=True).stderr.strip()
        try:
            self.gateway_port = self.start("gateway", "server { listen 80; location / { "
                "default_type application/json; return 401 '{\"fixture\":\"gateway\",\"status\":401}'; } }")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process.stderr:
                process.stderr.close()
        self.temporary.cleanup()

    def start(self, name: str, server: str, target: Path | None = None) -> int:
        prefix = self.root / (name + "-nginx")
        prefix.mkdir(mode=0o755)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        server = server.replace("listen 80;", f"listen 127.0.0.1:{port};")
        if target is not None:
            server = server.replace("/usr/share/nginx/html", str(target))
        server = server.replace("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt")
        configuration = prefix / "nginx.conf"
        configuration.write_text(
            f"pid {prefix}/nginx.pid;\nerror_log {prefix}/error.log;\n"
            "events { worker_connections 128; }\nhttp {\n"
            "types { text/html html; text/plain txt; application/json json; "
            "application/javascript js; text/css css; image/svg+xml svg; }\n"
            "access_log off;\n"
            f"client_body_temp_path {prefix}/body;\nproxy_temp_path {prefix}/proxy;\n"
            f"fastcgi_temp_path {prefix}/fastcgi;\nuwsgi_temp_path {prefix}/uwsgi;\n"
            f"scgi_temp_path {prefix}/scgi;\n{server}\n}}\n",
            encoding="utf-8",
        )
        process = subprocess.Popen([str(self.binary), "-p", str(prefix) + "/", "-c", str(configuration),
                                    "-g", "daemon off;"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        for _ in range(100):
            if process.poll() is not None:
                _, error = process.communicate()
                raise RuntimeError(error + (prefix / "error.log").read_text())
            try:
                NginxContainerFixture.request(port, "/healthz")
                return port
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"local Nginx {name} did not start")

    def start_ui(self, variant: str, choice: str) -> int:
        name = variant + "-" + choice.replace(",", "-")
        context = self.root / name
        context.mkdir(mode=0o755)
        source, target = context / "source", context / "html"
        source.mkdir(mode=0o755)
        target.mkdir(mode=0o755)
        for name, content in SECTION_FILES.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        environment = {"PATH": os.environ["PATH"], "UI_ENABLED_SECTIONS": choice}
        startup = (REPO_ROOT / "scripts/ui-selfhost-start.sh").read_text(encoding="utf-8")
        replacements = {
            ". /scripts/load-secrets-env.sh": ". " + shlex.quote(str(REPO_ROOT / "scripts/load-secrets-env.sh")),
            'SOURCE_DIR="/opt/marty-ui-static"': "SOURCE_DIR=" + shlex.quote(str(source)),
            'TARGET_DIR="/usr/share/nginx/html"': "TARGET_DIR=" + shlex.quote(str(target)),
        }
        for original, replacement in replacements.items():
            if startup.count(original) != 1:
                raise RuntimeError(f"startup filesystem adapter no longer matches {original}")
            startup = startup.replace(original, replacement)
        subprocess.run(["sh"], input=startup, text=True, env=environment, check=True, capture_output=True)
        if variant == "console":
            template = context / "console.template"
            template.write_bytes((REPO_ROOT / "docker/nginx-console.conf.template").read_bytes())
            rendered = context / "console.conf"
            hook = (REPO_ROOT / "scripts/console-api-start.sh").read_text(encoding="utf-8")
            hook = hook.replace("/etc/nginx/marty-console.conf.template", str(template))
            hook = hook.replace("/etc/nginx/conf.d/default.conf", str(rendered))
            environment["MARTY_SERVER_ORIGIN"] = f"http://127.0.0.1:{self.gateway_port}"
            subprocess.run(["sh"], input=hook, text=True, env=environment, check=True, capture_output=True)
            server = rendered.read_text(encoding="utf-8")
        else:
            server = (UI_ROOT / "nginx.spa.conf").read_text(encoding="utf-8")
        return self.start(context.name, server, target)


class NginxSectionRouteContract(NginxContainerFixture):
    @classmethod
    def setUpClass(cls) -> None:
        cls.local = LocalSectionNginx(LOCAL_NGINX) if LOCAL_NGINX else None
        if cls.local is None:
            super().setUpClass()
        cls.section_images: dict[str, str] = {}

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.local:
            cls.local.close()
        else:
            super().tearDownClass()

    def start_sections(self, variant: str, choice: str) -> int:
        if self.local:
            return self.local.start_ui(variant, choice)
        if variant not in self.section_images:
            context = self.root / ("section-" + variant)
            write_image_context(context, UI_ROOT / "nginx.spa.conf", SECTION_FILES)
            for script in ("ui-selfhost-start.sh", "load-secrets-env.sh", "console-api-start.sh"):
                shutil.copy2(REPO_ROOT / "scripts" / script, context / script)
            shutil.copy2(REPO_ROOT / "docker/nginx-console.conf.template", context / "console.template")
            (context / "Dockerfile").write_text(
                f"FROM {PINNED_NGINX_IMAGE}\n"
                "COPY default.conf /etc/nginx/conf.d/default.conf\n"
                "COPY html/ /opt/marty-ui-static/\n"
                "COPY load-secrets-env.sh /scripts/load-secrets-env.sh\n"
                "COPY ui-selfhost-start.sh /docker-entrypoint.d/40-ui-selfhost.sh\n"
                "RUN chmod +x /docker-entrypoint.d/40-ui-selfhost.sh\n"
                + ("COPY console.template /etc/nginx/marty-console.conf.template\n"
                   "COPY console-api-start.sh /docker-entrypoint.d/45-console-api.sh\n"
                   "RUN chmod +x /docker-entrypoint.d/45-console-api.sh\n" if variant == "console" else ""),
                encoding="utf-8",
            )
            image = f"{self.identifier}-section-{variant}"
            self.images.append(image)
            docker("build", "--quiet", "--tag", image, str(context))
            self.section_images[variant] = image
        container = f"{self.identifier}-{variant}-{choice.replace(',', '-')}"
        self.containers.append(container)
        docker("run", "--detach", "--name", container, "--network", self.network,
               "--publish", "127.0.0.1::80", "--env", "UI_ENABLED_SECTIONS=" + choice,
               "--env", "MARTY_SERVER_ORIGIN=http://gateway:8000", self.section_images[variant])
        ports = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Ports}}", container).stdout)
        port = int(ports["80/tcp"][0]["HostPort"])
        for _ in range(100):
            if docker("inspect", "--format", "{{.State.Running}}", container).stdout.strip() != "true":
                raise RuntimeError(docker("logs", container, check=False).stderr)
            try:
                self.request(port, "/healthz")
                return port
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"{container} did not accept connections")

    def verify_sections(self, variant: str, choice: str) -> None:
        port = self.start_sections(variant, choice)
        sections = [] if choice == "none" else choice.split(",")
        public, console = "public" in sections, "console" in sections
        for path in ("/", "/index.html", "/index.html?section=console", "/login", "/verification"):
            with self.subTest(variant=variant, mode=choice, path=path):
                status, _, body = self.request(port, path)
                self.assertEqual(status, 200 if public else 404)
                self.assertEqual("customer application fixture" in body, public)
        for path in ("/console", "/console/", "/console/index.html", "/console/login",
                     "/console/auth/callback", "/console/org/credentials", "/%63onsole/index.html"):
            with self.subTest(variant=variant, mode=choice, path=path):
                status, _, body = self.request(port, path)
                self.assertEqual(status, 200 if console else 404)
                self.assertEqual("customer console fixture" in body, console)
        for alias, destination in CONSOLE_ALIASES.items():
            with self.subTest(variant=variant, mode=choice, alias=alias):
                status, headers, _ = self.request(port, alias + "?from=contract")
                self.assertEqual(status, 308 if console else 404)
                if console:
                    self.assertEqual(headers["location"], destination + "?from=contract")
                    self.assertEqual(self.request(port, headers["location"])[0], 200)
                else:
                    self.assertNotIn("location", headers)
        for path in ("/apply", "/apply/credential-template"):
            with self.subTest(variant=variant, mode=choice, path=path):
                self.assertEqual(self.request(port, path)[0], 200 if public and console else 404)
        for path in ("/assets/application.js", "/assets/application.css", "/favicon.svg",
                     "/locales/en/common.json", "/config.json", "/manifest.json", "/runtime-config.js",
                     "/auth/callback"):
            with self.subTest(variant=variant, mode=choice, path=path):
                status, _, body = self.request(port, path)
                self.assertEqual(status, 200 if sections else 404)
                self.assertEqual(self.request(port, path, "HEAD")[0], status)
                if path == "/runtime-config.js" and sections:
                    match = re.search(r"enabled_sections: (\[[^\]]*\])", body)
                    self.assertIsNotNone(match)
                    self.assertEqual(json.loads(match.group(1)), sections)
        for path in ("/.marty-ui-disabled", "/.marty-ui-public-disabled", "/.marty-ui-console-disabled",
                     "/assets/missing.js", "/locales/en/missing.json"):
            with self.subTest(variant=variant, mode=choice, path=path):
                self.assertEqual(self.request(port, path)[0], 404)
        status, _, body = self.request(port, "/healthz")
        self.assertEqual((status, body), (200, "ok\n"))
        self.assertEqual(self.request(port, "/healthz", "HEAD")[0], 200)
        if variant == "console":
            for path in ("/v1/private-fixture", "/auth/private-fixture"):
                with self.subTest(mode=choice, api=path):
                    status, headers, body = self.request(port, path)
                    self.assertEqual(status, 401)
                    self.assertTrue(headers["content-type"].startswith("application/json"))
                    self.assertEqual(json.loads(body)["fixture"], "gateway")

    def test_customer_section_modes_execute_real_startup_and_http_routes(self) -> None:
        for variant in ("selfhost", "console"):
            for choice in ("public,console", "public", "console", "none"):
                with self.subTest(variant=variant, mode=choice):
                    self.verify_sections(variant, choice)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--local-nginx", type=Path,
                        help="Developer-only section matrix; CI always requires pinned Docker Nginx")
    options, remaining = parser.parse_known_args()
    LOCAL_NGINX = options.local_nginx
    if LOCAL_NGINX:
        if remaining:
            parser.error("--local-nginx runs only the section matrix; do not supply other test selectors")
        print("Local section matrix against " + str(LOCAL_NGINX), flush=True)
        unittest.main(argv=[sys.argv[0], "NginxSectionRouteContract"], verbosity=2)
    else:
        unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
