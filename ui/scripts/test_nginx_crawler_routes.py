"""Containerized crawler-route integration against the production Nginx image."""

from __future__ import annotations

import http.client
import json
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

UI_ROOT = Path(__file__).resolve().parents[1]
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


class NginxCrawlerRouteContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("docker") is None:
            raise RuntimeError(
                "docker is required; this integration test must not skip"
            )
        docker("info")

        production_dockerfile = (UI_ROOT / "Dockerfile.prod").read_text(
            encoding="utf-8"
        )
        serving_images = re.findall(
            r"^FROM (nginx:\S+)$", production_dockerfile, re.MULTILINE
        )
        if serving_images != [PINNED_NGINX_IMAGE]:
            raise AssertionError(
                "integration image must exactly match Dockerfile.prod: "
                f"{serving_images!r}"
            )

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
                "return 502 '{\"fixture\":\"gateway\",\"status\":502}'; }\n"
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

    def start_ui(self, config_name: str) -> tuple[str, int]:
        variant = config_name.removeprefix("nginx.").removesuffix(".conf")
        context = self.root / variant
        write_image_context(
            context,
            UI_ROOT / config_name,
            {
                "index.html": "<h1>marketing fixture</h1>",
                "console/index.html": "<h1>console fixture</h1>",
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
        for path in ("/console", "/console/credentials"):
            status, _, body = self.request(port, path)
            self.assertEqual(status, 200)
            self.assertIn("console fixture", body)

        if config_name == "nginx.prod.conf":
            for path, expected in (
                ("/v1/private-fixture", 401),
                ("/auth/private-fixture", 401),
                ("/api/failure-fixture", 503),
                ("/openapi.json", 502),
                ("/ready", 503),
            ):
                with self.subTest(path=path):
                    status, headers, body = self.request(port, path)
                    self.assertEqual(status, expected)
                    self.assertIn("gateway", body)
                    self.assert_security_headers(headers)
        else:
            for path in ("/ready", "/health/ready"):
                status, headers, body = self.request(port, path)
                self.assertEqual(status, 503)
                self.assertIn("readiness_not_proxied", body)
                self.assert_security_headers(headers)

    def test_production_and_static_configs(self) -> None:
        for config_name in ("nginx.prod.conf", "nginx.spa.conf"):
            with self.subTest(config=config_name):
                self.verify_config(config_name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
