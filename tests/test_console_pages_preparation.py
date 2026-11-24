from __future__ import annotations

import importlib.util
import fnmatch
import json
from pathlib import Path
import tempfile
import re
import unittest


SPEC = importlib.util.spec_from_file_location(
    "console_pages",
    Path(__file__).parents[1] / "tools/cloudflare/prepare_console_pages.py",
)
pages = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pages)
REVISION = "a" * 40


class ConsolePagesTests(unittest.TestCase):
    def test_declared_browser_routes_cover_current_application_entrypoints(self):
        root = Path(__file__).parents[1]
        for name in ("public/PublicRoutes.jsx", "console/ConsoleRoutes.jsx"):
            source = (root / "ui/src/apps" / name).read_text(encoding="utf-8")
            for route in re.findall(r'path=["\'](/[^"\']*)["\']', source):
                with self.subTest(route=route):
                    self.assertTrue(
                        route == "/"
                        or route == "/console"
                        or route.startswith("/console/")
                        or any(
                            fnmatch.fnmatchcase(route, pattern)
                            for pattern in pages.PUBLIC_ROUTES
                        )
                    )

    def fixture(self, root):
        source = root / "application"
        (source / "console").mkdir(parents=True)
        (source / "assets").mkdir()
        (source / "index.html").write_text("public shell", encoding="utf-8")
        (source / "console/index.html").write_text("console shell", encoding="utf-8")
        (source / "assets/identity.wasm").write_bytes(b"\0asm")
        (source / "marty-web-routes.json").write_text(
            json.dumps(
                {
                    "schema": "marty.application-web-compatibility/v1",
                    "surface": "application",
                    "source_sha": REVISION,
                }
            ),
            encoding="utf-8",
        )
        return source

    def prepare(self, source, output):
        return pages.prepare(
            source,
            output,
            console="https://console.example.com",
            api="https://api.example.com",
            revision=REVISION,
        )

    def test_static_package_preserves_entries_and_restricts_api_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            output = root / "pages"
            report = self.prepare(source, output)
            self.assertEqual(b"\0asm", (output / "assets/identity.wasm").read_bytes())
            self.assertEqual(
                "console shell", (output / "console/index.html").read_text()
            )
            headers = (output / "_headers").read_text()
            self.assertIn("form-action 'self' https://api.example.com", headers)
            self.assertIn("connect-src 'self' https://api.example.com", headers)
            self.assertIn("'wasm-unsafe-eval'", headers)
            self.assertNotIn("'unsafe-eval'", headers)
            self.assertNotIn("Access-Control-Allow-Origin", headers)
            self.assertIn("Cache-Control: no-store", headers)
            redirects = (output / "_redirects").read_text()
            self.assertIn("/console/* /console/index.html 200", redirects)
            self.assertIn("/auth/callback/ /index.html 200", redirects)
            self.assertNotIn("\n/* ", redirects)
            self.assertNotIn("/v1/", redirects)
            self.assertNotIn("/assets/", redirects)
            self.assertTrue((output / "404.html").is_file())
            self.assertFalse(report["published"])
            self.assertFalse(report["compiled_api_origin_verified"])
            self.assertFalse(report["provider_journey_verified"])
            self.assertIn("_headers", report["files"])
            self.assertFalse((source / "_headers").exists())
            with self.assertRaises(ValueError):
                self.prepare(source, output)

    def test_origins_cannot_inject_headers_or_select_urls_paths_or_credentials(self):
        for value in (
            "https://api.example.com/",
            "http://api.example.com",
            "https://user@api.example.com",
            "https://api.example.com:443",
            "https://api.example.com?x",
            "https://api.example.com#x",
            "https://api.example.com\nX-Evil: yes",
            "https://*.example.com",
            "https://localhost",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                pages.origin(value)

    def test_wrong_build_and_existing_edge_overrides_are_rejected_before_copy(self):
        for mutation in ("revision", "worker", "headers", "entry"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                source = self.fixture(root)
                if mutation == "revision":
                    marker = source / "marty-web-routes.json"
                    marker.write_text(marker.read_text().replace(REVISION, "b" * 40))
                elif mutation == "entry":
                    (source / "console/index.html").unlink()
                else:
                    (
                        source / ("_worker.js" if mutation == "worker" else "_headers")
                    ).write_text("override")
                with self.assertRaises(ValueError):
                    self.prepare(source, root / "pages")
                self.assertFalse((root / "pages").exists())

    def test_nested_output_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = self.fixture(Path(temporary))
            with self.assertRaises(ValueError):
                self.prepare(source, source / "pages")


if __name__ == "__main__":
    unittest.main()
