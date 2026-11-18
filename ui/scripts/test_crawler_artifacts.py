import tempfile
import unittest
from pathlib import Path

from check_crawler_artifacts import CANONICAL_ORIGIN, validate


def sitemap(*paths: str) -> str:
    entries = "".join(
        f"<url><loc>{CANONICAL_ORIGIN}{path}</loc></url>" for path in paths
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{entries}</urlset>"
    )


class CrawlerArtifactContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".marty-crawler-artifacts-", dir=Path.cwd()
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "robots.txt").write_text(
            "User-agent: *\n"
            "Disallow: /console\n"
            "Disallow: /auth/*\n"
            "Disallow: /api/*\n"
            "Disallow: /v1/*\n"
            f"Sitemap: {CANONICAL_ORIGIN}/sitemap.xml\n",
            encoding="utf-8",
        )
        (self.root / "sitemap.xml").write_text(
            sitemap("/", "/product", "/docs"), encoding="utf-8"
        )

    def test_accepts_unique_canonical_public_artifacts(self) -> None:
        self.assertEqual(validate(self.root), (1, 3))

    def test_rejects_duplicate_root(self) -> None:
        (self.root / "sitemap.xml").write_text(
            sitemap("/", "/", "/product", "/docs"), encoding="utf-8"
        )
        with self.assertRaisesRegex(AssertionError, "duplicate sitemap location"):
            validate(self.root)

    def test_rejects_private_and_wrong_host_urls(self) -> None:
        for invalid in ("/console", "https://beta.elevenidllc.com/docs"):
            with self.subTest(invalid=invalid):
                value = (
                    invalid
                    if invalid.startswith("https://")
                    else f"{CANONICAL_ORIGIN}{invalid}"
                )
                (self.root / "sitemap.xml").write_text(
                    sitemap("/", "/product", "/docs").replace(
                        f"{CANONICAL_ORIGIN}/docs", value
                    ),
                    encoding="utf-8",
                )
                with self.assertRaises(AssertionError):
                    validate(self.root)

    def test_rejects_malformed_or_empty_artifacts(self) -> None:
        for content in ("", "<urlset>"):
            with self.subTest(content=content):
                (self.root / "sitemap.xml").write_text(content, encoding="utf-8")
                with self.assertRaises(AssertionError):
                    validate(self.root)

    def test_rejects_missing_robots_sitemap_link(self) -> None:
        (self.root / "robots.txt").write_text("User-agent: *\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "must contain exactly"):
            validate(self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
