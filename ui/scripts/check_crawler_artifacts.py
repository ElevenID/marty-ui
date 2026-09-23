"""Validate the crawler artifacts emitted by a public UI build.

Usage: python scripts/check_crawler_artifacts.py [dist-directory] [URL-output-file]
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree

CANONICAL_ORIGIN = "https://elevenidllc.com"
SITEMAP_NAMESPACE = "http://www.sitemaps.org/schemas/sitemap/0.9"
PRIVATE_PREFIXES = (
    "/console",
    "/applicant",
    "/admin",
    "/vendor",
    "/dashboard",
    "/test-harness",
    "/login",
    "/auth",
    "/api",
    "/v1",
)


def _require_nonempty(path: Path) -> bytes:
    if not path.is_file():
        raise AssertionError(f"required crawler artifact is missing: {path}")
    content = path.read_bytes()
    if not content.strip():
        raise AssertionError(f"crawler artifact is empty: {path}")
    return content


def _canonical_url(raw_url: str, *, artifact: Path) -> tuple[str, str]:
    parsed = urlsplit(raw_url)
    if parsed.scheme != "https" or parsed.netloc != "elevenidllc.com":
        raise AssertionError(
            f"{artifact.name} contains a noncanonical URL: {raw_url!r}"
        )
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise AssertionError(
            f"{artifact.name} contains a URL with forbidden components: {raw_url!r}"
        )
    if parsed.path != "/" and parsed.path.endswith("/"):
        raise AssertionError(
            f"{artifact.name} contains a noncanonical trailing slash: {raw_url!r}"
        )
    return parsed.path, raw_url


def _is_private(path: str) -> bool:
    return any(
        path == prefix or path.startswith(f"{prefix}/")
        for prefix in PRIVATE_PREFIXES
    )


def validate(dist_root: Path, url_output: Path | None = None) -> tuple[int, int]:
    dist_root = dist_root.resolve()
    robots_path = dist_root / "robots.txt"
    robots = _require_nonempty(robots_path).decode("utf-8")
    sitemap_lines = [
        line.strip()
        for line in robots.splitlines()
        if line.lower().startswith("sitemap:")
    ]
    expected_sitemap_line = f"Sitemap: {CANONICAL_ORIGIN}/sitemap.xml"
    if sitemap_lines != [expected_sitemap_line]:
        raise AssertionError(
            f"robots.txt must contain exactly {expected_sitemap_line!r}; "
            f"got {sitemap_lines!r}"
        )

    required_disallows = {"/console", "/auth/*", "/api/*", "/v1/*"}
    actual_disallows = {
        line.split(":", 1)[1].strip()
        for line in robots.splitlines()
        if line.lower().startswith("disallow:")
    }
    missing_disallows = sorted(required_disallows - actual_disallows)
    if missing_disallows:
        raise AssertionError(
            f"robots.txt is missing private crawl rules: {missing_disallows}"
        )

    sitemap_paths = sorted(dist_root.glob("sitemap*.xml"))
    root_sitemap = dist_root / "sitemap.xml"
    if root_sitemap not in sitemap_paths:
        raise AssertionError(f"required crawler artifact is missing: {root_sitemap}")

    public_urls: dict[str, Path] = {}
    sitemap_references: dict[str, Path] = {}
    for sitemap_path in sitemap_paths:
        document = _require_nonempty(sitemap_path)
        try:
            root = ElementTree.fromstring(document)
        except ElementTree.ParseError as error:
            raise AssertionError(f"invalid XML in {sitemap_path}: {error}") from error

        urlset_tag = f"{{{SITEMAP_NAMESPACE}}}urlset"
        sitemapindex_tag = f"{{{SITEMAP_NAMESPACE}}}sitemapindex"
        loc_tag = f"{{{SITEMAP_NAMESPACE}}}loc"
        if root.tag not in {urlset_tag, sitemapindex_tag}:
            raise AssertionError(
                f"{sitemap_path.name} has unsupported root element {root.tag!r}"
            )

        locations = [
            element.text.strip()
            for element in root.iter(loc_tag)
            if element.text and element.text.strip()
        ]
        if not locations:
            raise AssertionError(f"{sitemap_path.name} contains no locations")

        target = sitemap_references if root.tag == sitemapindex_tag else public_urls
        for location in locations:
            path, canonical = _canonical_url(location, artifact=sitemap_path)
            if root.tag == urlset_tag and _is_private(path):
                raise AssertionError(
                    f"{sitemap_path.name} exposes private URL {canonical!r}"
                )
            identity = path if root.tag == urlset_tag else canonical
            if identity in target:
                raise AssertionError(
                    f"duplicate sitemap location {canonical!r} in "
                    f"{target[identity].name} and {sitemap_path.name}"
                )
            target[identity] = sitemap_path

    for reference in sitemap_references:
        referenced_name = urlsplit(reference).path.removeprefix("/")
        if referenced_name not in {path.name for path in sitemap_paths}:
            raise AssertionError(
                f"sitemap index references missing artifact {reference!r}"
            )

    for required_path in ("/", "/product", "/docs"):
        if required_path not in public_urls:
            raise AssertionError(
                f"sitemap does not contain required public URL {required_path!r}"
            )

    if url_output is not None:
        url_output.write_text(
            "".join(f"{path}\n" for path in sorted(public_urls)), encoding="utf-8"
        )

    return len(sitemap_paths), len(public_urls)


def main() -> int:
    dist_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dist")
    url_output = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    sitemap_count, url_count = validate(dist_root, url_output)
    print(
        f"Validated {sitemap_count} nonempty sitemap artifact(s), {url_count} unique "
        f"canonical public URL(s), and robots.txt in {dist_root.resolve()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
