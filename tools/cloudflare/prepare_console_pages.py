"""Package an already-built application for static Pages; never publish it."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit


PUBLIC_ROUTES = (
    "/login",
    "/auth/callback",
    "/verify",
    "/apply",
    "/apply/*",
    "/docs",
    "/docs/*",
    "/organizations",
    "/organizations/*",
    "/console-handoff/*",
    "/invite/accept",
    "/credentials",
    "/catalog",
    "/my-applications",
    "/my-documents",
    "/wallet/setup",
    "/settings/notifications",
    "/applicant/preview",
    "/applicant/preview/*",
)


def origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", parsed.hostname)
        or parsed.hostname in {"localhost", "127.0.0.1"}
        or value != f"https://{parsed.hostname}"
    ):
        raise ValueError("Expected a canonical HTTPS DNS origin without a port or path")
    labels = parsed.hostname.split(".")
    if len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Expected a canonical HTTPS DNS origin")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return value
    raise ValueError("A DNS name is required for the Pages origin")


def ordinary_path(path: Path) -> Path:
    lexical = path.absolute()
    for component in (lexical, *lexical.parents):
        if component.is_symlink() or getattr(component, "is_junction", lambda: False)():
            raise ValueError(
                "Pages paths must not use links or junctions in their ancestry"
            )
    return lexical.resolve()


def prepare(
    source: Path,
    output: Path,
    *,
    console: str,
    api: str,
    revision: str,
    provider: str | None = None,
) -> dict:
    console, api = origin(console), origin(api)
    provider = origin(provider) if provider is not None else None
    if console == api:
        raise ValueError("Pages console and API must use separate origins")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("An exact source revision is required")
    if source.is_symlink() or not source.is_dir():
        raise ValueError("Application output must be an ordinary directory")
    source, output = ordinary_path(source), ordinary_path(output)
    if output.exists() or output.is_symlink() or output.is_relative_to(source):
        raise ValueError(
            "Pages output must be a new directory outside application output"
        )
    marker = json.loads((source / "marty-web-routes.json").read_text(encoding="utf-8"))
    if (
        marker.get("schema") != "marty.application-web-compatibility/v1"
        or marker.get("surface") != "application"
        or marker.get("source_sha") != revision
    ):
        raise ValueError("Application source marker differs from selected revision")
    files = []
    for path in source.rglob("*"):
        if (
            path.is_symlink()
            or getattr(path, "is_junction", lambda: False)()
            or not (path.is_file() or path.is_dir())
        ):
            raise ValueError("Application output contains a link or special file")
        relative = path.relative_to(source).as_posix()
        if relative.split("/", 1)[0].casefold() in {
            "_headers",
            "_redirects",
            "_worker.js",
            "functions",
            "404.html",
            "pages-deployment.json",
        }:
            raise ValueError(
                "Application output already contains a Pages deployment override"
            )
        if path.is_file():
            files.append((path, relative))
    for required in ("index.html", "console/index.html"):
        if not (source / required).is_file():
            raise ValueError(
                "Application output is missing a public or console entrypoint"
            )
    output.mkdir(parents=True, exist_ok=False)
    for path, relative in files:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    csp = "; ".join(
        (
            "default-src 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "frame-ancestors 'none'",
            "script-src 'self' 'wasm-unsafe-eval' https://cdn.redoc.ly https://cdn.jsdelivr.net https://static.cloudflareinsights.com https://www.googletagmanager.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data: blob: https://www.googletagmanager.com https://www.google-analytics.com https://region1.google-analytics.com",
            f"connect-src 'self' {api} https://cloudflareinsights.com https://www.googletagmanager.com https://www.google-analytics.com https://region1.google-analytics.com https://analytics.google.com https://region1.analytics.google.com",
            "form-action 'self' "
            + " ".join(dict.fromkeys(value for value in (api, provider) if value)),
            "frame-src 'self' https://www.youtube-nocookie.com",
        )
    )
    (output / "_headers").write_text(
        f"/*\n  Content-Security-Policy: {csp}\n  X-Content-Type-Options: nosniff\n"
        "  X-Frame-Options: DENY\n  Referrer-Policy: strict-origin-when-cross-origin\n"
        "  Cache-Control: no-store\n  Cloudflare-CDN-Cache-Control: no-store\n  X-Robots-Tag: noindex\n",
        encoding="utf-8",
        newline="\n",
    )
    # A custom 404 disables Pages' implicit global SPA fallback. Keep missing
    # API/assets/locales as real 404s; only declared browser routes get a shell.
    (output / "404.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Not found</title>'
        "<h1>Page not found</h1><p>Check the address and try again.</p></html>\n",
        encoding="utf-8",
    )
    redirects = [
        "/console /console/index.html 200",
        "/console/* /console/index.html 200",
    ]
    for route in PUBLIC_ROUTES:
        redirects.append(f"{route} /index.html 200")
        if not route.endswith("*"):
            redirects.append(f"{route}/ /index.html 200")
    (output / "_redirects").write_text(
        "\n".join(redirects) + "\n", encoding="utf-8", newline="\n"
    )
    report = {
        "schema": "elevenid.console-pages-preparation/v1",
        "source_revision": revision,
        "console_origin": console,
        "api_origin": api,
        "auth_provider_origin": provider,
        "published": False,
        "compiled_api_origin_verified": False,
        "provider_journey_verified": False,
        "files": {
            path.relative_to(output).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(output.rglob("*"))
            if path.is_file()
        },
    }
    (output / "pages-deployment.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--console-origin", required=True)
    parser.add_argument("--api-origin", required=True)
    parser.add_argument("--auth-provider-origin")
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    prepare(
        args.source,
        args.output,
        console=args.console_origin,
        api=args.api_origin,
        provider=args.auth_provider_origin,
        revision=args.source_revision,
    )
    print(
        "Prepared static Pages directory; publication and browser acceptance remain required."
    )


if __name__ == "__main__":
    main()
