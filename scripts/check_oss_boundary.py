#!/usr/bin/env python3
"""Fail when private commerce implementation leaks into the OSS repository."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


SOURCE_ROOTS = (
    ".github",
    "deploy-config",
    "docker",
    "k8s",
    "packages",
    "scripts",
    "services",
    "ui/src",
    "ui/public",
)
ROOT_FILES = (
    ".env.example",
    ".env.production.example",
    ".env.selfhost.production.example",
    "docker-compose.base.yml",
    "docker-compose.profile.ghcr.yml",
    "docker-compose.profile.local-build.yml",
    "docker-compose.selfhost.bundle.override.yml",
    "docker-compose.selfhost.prod.yml",
    "ui/package.json",
    "ui/package-lock.json",
    "ui/bun.lock",
)
FORBIDDEN_PATHS = (
    "services/billing",
    "packages/marty_common/billing_engine.py",
    "packages/marty_common/billing_middleware.py",
    "packages/marty_common/cedar/billing.cedarschema",
    "packages/marty_common/cedar/billing_policies.cedar",
    "packages/marty_common/licensing.py",
    "packages/marty_common/license_gate.py",
    "packages/marty_common/license_issuer.py",
    "packages/marty_common/plans.py",
    "packages/marty_common/plan_catalog.json",
    "services/gateway/plan_middleware.py",
    "scripts/install-selfhost-license.py",
)
FORBIDDEN_TEXT = (
    "@marty/subscriptions",
    "ElevenID/marty-subscriptions",
    "COMMERCE_REPOSITORY",
    "MARTY_SUBSCRIPTIONS_REF",
    "SQUARE_ACCESS_TOKEN",
    "SQUARE_WEBHOOK_SIGNATURE_KEY",
    "connect.squareup.com",
    "/v1/billing",
    "/v1/plans",
    "/v1/usage",
    "MARTY_LICENSE_ENFORCEMENT",
    "LICENSE_KEY_FILE",
    "commercial_offer",
    "selfhost-commercial",
    "pypi.pkg.github.com",
)
# These complete, exact statements only bind public release metadata to its
# private producer identity. Each is admitted once at its reviewed path. Do not
# exempt the whole file or the repository marker: new fetches, imports, aliases,
# dependencies, endpoints and payment credentials must still be rejected.
METADATA_IDENTITY_LINES = {
    "docker/ui.Dockerfile": (
        '      bun -e \'const p="dist-final/marty-ui-release.json"; '
        'const m=await Bun.file(p).json(); m.production_pages="full"; '
        'm.commerce_extension={repository:"ElevenID/marty-subscriptions",'
        'source_sha:process.env.MARTY_COMMERCE_SOURCE_SHA}; '
        'await Bun.write(p,JSON.stringify(m)+"\\n");\'; \\',
    ),
    "scripts/ui_release.py": (
        'COMMERCE_REPOSITORY = "ElevenID/marty-subscriptions"',
        '    return {"repository": COMMERCE_REPOSITORY, "source_sha": source_sha}',
        '        producer.update(repository=COMMERCE_REPOSITORY, source_sha=commerce_source_sha)',
    ),
    "scripts/website_release.py": (
        'REPOSITORIES = {ui.REPOSITORY: "1140864197", ui.COMMERCE_REPOSITORY: "1207411806"}',
        '    return {"repository": ui.COMMERCE_REPOSITORY if extension else ui.REPOSITORY,',
        '        legacy_p.update(repository=ui.COMMERCE_REPOSITORY, source_sha=private_sha)',
    ),
    "scripts/website_provenance.py": (
        '    ui.require(producer["repository"] == (ui.COMMERCE_REPOSITORY if private_image else ui.REPOSITORY),',
    ),
}
IGNORED_PARTS = {"__pycache__", "node_modules", "dist", "build", "artifacts"}
COMMERCIAL_CATALOG_KEYS = {
    "addons",
    "annual_price",
    "billing",
    "billing_intervals",
    "monthly_price",
    "onboarding_skus",
    "payment_methods",
    "price_annual",
    "starting_annual_price",
}


def _nested_keys(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _nested_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _nested_keys(nested)


def _candidate_files(root: Path):
    for relative in ROOT_FILES:
        path = root / relative
        if path.is_file():
            yield path
    for relative in SOURCE_ROOTS:
        source = root / relative
        if not source.exists():
            continue
        for path in source.rglob("*"):
            if not path.is_file() or IGNORED_PARTS.intersection(path.parts):
                continue
            if path == root / "scripts/check_oss_boundary.py":
                continue
            yield path


def _without_metadata_identity(relative: str, content: str) -> str:
    allowed = list(METADATA_IDENTITY_LINES.get(relative, ()))
    remaining = []
    for line in content.splitlines(keepends=True):
        statement = line.rstrip("\r\n")
        if statement in allowed:
            allowed.remove(statement)
        else:
            remaining.append(line)
    return "".join(remaining)


def scan_repository(root: Path) -> list[str]:
    root = root.resolve()
    findings: list[str] = []

    for relative in FORBIDDEN_PATHS:
        path = root / relative
        contains_source = path.is_file() or (
            path.is_dir()
            and any(
                candidate.is_file() and not IGNORED_PARTS.intersection(candidate.parts)
                for candidate in path.rglob("*")
            )
        )
        if contains_source:
            findings.append(f"forbidden path: {relative}")

    for path in _candidate_files(root):
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        relative = path.relative_to(root).as_posix()
        content = _without_metadata_identity(relative, content)
        for marker in FORBIDDEN_TEXT:
            if marker in content:
                findings.append(f"forbidden marker {marker!r}: {relative}")

    catalog_path = root / "packages/marty_common/plan_catalog.json"
    if catalog_path.is_file():
        try:
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(f"invalid public capability catalog: {exc}")
        else:
            leaked_keys = sorted(COMMERCIAL_CATALOG_KEYS.intersection(_nested_keys(catalog)))
            for key in leaked_keys:
                findings.append(f"commercial catalog key {key!r}: packages/marty_common/plan_catalog.json")

    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    findings = scan_repository(args.repo_root)
    if findings:
        print("OSS commerce boundary check failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1

    print("OSS commerce boundary check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
