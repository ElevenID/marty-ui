#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_BUNDLE_MANIFEST = Path("deploy-config/bundles/selfhost.json")

ASSET_PATHS = [
    Path("docker-compose.selfhost.prod.yml"),
    Path("docker-compose.selfhost.bundle.override.yml"),
    Path(".env.selfhost.production.example"),
    Path("SELFHOST_BUNDLE.md"),
    Path("docker/init-databases.sh"),
    Path("docker/nginx-selfhost.prod.conf.template"),
    Path("docker/tunnel-nginx-proxy.edge.conf"),
    Path("docker/openbao-init.sh"),
    Path("docker/secrets/selfhost.example"),
    Path("config/keycloak"),
    Path("scripts/bootstrap-selfhost-vault.sh"),
    Path("scripts/cloudflared-selfhost.sh"),
    Path("scripts/keycloak-selfhost-start.sh"),
    Path("scripts/load-openbao-token-and-start.sh"),
    Path("scripts/load-secrets-env.sh"),
    Path("scripts/nginx-entrypoint-selfhost.sh"),
    Path("scripts/setup-keycloak-selfhost-production.sh"),
    Path("scripts/setup-keycloak.sh"),
]

EXECUTABLE_SUFFIXES = {".sh"}
SOURCE_COMPOSE_INPUTS = {
    Path("docker-compose.selfhost.prod.yml"),
    Path("docker-compose.selfhost.bundle.override.yml"),
}
FORBIDDEN_MUTABLE_TAGS = {"latest", "prod", "main", "dev"}
IMAGE_LINE_PATTERN = re.compile(r"^\s*image:\s*(?P<value>\S+)")
IMAGE_TAG_ASSIGNMENT_PATTERN = re.compile(r"^\s*(?:SELFHOST_IMAGE_TAG|IMAGE_TAG)=(?P<value>[^#\s]+)")
BUILD_KEY_PATTERN = re.compile(r"^\s*build\s*:")


def load_asset_paths(repo_root: Path, manifest_path: Path = DEFAULT_BUNDLE_MANIFEST) -> list[Path]:
    full_manifest_path = repo_root / manifest_path
    if not full_manifest_path.exists():
        return ASSET_PATHS

    payload = json.loads(full_manifest_path.read_text(encoding="utf-8"))
    assets = payload.get("assets", [])
    if not isinstance(assets, list) or not all(isinstance(item, str) for item in assets):
        raise ValueError(f"Bundle manifest {manifest_path} must define an assets list of strings.")
    return [Path(item) for item in assets]


def copy_asset(repo_root: Path, output_dir: Path, relative_path: Path) -> None:
    source = repo_root / relative_path
    if not source.exists():
        raise FileNotFoundError(f"Bundle asset is missing: {relative_path}")

    destination = output_dir / relative_path
    if source.is_dir():
        shutil.copytree(source, destination)
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    if destination.suffix in EXECUTABLE_SUFFIXES:
        destination.chmod(destination.stat().st_mode | 0o755)


def stage_bundle(repo_root: Path, output_dir: Path) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for relative_path in load_asset_paths(repo_root):
        copy_asset(repo_root, output_dir, relative_path)

    bundle_readme = output_dir / "SELFHOST_BUNDLE.md"
    bundle_readme.replace(output_dir / "README.md")


def remove_source_compose_inputs(output_dir: Path) -> None:
    for relative_path in SOURCE_COMPOSE_INPUTS:
        path = output_dir / relative_path
        if path.exists():
            path.unlink()


def strip_build_blocks(rendered_compose: str) -> str:
    cleaned_lines: list[str] = []
    skipping = False

    for line in rendered_compose.splitlines():
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if skipping:
            if stripped and indent <= 4:
                skipping = False
            else:
                continue

        if line.startswith("    build:"):
            skipping = True
            continue

        cleaned_lines.append(line)

    return "\n".join(cleaned_lines).rstrip() + "\n"


def relativize_bundle_paths(rendered_compose: str, output_dir: Path) -> str:
    output_dir_str = str(output_dir.resolve())
    rewritten_lines: list[str] = []

    for line in rendered_compose.splitlines():
        stripped = line.strip()
        rewritten = line

        for key in ("source:", "file:"):
            prefix = f"{key} "
            if not stripped.startswith(prefix):
                continue

            value = stripped[len(prefix):]
            if not value.startswith(output_dir_str):
                continue

            relative = Path(value).relative_to(output_dir)
            leading = line[: len(line) - len(line.lstrip())]
            rewritten = f"{leading}{prefix}./{relative.as_posix()}"
            break

        rewritten_lines.append(rewritten)

    compose_text = "\n".join(rewritten_lines).rstrip() + "\n"
    return compose_text.replace("file: ./${", "file: ${")


def iter_service_blocks(compose_text: str) -> list[tuple[str, list[str]]]:
    services: list[tuple[str, list[str]]] = []
    in_services = False
    current_name: str | None = None
    current_lines: list[str] = []

    for line in compose_text.splitlines():
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if indent == 0:
            if stripped == "services:":
                in_services = True
                continue
            if in_services:
                break

        if not in_services:
            continue

        if indent == 2 and stripped.endswith(":"):
            if current_name is not None:
                services.append((current_name, current_lines))
            current_name = stripped[:-1]
            current_lines = []
            continue

        if current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        services.append((current_name, current_lines))

    return services


def validate_image_based_compose(compose_text: str) -> None:
    build_lines = [line for line in compose_text.splitlines() if BUILD_KEY_PATTERN.match(line)]
    if build_lines:
        raise RuntimeError(
            "Generated customer compose still contains build blocks; image-based bundles must not require source builds."
        )

    mutable_image_lines = mutable_image_reference_lines(compose_text)
    if mutable_image_lines:
        formatted = "\n".join(f"  - {line}" for line in mutable_image_lines)
        raise RuntimeError(
            "Generated customer compose contains mutable image tags; use immutable release tags only:\n" + formatted
        )

    missing_images = [
        service_name
        for service_name, service_lines in iter_service_blocks(compose_text)
        if not any(line.startswith("    image:") for line in service_lines)
    ]
    if missing_images:
        formatted = ", ".join(sorted(missing_images))
        raise RuntimeError(f"Generated customer compose services missing image declarations: {formatted}")


def image_uses_mutable_tag(image_ref: str) -> bool:
    for tag in FORBIDDEN_MUTABLE_TAGS:
        if image_ref.endswith(f":{tag}") or f":{tag}@" in image_ref:
            return True
        if f":-${tag}" in image_ref or f":?{tag}" in image_ref:
            return True
        if f":{tag}}}" in image_ref:
            return True
    return False


def mutable_image_reference_lines(text: str) -> list[str]:
    mutable_lines: list[str] = []

    for line in text.splitlines():
        image_match = IMAGE_LINE_PATTERN.match(line)
        if image_match and image_uses_mutable_tag(image_match.group("value")):
            mutable_lines.append(line.strip())
            continue

        assignment_match = IMAGE_TAG_ASSIGNMENT_PATTERN.match(line)
        if assignment_match and assignment_match.group("value").strip().lower() in FORBIDDEN_MUTABLE_TAGS:
            mutable_lines.append(line.strip())

    return mutable_lines


def read_text_if_supported(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def validate_customer_output(output_dir: Path) -> None:
    violations: list[str] = []

    for path in sorted(output_dir.rglob("*")):
        if not path.is_file():
            continue

        relative = path.relative_to(output_dir).as_posix()
        text = read_text_if_supported(path)
        if text is None:
            continue

        build_lines = [line.strip() for line in text.splitlines() if BUILD_KEY_PATTERN.match(line)]
        if build_lines:
            violations.append(f"{relative}: contains build keys ({', '.join(build_lines[:3])})")

        mutable_lines = mutable_image_reference_lines(text)
        if mutable_lines:
            violations.append(f"{relative}: contains mutable image tags ({', '.join(mutable_lines[:3])})")

    if violations:
        formatted = "\n".join(f"  - {violation}" for violation in violations)
        raise RuntimeError("Customer bundle validation failed:\n" + formatted)


def render_bundle_compose(output_dir: Path) -> None:
    command = [
        "docker",
        "compose",
        "--env-file",
        ".env.selfhost.production.example",
        "-f",
        "docker-compose.selfhost.prod.yml",
        "-f",
        "docker-compose.selfhost.bundle.override.yml",
        "config",
        "--no-interpolate",
    ]

    try:
        rendered = subprocess.run(
            command,
            cwd=output_dir,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("docker compose is required to render the final self-host bundle compose file") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(exc.stderr.strip() or exc.stdout.strip() or "docker compose config failed") from exc

    compose_text = strip_build_blocks(rendered.stdout)
    compose_text = relativize_bundle_paths(compose_text, output_dir)
    validate_image_based_compose(compose_text)
    (output_dir / "docker-compose.yml").write_text(compose_text, encoding="utf-8", newline="\n")


def build_parser(default_output_dir: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stage the image-based self-host customer bundle.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(default_output_dir),
        help="Directory to stage the bundle into.",
    )
    parser.add_argument(
        "--archive",
        default="",
        help="Optional zip archive path without the .zip suffix.",
    )
    return parser


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    parser = build_parser(repo_root / "dist" / "selfhost-bundle")
    args = parser.parse_args()

    output_dir = Path(args.output_dir).expanduser().resolve()
    stage_bundle(repo_root, output_dir)
    render_bundle_compose(output_dir)
    remove_source_compose_inputs(output_dir)
    validate_customer_output(output_dir)

    print(f"Staged self-host bundle at {output_dir}")

    if args.archive:
        archive_base = Path(args.archive).expanduser().resolve()
        archive_path = shutil.make_archive(
            str(archive_base),
            "zip",
            root_dir=output_dir.parent,
            base_dir=output_dir.name,
        )
        print(f"Created archive {archive_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())