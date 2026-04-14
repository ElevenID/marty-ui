#!/usr/bin/env python3

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ASSET_PATHS = [
    Path("docker-compose.selfhost.prod.yml"),
    Path("docker-compose.selfhost.bundle.override.yml"),
    Path(".env.selfhost.production.example"),
    Path("SELFHOST_BUNDLE.md"),
    Path("docker/init-databases.sh"),
    Path("docker/nginx-selfhost.prod.conf.template"),
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

    for relative_path in ASSET_PATHS:
        copy_asset(repo_root, output_dir, relative_path)

    bundle_readme = output_dir / "SELFHOST_BUNDLE.md"
    bundle_readme.replace(output_dir / "README.md")


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