from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "scripts" / "package-selfhost-bundle.py"
SPEC = importlib.util.spec_from_file_location("package_selfhost_bundle", MODULE_PATH)
package_selfhost_bundle = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(package_selfhost_bundle)


def test_validate_customer_output_allows_immutable_tag_placeholder(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  gateway:\n"
        "    image: ${SELFHOST_IMAGE_PREFIX:-ghcr.io/elevenid/marty-ui}/services:${SELFHOST_IMAGE_TAG:?set immutable tag}\n",
        encoding="utf-8",
    )
    (tmp_path / ".env.selfhost.production.example").write_text(
        "SELFHOST_IMAGE_TAG=REPLACE_WITH_RELEASE_TAG\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text(
        "Do not use latest, prod, main, or dev tags for customer releases.\n",
        encoding="utf-8",
    )

    package_selfhost_bundle.validate_customer_output(tmp_path)


def test_validate_customer_output_rejects_build_keys(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  gateway:\n"
        "    build: .\n"
        "    image: ghcr.io/elevenid/marty-ui/services:2026.05.0\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="contains build keys"):
        package_selfhost_bundle.validate_customer_output(tmp_path)


def test_validate_customer_output_rejects_mutable_image_tags(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  gateway:\n"
        "    image: ghcr.io/elevenid/marty-ui/services:latest\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="contains mutable image tags"):
        package_selfhost_bundle.validate_customer_output(tmp_path)


def test_validate_customer_output_rejects_mutable_tag_assignment(tmp_path):
    (tmp_path / ".env.selfhost.production.example").write_text(
        "SELFHOST_IMAGE_TAG=prod\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="contains mutable image tags"):
        package_selfhost_bundle.validate_customer_output(tmp_path)


def test_remove_source_compose_inputs_keeps_final_compose(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    for relative_path in package_selfhost_bundle.SOURCE_COMPOSE_INPUTS:
        (tmp_path / relative_path).write_text("services: {}\n", encoding="utf-8")

    package_selfhost_bundle.remove_source_compose_inputs(tmp_path)

    assert (tmp_path / "docker-compose.yml").exists()
    assert all(not (tmp_path / relative_path).exists() for relative_path in package_selfhost_bundle.SOURCE_COMPOSE_INPUTS)
