from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import build_selfhost_image_lock as builder  # noqa: E402
import release_transaction as transaction  # noqa: E402

PREFIX = "ghcr.io/elevenid/marty-ui"
EXACT = "ghcr.io/elevenid/marty-ui-oss"


def reference(name: str, character: str) -> str:
    return f"{EXACT}/{name}@sha256:{character * 64}"


def inputs(tmp_path: Path) -> tuple[dict, dict, Path, dict, dict]:
    (tmp_path / "base.yml").write_text(
        "services:\n"
        "  postgres: {image: 'postgres:15-alpine'}\n"
        "  db-migrate: {build: '.'}\n"
        "  gateway: {build: '.'}\n"
        "  issuance-migrations: {build: '.'}\n"
        "  issuance: {build: '.'}\n"
        "  ui: {image: 'nginx:alpine'}\n"
        "  cloudflared: {build: '.'}\n"
        "  cloudflared-beta: {build: '.'}\n", encoding="utf-8")
    (tmp_path / "override.yml").write_text(
        "services:\n"
        f"  db-migrate: {{image: '{PREFIX}/db-migrate:1.2.3'}}\n"
        f"  gateway: {{image: '{PREFIX}/services:1.2.3'}}\n"
        f"  issuance-migrations: {{image: '{PREFIX}/services:1.2.3'}}\n"
        f"  issuance: {{image: '{PREFIX}/services:1.2.3'}}\n"
        f"  ui: {{image: '{PREFIX}/ui-selfhost:1.2.3'}}\n"
        f"  cloudflared: {{image: '{PREFIX}/cloudflared-wrapper:1.2.3'}}\n"
        f"  cloudflared-beta: {{image: '{PREFIX}/cloudflared-wrapper:1.2.3'}}\n",
        encoding="utf-8")
    lock_file = tmp_path / "stack-lock.json"
    lock_file.write_text(json.dumps({
        "schema": "marty.stack-lock/v1", "release": "marty-ui@1.2.3",
        "release_state": "eligible", "components": [],
    }) + "\n", encoding="utf-8")
    if not (tmp_path / ".git").exists():
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "add", "base.yml",
                        "override.yml", "stack-lock.json"], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=CI",
                        "-c", "user.email=ci@example.invalid", "commit", "-qm",
                        "source fixture"], check=True)
    source_sha = subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
                                capture_output=True, check=True, text=True).stdout.strip()
    claim = transaction.create_claim(
        repository="ElevenID/marty-ui", tag="v1.2.3", source_sha=source_sha,
        stack_lock=lock_file, claim_run_id="91", image_uris=transaction.IMAGE_URIS,
        tag_absent=True, release_absent=True,
        version_tags_absent={role: True for role in transaction.REQUIRED_IMAGE_ROLES},
    )
    claim = transaction.record_digests(claim, {
        "ui": "sha256:" + "1" * 64,
        "services": "sha256:" + "2" * 64,
        "migrations": "sha256:" + "3" * 64,
    }, build_run_id="92")
    model = {"services": {
        "postgres": {"image": "postgres:15-alpine"},
        "db-migrate": {"image": f"{PREFIX}/db-migrate:1.2.3"},
        "gateway": {"image": f"{PREFIX}/services:1.2.3"},
        "issuance-migrations": {"image": f"{PREFIX}/services:1.2.3"},
        "issuance": {"image": f"{PREFIX}/services:1.2.3"},
        "ui": {"image": f"{PREFIX}/ui-selfhost:1.2.3"},
        "cloudflared": {"image": f"{PREFIX}/cloudflared-wrapper:1.2.3"},
        "cloudflared-beta": {"image": f"{PREFIX}/cloudflared-wrapper:1.2.3"},
    }}
    selfhost = {
        "ui-selfhost": reference("ui-selfhost", "4"),
        "cloudflared-wrapper": reference("cloudflared-wrapper", "5"),
    }
    external = {
        "postgres": "docker.io/library/postgres@sha256:" + "7" * 64,
    }
    return model, claim, lock_file, selfhost, external


def build(tmp_path: Path, **changes: object) -> dict:
    model, claim, stack_lock, selfhost, external = inputs(tmp_path)
    data = dict(model=model, transaction=claim, stack_lock=stack_lock,
                source_repo=tmp_path,
                base_compose=tmp_path / "base.yml",
                override_compose=tmp_path / "override.yml",
                source_sha=claim["source_sha"], claim_run_id="91", selfhost_images=selfhost,
                external_services=external)
    data.update(changes)
    return builder.build_lock(**data)


def test_deterministic_exact_role_mapping(tmp_path: Path) -> None:
    result = build(tmp_path)
    assert result == build(tmp_path)
    assert result["schema"] == "marty.selfhost-image-lock/v1"
    assert result["release"] == "marty-ui@1.2.3"
    assert result["services"]["gateway"] == reference("services", "2")
    assert result["services"]["issuance"] == result["services"]["issuance-migrations"] == reference("services", "2")
    assert result["services"]["db-migrate"] == reference("migrations", "3")
    assert result["services"]["ui"] == reference("ui-selfhost", "4")
    assert result["services"]["cloudflared"] == result["services"]["cloudflared-beta"]


def test_current_compose_source_ownership_is_closed() -> None:
    root = Path(__file__).parents[1]
    names, roles = builder._ownership(
        root / "docker-compose.selfhost.prod.yml",
        root / "docker-compose.selfhost.bundle.override.yml",
    )
    assert set(roles) | {
        "postgres", "redis", "keycloak", "keycloak-configurator",
        "edge", "tunnel-nginx-proxy",
    } == names
    assert roles["gateway"] == "services"
    assert roles["db-migrate"] == "db-migrate"
    assert roles["ui"] == "ui-selfhost"


@pytest.mark.parametrize("service,image", [
    ("db-migrate", f"{PREFIX}/services:1.2.3"),
    ("ui", f"{PREFIX}/services:1.2.3"),
    ("gateway", f"{PREFIX}/db-migrate:1.2.3"),
    ("gateway", "registry.example/gateway@sha256:" + "9" * 64),
    ("issuance", reference("issuance", "6")),
])
def test_rejects_wrong_role(tmp_path: Path, service: str, image: str) -> None:
    model, *_ = inputs(tmp_path)
    model["services"][service]["image"] = image
    with pytest.raises(builder.ImageLockError, match="role|Marty UI"):
        build(tmp_path, model=model)


def test_rejects_missing_and_extra_services(tmp_path: Path) -> None:
    model, *_ = inputs(tmp_path)
    del model["services"]["db-migrate"]
    with pytest.raises(builder.ImageLockError, match="service set"):
        build(tmp_path, model=model)
    model, *_ = inputs(tmp_path)
    model["services"]["new-infra"] = {"image": "nginx:alpine"}
    with pytest.raises(builder.ImageLockError, match="service set"):
        build(tmp_path, model=model)
    _, _, _, _, external = inputs(tmp_path)
    external["not-a-service"] = reference("unknown", "8")
    with pytest.raises(builder.ImageLockError, match="extra Compose"):
        build(tmp_path, external_services=external)


def test_rejects_mutable_and_wrong_selfhost_image(tmp_path: Path) -> None:
    _, _, _, selfhost, external = inputs(tmp_path)
    selfhost["ui-selfhost"] = f"{EXACT}/ui-selfhost:latest"
    with pytest.raises(builder.ImageLockError, match="exact OCI"):
        build(tmp_path, selfhost_images=selfhost)
    _, _, _, selfhost, _ = inputs(tmp_path)
    selfhost["ui-selfhost"] = reference("ui", "4")
    with pytest.raises(builder.ImageLockError, match="wrong OCI repository"):
        build(tmp_path, selfhost_images=selfhost)
    external["postgres"] = "postgres:15-alpine"
    with pytest.raises(builder.ImageLockError, match="exact OCI"):
        build(tmp_path, external_services=external)
    external["postgres"] = "docker.io/library/redis@sha256:" + "7" * 64
    with pytest.raises(builder.ImageLockError, match="repository differs"):
        build(tmp_path, external_services=external)


def test_rejects_release_and_source_revision_changes(tmp_path: Path) -> None:
    model, claim, stack_lock, selfhost, external = inputs(tmp_path)
    model["services"]["gateway"]["image"] = f"{PREFIX}/services:1.2.4"
    with pytest.raises(builder.ImageLockError, match="version differs"):
        build(tmp_path, model=model)
    with pytest.raises(builder.ImageLockError, match="source SHA changed"):
        build(tmp_path, source_sha="b" * 40)
    with pytest.raises(builder.ImageLockError, match="claim run changed"):
        build(tmp_path, claim_run_id="99")
    altered = deepcopy(claim)
    altered["images"]["services"]["uri"] = f"{EXACT}/wrong"
    with pytest.raises(builder.ImageLockError, match="image URI changed"):
        build(tmp_path, transaction=altered)
    stack_lock.write_text(json.dumps({"schema": "marty.stack-lock/v1",
                                      "release": "marty-ui@9.9.9"}) + "\n",
                          encoding="utf-8")
    with pytest.raises(builder.ImageLockError, match="stack lock digest changed"):
        builder.build_lock(model=model, transaction=claim, stack_lock=stack_lock,
                           source_repo=tmp_path,
                           base_compose=tmp_path / "base.yml",
                           override_compose=tmp_path / "override.yml",
                           source_sha=claim["source_sha"], claim_run_id="91",
                           selfhost_images=selfhost, external_services=external)


def test_rejects_unrecorded_transaction_and_mismatched_issuance(tmp_path: Path) -> None:
    model, claim, _, _, external = inputs(tmp_path)
    claim["state"] = "claimed"
    claim["images"] = {}
    with pytest.raises(builder.ImageLockError, match="no recorded image digests"):
        build(tmp_path, transaction=claim)
    external["issuance-migrations"] = reference("issuance", "8")
    with pytest.raises(builder.ImageLockError, match="extra Compose"):
        build(tmp_path, external_services=external)
    external.pop("issuance-migrations")
    external["issuance"] = reference("issuance", "8")
    with pytest.raises(builder.ImageLockError, match="extra Compose"):
        build(tmp_path, external_services=external)
    model["services"]["gateway"]["build"] = {"context": "."}
    with pytest.raises(builder.ImageLockError, match="image-only"):
        build(tmp_path, model=model)


def test_rejects_source_override_ownership_and_unmapped_build(tmp_path: Path) -> None:
    model, claim, stack_lock, selfhost, external = inputs(tmp_path)
    def build_changed_source() -> dict:
        return builder.build_lock(
            model=model, transaction=claim, stack_lock=stack_lock,
            source_repo=tmp_path,
            base_compose=tmp_path / "base.yml",
            override_compose=tmp_path / "override.yml",
            source_sha=claim["source_sha"], claim_run_id="91",
            selfhost_images=selfhost, external_services=external,
        )
    source = tmp_path / "override.yml"
    source.write_text(source.read_text(encoding="utf-8").replace(
        f"{PREFIX}/services:1.2.3", "registry.example/gateway@sha256:" + "9" * 64
    ), encoding="utf-8")
    with pytest.raises(builder.ImageLockError, match="claimed Git blob: override.yml"):
        build_changed_source()
    model, claim, stack_lock, selfhost, external = inputs(tmp_path)
    source.write_text(source.read_text(encoding="utf-8").replace(
        f"  gateway: {{image: '{PREFIX}/services:1.2.3'}}\n", ""
    ), encoding="utf-8")
    with pytest.raises(builder.ImageLockError, match="claimed Git blob: override.yml"):
        build_changed_source()


def test_tampered_base_and_override_cannot_reclassify_gateway_external(tmp_path: Path) -> None:
    model, claim, stack_lock, selfhost, external = inputs(tmp_path)
    base = tmp_path / "base.yml"
    override = tmp_path / "override.yml"
    base.write_text(base.read_text(encoding="utf-8").replace(
        "  gateway: {build: '.'}\n", "  gateway: {image: 'registry.example/gateway:1.2.3'}\n"
    ), encoding="utf-8")
    override.write_text(override.read_text(encoding="utf-8").replace(
        f"  gateway: {{image: '{PREFIX}/services:1.2.3'}}\n", ""
    ), encoding="utf-8")
    model["services"]["gateway"]["image"] = "registry.example/gateway:1.2.3"
    external["gateway"] = "registry.example/gateway@sha256:" + "9" * 64
    with pytest.raises(builder.ImageLockError, match="mandatory shared gateway"):
        builder._ownership(base, override)
    with pytest.raises(builder.ImageLockError, match="claimed Git blob"):
        builder.build_lock(
            model=model, transaction=claim, stack_lock=stack_lock,
            source_repo=tmp_path, base_compose=base, override_compose=override,
            source_sha=claim["source_sha"], claim_run_id="91",
            selfhost_images=selfhost, external_services=external,
        )
