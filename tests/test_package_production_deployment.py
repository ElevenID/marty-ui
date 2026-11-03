"""Offline package identity and real Compose merge tests; no runtime qualification."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import installer_release as installer
import package_production_deployment as production
import stable_installer_assets as stable
import ui_release as ui

SOURCE = "a" * 40


@pytest.fixture
def candidate(tmp_path):
    source = tmp_path / "source"
    for name in ("release/stack-lock.json", "docker/ui.Dockerfile"):
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    plan = ui.production_plan(source, SOURCE)
    version = plan["version"]
    metadata = {"component": "ui", "release_version": version, "marty_ui_sha": SOURCE,
                "audience": "production", "ui_variant": "public"}
    website = ui.production_release(source, plan, source_sha=SOURCE, image_digest="sha256:" + "d" * 64,
                                    run_id="125", run_attempt="1", metadata=metadata)
    manifest = tmp_path / "website.json"
    manifest.write_bytes(ui.canonical(website))
    assets = tmp_path / "assets"
    assets.mkdir()
    lock = {"schema": "marty.selfhost-image-lock/v1", "release": "marty-ui@" + version,
            "services": {name: "ghcr.io/elevenid/" + name + "@sha256:" + "b" * 64 for name in ("ui", "gateway")},
            "openbao_didcomm_image": "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "c" * 64}
    lock_bytes = ui.canonical(lock)
    model = {"services": {name: {"image": image} for name, image in lock["services"].items()}}
    model["services"]["ui"].update(environment={"ORGANIZATION_CREATION_ENABLED": "true"},
                                   healthcheck={"test": ["CMD", "wget", "http://127.0.0.1:80/healthz"]})
    bao = {"services": {name: {"image": lock["openbao_didcomm_image"]}
                        for name in ("openbao", "openbao-tls-init", "openbao-unseal", "openbao-bootstrap")}}
    contents = {".marty-selfhost-images.json": lock_bytes,
                "docker-compose.yml": yaml.safe_dump(model).encode(),
                "docker-compose.selfhost.openbao.yml": yaml.safe_dump(bao).encode()}
    marker = {"schema": "marty.selfhost-bundle-files/v1", "directories": [""],
              "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()}}
    with zipfile.ZipFile(assets / "prepared-selfhost-bundle.zip", "w") as archive:
        archive.writestr("bundle/", b"")
        for name, raw in contents.items():
            archive.writestr("bundle/" + name, raw)
        archive.writestr("bundle/.marty-selfhost-bundle.json", ui.canonical(marker))
    (assets / "prepared-selfhost-images.json").write_bytes(lock_bytes)
    for name in ("install.sh", "marty-deploy-linux-amd64"):
        (assets / name).write_bytes(b"test payload; never executed")
    inventory = installer.inventory(assets, source_sha=SOURCE, release_tag="v" + version,
        build_run_id=123, build_run_attempt=2, expected_services=set(lock["services"]))
    (assets / "installer-inventory.json").write_bytes(installer.encode(inventory))
    for name in stable.SUBJECTS:
        (assets / (name + ".provenance.jsonl")).write_bytes(b"fixture proof; crypto is tested by stable owner")
    return source, manifest, assets, "v" + version, lock, model


def test_package_preserves_backend_assets_and_only_selects_production_ui(candidate, tmp_path):
    source, website, assets, tag, lock, _ = candidate
    result = production.package(source, website, assets, source_sha=SOURCE, tag=tag, output=tmp_path / "output")
    assert result["openbao_didcomm_image"] == lock["openbao_didcomm_image"]
    assert result["images"]["gateway"] == lock["services"]["gateway"]
    assert result["images"]["ui"].startswith(ui.PUBLIC_IMAGE + "@sha256:")
    assert result["qualification"] == {"runtime_tested": False, "billing_journey_tested": False}
    with zipfile.ZipFile(tmp_path / "output/production-openbao.zip") as archive:
        for name in stable.SUBJECTS:
            assert archive.read("production-openbao/backend/" + name) == (assets / name).read_bytes()
        assert archive.getinfo("production-openbao/backend/install.sh").external_attr >> 16 & 0o777 == 0o755
    with pytest.raises(ValueError, match="already exists"):
        production.package(source, website, assets, source_sha=SOURCE, tag=tag, output=tmp_path / "output")


@pytest.mark.parametrize("fault", ["source", "version", "audience", "backend-bytes"])
def test_package_refuses_mismatched_release_without_output(candidate, tmp_path, fault):
    source, website, assets, tag, _, _ = candidate
    kwargs = dict(source_sha=SOURCE, tag=tag, output=tmp_path / "output")
    if fault == "source":
        kwargs["source_sha"] = "f" * 40
    elif fault == "version":
        kwargs["tag"] = "v9.9.9"
    elif fault == "audience":
        value = ui.read(website)
        value["image_metadata"]["audience"] = "customer"
        website.write_bytes(ui.canonical(value))
    else:
        (assets / "install.sh").write_bytes(b"changed")
    with pytest.raises(ValueError):
        production.package(source, website, assets, **kwargs)
    assert not kwargs["output"].exists()


def test_real_compose_overlay_changes_only_ui_image_health_and_mounts(candidate, tmp_path):
    _, _, _, _, _, model = candidate
    before = copy.deepcopy(model)
    base, overlay = tmp_path / "base.yml", tmp_path / "public.yml"
    base.write_text(yaml.safe_dump(model))
    image = ui.PUBLIC_IMAGE + "@sha256:" + "e" * 64
    overlay.write_bytes(production.compose_override(image))
    executable = os.environ.get("MARTY_INSTALLER_COMPOSE_EXECUTABLE")
    command = [executable] if executable else ["docker", "compose"]
    def render(files):
        arguments = [arg for file in files for arg in ("-f", str(file))]
        return json.loads(subprocess.run(command + ["--project-name", "production-test"] + arguments
                          + ["config", "--format", "json"], check=True, capture_output=True, text=True).stdout)
    original, current = render([base]), render([base, overlay])
    expected = copy.deepcopy(original)
    expected["services"]["ui"]["image"] = image
    expected["services"]["ui"]["healthcheck"]["test"] = [
        "CMD", "wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1:80/"]
    assert current == expected
    assert model == before
