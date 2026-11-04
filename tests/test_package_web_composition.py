"""Signed composition preserves original releases and requires a qualified cutover."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import zipfile

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import installer_release as installer
import package_web_composition as composition
import stable_installer_assets as stable
import ui_release as ui
import website_provenance as proof
import website_release as web

SOURCE, WEBSITE_SOURCE = "a" * 40, "b" * 40
PRIVATE = "c" * 40
IMAGE_DIGEST = "sha256:" + "d" * 64


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_bytes(ui.canonical(value))


def fake_crypto(monkeypatch):
    calls = []
    def subject(path, **kwargs):
        calls.append(("subject", path.name, kwargs["producer"]))
        for suffix in ("", ".provenance.jsonl", ".sigstore.json"):
            proof.verifier.local_file(path.with_name(path.name + suffix), private=True)
    def image(value, path, **kwargs):
        calls.append(("image", value["uri"], kwargs["producer"]))
        proof.verifier.local_file(path, private=True)
    def backend(path, *, source_sha, tag, gh):
        inventory = stable.read_inventory(path)
        stable.verify_inputs(path, source_sha=source_sha, tag=tag,
                             run_id=inventory["build_run_id"], run_attempt=inventory["build_run_attempt"])
        calls.append(("backend", source_sha, tag))
    monkeypatch.setattr(proof, "verify_subject", subject)
    monkeypatch.setattr(proof, "verify_image", image)
    monkeypatch.setattr(stable, "verify_published", backend)
    return calls


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    calls = fake_crypto(monkeypatch)
    source = tmp_path / "source"
    for name in ("release/stack-lock.json", "docker/ui.Dockerfile", web.ROUTE_PATH):
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    appdir, webdir, backend = (tmp_path / name for name in ("application", "website", "backend"))
    for directory in (appdir, webdir, backend):
        directory.mkdir(mode=0o700)
    appplan = ui.production_plan(source, SOURCE)
    version = appplan["version"]
    metadata = {"component": "ui", "release_version": version, "marty_ui_sha": SOURCE,
                "audience": "production", "ui_variant": "public"}
    application = ui.production_release(source, appplan, source_sha=SOURCE, image_digest=IMAGE_DIGEST,
                                         run_id="123", run_attempt="1", metadata=metadata)
    write_json(appdir / "production-web-release.json", application)
    compatibility = web.compatibility_record(application, web.application_marker(source, SOURCE),
                                               (appdir / "production-web-release.json").read_bytes())
    write_json(appdir / "application-web-compatibility.json", compatibility)
    webplan = web.plan(source, WEBSITE_SOURCE)
    website = web.record(source, webplan, source_sha=WEBSITE_SOURCE, metadata=web.image_metadata(webplan),
                         digest="sha256:" + "e" * 64, run_id="124", run_attempt="2")
    write_json(webdir / "website-release.json", website)
    (webdir / "web-surface-routes.json").write_bytes((source / web.ROUTE_PATH).read_bytes())
    for directory, files in ((appdir, composition.APPLICATION_FILES), (webdir, composition.WEBSITE_FILES)):
        for name in files:
            if not (directory / name).exists():
                (directory / name).write_bytes(b"proof fixture; original cryptography tested separately")
    lock = {"schema": "marty.selfhost-image-lock/v1", "release": "marty-ui@" + version,
            "services": {name: "ghcr.io/elevenid/" + name + "@sha256:" + "f" * 64 for name in ("ui", "gateway", "edge")},
            "openbao_didcomm_image": "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "1" * 64}
    lock_bytes = ui.canonical(lock)
    model = {"services": {name: {"image": image} for name, image in lock["services"].items()}}
    model["services"]["ui"].update(environment={"ORGANIZATION_CREATION_ENABLED": "true"},
                                    healthcheck={"test": ["CMD", "wget", "http://127.0.0.1:80/healthz"]})
    model["services"]["edge"].update(healthcheck={"test": ["CMD", "wget", "http://127.0.0.1/edge-healthz"]},
                                      ports=["127.0.0.1:19080:80"])
    bao = {"services": {name: {"image": lock["openbao_didcomm_image"]}
                        for name in ("openbao", "openbao-tls-init", "openbao-unseal", "openbao-bootstrap")}}
    contents = {".marty-selfhost-images.json": lock_bytes, "docker-compose.yml": yaml.safe_dump(model).encode(),
                "docker-compose.selfhost.openbao.yml": yaml.safe_dump(bao).encode(),
                "docker/nginx-selfhost.prod.conf.template": (ROOT / "docker/nginx-selfhost.prod.conf.template").read_bytes()}
    marker = {"schema": "marty.selfhost-bundle-files/v1", "directories": ["", "docker"],
              "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()}}
    with zipfile.ZipFile(backend / "prepared-selfhost-bundle.zip", "w") as archive:
        for directory in ("bundle/", "bundle/docker/"):
            archive.writestr(directory, b"")
        for name, raw in contents.items():
            archive.writestr("bundle/" + name, raw)
        archive.writestr("bundle/.marty-selfhost-bundle.json", ui.canonical(marker))
    (backend / "prepared-selfhost-images.json").write_bytes(lock_bytes)
    for name in ("install.sh", "marty-deploy-linux-amd64"):
        (backend / name).write_bytes(b"test payload; never executed")
    inventory = installer.inventory(backend, source_sha=SOURCE, release_tag="v" + version,
                                    build_run_id=121, build_run_attempt=2, expected_services=set(lock["services"]))
    (backend / "installer-inventory.json").write_bytes(installer.encode(inventory))
    for name in stable.SUBJECTS:
        (backend / (name + ".provenance.jsonl")).write_bytes(b"original backend proof fixture")
    kwargs = dict(website_assets=webdir, application_assets=appdir, backend_assets=backend,
                  producer=web.producer("2" * 40, None, "126", "1"), output=tmp_path / "output",
                  gh=tmp_path / "gh", cosign=tmp_path / "cosign")
    return kwargs, calls, lock, model


def test_composition_authenticates_every_owner_and_keeps_original_payloads(candidate):
    kwargs, calls, lock, _ = candidate
    result = composition.package(**kwargs)
    assert result["website"]["source_sha"] == WEBSITE_SOURCE
    assert result["application"]["source_sha"] == result["backend"]["source_sha"] == SOURCE
    assert result["images"]["gateway"] == lock["services"]["gateway"]
    assert result["images"]["ui"] == ui.PUBLIC_IMAGE + "@" + IMAGE_DIGEST
    assert result["openbao_didcomm_image"] == lock["openbao_didcomm_image"]
    assert result["qualification"] == {"runtime_tested": False, "billing_journey_tested": False}
    assert [item[0] for item in calls] == ["subject", "image", "subject", "subject", "image", "backend"]
    with zipfile.ZipFile(kwargs["output"] / "web-composition.zip") as archive:
        for prefix, directory, files in (("backend", kwargs["backend_assets"], composition.BACKEND_FILES),
                                         ("website", kwargs["website_assets"], composition.WEBSITE_FILES),
                                         ("application", kwargs["application_assets"], composition.APPLICATION_FILES)):
            for name in files:
                assert archive.read("web-composition/" + prefix + "/" + name) == (directory / name).read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        composition.package(**kwargs)


@pytest.mark.parametrize("fault", ["missing-compatibility", "wrong-routes", "slim-application", "backend-bytes", "backend-source", "wrong-pages"])
def test_composition_rejects_unqualified_or_incompatible_inputs_before_output(candidate, fault):
    kwargs, _, _, _ = candidate
    appdir = kwargs["application_assets"]
    if fault == "missing-compatibility":
        (appdir / "application-web-compatibility.json").unlink()
    elif fault in {"wrong-routes", "slim-application"}:
        path = appdir / "application-web-compatibility.json"
        value = web.read(path)
        if fault == "wrong-routes":
            value["marker"]["route_contract"]["sha256"] = "sha256:" + "9" * 64
        else:
            value["marker"]["surface"] = "application"
        write_json(path, value)
    elif fault == "backend-bytes":
        (kwargs["backend_assets"] / "install.sh").write_bytes(b"changed")
    elif fault == "backend-source":
        path = kwargs["backend_assets"] / "installer-inventory.json"
        value = web.read(path)
        value["source_sha"] = "9" * 40
        write_json(path, value)
    else:
        path = kwargs["website_assets"] / "website-release.json"
        value = web.read(path)
        value["production_pages"] = "full"
        write_json(path, value)
    with pytest.raises(ValueError):
        composition.package(**kwargs)
    assert not kwargs["output"].exists()


def test_composition_requires_real_provenance_success_before_packaging(candidate, monkeypatch):
    kwargs, _, _, _ = candidate
    def reject(*_args, **_kwargs):
        raise ValueError("original producer signature rejected")
    monkeypatch.setattr(proof, "verify_subject", reject)
    with pytest.raises(ValueError, match="signature rejected"):
        composition.package(**kwargs)
    assert not kwargs["output"].exists()


def test_consumer_rechecks_outer_and_original_evidence(candidate, tmp_path):
    kwargs, calls, _, _ = candidate
    manifest = composition.package(**kwargs)
    for name in ("web-composition.json", "web-composition.zip"):
        for suffix in (".sigstore.json", ".provenance.jsonl"):
            (kwargs["output"] / (name + suffix)).write_bytes(b"composition proof fixture")
    calls.clear()
    with composition.verified_package(kwargs["output"], gh=kwargs["gh"], cosign=kwargs["cosign"]) as (record, payload):
        assert record == manifest
        assert {path.relative_to(payload).as_posix() for path in payload.rglob("*") if path.is_file()} == composition.PAYLOAD_NAMES
        assert [item[1] for item in calls[:2]] == ["web-composition.json", "web-composition.zip"]
        assert calls[-1][0] == "backend"
    assert not payload.exists()


@pytest.mark.parametrize("fault", ["extra", "duplicate", "traversal", "symlink", "changed-bytes", "embedded-manifest"])
def test_archive_extraction_rejects_ambiguous_or_changed_payloads(candidate, tmp_path, fault):
    kwargs, _, _, _ = candidate
    manifest = composition.package(**kwargs)
    path = kwargs["output"] / "web-composition.zip"
    with zipfile.ZipFile(path) as archive:
        entries = [(item, archive.read(item)) for item in archive.infolist()]
    target = "web-composition/website/website-release.json"
    if fault in {"extra", "traversal"}:
        entries.append((zipfile.ZipInfo("extra" if fault == "extra" else "../../escape"), b"injected"))
    elif fault == "duplicate":
        entries.append(next(item for item in entries if item[0].filename == target))
    else:
        for index, (info, raw) in enumerate(entries):
            if info.filename == ("web-composition/web-composition.json" if fault == "embedded-manifest" else target):
                if fault == "symlink":
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                else:
                    raw = b"x" * len(raw)
                entries[index] = (info, raw)
    changed = tmp_path / "changed.zip"
    with zipfile.ZipFile(changed, "w") as archive:
        for info, raw in entries:
            archive.writestr(info, raw)
    with pytest.raises(ValueError):
        composition.extract(changed, manifest, tmp_path / "extracted")


@pytest.mark.parametrize("fault", ["extra-file", "qualification", "identity"])
def test_composition_record_is_closed_and_does_not_invent_runtime_qualification(candidate, fault):
    kwargs, _, _, _ = candidate
    manifest = composition.package(**kwargs)
    if fault == "extra-file":
        manifest["files"]["execute.py"] = {"sha256": IMAGE_DIGEST, "bytes": 1}
    elif fault == "qualification":
        manifest["qualification"]["runtime_tested"] = True
    else:
        manifest["website"]["revision"] = "changed"
    with pytest.raises(ValueError):
        composition.validate_record(manifest)
