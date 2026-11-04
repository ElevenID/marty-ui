"""Host transitions use real Compose rendering and simulated Docker mutations."""
from __future__ import annotations

from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml

from tests.test_package_web_composition import candidate, write_json, WEBSITE_SOURCE
import deploy_website as deploy
import package_web_composition as composition
import ui_release as ui
import website_release as web


class Host:
    def __init__(self, directory, manifest, model):
        self.directory = directory / ".marty-website"
        self.base = directory / "base.yml"
        model = copy.deepcopy(model)
        for name, image in manifest["images"].items():
            model["services"][name]["image"] = image
        # Public-only configuration is copied; application credentials stay out.
        model["services"]["ui"]["environment"].update(API_PASSWORD="never-copy", GOOGLE_SITE_VERIFICATION="public-proof")
        self.base.write_text(yaml.safe_dump(model))
        self.bao = manifest["openbao_didcomm_image"]
        self.events = []
        self.fail = None
        self.tamper_overlay = False

    def identity(self):
        return {"stack_directory": str(self.directory.parent), "project": "host-test"}

    def model(self, *, overlay=None):
        executable = os.environ.get("MARTY_INSTALLER_COMPOSE_EXECUTABLE")
        command = [executable] if executable else ["docker", "compose"]
        command += ["--project-name", "host-test", "-f", str(self.base)]
        if overlay:
            command += ["-f", str(overlay)]
        result = json.loads(subprocess.run(command + ["config", "--format", "json"], check=True,
                                           capture_output=True, text=True).stdout)
        if overlay and self.tamper_overlay:
            result["services"]["gateway"]["image"] = "example.invalid/changed@sha256:" + "a" * 64
        return result

    def snapshot(self, expected=None):
        model = self.model()
        images = {name: service["image"] for name, service in model["services"].items()}
        result = {"images": images, "openbao_didcomm_image": self.bao,
                  "configuration_sha256": ui.digest(ui.canonical({"model": model, "bao": self.bao}))}
        if expected:
            ui.require(images == expected["images"] and self.bao == expected["openbao_didcomm_image"],
                       "current product does not match selected composition")
        return result, model

    def event(self, name, *data):
        self.events.append((name, *data))
        if self.fail == name:
            self.fail = None
            raise ValueError("injected " + name + " failure")

    def stage(self, slot, overlay, metadata, *, pull=True):
        self.event("stage", slot, pull, metadata["revision"])

    def activate(self, overlay, *, initial=False):
        self.event("activate", initial)

    def stop_candidate(self, slot, overlay):
        self.event("stop", slot)

    def check_public(self, metadata):
        self.event("public", metadata["revision"])


@pytest.fixture
def host_candidate(candidate, tmp_path):
    kwargs, calls, _, model = candidate
    manifest = composition.package(**kwargs)
    for name in ("web-composition.json", "web-composition.zip"):
        for suffix in (".sigstore.json", ".provenance.jsonl"):
            (kwargs["output"] / (name + suffix)).write_bytes(b"outer proof fixture")
    host = Host(tmp_path, manifest, model)
    verifiers = {key: kwargs[key] for key in ("gh", "cosign")}
    return host, kwargs, manifest, calls, verifiers


def another_release(kwargs, source):
    root = kwargs["website_assets"].parent / "source"
    plan = web.plan(root, source)
    release = web.record(root, plan, source_sha=source, metadata=web.image_metadata(plan),
                         digest="sha256:" + source[0] * 64, run_id="200", run_attempt="1")
    write_json(kwargs["website_assets"] / "website-release.json", release)
    selected = {**kwargs, "output": kwargs["output"].parent / ("output-" + source)}
    manifest = composition.package(**selected)
    for name in ("web-composition.json", "web-composition.zip"):
        for suffix in (".sigstore.json", ".provenance.jsonl"):
            (selected["output"] / (name + suffix)).write_bytes(b"outer proof fixture")
    return selected["output"], manifest


def test_three_slots_retain_active_previous_assets_and_never_change_product(host_candidate):
    host, kwargs, manifest, _, verifiers = host_candidate
    before, _ = host.snapshot()
    first = deploy.apply(host, kwargs["output"], **verifiers)
    assert first["active"] == "website-a" and first["previous"] is None
    for source, slot, previous in (("c" * 40, "website-b", "website-a"),
                                   ("d" * 40, "website-c", "website-b"),
                                   ("e" * 40, "website-a", "website-c")):
        assets, _ = another_release(kwargs, source)
        state = deploy.apply(host, assets, **verifiers)
        assert (state["active"], state["previous"]) == (slot, previous)
        assert state["product"] == before
        routes = (host.directory / "routes/active.conf").read_text()
        assert f"location ^~ /_website/{source}/" in routes
        assert f"location ^~ /_website/{state['slots'][previous]['revision']}/" in routes
        assert "location = /resources {" in routes and "location = /resources/ {" not in routes
        assert "location = /login" not in routes and "location ^~ /_website/ {\n    return 404;" in routes
        overlay = web.read(host.directory / "compose.website.json")
        assert overlay["services"][slot]["environment"] == {"ORGANIZATION_CREATION_ENABLED": "true", "GOOGLE_SITE_VERIFICATION": "public-proof"}
        assert not overlay["services"][slot].get("depends_on")
    assert (host.snapshot()[0]) == before
    assert not (host.directory / "transaction.json").exists()
    assert [event[1] for event in host.events if event[0] == "stage"] == list(deploy.SLOTS) + ["website-a"]


def test_exact_active_release_is_idempotent_and_conflicting_revision_rejected(host_candidate):
    host, kwargs, _, _, verifiers = host_candidate
    first = deploy.apply(host, kwargs["output"], **verifiers)
    host.events.clear()
    assert deploy.apply(host, kwargs["output"], **verifiers) == first
    assert host.events == [("public", WEBSITE_SOURCE)]
    assets, _ = another_release(kwargs, WEBSITE_SOURCE)
    host.events.clear()
    with pytest.raises(ValueError, match="different immutable evidence"):
        deploy.apply(host, assets, **verifiers)
    assert host.events == [] and deploy.read_state(host.directory) == first


@pytest.mark.parametrize("operation", ["stage", "activate", "public"])
def test_failed_candidate_restores_verified_previous_selection(host_candidate, operation):
    host, kwargs, _, _, verifiers = host_candidate
    first = deploy.apply(host, kwargs["output"], **verifiers)
    before_routes = (host.directory / "routes/active.conf").read_bytes()
    before_overlay = (host.directory / "compose.website.json").read_bytes()
    assets, _ = another_release(kwargs, "c" * 40)
    host.events.clear()
    host.fail = operation
    with pytest.raises(ValueError, match="previous selection was restored"):
        deploy.apply(host, assets, **verifiers)
    assert deploy.read_state(host.directory) == first
    assert (host.directory / "routes/active.conf").read_bytes() == before_routes
    assert (host.directory / "compose.website.json").read_bytes() == before_overlay
    assert host.events[-1] == ("stop", "website-b")
    assert not (host.directory / "transaction.json").exists()


def test_overlay_validation_precedes_any_docker_mutation(host_candidate):
    host, kwargs, _, _, verifiers = host_candidate
    host.tamper_overlay = True
    with pytest.raises(ValueError, match="changes product"):
        deploy.apply(host, kwargs["output"], **verifiers)
    assert host.events == []
    assert deploy.read_state(host.directory) is None
    assert not (host.directory / "transaction.json").exists()


def test_website_rollback_retains_independently_upgraded_product_after_explicit_adoption(host_candidate, monkeypatch):
    host, kwargs, manifest, _, verifiers = host_candidate
    first = deploy.apply(host, kwargs["output"], **verifiers)
    assets, _ = another_release(kwargs, "c" * 40)
    second = deploy.apply(host, assets, **verifiers)
    model = yaml.safe_load(host.base.read_text())
    model["services"]["gateway"]["image"] = "ghcr.io/elevenid/gateway@sha256:" + "9" * 64
    model["services"]["ui"]["image"] = ui.PUBLIC_IMAGE + "@sha256:" + "8" * 64
    host.base.write_text(yaml.safe_dump(model))
    host.bao = "ghcr.io/elevenid/openbao@sha256:" + "7" * 64
    host.events.clear()
    with pytest.raises(ValueError, match="adopt the upgraded product"):
        deploy.rollback(host, **verifiers)
    assert host.events == []
    updated = copy.deepcopy(manifest)
    snapshot, _ = host.snapshot()
    updated.update(images=snapshot["images"], openbao_didcomm_image=snapshot["openbao_didcomm_image"])
    # The cryptographic composition boundary is covered above and in its own suite;
    # this injection isolates the adoption transaction after a real product change.
    @contextmanager
    def upgraded(*_args, **_kwargs):
        yield updated, kwargs["website_assets"].parent
    monkeypatch.setattr(composition, "verified_package", upgraded)
    adopted = deploy.apply(host, assets, adopt_current_product=True, **verifiers)
    assert adopted["active"] == second["active"] and adopted["previous"] == first["active"]
    assert host.events == []
    rolled = deploy.rollback(host, **verifiers)
    assert rolled["active"] == first["active"] and rolled["product"] == snapshot
    assert host.events[0] == ("stage", "website-a", False, WEBSITE_SOURCE)
    assert host.snapshot()[0] == snapshot


def test_interrupted_activation_retains_journal_and_recovery_checks_original_receipt(host_candidate, monkeypatch):
    host, kwargs, _, _, verifiers = host_candidate
    first = deploy.apply(host, kwargs["output"], **verifiers)
    assets, _ = another_release(kwargs, "c" * 40)
    def broken(*_args, **_kwargs):
        raise ValueError("edge unavailable")
    monkeypatch.setattr(host, "activate", broken)
    with pytest.raises(ValueError, match="rollback needs recovery"):
        deploy.apply(host, assets, **verifiers)
    assert (host.directory / "transaction.json").exists()
    with pytest.raises(ValueError, match="unfinished website transaction"):
        deploy.apply(host, assets, **verifiers)
    monkeypatch.setattr(host, "activate", Host.activate.__get__(host))
    assert deploy.recover(host, **verifiers) == first
    assert not (host.directory / "transaction.json").exists()
    assert host.events[-1] == ("stop", "website-b")


def test_committed_activation_cleanup_never_reverts_new_state(host_candidate, monkeypatch):
    host, kwargs, _, _, verifiers = host_candidate
    actual_write = deploy.atomic_write
    failed = False
    def interrupt_cleanup(path, payload):
        nonlocal failed
        if path.name == "transaction.json" and payload is None and not failed:
            failed = True
            raise OSError("interrupted cleanup")
        actual_write(path, payload)
    monkeypatch.setattr(deploy, "atomic_write", interrupt_cleanup)
    with pytest.raises(ValueError, match="activation committed"):
        deploy.apply(host, kwargs["output"], **verifiers)
    state = deploy.read_state(host.directory)
    assert state["active"] == "website-a" and (host.directory / "transaction.json").exists()
    assert not any(event[0] == "stop" for event in host.events)
    assert deploy.recover(host, **verifiers) == state
    assert not (host.directory / "transaction.json").exists()


def test_host_lock_and_symlink_receipts_fail_closed(host_candidate, tmp_path):
    host, kwargs, _, _, verifiers = host_candidate
    with deploy.host_lock(host.directory):
        with pytest.raises(ValueError, match="locked"):
            deploy.apply(host, kwargs["output"], **verifiers)
    deploy.apply(host, kwargs["output"], **verifiers)
    receipt = host.directory / "receipts" / WEBSITE_SOURCE / "website-release.json"
    receipt.unlink()
    receipt.symlink_to(kwargs["website_assets"] / "website-release.json")
    with pytest.raises(ValueError, match="non-symlink"):
        deploy.apply(host, kwargs["output"], **verifiers)


@pytest.mark.parametrize("value", ["https://user:secret@example.org", "https://example.org/login", "https://example.org?x=1", "https://example.org/#fragment", "https://example.org\\@evil.org", " https://example.org", "file:///tmp"])
def test_origin_rejects_ambiguous_or_credentialed_targets(value):
    with pytest.raises(ValueError):
        deploy.origin(value)


def test_runtime_inspection_checks_configured_and_installed_image_identity(tmp_path, monkeypatch):
    paths = [tmp_path / name for name in ("compose.yml", "env", "bao.yml", "bao.env")]
    for path in paths:
        path.write_text("nonempty fixture")
    host = deploy.DockerHost(stack=tmp_path, project="test", compose_files=[paths[0]], env_file=paths[1],
                             openbao_file=paths[2], openbao_env_file=paths[3], openbao_project="test-bao",
                             public_origin="https://example.org/")
    image = "ghcr.io/elevenid/gateway@sha256:" + "1" * 64
    container = {"Config": {"Labels": {"com.docker.compose.service": "gateway", "com.docker.compose.project": "test"},
                            "Image": image}, "Image": "sha256:" + "2" * 64}
    calls = []
    def run(args, **_kwargs):
        calls.append(args)
        if "ps" in args:
            return "a" * 64 + "\n"
        if args[:3] == ["docker", "image", "inspect"]:
            return json.dumps([{"Id": "sha256:" + "2" * 64}])
        return json.dumps([container])
    monkeypatch.setattr(host, "run", run)
    host.inspect_current({"gateway": image})
    assert calls[0][-4:] == ["ps", "--all", "--quiet", "gateway"]
    container["Image"] = "sha256:" + "3" * 64
    with pytest.raises(ValueError, match="image bytes differ"):
        host.inspect_current({"gateway": image})
    container["Config"]["Image"] = "ghcr.io/elevenid/gateway:latest"
    with pytest.raises(ValueError, match="configured digest"):
        host.inspect_current({"gateway": image})
