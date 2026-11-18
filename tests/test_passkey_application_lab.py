"""Failure containment for the opt-in real application qualification fixture."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def lab(tmp_path, monkeypatch):
    (tmp_path / "generated-lab-settings.json").write_text("{}")
    config = ModuleType("config")
    config.ROOT, config.OUT, config.IMAGE = ROOT, tmp_path, "synthetic-image"
    monkeypatch.setitem(sys.modules, "config", config)
    spec = importlib.util.spec_from_file_location(
        "passkey_application_bootstrap_test",
        ROOT / "scripts/passkey_application_lab/bootstrap.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, module.ApplicationLab({"network": "marty-keycloak-kms-net-test"})


@pytest.mark.parametrize("mismatch", ["name", "label", "network"])
def test_cleanup_refuses_unowned_container(lab, monkeypatch, mismatch):
    module, fixture = lab
    name = fixture.prefix + "-gateway"
    state = {
        "Config": {"Labels": {"marty.test": "passkey-application"}},
        "NetworkSettings": {"Networks": {fixture.context["network"]: {}}},
    }
    if mismatch == "name":
        name = "unrelated-runtime"
    elif mismatch == "label":
        state["Config"]["Labels"]["marty.test"] = "another-owner"
    else:
        state["NetworkSettings"]["Networks"] = {"another-network": {}}
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=0, stdout=json.dumps([state]), stderr=""
        ),
    )
    removed = []
    monkeypatch.setattr(module.native, "docker", lambda *a, **k: removed.append(a))
    with pytest.raises(AssertionError):
        fixture.cleanup_container(name)
    assert removed == []


def test_cleanup_accepts_removed_migration_but_reports_inspection_failure(
    lab, monkeypatch
):
    module, fixture = lab
    name = fixture.prefix + "-migration-bootstrap"
    result = SimpleNamespace(
        returncode=1, stdout="", stderr="No such container: " + name
    )
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: result)
    fixture.cleanup_container(name)
    result.stderr = "Cannot connect to the Docker daemon"
    with pytest.raises(RuntimeError, match="Could not inspect"):
        fixture.cleanup_container(name)


def test_timed_out_migration_is_registered_for_finally_cleanup(lab, monkeypatch):
    module, fixture = lab

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("docker", 180)

    monkeypatch.setattr(module.subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        fixture.run_binary("marty-migration-bootstrap", {})
    assert fixture.created == [fixture.prefix + "-migration-bootstrap"]
