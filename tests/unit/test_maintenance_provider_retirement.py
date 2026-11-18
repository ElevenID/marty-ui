"""Retired provider maintenance refuses before transport or authority access."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import beta_release_metadata as metadata
import scoped_northstar_fixture as northstar


def fresh_core():
    spec = importlib.util.spec_from_file_location("retirement_private_core", ROOT / "scripts/repair_beta_release_metadata.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("role", ["canvas-sync-worker", "CANVAS_SYNC_WORKER", "marty-canvas-sync-worker"])
def test_metadata_rejects_retired_roles_before_inspection(role):
    core = fresh_core()
    operation = core.Operation.__new__(core.Operation)
    operation.identities = {role: {}}
    operation.g = SimpleNamespace(inspect=lambda *args: pytest.fail("retired cohort reached transport"))
    with pytest.raises(ValueError, match="RETIRED_CONNECTOR_RUNTIME_ROLE"):
        operation.retained_twenty()


def test_marker_derivation_rejects_retired_roles():
    revision = "a" * 40
    lock = "\n".join('[[package]]\nname="' + name + '"\nversion="1"\nsource="git+https://example.test/' + name + '?rev=' + revision + '#' + revision + '"'
                     for name in ("marty-core", "marty-microservices-framework"))
    roles = [{"role": "retained-" + str(i)} for i in range(21)] + [{"role": "canvas-sync-worker"}]
    with pytest.raises(ValueError, match="RETIRED_CONNECTOR_RUNTIME_ROLE"):
        metadata.marker_maps(revision, lock.encode(), {"services": {}}, roles)


def test_retained_generic_service_requires_health():
    core = fresh_core()
    operation = core.Operation.__new__(core.Operation)
    rows = {}
    operation.identities = {}
    for i in range(22):
        role = "retained-" + str(i)
        operation.identities[role] = dict(containerId=role, imageId="image", reference="pinned", project="owned", hostPid=i + 1, startedAt="generation")
        rows[role] = dict(Id=role, Image="image", Config=dict(Image="pinned", Labels={"com.docker.compose.service": role, "com.docker.compose.project": "owned"}),
                          State=dict(Running=True, OOMKilled=False, Pid=i + 1, StartedAt="generation", Health={"Status": "healthy"}))
    operation.g = SimpleNamespace(inspect=lambda cid: rows[cid])
    operation.retained_twenty()
    for health in (None, {}, {"Status": "starting"}, {"Status": "unhealthy"}):
        rows["retained-0"]["State"]["Health"] = health
        with pytest.raises(ValueError, match="RETAINED_ROLE_UNHEALTHY"):
            operation.retained_twenty()


@pytest.mark.parametrize("mode", ["retired-scope", "retired-role"])
def test_northstar_rejects_before_configuration_or_transport_access(tmp_path, mode):
    core = fresh_core()
    cls = northstar.execution_type(core)
    assert cls.registration_snapshot is core.Operation.registration_snapshot
    assert cls.assert_registration_cohort is core.Operation.assert_registration_cohort
    config = {"protectedCohort": {}} if mode == "retired-scope" else {}
    identities = {} if mode == "retired-scope" else {"canvas-sync-worker": {}}
    expected = "RETIRED_PROVIDER_COHORT_NOT_SUPPORTED" if mode == "retired-scope" else "RETIRED_CONNECTOR_RUNTIME_ROLE"
    with pytest.raises(ValueError, match=expected):
        cls(config, tmp_path / "not-created", transport=None, identities=identities,
            representations=None, observe_external=None)
    assert not (tmp_path / "not-created").exists()


@pytest.mark.parametrize("name", ["_validate_scoped_result", "validate_scoped_registration_result"])
def test_old_scoped_receipts_cannot_fall_back_to_generic_admission(name):
    function = getattr(northstar, name)
    with pytest.raises(ValueError, match="RETIRED_PROVIDER_COHORT_NOT_SUPPORTED"):
        if name == "_validate_scoped_result":
            function({}, {}, "target", None)
        else:
            function({}, {}, None)


@pytest.mark.parametrize("action", ["provision", "revoke"])
def test_transit_cli_is_disabled_before_authority_input_access(tmp_path, action):
    source = tmp_path / "absent-private-input.json"
    result = subprocess.run([sys.executable, str(ROOT / "scripts/beta_external_transit_fixture.py"),
        "--input", str(source), "--sha256", "a" * 64, "--action", action], capture_output=True, text=True, timeout=15)
    assert result.returncode == 1
    assert json.loads(result.stdout)["code"] == "PLATFORM_NATIVE_RUNTIME_VERIFIER_PENDING"
    assert str(source) not in result.stdout + result.stderr
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("role", ["canvas-sync-worker", "CANVAS_SYNC_WORKER", "marty-canvas-sync-worker"])
def test_northstar_phase_guard_rejects_retired_roles_before_network_reads(role):
    cls = northstar.execution_type(fresh_core())
    operation = cls.__new__(cls)
    operation.identities = {role: {}}
    operation.g = SimpleNamespace(observe=lambda *args: pytest.fail("retired cohort reached network inspection"))
    with pytest.raises(ValueError, match="RETIRED_CONNECTOR_RUNTIME_ROLE"):
        operation.retained_twenty()


def test_northstar_retained_running_service_requires_health():
    core = fresh_core()
    cls = northstar.execution_type(core)
    core.load = lambda reference: reference
    operation = cls.__new__(cls)
    operation.networks = {}
    operation.identities = {}
    expected = {}
    for i in range(22):
        role = "retained-" + str(i)
        operation.identities[role] = dict(containerId=role, imageId="image", reference="pinned", project="owned")
        expected[role] = dict(Id=role, Image="image", Config=dict(Image="pinned", Labels={"com.docker.compose.service": role, "com.docker.compose.project": "owned"}),
            State=dict(Running=True, OOMKilled=False, Restarting=False, Pid=i + 1, StartedAt="generation", FinishedAt="", Health={"Status": "healthy"}))
    actual = deepcopy(expected)
    operation.c = {"retainedContainers": expected}
    operation.g = SimpleNamespace(old_guard=lambda row, running: actual[row["Id"]])
    operation.retained_twenty()
    for health in (None, {}, {"Status": "starting"}, {"Status": "unhealthy"}):
        actual["retained-0"]["State"]["Health"] = health
        with pytest.raises(ValueError, match="RETAINED_ROLE_UNHEALTHY"):
            operation.retained_twenty()
