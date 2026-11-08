"""Current D12 cohort stays distinct from the historical Canvas cohort."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES, RUNTIME_ROLES, ref, runtime_roles
from scoped_native_profiles import D12_PASSPORT_CURRENT
from scoped_d12_native_execution import D12CurrentExecution
import scoped_passport_maintenance as maintenance
from test_scoped_passport_maintenance import fixture, freeze_models

PROFILE = "d12-passport-current-functional"

def current_fixture(directory):
    plan, before, stopped, outcomes, models = fixture(directory)
    for snapshot in (before, stopped):
        next(row for row in snapshot["roles"] if row["role"] == "canvas-sandbox")["role"] = "event-stream"
    outcomes["event-stream"] = outcomes.pop("canvas-sandbox")
    models["elevenid-beta"]["services"]["event-stream"] = models["elevenid-beta"]["services"].pop("canvas-sandbox")
    old_policy = json.loads(Path(plan["stopContracts"].pop("canvas-sandbox")["path"]).read_text())
    old_policy["role"] = "event-stream"
    source = directory / "event-stream-source.json"
    proof = json.loads(Path(old_policy["sourceProof"]["path"]).read_text())
    proof["role"] = "event-stream"
    source.write_text(json.dumps(proof))
    old_policy["sourceProof"] = ref(source)
    policy = directory / "event-stream-stop.json"
    policy.write_text(json.dumps(old_policy))
    plan["stopContracts"]["event-stream"] = ref(policy)
    plan.update(rolloutProfile=PROFILE, buildProfile=None,
                uiRevision=D12_PASSPORT_CURRENT.ui_revision,
                coreRevision=D12_PASSPORT_CURRENT.core_revision,
                roleBinaries=dict(D12_PASSPORT_CURRENT.roles))
    freeze_models(plan, models, directory)
    return plan, before, stopped, outcomes, models

def test_current_cohort_previews_exact_event_stream_and_historical_default_remains(tmp_path):
    # Separate directories preserve immutable historical contracts.
    historical = tmp_path / "historical"
    historical.mkdir()
    old_plan, old_before, _, _, old_models = fixture(historical)
    assert "canvas-sandbox" in maintenance.preview(old_plan, old_before, old_models)["allStopRoles"]
    current = tmp_path / "current"
    current.mkdir()
    plan, before, stopped, outcomes, models = current_fixture(current)
    value = maintenance.preview(plan, before, models)
    assert len(value["allStopRoles"]) == 22
    assert set(value["allStopRoles"]) == D12_CURRENT_RUNTIME_ROLES
    assert "event-stream" in value["allStopRoles"] and "canvas-sandbox" not in value["allStopRoles"]
    assert maintenance.validate_quiescent(before, stopped, outcomes, PROFILE)["all22Quiescent"]
    assert len(maintenance.restore_commands(before, stopped, outcomes, value["restoreOrder"], PROFILE)["startPass"]) == 22
    assert runtime_roles(None) == RUNTIME_ROLES

def test_current_refuses_historical_role_substitution_and_unknown_profile(tmp_path):
    current = tmp_path / "current"
    current.mkdir()
    plan, before, stopped, outcomes, models = current_fixture(current)
    wrong = copy.deepcopy(before)
    next(row for row in wrong["roles"] if row["role"] == "event-stream")["role"] = "canvas-sandbox"
    with pytest.raises(ValueError, match="EXACT_22_ROLE_SET_REQUIRED"):
        maintenance.preview(plan, wrong, models)
    with pytest.raises(ValueError, match="EXACT_22_ROLE_SET_REQUIRED"):
        maintenance.validate_quiescent(wrong, stopped, outcomes, PROFILE)
    with pytest.raises(ValueError, match="UNREVIEWED_RUNTIME_ROLE_PROFILE"):
        runtime_roles("foreign")

def test_current_executor_inspects_event_stream_not_canvas_sandbox(tmp_path):
    current = tmp_path / "current"
    current.mkdir()
    _, before, _, _, _ = current_fixture(current)
    by_role = {row["role"]: row for row in before["roles"]}
    inspected = []
    executor = D12CurrentExecution({"inspect_role": lambda role: (inspected.append(role), by_role[role])[1]},
                                   {"runId": "00000000-0000-4000-8000-000000000001"}, object())
    assert len(executor.inspect_all22()["roles"]) == 22
    assert set(inspected) == D12_CURRENT_RUNTIME_ROLES


def test_current_executor_reaches_exact_current_22_start_ack_gate(tmp_path, monkeypatch):
    import scoped_beta_binary_overlay as overlay
    source = tmp_path / "current"
    source.mkdir()
    _, before, stopped, outcomes, _ = current_fixture(source)
    selected = dict(D12_PASSPORT_CURRENT.roles)
    for row in before["roles"]:
        if row["role"] in selected:
            binary = selected[row["role"]]
            row["binaryMounts"] = [{"destination": "/usr/local/bin/" + binary,
                                   "type": "bind", "source": "/old/" + binary, "writable": False}]
    for row in stopped["roles"]:
        row["binaryMounts"] = next(prior["binaryMounts"] for prior in before["roles"] if prior["role"] == row["role"])
    created = copy.deepcopy(stopped)
    binaries = {role: {"path": "/owned/" + binary, "sha256": "a" * 64}
                for role, binary in D12_PASSPORT_CURRENT.roles}
    for index, row in enumerate(created["roles"]):
        if row["role"] in binaries:
            row.update(containerId=f"{index + 101:064x}", state="created")
            row["binaryMounts"][0]["source"] = binaries[row["role"]]["path"]
    by_cid = {row["containerId"]: row for row in created["roles"]}
    saved = {}
    def save(name, value):
        file = tmp_path / name
        file.write_text(json.dumps(value))
        saved[name] = value
        return ref(file)
    barrier = {"fileFsync": True, "parentDirectory": {"supported": True, "synced": True}}
    class Journal:
        def exclusive(self, *args): return barrier
        def state(self, *args): return barrier
    class Database:
        identity = {"containerId": "b" * 64}
        engine_id = "engine"
        selection = {"binaries": binaries}
        commands = []
        def command(self, args):
            if args[:2] == ["docker", "inspect"]:
                cid = args[2]
                row = by_cid[cid]
                return json.dumps([{"Id": cid, "Image": row["imageId"],
                    "Config": {"Labels": {"com.docker.compose.project": row["project"],
                                           "com.docker.compose.service": row["role"]}},
                    "State": {"Status": "running", "Running": True, "OOMKilled": False,
                              "Pid": 500, "StartedAt": "2026-10-28T15:00:00Z"}}]).encode()
            return b""
        def run(self): return {"actual": "test-only"}
        def node(self, mode, **kwargs):
            assert mode == "verify"
            return {"sourceCommit": D12_PASSPORT_CURRENT.ui_revision,
                    "databaseIdentity": self.identity}
    plan = {"stopSteps": [{"role": row["role"], "containerId": row["containerId"],
                            "argv": ["docker", "stop", row["containerId"]]} for row in before["roles"]],
            "restoreOrder": sorted(D12_CURRENT_RUNTIME_ROLES)}
    stopped_by_role = {row["role"]: row for row in stopped["roles"]}
    context = {"save": save, "inspect_role": lambda role: stopped_by_role[role],
               "wait_all22_healthy": lambda deadline: False}
    executor = D12CurrentExecution(context, {"runId": "00000000-0000-4000-8000-000000000001",
                                               "selection": {"sha256": "a" * 64},
                                               "executorSource": {}, "composeArguments": {}, "runtimeBefore": {},
                                               "databaseBefore": {"sha256": "b" * 64}, "d12Authority": {}}, Journal())
    executor.preflight = lambda: (Database(), before, plan, {"path": "test-only"})
    snapshots = iter((stopped, created))
    executor.inspect_all22 = lambda: next(snapshots)
    monkeypatch.setattr(overlay, "compose_recreate_arguments", lambda *args, **kwargs: ["docker", "create"])
    with pytest.raises(ValueError, match="D12_ALL22_HEALTH_DEADLINE_REQUIRED"):
        executor.run()
    assert set(saved["d12-start-acks.private.json"]["acks"]) == D12_CURRENT_RUNTIME_ROLES
    assert "event-stream" in saved["d12-start-acks.private.json"]["acks"]
    assert "canvas-sandbox" not in saved["d12-start-acks.private.json"]["acks"]
