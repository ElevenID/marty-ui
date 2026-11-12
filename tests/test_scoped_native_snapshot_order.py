"""Full-state order controls; synthetic inspections, no daemon, SQL or journal IO."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scoped_passport_maintenance as maintenance
import scoped_d12_native_execution as execution
from scoped_d12_native_effect_host import D12CurrentEffectObserver, D12CurrentHostBindings
from scoped_d12_native_host import D12ReadOnlyHost
from scoped_linux_journal import LinuxBuildJournal
from scoped_native_profiles import current_rollout_build
from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES, ref, sha

CURRENT = "d05-membership-current-functional"


def projections(profile=CURRENT):
    # Match the real retained receipt shape: 21 ELF roles followed by image UI.
    roles = [*sorted(D12_CURRENT_RUNTIME_ROLES - {"ui-prod"}), "ui-prod"]
    binding = {"roles": []}
    inspections = []
    for index, role in enumerate(roles):
        row = {"role": role, "containerId": f"{index+1:064x}", "imageId": "sha256:"+"b"*64,
               "project": "elevenid-beta-ui" if role == "ui-prod" else "elevenid-beta",
               "binary": None if role == "ui-prod" else "marty-"+role, "source": "a"*40,
               "sha256": None if role == "ui-prod" else "c"*64,
               "kind": "SIGNED_NIGHTLY_IMAGE" if role == "ui-prod" else "NATIVE_ELF",
               "health": "healthy", "startedAt": "2026-11-11T14:54:24Z", "hostPid": index+100,
               "executablePath": "/fixture/"+role, "processExecutableSha256": "c"*64,
               "binaryMounts": [], "effectiveUid": 10001, "configuredRuntimeUid": 10001,
               "effectiveGid": 10001, "configuredRuntimeGid": 10001}
        binding["roles"].append(row)
        inspections.append({"Id": row["containerId"], "Image": row["imageId"], "Mounts": [],
            "Config": {"Labels": {"com.docker.compose.project": row["project"],
                                   "com.docker.compose.service": role}},
            "State": {"StartedAt": row["startedAt"], "Pid": row["hostPid"], "Running": True,
                      "Paused": False, "Status": "running", "ExitCode": 0, "OOMKilled": False,
                      "Health": {"Status": "healthy"}}})
    retained = maintenance.with_observed_state(binding, inspections)
    host = D12ReadOnlyHost.__new__(D12ReadOnlyHost)
    host.before = maintenance.exact_roles(retained, profile)
    host.engine_id = "00000000-0000-4000-8000-000000000001"
    host._recheck_source = lambda: None
    def docker(args):
        if args == ["info", "--format", "{{.ID}}"]:
            return host.engine_id
        assert args[0] == "inspect" and set(args[1:]) == {r["Id"] for r in inspections}
        return json.dumps(inspections)
    host._docker = docker
    observer = D12CurrentEffectObserver(host, {}, LinuxBuildJournal.__new__(LinuxBuildJournal), None, profile)
    return retained, observer.inspect_all22()


@pytest.mark.parametrize("profile", ["d12-passport-current-functional", CURRENT])
def test_retained_ui_last_and_real_observer_order_compare_without_changing_receipts(profile):
    retained, observed = projections(profile)
    originals = deepcopy((retained, observed))
    assert retained["roles"][-1]["role"] == "ui-prod"
    assert observed["roles"][-1]["role"] == "verification"
    assert observed != retained  # This was the preflight's unavoidable refusal.
    assert maintenance.same_full_role_snapshot(observed, retained, profile)
    assert (retained, observed) == originals


@pytest.mark.parametrize("change", ["state", "source", "nested", "top", "extra"])
def test_every_state_source_and_metadata_field_still_compares(change):
    retained, observed = projections()
    retained["roles"][0]["additionalMetadata"] = {"owned": [1, 2]}
    observed = deepcopy(retained)
    observed["roles"].reverse()
    if change == "state": observed["roles"][0]["running"] = False
    if change == "source": observed["roles"][0]["source"] = "d"*40
    if change == "nested": observed["roles"][-1]["additionalMetadata"]["owned"].append(3)
    if change == "top": observed["releaseQualified"] = True
    if change == "extra": observed["unexpectedMetadata"] = True
    assert not maintenance.same_full_role_snapshot(observed, retained, CURRENT)


@pytest.mark.parametrize("change", ["missing", "duplicate-role", "duplicate-cid"])
def test_invalid_cohorts_are_refused_before_mapping(change):
    retained, observed = projections()
    if change == "missing": observed["roles"].pop()
    if change == "duplicate-role": observed["roles"][0]["role"] = observed["roles"][1]["role"]
    if change == "duplicate-cid": observed["roles"][0]["containerId"] = observed["roles"][1]["containerId"]
    with pytest.raises(ValueError, match="EXACT_22_ROLE_SET_REQUIRED|UNIQUE_BOUND_CONTAINER_IDS_REQUIRED"):
        maintenance.same_full_role_snapshot(observed, retained, CURRENT)


def test_real_preflight_accepts_order_and_reaches_next_database_guard(tmp_path, monkeypatch):
    retained, observed = projections()
    def save(name, value):
        path = tmp_path/name;path.write_text(json.dumps(value));return ref(path)
    build = current_rollout_build(CURRENT)
    runtime = save("runtime.json", retained)
    selection = save("selection.json", {})
    metadata = save("native-maintenance-metadata.js", {})
    functional = save("functional-debug-runtime.js", {})
    reader = save("d12-current-native-runtime.js", {})
    code = ref(execution.__file__)
    authority = save("authority.json", {"dispatchAuthorized": True, "runId": "run",
        "approvedExecutionSourceSha256": code["sha256"], "approvedMetadataModuleSha256": metadata["sha256"],
        "approvedFunctionalRuntimeSha256": functional["sha256"], "approvedRuntimeReaderSha256": reader["sha256"],
        "approvedProfileSourceSha256": sha(Path(execution.__file__).with_name("scoped_native_profiles.py")),
        "approvedSelectionSha256": selection["sha256"], "approvedRuntimeBeforeSha256": runtime["sha256"]})
    values = {"rolloutProfile": CURRENT, "runId": "run", "roleBinaries": dict(build.roles),
        "scope": "FUNCTIONAL_ONLY", "releaseQualified": False, "recordingQualified": False,
        "d12Authority": authority, "executionSource": code, "metadataModule": metadata,
        "functionalRuntimeModule": functional, "d12RuntimeModule": reader, "preparedSource": save("prepared.json", {}),
        "canonicalBuildReceipt": {}, "selection": selection, "runtimeBefore": runtime,
        "compatibility": {"plan": save("abi.json", {"beforeBinding": runtime, "nativeInspections": {}})}}
    monkeypatch.setattr(execution, "selected_sources", lambda *a: None)
    monkeypatch.setattr(execution, "select_current_binaries", lambda *a: {})
    monkeypatch.setattr(execution, "exact_exported_sql", lambda *a: None)
    calls = []
    def database():
        calls.append("database")
        raise RuntimeError("NEXT_DATABASE_GUARD_REACHED")
    context = {"dispatch_enabled": True, "operation_lock_held": lambda: True,
        "recording_lock_held": lambda: True, "authorization_verified": lambda _: True,
        "build_journal": object(), "observe22": lambda: observed, "database_snapshot": database}
    with pytest.raises(RuntimeError, match="NEXT_DATABASE_GUARD_REACHED"):
        execution.D12CurrentExecution(context, values, object()).preflight()
    assert calls == ["database"]


def test_quiescence_compares_full_state_across_order(tmp_path):
    retained, observed = projections()
    for snapshot in [retained, observed]:
        for row in snapshot["roles"]: row.update(state="exited", running=False, hostPid=0)
    path=tmp_path/'quiescent.json';path.write_text(json.dumps(retained));bound=ref(path)
    bindings=D12CurrentHostBindings.__new__(D12CurrentHostBindings)
    bindings.profile=CURRENT;bindings.assert_inputs=lambda: None
    bindings.store=SimpleNamespace(read=lambda _: {"phase":"ALL22_QUIESCENT","quiescenceSha256":bound['sha256']})
    bindings.observer=SimpleNamespace(inspect_all22=lambda: observed)
    assert bindings.verify_all22_quiescent(bound) is True
    observed['roles'][0]['oomKilled']=True
    with pytest.raises(ValueError,match='D12_QUIESCENCE_CHANGED_BEFORE_DATABASE'):
        bindings.verify_all22_quiescent(bound)
