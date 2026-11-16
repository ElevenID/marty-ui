"""Adapter controls only; no requests, containers or demo qualification."""
from copy import deepcopy
from types import SimpleNamespace
import hashlib
import json
import pytest
from scripts import beta_passport_functional_audit as audit
from scripts import probe_passport_beta_host as host

from scripts.bind_deployed_demo_manifest import bind_manifest
from scripts.create_demo_manifest_draft import build_manifest


def manifest_fixture():
    source = "225818494f4ba716e75df7225d6c43d71b038879"
    return bind_manifest(build_manifest(), dict(source_kind="signed-nightly-deployment",
        scope="FUNCTIONAL_ONLY", promotion_eligible=False, release_ready=False,
        release_version="local-d12-control", mip_version="0.5.0", marty_ui_sha=source,
        capture_recorder_revision="b"*40, repositories={"marty-ui":{"head_sha":source}},
        component_revisions=[dict(component="marty-ui", repository="https://github.com/ElevenID/marty-ui", revision=source)]),
        {"services":"sha256:"+"a"*64, "ui-prod":"sha256:"+"c"*64})

@pytest.fixture
def current(monkeypatch, tmp_path):
    source = "225818494f4ba716e75df7225d6c43d71b038879"
    roles = [dict(role=role, source=("b"*40 if role=="gateway" else source), containerId=f"{index:064x}",
        imageId="sha256:"+"a"*64, startedAt="fixed-generation", hostPid=index+1)
        for index,role in enumerate((*audit.ROLES,"ui-prod"),1)]
    observed = dict(schema="marty.canvas-functional-runtime-observation/v2", scope="FUNCTIONAL_ONLY",
        releaseQualified=False, recordingQualified=False, profileSha256="a"*64,
        binding=dict(schema="marty.functional-mixed-runtime-binding/v2", scope="FUNCTIONAL_ONLY",
            releaseQualified=False, recordingQualified=False, roles=roles))
    receipt=tmp_path / "observation.json"
    raw=json.dumps(observed).encode();receipt.write_bytes(raw)
    acknowledgement = dict(kind="FUNCTIONAL_RUNTIME_V2", profileSha256=observed["profileSha256"],
        receiptSha256=hashlib.sha256(raw).hexdigest(), scope="FUNCTIONAL_ONLY",
        releaseQualified=False, recordingQualified=False)
    for key in ("DEMO_LOCAL_NATIVE_OVERLAY_RECEIPT", "DEMO_LOCAL_NATIVE_LIVE_BINDING"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT", str(receipt))
    monkeypatch.setenv("DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256", acknowledgement["receiptSha256"])
    monkeypatch.setenv("RECORD_VIDEO", "0")
    capture = SimpleNamespace(native_runtime_binding=None, functional_runtime_binding=acknowledgement)
    containers, selected = {}, {}
    for row in observed["binding"]["roles"]:
        role = row["role"]
        if role not in audit.ROLES:
            continue
        env = dict(audit.FEATURES[role])
        if role == "passport-callback-signer":
            env.update(BAO_ADDR="https://openbao:8200", BAO_CACERT="/bao/public-ca/ca.crt", BAO_TOKEN_FILE="/bao/passport-callback/token")
        selected[role] = row["containerId"]
        containers[row["containerId"]] = dict(Id=row["containerId"], Image=row["imageId"],
            State=dict(Running=True, StartedAt=row["startedAt"], Pid=row["hostPid"], Health=dict(Status="healthy")), Config=dict(Env=[f"{k}={v}" for k,v in env.items()],
            Labels={"com.docker.compose.project":"elevenid-beta", "com.docker.compose.service":role}))
    kms = "e" * 64
    containers[kms] = dict(Id=kms, State=dict(Running=True), Config=dict(Labels={"com.docker.compose.project":"elevenid-beta", "com.docker.compose.service":"openbao"}))
    network = dict(Id="f"*64, Name=audit.CALLBACK_NETWORK, Internal=True,
        Labels={"com.docker.compose.project":"elevenid-beta", "com.docker.compose.network":"passport-callback-signing"},
        Containers={selected["passport-beta-bureau"]:{}, selected["passport-callback-signer"]:{}, kms:{}})
    def observe(*args):
        return [deepcopy(network if args[:2] == ("network", "inspect") else containers.get(args[1], {}))]
    return capture, observed, manifest_fixture(), containers, network, observe


def test_current_signed_manifest_and_mixed_role_identity_use_recorder_acknowledgement(current):
    capture, observed, manifest, _, _, observe = current
    result = audit.verify_functional_runtime(capture, observed, manifest, observe=observe)
    assert result["sourceId"] == "225818494f4ba716e75df7225d6c43d71b038879"
    assert set(result["containers"]) == set(audit.ROLES)
    assert result["nativeSources"]["gateway"] != result["nativeSources"]["passport-beta-bureau"]
    assert result["physicalClaim"] == "not_claimed"


@pytest.mark.parametrize("change", ["ack", "bytes", "manifest", "image", "generation", "flag", "network", "kms"])
def test_current_runtime_refuses_changed_authority_and_role_preconditions(current, change):
    capture, observed, manifest, containers, network, observe = current
    if change == "ack":
        capture.functional_runtime_binding = {**capture.functional_runtime_binding, "profileSha256":"0"*64}
    elif change == "bytes":
        observed["binding"]["roles"][0]["source"] = "0"*40
    elif change == "manifest":
        manifest["demo_application_revision"] = "0"*40
    elif change == "network":
        network["Internal"] = False
    else:
        role = "passport-callback-signer" if change == "kms" else "gateway"
        row = next(row for row in observed["binding"]["roles"] if row["role"] == role)
        item = containers[row["containerId"]]
        if change == "image":
            item["Image"] = "sha256:"+"0"*64
        elif change == "generation":
            item["State"]["Pid"] += 1
        elif change == "flag":
            item["Config"]["Env"] = []
        else:
            item["Config"]["Env"] = [entry for entry in item["Config"]["Env"] if not entry.startswith("BAO_TOKEN_FILE=")]
    with pytest.raises((audit.PassportPrerequisiteError, ValueError)):
        audit.verify_functional_runtime(capture, observed, manifest, observe=observe)


@pytest.fixture
def production_off():
    rows = {}
    for i, (project, services) in enumerate(host.REQUIRED_PRODUCTION_SERVICES.items()):
        for j, service in enumerate(sorted(services)):
            cid = str(i*4+j+1)*64
            rows[cid] = dict(Id=cid, Name="/owned-production-"+service, Image="sha256:"+"a"*64,
                Config=dict(Env=["PRIVATE_VALUE=synthetic"], Labels={"com.docker.compose.project":project,"com.docker.compose.service":service}),
                HostConfig={}, Mounts=[], NetworkSettings={}, RestartCount=0,
                State=dict(Running=False, Status="exited", Pid=0, Restarting=False, Paused=False, OOMKilled=False, StartedAt="fixed", ExitCode=0))
    baseline = dict(schema="marty.passport-production-baseline/v1", mode="EXPECTED_OFF",
        rows=sorted([host.production_off_projection(row) for row in rows.values()], key=lambda row:row["id"]))
    def runner(command):
        if command[1] == "ps":
            project=command[command.index("--filter")+1].rsplit("=",1)[1]
            return "\n".join(cid for cid,row in rows.items() if row["Config"]["Labels"]["com.docker.compose.project"]==project)
        assert command[1] == "inspect"
        return json.dumps([rows[command[2]]])
    return rows, baseline, runner


def test_explicit_off_snapshot_is_exact_and_legacy_required_running_stays_strict(production_off):
    _, baseline, runner = production_off
    before = host.production_snapshot(runner, expected_off=baseline)
    assert before == host.production_snapshot(runner, expected_off=baseline)
    assert before["mode"] == "EXPECTED_OFF"
    with pytest.raises(host.HostProbeError, match="Required production runtime"):
        host.production_snapshot(runner)


@pytest.mark.parametrize("change", ["running", "pid", "oom", "config", "image", "state", "extra", "missing", "mode"])
def test_expected_off_refuses_unexpected_state_and_exact_cohort_drift(production_off, change):
    rows, baseline, runner = production_off
    row = next(iter(rows.values()))
    if change == "running": row["State"].update(Running=True, Status="running")
    elif change == "pid": row["State"]["Pid"] = 99
    elif change == "oom": row["State"]["OOMKilled"] = True
    elif change == "config": row["Config"]["Env"] = ["PRIVATE_VALUE=changed"]
    elif change == "image": row["Image"] = "sha256:"+"b"*64
    elif change == "state": row["State"]["StartedAt"] = "new"
    elif change == "mode": baseline["mode"] = "ANY"
    elif change == "missing": rows.pop(row["Id"])
    else:
        new=deepcopy(row);new["Id"]="d"*64;rows[new["Id"]]=new
    with pytest.raises(host.HostProbeError):
        host.production_snapshot(runner, expected_off=baseline)


def test_off_fingerprint_canonicalizes_only_unique_inspected_mount_order(production_off):
    rows, _, runner = production_off
    row = next(iter(rows.values()))
    row["Mounts"] = [dict(Type="bind", Source="source-a", Destination="/b", RW=False, Propagation="rprivate"),
                     dict(Type="volume", Name="owned-data", Source="source-b", Destination="/a", RW=True)]
    row["Config"].update(Env=["A=one", "B=two"], Cmd=["server", "first", "second"])
    baseline = dict(schema="marty.passport-production-baseline/v1", mode="EXPECTED_OFF",
        rows=sorted([host.production_off_projection(item) for item in rows.values()], key=lambda item:item["id"]))
    before = host.production_snapshot(runner, expected_off=baseline)
    row["Mounts"].reverse()
    assert host.production_snapshot(runner, expected_off=baseline) == before
    for field, value in [("Source", "foreign-source"), ("RW", False), ("Mode", "changed-options")]:
        changed = deepcopy(row)
        changed["Mounts"][0][field] = value
        assert host.production_off_projection(changed) != host.production_off_projection(row)
    repeated = deepcopy(row)
    repeated["Mounts"].append(deepcopy(repeated["Mounts"][0]))
    with pytest.raises(host.HostProbeError, match="mounts"):
        host.production_off_projection(repeated)
    for field in ("Env", "Cmd"):
        changed = deepcopy(row)
        changed["Config"][field].reverse()
        assert host.production_off_projection(changed) != host.production_off_projection(row)
